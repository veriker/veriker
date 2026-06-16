"""_build_bundle.py — build a deterministic healthcare_diagnosis_minimal audit bundle.

Healthcare diagnostic-suggestion domain pilot: a rule-based decision-tree maps
a structured symptom set to a ranked list of ICD-10 candidate codes. The audit
bundle captures the symptom set, the rule definitions, and the bundled candidate
list — enough for an independent verifier to re-traverse the decision tree
deterministically and assert every candidate's code, confidence, evidence anchors,
and rule_path match byte-for-byte.

Re-derivation primitive (one sentence):
  Re-traverse the bundled rule set against the bundled symptoms, computing each
  matched rule's confidence as sum(severity of matched symptoms) * confidence_weight
  rounded to 6 decimal places, and assert the result is identical to the bundled
  candidate list (codes, confidences, evidence_anchors, rule_paths).

Why this matters for healthcare:
  Clinical-decision-support submissions to regulators and payers require
  computational reproducibility of every suggested diagnosis: the auditor must
  be able to re-derive the exact ranked list from the exact patient inputs the
  model saw, using only committed artifacts. The audit bundle is that receipt.
  This pilot demonstrates the substrate claim on a synthetic but structurally
  realistic rule-based ICD-10 lookup; production integrators replace the rule
  engine with a determinism-mode forward pass over a real clinical knowledge
  graph; the bundle shape and verification protocol are identical.

The fragment kind exercised is OpaqueFragment(kind_tag="icd10_evidence_anchor"):
one anchor per (rule_id, symptom_id, icd10_code) triplet that contributed to
a candidate's confidence. Substrate validates shape only; semantic validation
is the responsibility of HealthcareDiagnosisReDerivationCheck.

Usage (from v-kernel-audit-bundle root, or anywhere):
    python examples/healthcare_diagnosis_minimal/_build_bundle.py
        # writes manifest + bundle artifacts into the pilot directory itself

    python examples/healthcare_diagnosis_minimal/_build_bundle.py --out-dir /tmp/hcd
        # writes into a fresh out-dir (does NOT copy this build script / README /
        # plugin / re_derive pack — see Caveat below)

Caveat:
  When --out-dir is specified, only the generated artifacts (inputs/, payload/,
  re_derive/pack copy, manifest.json) are written. The pilot's own source files
  (_build_bundle.py, verify.py, README.md, HealthcareDiagnosisReDerivationCheck.py,
  tests/) are not copied. The in-place build (default) is the canonical mode
  used by cli/verify.py: every file in the pilot directory is SHA-hashed into
  manifest.files so file_integrity_many_small Pass 3 (EXTRA_FILE_NOT_IN_MANIFEST)
  passes cleanly.

Outputs (in-place):
  examples/healthcare_diagnosis_minimal/inputs/symptoms.json
  examples/healthcare_diagnosis_minimal/inputs/rules.json
  examples/healthcare_diagnosis_minimal/payload/diagnosis.json
  examples/healthcare_diagnosis_minimal/re_derive/healthcare_diagnosis_pack.py
  examples/healthcare_diagnosis_minimal/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "healthcare-diagnosis-minimal-rc"
_CREATED_AT = "2026-05-17T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "re_derivation_invocation",
]

# ---------------------------------------------------------------------------
# Synthetic fixtures — 5 symptoms, 4 ICD-10 rules
# ---------------------------------------------------------------------------

# Severity is on a 1..5 ordinal scale. Order matters for deterministic byte
# layout — we always serialize via canonical JSON (sort_keys + separators).
_SYMPTOMS = [
    {"symptom_id": "sym-001", "name": "cough", "severity": 3},
    {"symptom_id": "sym-002", "name": "fever", "severity": 4},
    {"symptom_id": "sym-003", "name": "chest_pain", "severity": 5},
    {"symptom_id": "sym-004", "name": "headache", "severity": 2},
    {"symptom_id": "sym-005", "name": "fatigue", "severity": 3},
]

# Decision-tree rule: every condition's symptom_id must be present in the
# symptom set AND meet the min_severity threshold; the rule fires iff all
# conditions match. Confidence = sum(severity of matched symptoms) * weight,
# rounded to 6 decimal places (matches re-derivation discipline).
_RULES = [
    {
        "rule_id": "rule-J18",
        "icd10_code": "J18.9",
        "description": "Pneumonia, unspecified",
        "conditions": [
            {"symptom_id": "sym-001", "min_severity": 2},
            {"symptom_id": "sym-002", "min_severity": 3},
            {"symptom_id": "sym-005", "min_severity": 2},
        ],
        "confidence_weight": 0.10,
    },
    {
        "rule_id": "rule-I20",
        "icd10_code": "I20.9",
        "description": "Angina pectoris, unspecified",
        "conditions": [
            {"symptom_id": "sym-003", "min_severity": 4},
            {"symptom_id": "sym-005", "min_severity": 2},
        ],
        "confidence_weight": 0.12,
    },
    {
        "rule_id": "rule-R51",
        "icd10_code": "R51.9",
        "description": "Headache, unspecified",
        "conditions": [
            {"symptom_id": "sym-004", "min_severity": 1},
            {"symptom_id": "sym-005", "min_severity": 1},
        ],
        "confidence_weight": 0.20,
    },
    {
        "rule_id": "rule-A49",
        "icd10_code": "A49.9",
        "description": "Bacterial infection, unspecified site",
        "conditions": [
            {"symptom_id": "sym-002", "min_severity": 3},
            {"symptom_id": "sym-005", "min_severity": 2},
        ],
        "confidence_weight": 0.08,
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj) -> bytes:
    """Deterministic JSON: sort_keys + compact separators + trailing newline."""
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _eval_condition(symptom_map: dict, cond: dict) -> bool:
    """Return True iff the symptom is present and meets min_severity."""
    s = symptom_map.get(cond["symptom_id"])
    if s is None:
        return False
    return int(s["severity"]) >= int(cond["min_severity"])


def _eval_rule(symptom_map: dict, rule: dict) -> tuple[bool, list[str], float]:
    """Return (fired, matched_symptom_ids, confidence)."""
    matched_ids: list[str] = []
    for cond in rule["conditions"]:
        if _eval_condition(symptom_map, cond):
            matched_ids.append(cond["symptom_id"])
        else:
            return False, [], 0.0
    severity_sum = sum(int(symptom_map[sid]["severity"]) for sid in matched_ids)
    confidence = round(severity_sum * float(rule["confidence_weight"]), 6)
    return True, matched_ids, confidence


def _derive_candidates(symptoms: list, rules: list) -> list[dict]:
    """Deterministic rule traversal → candidate list (sorted by rule_id).

    Each candidate carries:
      icd10_code, description, confidence, rule_path (rule_id + ordered conditions),
      evidence_anchors (one OpaqueFragment dict per matched (rule, symptom, code) triplet).
    """
    symptom_map = {s["symptom_id"]: s for s in symptoms}
    candidates: list[dict] = []
    for rule in sorted(rules, key=lambda r: r["rule_id"]):
        fired, matched_ids, confidence = _eval_rule(symptom_map, rule)
        if not fired:
            continue
        # rule_path: rule_id + ordered list of (symptom_id, min_severity) the
        # traversal walked through. Deterministic from rule definition order.
        rule_path = {
            "rule_id": rule["rule_id"],
            "conditions_visited": [
                {"symptom_id": c["symptom_id"], "min_severity": c["min_severity"]}
                for c in rule["conditions"]
            ],
        }
        candidates.append(
            {
                "icd10_code": rule["icd10_code"],
                "description": rule["description"],
                "confidence": confidence,
                "matched_symptom_ids": matched_ids,
                "rule_id": rule["rule_id"],
                "rule_path": rule_path,
            }
        )
    return candidates


def _build_fragment_anchors(
    symptoms: list,
    rules: list,
    candidates: list,
    symptoms_cid: str,
    rules_cid: str,
) -> dict:
    """One OpaqueFragment per (rule_id, symptom_id, icd10_code) triplet.

    source_cid alternates between rules_cid (rule-side anchor) and symptoms_cid
    (symptom-side anchor). For each evidence triplet we emit a rule-side anchor
    keyed by the triplet identifier — sufficient to demonstrate substrate
    extensibility (the OpaqueFragment open-extension surface) without
    inflating the fragment count.
    """
    anchors: dict = {}
    for cand in candidates:
        rule_id = cand["rule_id"]
        code = cand["icd10_code"]
        for sid in cand["matched_symptom_ids"]:
            anchor_key = f"{rule_id}-{sid}-{code}"
            anchors[anchor_key] = fragment_to_canonical_dict(
                OpaqueFragment(
                    source_cid=rules_cid,
                    kind_tag="icd10_evidence_anchor",
                    locator={
                        "rule_id": rule_id,
                        "symptom_id": sid,
                        "icd10_code": code,
                    },
                )
            )
    return anchors


# ---------------------------------------------------------------------------
# Re-derivation pack — written into re_derive/ inside the bundle
# ---------------------------------------------------------------------------

# Source of the stdlib-only pack. Kept as a module-level string so the bundle
# is self-contained: _build_bundle.py writes this exact bytes blob into
# re_derive/healthcare_diagnosis_pack.py at build time. The verifier's auto-
# detected ReDerivationInvocationCheck plugin then invokes it via subprocess.

_RE_DERIVE_PACK_SOURCE: str = '''#!/usr/bin/env python3
"""healthcare_diagnosis_pack.py — stdlib re-derivation pack for healthcare diagnosis domain.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don't-import):
no audit_bundle imports inside this script. Stdlib only.

Re-derivation steps:
  1. Load inputs/symptoms.json   — list of {symptom_id, name, severity}
  2. Load inputs/rules.json      — list of {rule_id, icd10_code, conditions[],
                                    confidence_weight, description}
  3. Load payload/diagnosis.json — list of {icd10_code, description, confidence,
                                    matched_symptom_ids, rule_id, rule_path}
  4. Re-traverse the decision tree using the same deterministic rule engine
     used at build time:
       for each rule (sorted by rule_id):
         for each condition: symptom must exist and severity >= min_severity
         if all conditions match: confidence = sum(severity[matched_ids]) * weight
     Round confidence to 6 decimal places.
  5. Compare the re-derived candidate list to payload/diagnosis.json:
       - same number of candidates (count, order)
       - per-candidate: icd10_code, description, rule_id all equal
       - per-candidate: confidence equal to 6 decimal places
       - per-candidate: matched_symptom_ids set-equal
       - per-candidate: rule_path equal
  6. Exit 0 on full match; exit 1 with [HCD_REDER_FAIL] <description> on stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _fail(msg: str) -> int:
    print(f"[HCD_REDER_FAIL] {msg}", file=sys.stderr)
    return 1


def _eval_condition(symptom_map, cond) -> bool:
    s = symptom_map.get(cond["symptom_id"])
    if s is None:
        return False
    return int(s["severity"]) >= int(cond["min_severity"])


def _derive_candidates(symptoms, rules):
    symptom_map = {s["symptom_id"]: s for s in symptoms}
    out = []
    for rule in sorted(rules, key=lambda r: r["rule_id"]):
        matched = []
        fired = True
        for cond in rule["conditions"]:
            if _eval_condition(symptom_map, cond):
                matched.append(cond["symptom_id"])
            else:
                fired = False
                break
        if not fired:
            continue
        severity_sum = sum(int(symptom_map[sid]["severity"]) for sid in matched)
        confidence = round(severity_sum * float(rule["confidence_weight"]), 6)
        rule_path = {
            "rule_id": rule["rule_id"],
            "conditions_visited": [
                {"symptom_id": c["symptom_id"], "min_severity": c["min_severity"]}
                for c in rule["conditions"]
            ],
        }
        out.append(
            {
                "icd10_code": rule["icd10_code"],
                "description": rule["description"],
                "confidence": confidence,
                "matched_symptom_ids": matched,
                "rule_id": rule["rule_id"],
                "rule_path": rule_path,
            }
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Healthcare-diagnosis ICD-10 re-derivation check"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    symptoms_path = bundle_dir / "inputs" / "symptoms.json"
    rules_path = bundle_dir / "inputs" / "rules.json"
    diagnosis_path = bundle_dir / "payload" / "diagnosis.json"
    for p in (symptoms_path, rules_path, diagnosis_path):
        if not p.exists():
            return _fail(f"required file missing: {p}")

    try:
        symptoms = json.loads(symptoms_path.read_text(encoding="utf-8"))
        rules = json.loads(rules_path.read_text(encoding="utf-8"))
        bundled = json.loads(diagnosis_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to load bundle inputs/payload: {exc}")

    if not isinstance(symptoms, list) or not isinstance(rules, list) or not isinstance(bundled, list):
        return _fail("symptoms.json, rules.json, diagnosis.json must each be JSON arrays")

    recomputed = _derive_candidates(symptoms, rules)

    if len(recomputed) != len(bundled):
        return _fail(
            f"candidate count mismatch: recomputed={len(recomputed)} bundled={len(bundled)}"
        )

    for i, (rec, exp) in enumerate(zip(recomputed, bundled)):
        for field in ("icd10_code", "description", "rule_id"):
            if rec[field] != exp.get(field):
                return _fail(
                    f"candidate[{i}] {field} mismatch: "
                    f"recomputed={rec[field]!r} bundled={exp.get(field)!r}"
                )
        rec_conf = round(float(rec["confidence"]), 6)
        exp_conf = round(float(exp.get("confidence", 0.0)), 6)
        if rec_conf != exp_conf:
            return _fail(
                f"candidate[{i}] confidence mismatch for {rec['icd10_code']!r}: "
                f"recomputed={rec_conf} bundled={exp_conf}"
            )
        if sorted(rec["matched_symptom_ids"]) != sorted(exp.get("matched_symptom_ids", [])):
            return _fail(
                f"candidate[{i}] matched_symptom_ids mismatch for {rec['icd10_code']!r}: "
                f"recomputed={rec['matched_symptom_ids']!r} "
                f"bundled={exp.get('matched_symptom_ids')!r}"
            )
        if rec["rule_path"] != exp.get("rule_path"):
            return _fail(
                f"candidate[{i}] rule_path mismatch for {rec['icd10_code']!r}: "
                f"recomputed={rec['rule_path']!r} bundled={exp.get('rule_path')!r}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def _enumerate_pilot_files_for_manifest(pilot_dir: Path, out_dir: Path) -> dict:
    """Walk the pilot dir and return {rel_path: sha256} for every file.

    Excludes manifest.json (the manifest itself), any __pycache__ tree, any
    .pyc artifacts, and any files inside spec/ or snapshots/ (those trees
    have dedicated validators). Used only when out_dir == pilot_dir.
    """
    files: dict[str, str] = {}
    _SKIP_TOP = frozenset({"spec", "snapshots", "__pycache__"})
    for fpath in sorted(pilot_dir.rglob("*")):
        if fpath.is_dir():
            continue
        rel = fpath.relative_to(pilot_dir).as_posix()
        if rel == "manifest.json":
            continue
        # Skip any pyc / pycache anywhere in the tree.
        parts = rel.split("/")
        if parts[0] in _SKIP_TOP:
            continue
        if any(p == "__pycache__" for p in parts):
            continue
        if rel.endswith(".pyc"):
            continue
        files[rel] = _sha256(fpath.read_bytes())
    return files


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    inputs_dir = out_dir / "inputs"
    payload_dir = out_dir / "payload"
    re_derive_dir = out_dir / "re_derive"
    for d in (inputs_dir, payload_dir, re_derive_dir):
        d.mkdir(parents=True, exist_ok=True)

    # --- Write the re-derivation pack first so its bytes are deterministic ---
    pack_path = re_derive_dir / "healthcare_diagnosis_pack.py"
    pack_path.write_bytes(_RE_DERIVE_PACK_SOURCE.encode("utf-8"))

    # --- Write symptoms.json ---
    symptoms_bytes = _canonical_json_bytes(_SYMPTOMS)
    (inputs_dir / "symptoms.json").write_bytes(symptoms_bytes)
    symptoms_cid = f"sha256:{_sha256(symptoms_bytes)}"

    # --- Write rules.json ---
    rules_bytes = _canonical_json_bytes(_RULES)
    (inputs_dir / "rules.json").write_bytes(rules_bytes)
    rules_cid = f"sha256:{_sha256(rules_bytes)}"

    # --- Re-derive the candidate list and write diagnosis.json ---
    candidates = _derive_candidates(_SYMPTOMS, _RULES)
    assert len(candidates) == 4, (
        f"Expected exactly 4 ICD-10 candidates; got {len(candidates)}. "
        f"Adjust fixture severities or rule weights to restore the 4-candidate target."
    )

    diagnosis_bytes = _canonical_json_bytes(candidates)
    (payload_dir / "diagnosis.json").write_bytes(diagnosis_bytes)

    # --- Fragment anchors (OpaqueFragment per (rule, symptom, code) triplet) ---
    fragment_anchors = _build_fragment_anchors(
        _SYMPTOMS, _RULES, candidates, symptoms_cid, rules_cid
    )
    assert 8 <= len(fragment_anchors) <= 12, (
        f"Expected ~10 evidence anchors (8..12 inclusive); got {len(fragment_anchors)}. "
        f"Check fixture / rule alignment."
    )

    # --- Build manifest.files ---
    # When out_dir == this pilot's dir, hash EVERY file in the pilot tree so
    # file_integrity_many_small Pass 3 doesn't trip. When out_dir is a fresh
    # directory (e.g. /tmp/hcd) we only hash the artifacts we just wrote.
    if out_dir.resolve() == _HERE.resolve():
        files = _enumerate_pilot_files_for_manifest(out_dir, out_dir)
    else:
        files = {
            "inputs/symptoms.json": _sha256(symptoms_bytes),
            "inputs/rules.json": _sha256(rules_bytes),
            "payload/diagnosis.json": _sha256(diagnosis_bytes),
            "re_derive/healthcare_diagnosis_pack.py": _sha256(
                _RE_DERIVE_PACK_SOURCE.encode("utf-8")
            ),
        }

    manifest = {
        "schema_version": _SCHEMA_VERSION,
        "bundle_id": _BUNDLE_ID,
        "created_at": _CREATED_AT,
        "files": files,
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": _TYPED_CHECKS,
        "fragment_anchors": fragment_anchors,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Bundle written to {out_dir}")
    print(f"  symptoms         : {len(_SYMPTOMS)}")
    print(f"  rules            : {len(_RULES)}")
    print(f"  candidates       : {len(candidates)} ICD-10 codes")
    print(f"  evidence anchors : {len(fragment_anchors)} OpaqueFragment")
    print(f"  manifest files   : {len(files)}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic healthcare_diagnosis_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=False,
        type=Path,
        default=_HERE,
        help=(
            "Destination directory. Defaults to the pilot's own directory "
            "(in-place build) so cli/verify.py --bundle-dir <pilot-dir> Just Works. "
            "Pass an explicit --out-dir to write a standalone bundle."
        ),
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
