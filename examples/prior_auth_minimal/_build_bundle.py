"""_build_bundle.py — build a deterministic prior_auth_minimal audit bundle.

Writes a health-plan AI prior-authorization domain bundle into --out-dir:
  clinical/findings.jsonl               (5 deterministic prior-auth requests,
                                          each with clinical features as JSONL)
  payload/prior_auth_decisions.json     (approve/deny outcomes per request)
  payload/decision_provenance.jsonl     (provider attestation log — the differentiator)
  manifest.json

Exercises three V-Kernel extension points:
  OpaqueFragment(source_cid, kind_tag="clinical_finding", locator={...})
    — one fragment anchor per clinical feature (diagnosis code, prior treatment, lab value)
  decision_provenance_log               — manifest field binding provider HMAC-attestations
                                          to each prior-auth decision verdict
  DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({
      "MEDICAL_NECESSITY_EVAL", "PROVIDER_ATTEST", "COMPUTE"
  }))                                   — admits domain-specific op kinds for this pilot

Regulatory anchor:
  Colorado Reg 10-1-1 § 5.A.5 — health insurer AI systems in utilization management;
  CA SB 1120; TX/AZ/MD adverse-determination laws; CMS WISER; NAIC AI Evaluation Tool.

Usage (from v-kernel-audit-bundle root):
    python examples/prior_auth_minimal/_build_bundle.py --out-dir /tmp/prior_auth_bundle

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import hmac as _hmac
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "prior-auth-minimal-rc"
_CREATED_AT = "2026-05-19T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "prior_auth_re_derivation",
    "dispatch_record_wellformed",
]

# -----------------------------------------------------------------------
# Synthetic HMAC key for provider attestation — kept in bundle for re-verify.
# In production this would be a HSM-backed key; for the demo pilot it is a
# deterministic synthetic secret that the bundle carries so the verifier can
# re-compute every attestation HMAC from first principles.
# -----------------------------------------------------------------------
_ATTESTATION_KEY = b"synthetic-attestation-key-co-reg-10-1-1-prior-auth-2026"

# -----------------------------------------------------------------------
# Synthetic plan rules (medical-necessity decision tree)
# -----------------------------------------------------------------------
_PLAN_RULES: list[dict] = [
    {
        "rule_id": "rule-MRI-spine",
        "procedure_category": "advanced_imaging",
        "required_diagnoses": ["M54.5"],  # Low back pain
        "required_prior_treatments": ["PT-6wk"],  # 6 weeks of physical therapy
        "max_lab_value": None,
        "verdict": "approve",
    },
    {
        "rule_id": "rule-specialty-pharma-biologics",
        "procedure_category": "specialty_pharmacy",
        "required_diagnoses": ["M05.79"],  # Rheumatoid arthritis
        "required_prior_treatments": ["DMARD-fail"],
        "max_lab_value": None,
        "verdict": "approve",
    },
    {
        "rule_id": "rule-elective-surgery-obesity",
        "procedure_category": "elective_surgery",
        "required_diagnoses": ["E66.01"],  # Morbid obesity
        "required_prior_treatments": ["diet-6mo"],
        "max_lab_value": {"lab": "BMI", "threshold": 40.0, "comparator": ">="},
        "verdict": "approve",
    },
    {
        "rule_id": "rule-inpatient-admission-pneumonia",
        "procedure_category": "inpatient_admission",
        "required_diagnoses": ["J18.9"],  # Pneumonia
        "required_prior_treatments": [],  # no prior treatment required
        "max_lab_value": {"lab": "SpO2", "threshold": 92.0, "comparator": "<="},
        "verdict": "approve",
    },
    {
        "rule_id": "rule-deny-all-elective-cosmetic",
        "procedure_category": "cosmetic_procedure",
        "required_diagnoses": [],
        "required_prior_treatments": [],
        "max_lab_value": None,
        "verdict": "deny",
    },
]

# -----------------------------------------------------------------------
# Synthetic prior-auth requests (5 cases — mix of approve and deny)
# -----------------------------------------------------------------------
_REQUESTS: list[dict] = [
    {
        "request_id": "PA-2026-001",
        "patient_id": "P-10001",
        "procedure_category": "advanced_imaging",
        "diagnoses": ["M54.5"],
        "prior_treatments": ["PT-6wk"],
        "lab_values": {},
    },
    {
        "request_id": "PA-2026-002",
        "patient_id": "P-10002",
        "procedure_category": "specialty_pharmacy",
        "diagnoses": ["M05.79"],
        "prior_treatments": ["DMARD-fail"],
        "lab_values": {},
    },
    {
        "request_id": "PA-2026-003",
        "patient_id": "P-10003",
        "procedure_category": "elective_surgery",
        "diagnoses": ["E66.01"],
        "prior_treatments": ["diet-6mo"],
        "lab_values": {"BMI": 42.5},
    },
    {
        "request_id": "PA-2026-004",
        "patient_id": "P-10004",
        "procedure_category": "inpatient_admission",
        "diagnoses": ["J18.9"],
        "prior_treatments": [],
        "lab_values": {"SpO2": 88.0},
    },
    {
        "request_id": "PA-2026-005",
        "patient_id": "P-10005",
        "procedure_category": "cosmetic_procedure",
        "diagnoses": [],
        "prior_treatments": [],
        "lab_values": {},
    },
]

# -----------------------------------------------------------------------
# Synthetic provider roster — one responsible provider per decision
# -----------------------------------------------------------------------
_PROVIDERS: list[dict] = [
    {"provider_id": "NPI-9900001", "provider_role": "medical_director"},
    {"provider_id": "NPI-9900002", "provider_role": "medical_director"},
    {"provider_id": "NPI-9900003", "provider_role": "attending_physician"},
    {"provider_id": "NPI-9900004", "provider_role": "medical_director"},
    {"provider_id": "NPI-9900005", "provider_role": "attending_physician"},
]

# One fixed timestamp per decision (deterministic for re-verification)
_TIMESTAMPS: list[str] = [
    "2026-05-19T08:01:00Z",
    "2026-05-19T08:02:00Z",
    "2026-05-19T08:03:00Z",
    "2026-05-19T08:04:00Z",
    "2026-05-19T08:05:00Z",
]


# -----------------------------------------------------------------------
# Re-derivation logic (mirrored in prior_auth_re_derivation.py)
# -----------------------------------------------------------------------


def _evaluate_rule(request: dict, rule: dict) -> bool:
    """Return True if the request satisfies all conditions in the rule."""
    if request["procedure_category"] != rule["procedure_category"]:
        return False
    for diag in rule["required_diagnoses"]:
        if diag not in request["diagnoses"]:
            return False
    for tx in rule["required_prior_treatments"]:
        if tx not in request["prior_treatments"]:
            return False
    if rule["max_lab_value"] is not None:
        lab = rule["max_lab_value"]["lab"]
        threshold = rule["max_lab_value"]["threshold"]
        comparator = rule["max_lab_value"]["comparator"]
        value = request["lab_values"].get(lab)
        if value is None:
            return False
        if comparator == ">=":
            if not (value >= threshold):
                return False
        elif comparator == "<=":
            if not (value <= threshold):
                return False
        else:
            raise ValueError(
                f"unknown max_lab_value comparator {comparator!r} "
                "(supported: '>=', '<=') — refusing to build a bundle from "
                "a policy with an unevaluable condition"
            )
    return True


def _derive_decision(request: dict, rules: list[dict]) -> dict:
    """Walk the rule set (sorted by rule_id) and return the first matching verdict."""
    for rule in sorted(rules, key=lambda r: r["rule_id"]):
        if _evaluate_rule(request, rule):
            return {
                "request_id": request["request_id"],
                "model_recommendation": rule["verdict"],
                "matched_rule_id": rule["rule_id"],
            }
    return {
        "request_id": request["request_id"],
        "model_recommendation": "deny",
        "matched_rule_id": None,
    }


def _compute_attestation_hmac(
    provider_id: str,
    decision_id: str,
    provider_verdict: str,
    timestamp: str,
    key: bytes,
) -> str:
    """HMAC-SHA256 of (provider_id || decision_id || provider_verdict || timestamp)."""
    msg = f"{provider_id}|{decision_id}|{provider_verdict}|{timestamp}".encode("utf-8")
    return _hmac.new(key, msg, hashlib.sha256).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -----------------------------------------------------------------------
# Bundle builder
# -----------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Build clinical/findings.jsonl bytes
    # Each line is a single prior-auth request (the "input bytes" for re-derivation)
    # ------------------------------------------------------------------
    findings_lines = [json.dumps(req, sort_keys=True) for req in _REQUESTS]
    findings_text = "\n".join(findings_lines) + "\n"
    findings_bytes = findings_text.encode("utf-8")

    # ------------------------------------------------------------------
    # Build clinical/plan_rules.json bytes
    # ------------------------------------------------------------------
    rules_text = json.dumps(_PLAN_RULES, indent=2, sort_keys=True) + "\n"
    rules_bytes = rules_text.encode("utf-8")

    # ------------------------------------------------------------------
    # Build payload/attestation_key.hex bytes
    # ------------------------------------------------------------------
    key_hex = _ATTESTATION_KEY.hex()
    attestation_key_bytes = (key_hex + "\n").encode("utf-8")

    # ------------------------------------------------------------------
    # Derive decisions + build decision provenance log
    # ------------------------------------------------------------------
    decisions: list[dict] = []
    provenance_rows: list[dict] = []

    for i, request in enumerate(_REQUESTS):
        model_decision = _derive_decision(request, _PLAN_RULES)
        provider = _PROVIDERS[i]
        timestamp = _TIMESTAMPS[i]

        # Provider adopts model recommendation (simulated sign-off)
        provider_verdict = model_decision["model_recommendation"]

        attest_hmac = _compute_attestation_hmac(
            provider_id=provider["provider_id"],
            decision_id=request["request_id"],
            provider_verdict=provider_verdict,
            timestamp=timestamp,
            key=_ATTESTATION_KEY,
        )

        decisions.append(
            {
                "request_id": request["request_id"],
                "model_recommendation": model_decision["model_recommendation"],
                "matched_rule_id": model_decision["matched_rule_id"],
                "final_verdict": provider_verdict,
            }
        )

        provenance_rows.append(
            {
                "decision_id": request["request_id"],
                "provider_id": provider["provider_id"],
                "provider_role": provider["provider_role"],
                "model_recommendation": model_decision["model_recommendation"],
                "provider_verdict": provider_verdict,
                "attestation_hmac": attest_hmac,
                "attestation_timestamp": timestamp,
            }
        )

    # Build payload/prior_auth_decisions.json bytes
    decisions_text = json.dumps(decisions, indent=2, sort_keys=True) + "\n"
    decisions_bytes = decisions_text.encode("utf-8")

    # Build payload/decision_provenance.jsonl bytes
    provenance_lines = [json.dumps(row, sort_keys=True) for row in provenance_rows]
    provenance_text = "\n".join(provenance_lines) + "\n"
    provenance_bytes = provenance_text.encode("utf-8")

    # ------------------------------------------------------------------
    # OpaqueFragment anchors — one per clinical feature contributing to a decision
    # kind_tag="clinical_finding"; locator = {finding_id, patient_id}
    # source_cid derived from clinical/findings.jsonl SHA
    # ------------------------------------------------------------------
    findings_cid = f"sha256:{_sha256(findings_bytes)}"
    fragment_anchors: dict[str, dict] = {}

    for req in _REQUESTS:
        # Anchor each diagnosis code as a clinical finding
        for diag in req["diagnoses"]:
            finding_id = f"{req['request_id']}-diag-{diag}"
            frag = OpaqueFragment(
                source_cid=findings_cid,
                kind_tag="clinical_finding",
                locator={
                    "finding_id": finding_id,
                    "patient_id": req["patient_id"],
                    "finding_type": "diagnosis",
                    "value": diag,
                },
            )
            fragment_anchors[finding_id] = fragment_to_canonical_dict(frag)

        # Anchor each prior treatment as a clinical finding
        for tx in req["prior_treatments"]:
            finding_id = f"{req['request_id']}-tx-{tx}"
            frag = OpaqueFragment(
                source_cid=findings_cid,
                kind_tag="clinical_finding",
                locator={
                    "finding_id": finding_id,
                    "patient_id": req["patient_id"],
                    "finding_type": "prior_treatment",
                    "value": tx,
                },
            )
            fragment_anchors[finding_id] = fragment_to_canonical_dict(frag)

        # Anchor each lab value as a clinical finding
        for lab, val in req["lab_values"].items():
            finding_id = f"{req['request_id']}-lab-{lab}"
            frag = OpaqueFragment(
                source_cid=findings_cid,
                kind_tag="clinical_finding",
                locator={
                    "finding_id": finding_id,
                    "patient_id": req["patient_id"],
                    "finding_type": "lab_value",
                    "value": str(val),
                    "lab": lab,
                },
            )
            fragment_anchors[finding_id] = fragment_to_canonical_dict(frag)

    assert len(fragment_anchors) >= 3, (
        f"Expected >= 3 OpaqueFragment anchors; got {len(fragment_anchors)}"
    )

    # ------------------------------------------------------------------
    # dispatch_records — three op kinds exercising C15
    # COMPUTE: fixture prep
    # MEDICAL_NECESSITY_EVAL: the rule-tree evaluation step
    # PROVIDER_ATTEST: the provider attestation binding step
    # ------------------------------------------------------------------
    dispatch_records = [
        {
            "schema_version": "0.1",
            "op": {
                "kind": "COMPUTE",
                "name": "prior_auth_fixture_prep",
            },
            "inputs": [],
            "outputs": [],
            "effect": {},
            "locale": "en-US",
            "predicates": [],
            "stamp_declared": "INTERNAL_BENCHMARK",
            "stamp_observed": None,
        },
        {
            "schema_version": "0.1",
            "op": {
                "kind": "MEDICAL_NECESSITY_EVAL",
                "name": "prior_auth_rule_tree_evaluation",
            },
            "inputs": [],
            "outputs": [],
            "effect": {},
            "locale": "en-US",
            "predicates": [],
            "stamp_declared": "INTERNAL_BENCHMARK",
            "stamp_observed": None,
        },
        {
            "schema_version": "0.1",
            "op": {
                "kind": "PROVIDER_ATTEST",
                "name": "prior_auth_provider_attestation_binding",
            },
            "inputs": [],
            "outputs": [],
            "effect": {},
            "locale": "en-US",
            "predicates": [],
            "stamp_declared": "INTERNAL_BENCHMARK",
            "stamp_observed": None,
        },
    ]

    # ------------------------------------------------------------------
    # Emit via the reference-emitter SDK (scaffold + digests + manifest).
    # decision_provenance_log references the JSONL path relative to bundle root
    # ------------------------------------------------------------------
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "clinical/findings.jsonl": findings_bytes,
            "clinical/plan_rules.json": rules_bytes,
            "payload/prior_auth_decisions.json": decisions_bytes,
            "payload/decision_provenance.jsonl": provenance_bytes,
            "payload/attestation_key.hex": attestation_key_bytes,
        },
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "dispatch_records": dispatch_records,
            "decision_provenance_log": "payload/decision_provenance.jsonl",
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  prior-auth requests  : {len(_REQUESTS)}")
    print(f"  plan rules           : {len(_PLAN_RULES)}")
    print(f"  decisions            : {len(decisions)}")
    print(f"  provenance rows      : {len(provenance_rows)}")
    print(
        f"  fragment anchors     : {len(fragment_anchors)} OpaqueFragment (kind_tag=clinical_finding)"
    )
    print(
        f"  dispatch records     : {len(dispatch_records)} (COMPUTE + MEDICAL_NECESSITY_EVAL + PROVIDER_ATTEST)"
    )
    print(f"  manifest             : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic prior_auth_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        out_dir = args.out_dir.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        build(out_dir)
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
