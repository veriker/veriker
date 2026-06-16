#!/usr/bin/env python3
"""aigov_rederivation.py — stdlib re-derivation engine for AI-governance control verdicts.

Continuous, verifiable AI-governance attestation. Same re-derivation substrate
as the SOC 2 IAM-root slice, pointed at EU AI Act / ISO 42001 controls instead
of cloud-security controls.

Domain: an organization's AI-system registry. Two high-risk-AI obligations, each mapped
across frameworks ("test once, map many"):

  AIGOV-RISK-CLASS      — every AI system carries a valid EU AI Act risk classification,
                          and every high-risk system references its Annex IV technical
                          documentation                  (EU AI Act Art.6+Annex IV, ISO42001 A.6.1.2, NIST-AI-RMF MAP-1.1)
  AIGOV-HUMAN-OVERSIGHT — every high-risk AI system has human oversight enabled with a
                          named mechanism                 (EU AI Act Art.14, ISO42001 A.9.2, NIST-AI-RMF GOVERN-3.2)

Same load-bearing property as the SOC 2 slice and payroll_agent_gate_minimal:
**the verdict is computed by the verifier, never trusted from the attestation.**

Re-derivability boundary: the verifier re-runs the pinned test_fn
over the CAPTURED registry snapshot at time T and reproduces the verdict; it attests
"given THIS registry state (hash-pinned), control X returns verdict V" — it does NOT
re-query the live governance system. Trust anchor is the evidence SHA bound into the
signed attestation, not a wall-clock re-fetch.

Fail-closed: a verdict is accepted only if (control known AND cited test_fn+version
matches the pinned control AND evidence hash matches the captured object AND test_fn
registered AND signature valid AND re-derivation matches the claim).

Responsible-actor binding (no scapegoat): attestation signatures are re-checked against
a VERIFIER-WIRED key (env VKERNEL_COLLECTOR_HMAC_KEY, hex) — never against key material
read from the bundle. A bundle-supplied key would let the bundle author mint both the
key and the signature, making the binding theater against an adversarial producer
(the authority must be exogenous to the prover). FAIL-CLOSED when no key is wired:
any signature-bearing attestation rejects as SIGNATURE_UNVERIFIABLE_NO_KEY, mirroring
the refinement_discharge / stamp_lattice posture.

Implements the audit-bundle contract §C6 (domain-agnostic re-derivation) and the §C16
spirit. Stdlib only — argparse, hashlib, hmac, json, sys, pathlib. No imports from
audit_bundle (this plugin is duplicated, not imported, into pilot bundles).

Reads:
  spec/controls.json                  — nexi-control-lib-v1 (AI-gov controls + framework maps + pinned test_fn versions)
  env VKERNEL_COLLECTOR_HMAC_KEY      — verifier-wired collector-recheck key (hex); a legacy
                                        bundle's spec/collector_hmac_key.hex is IGNORED
  evidence/ai_system_registry.json    — captured AI-system registry snapshot at time T
  payload/control_attestations.json   — per-control signed attestation (verdict + evidence hash + observed_at)
  coverage/control_period.json        — closed-world: n_issued = passing controls, n_withheld = failing controls

Exits 0 when every attestation is consistent and every verifier-computed verdict matches
the claim; 1 with [AIGOV_REDERIVE_FAIL] <reason>: <detail> on stderr on first violation.

Usage:
    python aigov_rederivation.py --bundle-dir /path/to/bundle [--emit-ledger]
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

PASS = "pass"
FAIL = "fail"
_VALID_VERDICTS = frozenset({PASS, FAIL})

# EU AI Act risk tiers (Art. 5 prohibited; Art. 6 high-risk; Art. 50 limited/transparency;
# minimal). A system MUST be classified into exactly one of these.
_VALID_RISK_CLASSES = frozenset(
    {"prohibited", "high_risk", "limited_risk", "minimal_risk"}
)
_HIGH_RISK = "high_risk"


# ---------------------------------------------------------------------------
# Admission-bounded JSON loading — duplicated, not imported (this file is a
# stdlib-only / standalone reference verifier; see module docstring). Mirrors
# audit_bundle.admission's discipline (RES-02, 2026-06-11): size-reject BEFORE
# allocation, bracket-depth scan BEFORE json.loads so a hostile depth bomb is
# a clean ValueError, never a RecursionError out of the parser.
# ---------------------------------------------------------------------------

_ADMIT_MAX_BYTES = 16 * 1024 * 1024
_ADMIT_MAX_DEPTH = 64


def _admit_depth_scan(raw, name):
    """Reject (ValueError) if raw's bracket/brace nesting outside JSON string
    literals exceeds _ADMIT_MAX_DEPTH — a structural upper bound on the
    recursion json.loads would perform."""
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # closing quote
                in_string = False
            continue
        if byte == 0x22:  # opening quote
            in_string = True
        elif byte in b"[{":
            depth += 1
            if depth > _ADMIT_MAX_DEPTH:
                raise ValueError(
                    f"{name}: JSON nesting exceeds max depth {_ADMIT_MAX_DEPTH}"
                )
        elif byte in b"]}":
            if depth > 0:
                depth -= 1


def _admitted_json(path):
    """Size- and depth-bounded replacement for json.loads(path.read_text())."""
    size = path.stat().st_size
    if size > _ADMIT_MAX_BYTES:
        raise ValueError(f"{path.name}: {size} bytes exceeds max {_ADMIT_MAX_BYTES}")
    raw = path.read_bytes()
    _admit_depth_scan(raw, path.name)
    return json.loads(raw)


# ---------------------------------------------------------------------------
# test_fn registry — deterministic predicates over a captured registry snapshot.
# Keyed by (test_fn name, version). AB4: duplicated, never imported.
# ---------------------------------------------------------------------------


def _systems(evidence: dict) -> list:
    systems = evidence.get("systems")
    if not isinstance(systems, list):
        raise ValueError("evidence missing array field 'systems'")
    return systems


def _nonempty_str(v) -> bool:
    return isinstance(v, str) and v.strip() != ""


def _tf_eu_ai_act_risk_classification(evidence: dict) -> str:
    """EU AI Act Art.6 + Annex IV — every system validly classified; every high-risk
    system references its Annex IV technical documentation."""
    for sys_rec in _systems(evidence):
        rc = sys_rec.get("risk_classification")
        if rc not in _VALID_RISK_CLASSES:
            return FAIL
        if rc == _HIGH_RISK and not _nonempty_str(sys_rec.get("annex_iv_doc_ref")):
            return FAIL
    return PASS


def _tf_eu_ai_act_human_oversight(evidence: dict) -> str:
    """EU AI Act Art.14 — every high-risk system has human oversight enabled with a
    named mechanism. Non-high-risk systems are out of scope (not a failure)."""
    for sys_rec in _systems(evidence):
        if sys_rec.get("risk_classification") != _HIGH_RISK:
            continue
        oversight = sys_rec.get("human_oversight")
        if not isinstance(oversight, dict):
            return FAIL
        if oversight.get("enabled") is not True:
            return FAIL
        if not _nonempty_str(oversight.get("mechanism")):
            return FAIL
    return PASS


_TEST_FNS = {
    ("eu_ai_act_risk_classification", "1.0.0"): _tf_eu_ai_act_risk_classification,
    ("eu_ai_act_human_oversight", "1.0.0"): _tf_eu_ai_act_human_oversight,
}


def run_test_fn(test_fn: str, test_fn_version: str, evidence: dict) -> str:
    fn = _TEST_FNS.get((test_fn, test_fn_version))
    if fn is None:
        raise KeyError(
            f"test_fn {test_fn!r}@{test_fn_version!r} not in verifier registry"
        )
    return fn(evidence)


# ---------------------------------------------------------------------------
# Responsible-actor binding
# ---------------------------------------------------------------------------


def _canonical(record: dict) -> bytes:
    body = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_attestation(record: dict, key: bytes) -> str:
    return hmac.new(key, _canonical(record), hashlib.sha256).hexdigest()


def _signature_ok(record: dict, key: bytes) -> bool:
    claimed = record.get("signature")
    if not isinstance(claimed, str):
        return False
    return hmac.compare_digest(sign_attestation(record, key), claimed)


_VERIFIER_KEY_ENV = "VKERNEL_COLLECTOR_HMAC_KEY"


def _load_verifier_hmac_key() -> tuple[bytes | None, str | None]:
    """Resolve the verifier-wired collector-recheck key from the environment.

    Returns (key_bytes, None); (None, None) when the env var is absent/empty
    (the caller fails closed per signature-bearing attestation); or
    (None, error) when the value is set but not valid hex. The key is
    deliberately NEVER read from the bundle: a bundle-supplied key is
    endogenous to the prover and carries no authority the bundle author
    couldn't forge. Same exogenous-key shape as the plugin layer's
    _load_verifier_recheck_key, replicated locally because this pack is
    stdlib-only / standalone (no audit_bundle imports), same as the local
    _resolve_within. The env var is deliberately NOT VKERNEL_VERIFIER_HMAC_KEY:
    that one is the verifier's OWN raw-string signing secret (C14/C16 stamp
    upgrades); this one is the COLLECTOR's hex key, received out-of-band.
    """
    raw = os.environ.get(_VERIFIER_KEY_ENV, "").strip()
    if not raw:
        return (None, None)
    try:
        return (bytes.fromhex(raw), None)
    except ValueError as exc:
        return (
            None,
            f"COLLECTOR_KEY_MALFORMED: {_VERIFIER_KEY_ENV} is set but is not "
            f"valid hex: {exc}",
        )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_within(root: Path, rel: str) -> Path | None:
    """Contain a bundle-controlled relative path inside ``root``; return None on
    escape (``..`` traversal, an absolute path, or a symlink out of tree) so the
    caller fails closed instead of reading an out-of-bundle file. Mirrors
    audit_bundle/rederivation/primitives/_safepath.resolve_within — this pack is
    stdlib-only / standalone, so it carries its own copy."""
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _verify(bundle_dir: Path) -> tuple[str | None, list[dict]]:
    controls_path = bundle_dir / "spec" / "controls.json"
    attestations_path = bundle_dir / "payload" / "control_attestations.json"
    coverage_path = bundle_dir / "coverage" / "control_period.json"

    for p in (controls_path, attestations_path, coverage_path):
        if not p.exists():
            return (
                f"MISSING_INPUT: {p.relative_to(bundle_dir)} absent from bundle",
                [],
            )

    try:
        lib = _admitted_json(controls_path)
    except (ValueError, OSError) as exc:
        return (f"CONTROLS_UNREADABLE: {exc}", [])
    if lib.get("schema") != "nexi-control-lib-v1":
        return (
            f"CONTROLS_SCHEMA: expected 'nexi-control-lib-v1', got {lib.get('schema')!r}",
            [],
        )
    controls = lib.get("controls")
    if not isinstance(controls, dict):
        return ("CONTROLS_SCHEMA: 'controls' map missing", [])

    # Verifier-wired key only. The pre-fix code read the key FROM THE BUNDLE
    # (spec/collector_hmac_key.hex) — since the bundle author writes both the
    # key and the signatures, that made the responsible-actor binding theater
    # against an adversarial producer.
    verifier_key, key_error = _load_verifier_hmac_key()
    if key_error is not None:
        return (key_error, [])

    try:
        attestations = _admitted_json(attestations_path)
    except (ValueError, OSError) as exc:
        return (f"ATTESTATIONS_UNREADABLE: {exc}", [])
    if not isinstance(attestations, list):
        return (
            "ATTESTATIONS_SCHEMA: payload/control_attestations.json must be a JSON array",
            [],
        )

    ledger: list[dict] = []
    n_pass = 0
    n_fail = 0
    seen: set[str] = set()

    for idx, att in enumerate(attestations):
        try:
            control_id = att["control_id"]
            test_fn = att["test_fn"]
            test_fn_version = att["test_fn_version"]
            evidence_ref = att["evidence_ref"]
            evidence_sha = att["evidence_sha256"]
            claimed_verdict = att["claimed_verdict"]
            observed_at = att["observed_at"]
            collector_id = att["attestor_id"]
        except (KeyError, TypeError) as exc:
            return (f"ATTESTATION_MALFORMED: attestation[{idx}] — {exc}", ledger)

        # 1. Responsible-actor binding — verified against the VERIFIER-WIRED
        #    key only (exogenous). Fail closed when no key is wired: a
        #    signature that cannot be checked must never ride a PASS
        #    (present-but-unverified is a reject, not exit 0 + prose).
        if verifier_key is None:
            return (
                f"SIGNATURE_UNVERIFIABLE_NO_KEY: {control_id}: attestation carries "
                f"a signature but no verifier key is wired (set "
                f"{_VERIFIER_KEY_ENV}); responsible-actor binding cannot be "
                f"verified — failing closed",
                ledger,
            )
        if not _signature_ok(att, verifier_key):
            return (
                f"SIGNATURE_INVALID: {control_id}: HMAC over attestation does not verify "
                f"under the verifier-wired key (attestor={collector_id!r})",
                ledger,
            )

        # 2. Control must exist in the pinned library.
        control = controls.get(control_id)
        if control is None:
            return (
                f"UNKNOWN_CONTROL: {control_id}: not in pinned spec/controls.json (fail-closed)",
                ledger,
            )

        # 3. Cited test_fn+version must match the control's pinned test_fn+version.
        pinned_fn = control.get("test_fn")
        pinned_ver = control.get("test_fn_version")
        if test_fn != pinned_fn or test_fn_version != pinned_ver:
            return (
                f"TEST_FN_MISMATCH: {control_id}: attestation cites {test_fn!r}@{test_fn_version!r} "
                f"but the pinned control test is {pinned_fn!r}@{pinned_ver!r}",
                ledger,
            )

        # 4. Evidence present and hash-bound (the §10-Q3 boundary in code).
        # evidence_ref is bundle-controlled; contain the read inside the bundle
        # so a hostile "../../etc/passwd" or absolute path can't steer an
        # arbitrary host-file read/hash. Escape fails closed.
        evidence_path = _resolve_within(bundle_dir, evidence_ref)
        if evidence_path is None:
            return (
                f"EVIDENCE_REF_UNSAFE: {control_id}: evidence_ref {evidence_ref!r} "
                f"resolves outside the bundle — refusing the read",
                ledger,
            )
        if not evidence_path.exists():
            return (
                f"EVIDENCE_MISSING: {control_id}: evidence_ref {evidence_ref!r} absent from bundle",
                ledger,
            )
        actual_sha = sha256_file(evidence_path)
        if actual_sha.lower() != str(evidence_sha).lower():
            return (
                f"EVIDENCE_HASH_MISMATCH: {control_id}: attestation pins evidence sha={evidence_sha!r} "
                f"but {evidence_ref!r} hashes to {actual_sha!r} (verdict not bound to this evidence)",
                ledger,
            )

        try:
            evidence = _admitted_json(evidence_path)
        except (ValueError, OSError) as exc:
            return (f"EVIDENCE_UNREADABLE: {control_id}: {evidence_ref}: {exc}", ledger)

        if claimed_verdict not in _VALID_VERDICTS:
            return (
                f"VERDICT_SCHEMA: {control_id}: claimed_verdict {claimed_verdict!r} "
                f"not in {sorted(_VALID_VERDICTS)}",
                ledger,
            )

        # 5. Re-run the pinned test_fn over the captured evidence.
        try:
            verifier_verdict = run_test_fn(test_fn, test_fn_version, evidence)
        except (KeyError, ValueError, TypeError) as exc:
            return (f"REDERIVATION_ERROR: {control_id}: {exc} (fail-closed)", ledger)

        # 6. Claimed verdict MUST equal the verifier's re-derived verdict.
        if claimed_verdict != verifier_verdict:
            return (
                f"VERDICT_DIVERGENCE: {control_id}: attestation claims {claimed_verdict!r} but the "
                f"verifier re-derives {verifier_verdict!r} from the captured registry "
                f"(test_fn {test_fn}@{test_fn_version})",
                ledger,
            )

        if control_id in seen:
            return (
                f"DUPLICATE_ATTESTATION: {control_id}: more than one attestation for the same control",
                ledger,
            )
        seen.add(control_id)

        if verifier_verdict == PASS:
            n_pass += 1
        else:
            n_fail += 1
        ledger.append(
            {
                "control_id": control_id,
                "test_fn": f"{test_fn}@{test_fn_version}",
                "verifier_verdict": verifier_verdict,
                "evidence_ref": evidence_ref,
                "observed_at": observed_at,
                "frameworks": [
                    m.get("framework") for m in control.get("framework_mappings", [])
                ],
                "attestor_id": collector_id,
            }
        )

    # 7. Closed-world: every pinned control attested exactly once.
    missing = sorted(set(controls) - seen)
    if missing:
        return (
            f"CONTROL_UNATTESTED: {len(missing)} pinned control(s) have no attestation: {missing} "
            f"(closed-world violation)",
            ledger,
        )

    # 8. Closed-world cross-check against the verifier's own counts.
    try:
        cov = _admitted_json(coverage_path)
        cov_pass = int(cov["n_issued"])
        cov_fail = int(cov["n_withheld"])
    except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as exc:
        return (f"COVERAGE_UNREADABLE: {exc}", ledger)
    if cov_pass != n_pass or cov_fail != n_fail:
        return (
            f"COVERAGE_COUNT_MISMATCH: coverage row claims pass={cov_pass}/fail={cov_fail} but the "
            f"verifier computes pass={n_pass}/fail={n_fail}",
            ledger,
        )

    return (None, ledger)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AI-governance control re-derivation verifier — the verifier computes the verdict"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument(
        "--emit-ledger",
        action="store_true",
        help="On success, print the verifier-computed per-control verdict ledger to stdout",
    )
    args = parser.parse_args()

    error, ledger = _verify(args.bundle_dir.resolve())
    if error is not None:
        print(f"[AIGOV_REDERIVE_FAIL] {error}", file=sys.stderr)
        return 1

    if args.emit_ledger:
        print("verifier-re-derived AI-governance control verdicts:")
        for row in ledger:
            fws = ", ".join(f for f in row["frameworks"] if f)
            print(
                f"  {row['control_id']:<22} [{row['test_fn']:<34}] "
                f"{row['verifier_verdict']:>4}   maps→ {fws}"
            )
        print(
            f"  -> {sum(1 for r in ledger if r['verifier_verdict'] == PASS)}/{len(ledger)} "
            f"controls re-derive PASS over the captured registry"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
