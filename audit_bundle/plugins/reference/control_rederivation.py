#!/usr/bin/env python3
"""control_rederivation.py — stdlib re-derivation engine for compliance-control verdicts.

It demonstrates a control verdict that the auditor RE-DERIVES rather than trusts.

Domain: AWS IAM root-account hygiene. Two SOC 2 controls, each mapped to several
frameworks ("test once, map many"):

  IAM-ROOT-KEYS  — the account root user has no active access keys   (SOC2 CC6.1, ISO27001 A.5.15, ISO42001 A.9.2, CIS-AWS 1.4)
  IAM-ROOT-MFA   — the account root user has MFA enabled              (SOC2 CC6.6, ISO27001 A.5.17, CIS-AWS 1.5)

The load-bearing safety property:
**the verdict is computed by the verifier, never trusted from the attestation.**

The re-derivability boundary:
the verifier re-runs the pinned test_fn over the CAPTURED evidence object at time T
and reproduces the verdict byte-for-byte. It attests "given THIS evidence (hash-pinned),
control X returns verdict V" — it does NOT re-query the live cloud. The trust anchor is
the evidence hash bound into the signed attestation, not a wall-clock re-fetch.

Fail-closed by construction: a verdict is accepted only if (control is known AND the
cited test_fn+version matches the pinned control AND the evidence hash matches the
captured object AND the test_fn is registered AND signature valid AND re-derivation
matches the claim). Any error, unknown control/test_fn, bad signature, hash mismatch,
or verdict divergence fails the bundle.

Responsible-actor binding (no scapegoat): every attestation is HMAC-signed over its full
content with the collector key, and the verifier re-checks that signature against a
VERIFIER-WIRED key (env VKERNEL_COLLECTOR_HMAC_KEY, hex) — never against key material
read from the bundle. A bundle-supplied key would let the bundle author mint both the
key and the signature, making the binding theater against an adversarial producer
(the authority must be exogenous to the prover). FAIL-CLOSED when no key is wired:
any signature-bearing attestation rejects as SIGNATURE_UNVERIFIABLE_NO_KEY, mirroring
the refinement_discharge / stamp_lattice posture. (Demo uses symmetric HMAC; production
binds to an asymmetric collector identity — C18 verifier-identity.)

Implements the audit-bundle contract §C6 (domain-agnostic re-derivation) and the §C16
spirit (the verifier decides the verdict, never the dispatcher). Stdlib only — argparse,
hashlib, hmac, json, sys, pathlib. No imports from audit_bundle (duplicated, not imported).

Reads:
  spec/controls.json                  — nexi-control-lib-v1 (control statements + framework maps + pinned test_fn versions)
  env VKERNEL_COLLECTOR_HMAC_KEY      — verifier-wired collector-recheck key (hex); a legacy
                                        bundle's spec/collector_hmac_key.hex is IGNORED
  evidence/<file>.json                — captured evidence object(s), e.g. iam:GetAccountSummary at time T
  payload/control_attestations.json   — per-control: control_id, test_fn(+version), evidence_ref(+sha), claimed_verdict, observed_at, signature
  coverage/control_period.json        — closed-world: n_issued = passing controls, n_withheld = failing controls

Exits 0 when every attestation is consistent and every verifier-computed verdict matches
the claim; 1 with [CONTROL_REDERIVE_FAIL] <reason>: <detail> on stderr on first violation.

Usage:
    python control_rederivation.py --bundle-dir /path/to/bundle [--emit-ledger]
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
# test_fn registry — deterministic predicates over a captured evidence object.
# Keyed by (test_fn name, test_fn_version) so a version bump is a distinct, pinned
# function. AB4: duplicated here, never imported — the verifier owns these locally.
# ---------------------------------------------------------------------------


def _summary_map(evidence: dict) -> dict:
    sm = evidence.get("SummaryMap")
    if not isinstance(sm, dict):
        raise ValueError("evidence missing object field 'SummaryMap'")
    return sm


def _tf_aws_root_no_access_keys(evidence: dict) -> str:
    """SOC2 CC6.1 / CIS-AWS 1.4 — root user has zero active access keys."""
    return (
        PASS if int(_summary_map(evidence)["AccountAccessKeysPresent"]) == 0 else FAIL
    )


def _tf_aws_root_mfa_enabled(evidence: dict) -> str:
    """SOC2 CC6.6 / CIS-AWS 1.5 — root user has MFA enabled."""
    return PASS if int(_summary_map(evidence)["AccountMFAEnabled"]) == 1 else FAIL


_TEST_FNS = {
    ("aws_root_no_access_keys", "1.0.0"): _tf_aws_root_no_access_keys,
    ("aws_root_mfa_enabled", "1.0.0"): _tf_aws_root_mfa_enabled,
}


def run_test_fn(test_fn: str, test_fn_version: str, evidence: dict) -> str:
    """Re-run a pinned test_fn over an evidence object. Raises on unknown fn or
    malformed evidence (caller maps the exception to a fail-closed reason)."""
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
    """Canonical bytes of an attestation, excluding its own signature."""
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
    """Return (error_or_None, verdict_ledger). The ledger is the verifier's OWN
    per-control verdict, usable for display on the PASS path."""
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

        # 1. Responsible-actor binding — no scapegoat, no silent post-hoc edit.
        #    Verified against the VERIFIER-WIRED key only (exogenous). Fail
        #    closed when no key is wired: a signature that cannot be checked
        #    must never ride a PASS (present-but-unverified is a reject, not
        #    exit 0 + prose).
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

        # 2. The control must exist in the pinned control library.
        control = controls.get(control_id)
        if control is None:
            return (
                f"UNKNOWN_CONTROL: {control_id}: not in pinned spec/controls.json "
                f"(fail-closed — cannot attest an unlisted control)",
                ledger,
            )

        # 3. The cited test_fn+version must match the control's pinned test_fn+version
        #    (no citing a friendlier or stale test to reach a passing verdict).
        pinned_fn = control.get("test_fn")
        pinned_ver = control.get("test_fn_version")
        if test_fn != pinned_fn or test_fn_version != pinned_ver:
            return (
                f"TEST_FN_MISMATCH: {control_id}: attestation cites {test_fn!r}@{test_fn_version!r} "
                f"but the pinned control test is {pinned_fn!r}@{pinned_ver!r}",
                ledger,
            )

        # 4. The evidence object must be present and its hash must match the one the
        #    attestation was signed over. This is the §10-Q3 boundary in code: the
        #    verdict is bound to THIS captured evidence at time T, not a live re-query.
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

        # 5. Re-run the pinned test_fn over the captured evidence — the verifier's verdict.
        try:
            verifier_verdict = run_test_fn(test_fn, test_fn_version, evidence)
        except (KeyError, ValueError, TypeError) as exc:
            return (f"REDERIVATION_ERROR: {control_id}: {exc} (fail-closed)", ledger)

        # 6. The claimed verdict MUST equal the verifier's re-derived verdict. This is the
        #    whole point: you cannot record a 'pass' the evidence does not support, even
        #    with a valid signature and integrity-clean evidence. A claim is not evidence;
        #    the re-derivation is.
        if claimed_verdict != verifier_verdict:
            return (
                f"VERDICT_DIVERGENCE: {control_id}: attestation claims {claimed_verdict!r} but the "
                f"verifier re-derives {verifier_verdict!r} from the captured evidence "
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

    # 7. Closed-world: every pinned control must have exactly one attestation.
    missing = sorted(set(controls) - seen)
    if missing:
        return (
            f"CONTROL_UNATTESTED: {len(missing)} pinned control(s) have no attestation: {missing} "
            f"(closed-world violation)",
            ledger,
        )

    # 8. Closed-world cross-check: the coverage row's pass/fail counts must equal the
    #    VERIFIER's own counts (not the collector's claims). issued = passing controls.
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
        description="Compliance-control re-derivation verifier — the verifier computes the verdict"
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
        print(f"[CONTROL_REDERIVE_FAIL] {error}", file=sys.stderr)
        return 1

    if args.emit_ledger:
        print("verifier-re-derived control verdicts:")
        for row in ledger:
            fws = ",".join(f for f in row["frameworks"] if f)
            print(
                f"  {row['control_id']:<14} [{row['test_fn']:<28}] "
                f"{row['verifier_verdict']:>4}   maps→ {fws}"
            )
        print(
            f"  -> {sum(1 for r in ledger if r['verifier_verdict'] == PASS)}/{len(ledger)} "
            f"controls re-derive PASS over the captured evidence"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
