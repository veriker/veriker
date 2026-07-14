#!/usr/bin/env python3
"""prior_auth_re_derivation.py — stdlib re-derivation pack for prior_auth_minimal.

Re-evaluates the medical-necessity decision-tree against bundled clinical features
(clinical/findings.jsonl) + bundled plan-rules (clinical/plan_rules.json) to
recompute the approve/deny verdict + the cited rule IDs for every prior-auth
request. Compares against bundled payload/prior_auth_decisions.json.

Additionally re-verifies every HMAC-signed provider attestation in
payload/decision_provenance.jsonl against the synthetic key in
payload/attestation_key.hex.

the audit-bundle contract §C6 (domain-agnostic re-derivation) + AB4.

Exit codes:
  0  all invariants pass
  1  mismatch found — see stderr for [PRIOR_AUTH_REDERIVATION_MISMATCH] or
                       [PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID]

Stdlib only: json, hmac, hashlib, argparse, pathlib, sys.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac as _hmac
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def _load_findings(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "clinical" / "findings.jsonl"
    if not p.exists():
        return None
    requests = []
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            requests.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(
                f"[PRIOR_AUTH_REDERIVATION_MISMATCH] clinical/findings.jsonl line {i}: "
                f"JSON parse error: {exc}",
                file=sys.stderr,
            )
            return None
    return requests


def _load_rules(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "clinical" / "plan_rules.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[PRIOR_AUTH_REDERIVATION_MISMATCH] clinical/plan_rules.json: "
            f"JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_decisions(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "payload" / "prior_auth_decisions.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[PRIOR_AUTH_REDERIVATION_MISMATCH] payload/prior_auth_decisions.json: "
            f"JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_provenance(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "payload" / "decision_provenance.jsonl"
    if not p.exists():
        return None
    rows = []
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(
                f"[PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID] "
                f"payload/decision_provenance.jsonl line {i}: JSON parse error: {exc}",
                file=sys.stderr,
            )
            return None
    return rows


def _load_attestation_key(bundle_dir: Path) -> bytes | None:
    p = bundle_dir / "payload" / "attestation_key.hex"
    if not p.exists():
        print(
            "[PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID] "
            "payload/attestation_key.hex not found in bundle",
            file=sys.stderr,
        )
        return None
    try:
        key_hex = p.read_text(encoding="utf-8").strip()
        return bytes.fromhex(key_hex)
    except ValueError as exc:
        print(
            f"[PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID] "
            f"payload/attestation_key.hex: invalid hex: {exc}",
            file=sys.stderr,
        )
        return None


# ---------------------------------------------------------------------------
# Re-derivation logic (mirrors _build_bundle.py — stdlib only)
# ---------------------------------------------------------------------------


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
                "(supported: '>=', '<=') — refusing to treat an unevaluable "
                "policy condition as satisfied"
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


# ---------------------------------------------------------------------------
# Main verification
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Prior-auth re-derivation + provider attestation check "
            "for prior_auth_minimal audit bundles"
        )
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # Load all inputs
    findings = _load_findings(bundle_dir)
    if findings is None:
        if not (bundle_dir / "clinical" / "findings.jsonl").exists():
            return 0  # domain opted out
        return 1

    rules = _load_rules(bundle_dir)
    if rules is None:
        if not (bundle_dir / "clinical" / "plan_rules.json").exists():
            return 0
        return 1

    decisions = _load_decisions(bundle_dir)
    if decisions is None:
        if not (bundle_dir / "payload" / "prior_auth_decisions.json").exists():
            return 0
        return 1

    provenance = _load_provenance(bundle_dir)
    if provenance is None:
        return 1

    attestation_key = _load_attestation_key(bundle_dir)
    if attestation_key is None:
        return 1

    # -----------------------------------------------------------------------
    # Invariant 1: re-derive every decision and compare to bundled decisions
    # -----------------------------------------------------------------------
    bundled_by_id: dict[str, dict] = {d["request_id"]: d for d in decisions}

    for request in findings:
        req_id = request.get("request_id")
        if req_id is None:
            print(
                "[PRIOR_AUTH_REDERIVATION_MISMATCH] request missing request_id",
                file=sys.stderr,
            )
            return 1

        derived = _derive_decision(request, rules)
        bundled = bundled_by_id.get(req_id)
        if bundled is None:
            print(
                f"[PRIOR_AUTH_REDERIVATION_MISMATCH] request_id={req_id!r} "
                "not found in bundled decisions",
                file=sys.stderr,
            )
            return 1

        if derived["model_recommendation"] != bundled.get("model_recommendation"):
            print(
                f"[PRIOR_AUTH_REDERIVATION_MISMATCH] request_id={req_id!r}: "
                f"re-derived model_recommendation={derived['model_recommendation']!r} "
                f"but bundled={bundled.get('model_recommendation')!r}",
                file=sys.stderr,
            )
            return 1

        if derived["matched_rule_id"] != bundled.get("matched_rule_id"):
            print(
                f"[PRIOR_AUTH_REDERIVATION_MISMATCH] request_id={req_id!r}: "
                f"re-derived matched_rule_id={derived['matched_rule_id']!r} "
                f"but bundled={bundled.get('matched_rule_id')!r}",
                file=sys.stderr,
            )
            return 1

    # -----------------------------------------------------------------------
    # Invariant 2: every bundled decision has a corresponding provenance row
    # -----------------------------------------------------------------------
    provenance_by_id: dict[str, dict] = {row["decision_id"]: row for row in provenance}

    for decision in decisions:
        req_id = decision["request_id"]
        if req_id not in provenance_by_id:
            print(
                f"[PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID] "
                f"request_id={req_id!r}: no provenance row found in "
                "payload/decision_provenance.jsonl",
                file=sys.stderr,
            )
            return 1

    # -----------------------------------------------------------------------
    # Invariant 3: re-verify every provider attestation HMAC
    # -----------------------------------------------------------------------
    for row in provenance:
        decision_id = row.get("decision_id", "")
        provider_id = row.get("provider_id", "")
        provider_verdict = row.get("provider_verdict", "")
        timestamp = row.get("attestation_timestamp", "")
        stored_hmac = row.get("attestation_hmac", "")

        expected_hmac = _compute_attestation_hmac(
            provider_id=provider_id,
            decision_id=decision_id,
            provider_verdict=provider_verdict,
            timestamp=timestamp,
            key=attestation_key,
        )

        if not _hmac.compare_digest(expected_hmac, stored_hmac):
            print(
                f"[PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID] "
                f"decision_id={decision_id!r} provider_id={provider_id!r}: "
                f"HMAC mismatch — stored={stored_hmac[:16]!r}... "
                f"expected={expected_hmac[:16]!r}... "
                "(provider_verdict or timestamp may have been tampered)",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
