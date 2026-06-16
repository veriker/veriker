#!/usr/bin/env python3
"""anticheat_re_derivation.py — stdlib re-derivation pack for anticheat_adjudication_minimal.

Re-evaluates the detection-policy decision rules against bundled detection signals
(evidence/detection_signals.jsonl) + bundled policy (evidence/detection_policy.json)
to recompute the ban / review / clear verdict + the cited rule ID for every flagged
case. Compares against bundled payload/ban_decisions.json.

Additionally re-verifies every HMAC-signed adjudicator attestation in
payload/adjudication_provenance.jsonl against the synthetic key in
payload/attestation_key.hex.

the audit-bundle contract §C6 (domain-agnostic re-derivation) + AB4.

What this proves: the ban verdict followed the committed detection policy over the
committed evidence, AND the named adjudicator's signature genuinely binds to that
verdict (a post-hoc verdict flip is detectable even when file SHAs are re-aligned).
What this does NOT prove: that the policy correctly distinguishes cheaters from
skilled players. Detection quality is upstream and untouched by this pilot.

Exit codes:
  0  all invariants pass
  1  mismatch found — see stderr for [ANTICHEAT_REDERIVATION_MISMATCH] or
                       [ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID]

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


def _load_signals(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "evidence" / "detection_signals.jsonl"
    if not p.exists():
        return None
    cases = []
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            cases.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(
                f"[ANTICHEAT_REDERIVATION_MISMATCH] evidence/detection_signals.jsonl line {i}: "
                f"JSON parse error: {exc}",
                file=sys.stderr,
            )
            return None
    return cases


def _load_policy(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "evidence" / "detection_policy.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[ANTICHEAT_REDERIVATION_MISMATCH] evidence/detection_policy.json: "
            f"JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_decisions(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "payload" / "ban_decisions.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[ANTICHEAT_REDERIVATION_MISMATCH] payload/ban_decisions.json: "
            f"JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_provenance(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "payload" / "adjudication_provenance.jsonl"
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
                f"[ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID] "
                f"payload/adjudication_provenance.jsonl line {i}: JSON parse error: {exc}",
                file=sys.stderr,
            )
            return None
    return rows


def _load_attestation_key(bundle_dir: Path) -> bytes | None:
    p = bundle_dir / "payload" / "attestation_key.hex"
    if not p.exists():
        print(
            "[ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID] "
            "payload/attestation_key.hex not found in bundle",
            file=sys.stderr,
        )
        return None
    try:
        key_hex = p.read_text(encoding="utf-8").strip()
        return bytes.fromhex(key_hex)
    except ValueError as exc:
        print(
            f"[ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID] "
            f"payload/attestation_key.hex: invalid hex: {exc}",
            file=sys.stderr,
        )
        return None


# ---------------------------------------------------------------------------
# Re-derivation logic (mirrors _build_bundle.py — stdlib only)
# ---------------------------------------------------------------------------


def _evaluate_rule(signals: dict, rule: dict) -> bool:
    """Return True if the case signals satisfy every condition in the rule (AND)."""
    for cond in rule["conditions"]:
        sig = cond["signal"]
        comparator = cond["comparator"]
        threshold = cond["threshold"]
        value = signals.get(sig)
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
                f"unknown condition comparator {comparator!r} "
                "(supported: '>=', '<=') — refusing to treat an unevaluable "
                "policy condition as satisfied"
            )
    return True


def _derive_decision(case: dict, policy: list[dict]) -> dict:
    """Walk the rule set (sorted by rule_id) and return the first matching verdict."""
    for rule in sorted(policy, key=lambda r: r["rule_id"]):
        if _evaluate_rule(case["signals"], rule):
            return {
                "case_id": case["case_id"],
                "model_recommendation": rule["verdict"],
                "matched_rule_id": rule["rule_id"],
            }
    return {
        "case_id": case["case_id"],
        "model_recommendation": "clear",
        "matched_rule_id": None,
    }


def _compute_attestation_hmac(
    adjudicator_id: str,
    case_id: str,
    final_verdict: str,
    timestamp: str,
    key: bytes,
) -> str:
    """HMAC-SHA256 of (adjudicator_id || case_id || final_verdict || timestamp)."""
    msg = f"{adjudicator_id}|{case_id}|{final_verdict}|{timestamp}".encode("utf-8")
    return _hmac.new(key, msg, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Main verification
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Anti-cheat ban-adjudication re-derivation + adjudicator attestation "
            "check for anticheat_adjudication_minimal audit bundles"
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
    cases = _load_signals(bundle_dir)
    if cases is None:
        if not (bundle_dir / "evidence" / "detection_signals.jsonl").exists():
            return 0  # domain opted out
        return 1

    policy = _load_policy(bundle_dir)
    if policy is None:
        if not (bundle_dir / "evidence" / "detection_policy.json").exists():
            return 0
        return 1

    decisions = _load_decisions(bundle_dir)
    if decisions is None:
        if not (bundle_dir / "payload" / "ban_decisions.json").exists():
            return 0
        return 1

    provenance = _load_provenance(bundle_dir)
    if provenance is None:
        return 1

    attestation_key = _load_attestation_key(bundle_dir)
    if attestation_key is None:
        return 1

    # -----------------------------------------------------------------------
    # Invariant 1: re-derive every verdict and compare to bundled decisions
    # -----------------------------------------------------------------------
    bundled_by_id: dict[str, dict] = {d["case_id"]: d for d in decisions}

    for case in cases:
        case_id = case.get("case_id")
        if case_id is None:
            print(
                "[ANTICHEAT_REDERIVATION_MISMATCH] case missing case_id",
                file=sys.stderr,
            )
            return 1

        derived = _derive_decision(case, policy)
        bundled = bundled_by_id.get(case_id)
        if bundled is None:
            print(
                f"[ANTICHEAT_REDERIVATION_MISMATCH] case_id={case_id!r} "
                "not found in bundled decisions",
                file=sys.stderr,
            )
            return 1

        if derived["model_recommendation"] != bundled.get("model_recommendation"):
            print(
                f"[ANTICHEAT_REDERIVATION_MISMATCH] case_id={case_id!r}: "
                f"re-derived model_recommendation={derived['model_recommendation']!r} "
                f"but bundled={bundled.get('model_recommendation')!r}",
                file=sys.stderr,
            )
            return 1

        if derived["matched_rule_id"] != bundled.get("matched_rule_id"):
            print(
                f"[ANTICHEAT_REDERIVATION_MISMATCH] case_id={case_id!r}: "
                f"re-derived matched_rule_id={derived['matched_rule_id']!r} "
                f"but bundled={bundled.get('matched_rule_id')!r}",
                file=sys.stderr,
            )
            return 1

    # -----------------------------------------------------------------------
    # Invariant 2: every bundled decision has a corresponding provenance row
    # -----------------------------------------------------------------------
    provenance_by_id: dict[str, dict] = {row["case_id"]: row for row in provenance}

    for decision in decisions:
        case_id = decision["case_id"]
        if case_id not in provenance_by_id:
            print(
                f"[ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID] "
                f"case_id={case_id!r}: no provenance row found in "
                "payload/adjudication_provenance.jsonl",
                file=sys.stderr,
            )
            return 1

    # -----------------------------------------------------------------------
    # Invariant 3: re-verify every adjudicator attestation HMAC
    # -----------------------------------------------------------------------
    for row in provenance:
        case_id = row.get("case_id", "")
        adjudicator_id = row.get("adjudicator_id", "")
        final_verdict = row.get("final_verdict", "")
        timestamp = row.get("attestation_timestamp", "")
        stored_hmac = row.get("attestation_hmac", "")

        expected_hmac = _compute_attestation_hmac(
            adjudicator_id=adjudicator_id,
            case_id=case_id,
            final_verdict=final_verdict,
            timestamp=timestamp,
            key=attestation_key,
        )

        if not _hmac.compare_digest(expected_hmac, stored_hmac):
            print(
                f"[ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID] "
                f"case_id={case_id!r} adjudicator_id={adjudicator_id!r}: "
                f"HMAC mismatch — stored={stored_hmac[:16]!r}... "
                f"expected={expected_hmac[:16]!r}... "
                "(final_verdict, adjudicator_id, or timestamp may have been tampered)",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
