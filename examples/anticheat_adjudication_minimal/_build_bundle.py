"""_build_bundle.py — build a deterministic anticheat_adjudication_minimal audit bundle.

Writes a competitive-game anti-cheat ban-adjudication domain bundle into --out-dir:
  evidence/detection_signals.jsonl       (6 deterministic flagged cases, each with
                                           server-side detection signals as JSONL)
  evidence/detection_policy.json         (committed threshold rule set)
  payload/ban_decisions.json             (ban / review / clear outcomes per case)
  payload/adjudication_provenance.jsonl  (adjudicator attestation log — the differentiator)
  payload/attestation_key.hex            (synthetic HMAC key committed to bundle)
  manifest.json

Exercises three V-Kernel extension points (same shape family as prior_auth_minimal):
  OpaqueFragment(source_cid, kind_tag="detection_signal", locator={...})
    — one fragment anchor per detection signal contributing to a case
  decision_provenance_log                — manifest field binding adjudicator HMAC-attestations
                                           to each ban-adjudication verdict
  DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({
      "DETECTION_EVAL", "ADJUDICATOR_ATTEST", "COMPUTE"
  }))                                    — admits domain-specific op kinds for this pilot

Domain framing (NO fabricated statute — anchored on documented industry pain):
  Competitive games (CS2/VAC archetype) ban players from opaque, unappealable verdicts.
  Valve does not disclose the detected cheat (revealing signatures aids evasion); players
  cannot verify; cheaters lie about "false bans" online; legal teams want ~100% proof. The
  asymmetric-information trust collapse (Irdeto) is an ADJUDICATION problem, not a detection
  problem. This bundle does NOT improve detection or lower the false-positive rate. It makes
  a ban verdict independently re-derivable against a committed policy + cryptographically
  bound to the adjudicator who signed it — without disclosing detection signatures to the
  public (in production only committed hashes + policy + verdict go to an arbiter).

Usage (from v-kernel-audit-bundle root):
    python examples/anticheat_adjudication_minimal/_build_bundle.py --out-dir /tmp/anticheat_bundle

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
_BUNDLE_ID = "anticheat-adjudication-minimal-rc"
_CREATED_AT = "2026-05-23T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "anticheat_re_derivation",
    "dispatch_record_wellformed",
]

# -----------------------------------------------------------------------
# Synthetic HMAC key for adjudicator attestation — kept in bundle for re-verify.
# In production this would be an HSM-backed key NOT shipped in the bundle (the
# arbiter holds it); for the demo pilot it is a deterministic synthetic secret
# the bundle carries so the verifier can re-compute every attestation HMAC.
# -----------------------------------------------------------------------
_ATTESTATION_KEY = b"synthetic-attestation-key-anticheat-adjudication-2026"

# -----------------------------------------------------------------------
# Committed detection-policy contract (threshold decision rules).
#
# Each rule is a conjunction of conditions over server-side detection signals.
# First matching rule (sorted by rule_id) wins. Signals are the privacy-friendly,
# legally-defensible server-side statistics (movement / accuracy / timing) — the
# pilot deliberately does NOT model client kernel telemetry or memory scans.
#
# Verdicts:
#   ban    — auto-actionable: signal pattern crosses a conclusive threshold
#   review — flag for human moderator; do NOT auto-ban (the false-positive guard)
#   clear  — no rule fires
#
# Thresholds are illustrative synthetic values, NOT lifted from any real
# anti-cheat vendor's tuning. They exist to make the re-derivation deterministic.
# -----------------------------------------------------------------------
_DETECTION_POLICY: list[dict] = [
    {
        "rule_id": "rule-A-aimbot-snap",
        "description": "Superhuman aim-snap: low angular variance + sub-human flick reaction",
        "conditions": [
            {"signal": "snap_variance_deg", "comparator": "<=", "threshold": 0.5},
            {"signal": "flick_reaction_ms", "comparator": "<=", "threshold": 80.0},
        ],
        "verdict": "ban",
    },
    {
        "rule_id": "rule-B-triggerbot",
        "description": "Triggerbot: inhuman reaction time with near-perfect headshot ratio",
        "conditions": [
            {"signal": "flick_reaction_ms", "comparator": "<=", "threshold": 50.0},
            {"signal": "headshot_ratio", "comparator": ">=", "threshold": 0.9},
        ],
        "verdict": "ban",
    },
    {
        "rule_id": "rule-C-wallhack-prefire",
        "description": "Wallhack: consistently firing before opponent is line-of-sight visible",
        "conditions": [
            {"signal": "prefire_rate", "comparator": ">=", "threshold": 0.6},
        ],
        "verdict": "ban",
    },
    {
        "rule_id": "rule-D-suspicious-review",
        "description": "Elevated-but-inconclusive skill signal — route to human review, do NOT auto-ban",
        "conditions": [
            {"signal": "hit_ratio", "comparator": ">=", "threshold": 0.75},
            {"signal": "flick_reaction_ms", "comparator": "<=", "threshold": 130.0},
        ],
        "verdict": "review",
    },
]

# -----------------------------------------------------------------------
# Synthetic flagged cases (6 — mix of ban / review / clear).
#   AC-...-001  aimbot      → rule-A → ban
#   AC-...-002  triggerbot  → rule-B → ban
#   AC-...-003  wallhack    → rule-C → ban
#   AC-...-004  skilled pro → rule-D → review  (the false-positive guard / dispute centerpiece)
#   AC-...-005  legit avg   → no rule → clear
#   AC-...-006  legit low   → no rule → clear
# -----------------------------------------------------------------------
_CASES: list[dict] = [
    {
        "case_id": "AC-2026-001",
        "player_id": "STEAM-7656119000001",
        "match_id": "M-50001",
        "signals": {
            "hit_ratio": 0.80,
            "headshot_ratio": 0.95,
            "prefire_rate": 0.20,
            "flick_reaction_ms": 70.0,
            "snap_variance_deg": 0.30,
        },
    },
    {
        "case_id": "AC-2026-002",
        "player_id": "STEAM-7656119000002",
        "match_id": "M-50002",
        "signals": {
            "hit_ratio": 0.70,
            "headshot_ratio": 0.92,
            "prefire_rate": 0.10,
            "flick_reaction_ms": 45.0,
            "snap_variance_deg": 2.00,
        },
    },
    {
        "case_id": "AC-2026-003",
        "player_id": "STEAM-7656119000003",
        "match_id": "M-50003",
        "signals": {
            "hit_ratio": 0.55,
            "headshot_ratio": 0.50,
            "prefire_rate": 0.72,
            "flick_reaction_ms": 180.0,
            "snap_variance_deg": 3.00,
        },
    },
    {
        "case_id": "AC-2026-004",
        "player_id": "STEAM-7656119000004",
        "match_id": "M-50004",
        "signals": {
            "hit_ratio": 0.82,
            "headshot_ratio": 0.78,
            "prefire_rate": 0.25,
            "flick_reaction_ms": 120.0,
            "snap_variance_deg": 1.20,
        },
    },
    {
        "case_id": "AC-2026-005",
        "player_id": "STEAM-7656119000005",
        "match_id": "M-50005",
        "signals": {
            "hit_ratio": 0.52,
            "headshot_ratio": 0.45,
            "prefire_rate": 0.15,
            "flick_reaction_ms": 210.0,
            "snap_variance_deg": 2.50,
        },
    },
    {
        "case_id": "AC-2026-006",
        "player_id": "STEAM-7656119000006",
        "match_id": "M-50006",
        "signals": {
            "hit_ratio": 0.40,
            "headshot_ratio": 0.30,
            "prefire_rate": 0.05,
            "flick_reaction_ms": 250.0,
            "snap_variance_deg": 4.00,
        },
    },
]

# -----------------------------------------------------------------------
# Synthetic adjudicator roster — one responsible adjudicator per case.
# adjudicator_type distinguishes an automated detector-version sign-off from a
# human moderator sign-off. The "review" case is signed by a human moderator;
# the auto-ban cases are signed by the automated detector build that produced
# them. This is the responsible-actor binding: WHO stands behind this verdict.
# -----------------------------------------------------------------------
_ADJUDICATORS: list[dict] = [
    {"adjudicator_id": "vac-detector-v2026.05.1", "adjudicator_type": "automated"},
    {"adjudicator_id": "vac-detector-v2026.05.1", "adjudicator_type": "automated"},
    {"adjudicator_id": "vac-detector-v2026.05.1", "adjudicator_type": "automated"},
    {"adjudicator_id": "mod-9920014", "adjudicator_type": "human"},
    {"adjudicator_id": "vac-detector-v2026.05.1", "adjudicator_type": "automated"},
    {"adjudicator_id": "vac-detector-v2026.05.1", "adjudicator_type": "automated"},
]

# One fixed timestamp per case (deterministic for re-verification)
_TIMESTAMPS: list[str] = [
    "2026-05-23T08:01:00Z",
    "2026-05-23T08:02:00Z",
    "2026-05-23T08:03:00Z",
    "2026-05-23T08:04:00Z",
    "2026-05-23T08:05:00Z",
    "2026-05-23T08:06:00Z",
]


# -----------------------------------------------------------------------
# Re-derivation logic (mirrored in anticheat_re_derivation.py)
# -----------------------------------------------------------------------


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
                "(supported: '>=', '<=') — refusing to build a bundle from "
                "a policy with an unevaluable condition"
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


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -----------------------------------------------------------------------
# Bundle builder
# -----------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Build evidence/detection_signals.jsonl bytes
    # ------------------------------------------------------------------
    signals_lines = [json.dumps(case, sort_keys=True) for case in _CASES]
    signals_text = "\n".join(signals_lines) + "\n"
    signals_bytes = signals_text.encode("utf-8")

    # ------------------------------------------------------------------
    # Build evidence/detection_policy.json bytes
    # ------------------------------------------------------------------
    policy_text = json.dumps(_DETECTION_POLICY, indent=2, sort_keys=True) + "\n"
    policy_bytes = policy_text.encode("utf-8")

    # ------------------------------------------------------------------
    # Build payload/attestation_key.hex bytes
    # ------------------------------------------------------------------
    key_hex = _ATTESTATION_KEY.hex()
    attestation_key_bytes = (key_hex + "\n").encode("utf-8")

    # ------------------------------------------------------------------
    # Derive decisions + build adjudication provenance log
    # ------------------------------------------------------------------
    decisions: list[dict] = []
    provenance_rows: list[dict] = []

    for i, case in enumerate(_CASES):
        model_decision = _derive_decision(case, _DETECTION_POLICY)
        adjudicator = _ADJUDICATORS[i]
        timestamp = _TIMESTAMPS[i]

        # Adjudicator adopts the model recommendation as the final verdict
        # (simulated sign-off — automated detector or human moderator).
        final_verdict = model_decision["model_recommendation"]

        attest_hmac = _compute_attestation_hmac(
            adjudicator_id=adjudicator["adjudicator_id"],
            case_id=case["case_id"],
            final_verdict=final_verdict,
            timestamp=timestamp,
            key=_ATTESTATION_KEY,
        )

        decisions.append(
            {
                "case_id": case["case_id"],
                "model_recommendation": model_decision["model_recommendation"],
                "matched_rule_id": model_decision["matched_rule_id"],
                "final_verdict": final_verdict,
            }
        )

        provenance_rows.append(
            {
                "case_id": case["case_id"],
                "adjudicator_id": adjudicator["adjudicator_id"],
                "adjudicator_type": adjudicator["adjudicator_type"],
                "model_recommendation": model_decision["model_recommendation"],
                "final_verdict": final_verdict,
                "attestation_hmac": attest_hmac,
                "attestation_timestamp": timestamp,
            }
        )

    # Build payload/ban_decisions.json bytes
    decisions_text = json.dumps(decisions, indent=2, sort_keys=True) + "\n"
    decisions_bytes = decisions_text.encode("utf-8")

    # Build payload/adjudication_provenance.jsonl bytes
    provenance_lines = [json.dumps(row, sort_keys=True) for row in provenance_rows]
    provenance_text = "\n".join(provenance_lines) + "\n"
    provenance_bytes = provenance_text.encode("utf-8")

    # ------------------------------------------------------------------
    # OpaqueFragment anchors — one per detection signal contributing to a case
    # kind_tag="detection_signal"; locator = {finding_id, player_id, signal_type, value}
    # source_cid derived from evidence/detection_signals.jsonl SHA
    # ------------------------------------------------------------------
    signals_cid = f"sha256:{_sha256(signals_bytes)}"
    fragment_anchors: dict[str, dict] = {}

    for case in _CASES:
        for signal_name, signal_value in sorted(case["signals"].items()):
            finding_id = f"{case['case_id']}-sig-{signal_name}"
            frag = OpaqueFragment(
                source_cid=signals_cid,
                kind_tag="detection_signal",
                locator={
                    "finding_id": finding_id,
                    "player_id": case["player_id"],
                    "match_id": case["match_id"],
                    "signal_type": signal_name,
                    "value": str(signal_value),
                },
            )
            fragment_anchors[finding_id] = fragment_to_canonical_dict(frag)

    assert len(fragment_anchors) >= 3, (
        f"Expected >= 3 OpaqueFragment anchors; got {len(fragment_anchors)}"
    )

    # ------------------------------------------------------------------
    # dispatch_records — three op kinds exercising C15
    #   COMPUTE:           fixture prep
    #   DETECTION_EVAL:    the threshold-rule evaluation step
    #   ADJUDICATOR_ATTEST: the adjudicator attestation binding step
    # ------------------------------------------------------------------
    dispatch_records = [
        {
            "schema_version": "0.1",
            "op": {"kind": "COMPUTE", "name": "anticheat_fixture_prep"},
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
                "kind": "DETECTION_EVAL",
                "name": "anticheat_policy_threshold_evaluation",
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
                "kind": "ADJUDICATOR_ATTEST",
                "name": "anticheat_adjudicator_attestation_binding",
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
            "evidence/detection_signals.jsonl": signals_bytes,
            "evidence/detection_policy.json": policy_bytes,
            "payload/ban_decisions.json": decisions_bytes,
            "payload/adjudication_provenance.jsonl": provenance_bytes,
            "payload/attestation_key.hex": attestation_key_bytes,
        },
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "dispatch_records": dispatch_records,
            "decision_provenance_log": "payload/adjudication_provenance.jsonl",
        },
    )
    write_bundle(out_dir, content)

    n_ban = sum(1 for d in decisions if d["final_verdict"] == "ban")
    n_review = sum(1 for d in decisions if d["final_verdict"] == "review")
    n_clear = sum(1 for d in decisions if d["final_verdict"] == "clear")

    print(f"Bundle written to {out_dir}")
    print(f"  flagged cases        : {len(_CASES)}")
    print(f"  detection rules      : {len(_DETECTION_POLICY)}")
    print(
        f"  decisions            : {len(decisions)} (ban={n_ban} review={n_review} clear={n_clear})"
    )
    print(f"  provenance rows      : {len(provenance_rows)}")
    print(
        f"  fragment anchors     : {len(fragment_anchors)} OpaqueFragment (kind_tag=detection_signal)"
    )
    print(
        f"  dispatch records     : {len(dispatch_records)} (COMPUTE + DETECTION_EVAL + ADJUDICATOR_ATTEST)"
    )
    print(f"  manifest             : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic anticheat_adjudication_minimal audit bundle"
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
