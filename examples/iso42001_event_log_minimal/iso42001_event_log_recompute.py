"""iso42001_event_log_recompute.py — verifier-side event-log chain re-derivation.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3).

Domain: ISO/IEC 42001:2023 Annex A.6 (AI System Life Cycle) — the sub-control
"AI-System Recording of Event Logs". A 42001-conforming AIMS keeps operational
event logs and commits/discloses a tamper-evident digest over them. Unlike the
A.6 V&V pilot (which re-derives a numeric metric), this pilot re-derives an
INTEGRITY DIGEST: the head of a hash-chain over the ordered event log.

Re-derivation primitive (one sentence):
    walk the ordered events folding a SHA-256 hash chain
        h_0 = sha256(GENESIS); h_i = sha256(h_{i-1} || sha256(canonical(event_i)))
    and return the final head digest (hex).

Because the chain folds order in, ANY tamper — editing a field, reordering,
inserting, or deleting an event — changes the head digest. The disclosed head is
compared with the `exact` comparator (hex-string equality).

HONEST CLAIM BOUNDARY: proves the disclosed log-head digest is RE-DERIVABLE from
the declared event log and that the log is internally tamper-evident under the
auditor's pinned chaining rule. It does NOT prove the log is COMPLETE (no event
was withheld before commitment), that the recorded events are truthful, or that
the org satisfies the A.6 logging control (which needs the logging process the
AIMS owns). Synthetic data; no customer.

Stdlib-only (§C5 contract).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

# Fixed genesis seed for the chain (part of the pinned rule).
_GENESIS = hashlib.sha256(b"V-KERNEL-ISO42001-A6-EVENTLOG-GENESIS").hexdigest()


def _canonical(event: dict) -> bytes:
    """Deterministic per-event serialization (sorted keys, tight separators)."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


# ---------------------------------------------------------------------------
# Canonical computation (shared by _build_bundle.py via direct import)
# ---------------------------------------------------------------------------


def compute_log_head_digest(events: list) -> str:
    """Fold a SHA-256 hash chain over the ordered events; return the head (hex).

    Order-sensitive by construction: reordering, inserting, deleting, or editing
    any event changes the head.
    """
    if not events:
        raise ValueError("event log is empty — head digest undefined")
    h = _GENESIS
    for ev in events:
        if not isinstance(ev, dict):
            raise ValueError(f"each event must be an object, got {type(ev).__name__}")
        leaf = hashlib.sha256(_canonical(ev)).hexdigest()
        h = hashlib.sha256((h + leaf).encode("ascii")).hexdigest()
    return h


# ---------------------------------------------------------------------------
# ReDerivationPrimitive class (registered by verify.py before BundleVerifier)
# ---------------------------------------------------------------------------


class Iso42001LogChainHeadRecompute:
    """Verifier-side primitive for re-deriving an event-log chain head digest."""

    primitive_id: str = "iso42001_log_chain_head_recompute"

    def recompute(self, inputs, pack_section: dict):
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        path = bundle_dir / "inputs" / "event_log.json"
        if not path.is_file():
            raise FileNotFoundError(
                f"inputs/event_log.json not found in bundle at {bundle_dir}"
            )
        doc = json.loads(path.read_bytes())
        events = doc.get("events")
        if not isinstance(events, list):
            raise ValueError("inputs/event_log.json must contain an 'events' array")
        value = compute_log_head_digest(events)
        return RecomputedValue(
            value=value,
            detail=f"re-derived hash-chain head over {len(events)} ordered events",
        )
