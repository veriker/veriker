"""event_log_replay_recompute — verifier-side append-only-log replay re-derivation.

Axis-2 value-return form, PROMOTED into the shippable core registry (RECIPE_BOOK.md,
shape `event-log replay → reconstructed-record digest`). The generic verifier
recomputes the representative output on the SAFE spec-pinned path: no subprocess,
no bundle-supplied code. ONE generic primitive serves every domain whose
authoritative record is reconstructable from an append-only event log — the
auditor binds a domain output type to this primitive_id and an `exact` comparator.

Re-derivation primitive (one sentence):
    Replay the bundle's single append-only JSONL event log (inputs/<log>.jsonl)
    from its genesis CREATE event, applying each subsequent AMEND patch in file
    order, to reconstruct the authoritative current record; the re-derived value
    is the SHA-256 digest of that canonical reconstructed record.

Related to but not the `build artifact digest` shape: there is no build to
re-execute — the value is the digest of a STATE reconstructed by folding an
ordered CREATE/AMEND event stream (later writes win; LOG / disposition ops are
recorded but do not mutate the authoritative record). A dropped, reordered, or
forged AMEND changes the reconstructed state and therefore the digest →
REDERIVATION_MISMATCH.

Generic over domain (no per-pilot code):
  - The event log is located STRUCTURALLY as the sole `inputs/*.jsonl` in the
    bundle. The primitive FAILS CLOSED if there is not exactly one (zero or
    several) rather than guessing — a producer cannot point the verifier at a
    decoy log, and an ambiguous bundle is rejected, not silently resolved. The
    path is therefore not producer-asserted; the digest definition and the
    output→primitive binding are auditor-pinned in the spec.
  - The CREATE/AMEND/non-mutating-op semantics and the canonical serialization
    are FIXED here — the primitive_id ("event_log_replay_recompute") IS the rule.
    The non-mutating op-set (LOG + dispositions) is a SUPERSET: it tolerates a LOG
    op by skipping it. Six of the seven reproduced pilots match this op-set
    exactly; sec_17a4's demo-local copy is STRICTER (no LOG branch — a LOG op
    would raise there). Re-pointing sec_17a4's spec to this primitive would
    therefore BROADEN its accepted ops to include LOG (a migration-time decision,
    flagged in RECIPE_BOOK).

Domains it reproduces (RECIPE_BOOK Tier 3, verified on each pilot's shipped
fixture): HIPAA ePHI-system record, MiCA CASP record, MiFID II firm record,
PCI-DSS CDE record, SEC 17a-4 record, EU AI Act Art.12 logging
records. The pilots' OWN specs are NOT yet re-pointed at this primitive (they
still bind their demo-local primitive_ids) — that migration is the Tier-3
follow-on. (Pilots may carry premium trusted-time / retention / cross-org legs on
top; those are separate checks — this open re-derivation is the floor.)

Faithfulness (Gate B): the promoted test derives the honest claim from each
pilot's OWN demo-local producer (a code copy separate from this module, enforced
by the static disjointness guard), never from this module; an honest PASS proves
the producer's reconstructed record and the verifier's replay agree.

Stdlib-only (§C5 core verify() path): hashlib / json are stdlib.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ...admission import admit_jsonl_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive

# Recorded but non-record-mutating ops: operational/access LOG entries and
# disposition ops. They are integrity-guarded by the append-only chain and
# evaluated by separate completeness/retention legs, but do not mutate the
# authoritative record reconstructed here.
_NON_MUTATING_OPS = frozenset({"LOG", "DELETE", "DISPOSE", "PURGE", "DESTROY"})


# ---------------------------------------------------------------------------
# Canonical record serialization + replay (shared by builder + verifier)
# ---------------------------------------------------------------------------


def canonical_record_bytes(obj) -> bytes:
    """Deterministic record serialization for digesting (sorted keys, compact)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def parse_event_log(path: Path) -> list[dict]:
    """Parse an append-only JSONL event log into a list of event dicts.

    One JSON object per non-empty line. Raises ValueError on a malformed line so
    the verifier fails closed rather than silently skipping a tampered entry.
    """
    # Admission-bounded (RES-02): size-reject before allocation, per-line
    # depth-scan before parse. InputInadmissible subclasses ValueError, so the
    # fail-closed contract above is unchanged (a breach raises like any
    # malformed line did).
    events: list[dict] = []
    for lineno, rec in enumerate(
        admit_jsonl_file(path, check_name="event_log_replay"), start=1
    ):
        if not isinstance(rec, dict):
            raise ValueError(f"event log line {lineno} is not a JSON object")
        events.append(rec)
    return events


def replay_event_log(events: list[dict]) -> dict:
    """Replay events in order to reconstruct the authoritative record.

    CREATE seeds the record from its `fields`; each AMEND applies its `patch` via
    dict update (later writes win). Non-mutating ops (LOG + dispositions) do not
    mutate the authoritative record. Raises ValueError on a malformed log (no
    genesis CREATE, a second CREATE, an AMEND before CREATE, or an unknown op) so
    the verifier fails closed.
    """
    if not events:
        raise ValueError("empty event log — nothing to replay")
    record: dict = {}
    seen_create = False
    for i, ev in enumerate(events):
        op = ev.get("op")
        if op == "CREATE":
            if seen_create:
                raise ValueError(
                    f"event[{i}]: second CREATE in log (only genesis may CREATE)"
                )
            fields = ev.get("fields")
            if not isinstance(fields, dict):
                raise ValueError(f"event[{i}]: CREATE missing object 'fields'")
            record = dict(fields)
            seen_create = True
        elif op == "AMEND":
            if not seen_create:
                raise ValueError(f"event[{i}]: AMEND before genesis CREATE")
            patch = ev.get("patch")
            if not isinstance(patch, dict):
                raise ValueError(f"event[{i}]: AMEND missing object 'patch'")
            record.update(patch)
        elif op in _NON_MUTATING_OPS:
            continue
        else:
            raise ValueError(f"event[{i}]: unknown op {op!r}")
    if not seen_create:
        raise ValueError("event log has no genesis CREATE event")
    return record


def genesis_record_digest(events: list[dict]) -> str:
    """SHA-256 hex of the canonical genesis CREATE `fields`.

    Used by premium trusted-time legs that bind the timestamp to THIS record's
    registration (anti-backdating anchor). Open/stdlib — premium consumes it.
    """
    for ev in events:
        if ev.get("op") == "CREATE":
            fields = ev.get("fields")
            if not isinstance(fields, dict):
                raise ValueError("CREATE event missing object 'fields'")
            return hashlib.sha256(canonical_record_bytes(fields)).hexdigest()
    raise ValueError("event log has no genesis CREATE event")


def authoritative_record_digest(events: list[dict]) -> str:
    """SHA-256 hex of the canonical authoritative record after full replay."""
    record = replay_event_log(events)
    return hashlib.sha256(canonical_record_bytes(record)).hexdigest()


def _locate_event_log(bundle_dir: Path) -> Path:
    """Locate the bundle's single append-only event log (inputs/*.jsonl).

    Fail closed if there is not exactly one: zero is a missing log; several is an
    ambiguous bundle the verifier must not silently resolve.
    """
    inputs_dir = bundle_dir / "inputs"
    if not inputs_dir.is_dir():
        raise FileNotFoundError(
            f"inputs/ directory not found in bundle at {bundle_dir}"
        )
    logs = sorted(inputs_dir.glob("*.jsonl"))
    if len(logs) != 1:
        raise ValueError(
            f"event_log_replay expects exactly one inputs/*.jsonl event log, "
            f"found {len(logs)}: {[p.name for p in logs]}"
        )
    return logs[0]


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class EventLogReplayRecompute:
    """Verifier-side primitive: reconstruct the authoritative record by replaying
    the bundle's append-only event log; return its SHA-256 digest."""

    primitive_id: str = "event_log_replay_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Replay the sole inputs/*.jsonl event log and return the authoritative
        record digest. Returns the recomputed VALUE only; the auditor-anchored
        `exact` comparator decides agreement against the producer's claim.
        """
        bundle_dir: Path = inputs.bundle_dir
        log_path = _locate_event_log(bundle_dir)
        events = parse_event_log(log_path)
        digest = authoritative_record_digest(events)
        n_amend = sum(1 for e in events if e.get("op") == "AMEND")
        n_log = sum(1 for e in events if e.get("op") == "LOG")
        detail = (
            f"reconstructed authoritative record by replaying {len(events)} event(s) "
            f"from {log_path.name} ({n_amend} AMEND(s), {n_log} LOG event(s)); "
            f"digest={digest[:16]}…"
        )
        return RecomputedValue(value=digest, detail=detail)


register_primitive(EventLogReplayRecompute())
