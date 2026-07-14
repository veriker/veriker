"""Provenance record for source-property assignments.

Per SCOPING.md §Load-bearing omissions item 4 (source-properties decision
provenance + versioning, formerly framed as "attestation decision provenance"
pre-K3 rename). Records the who/what/when/why of a source-property assignment as
a transcript of an *externally-made* decision — the verifier records it, it does
not make the admission/trust decision.

Append-only: prior rows are never mutated, mirroring the invariant in
audit_bundle.event_stream.append_event.

What "append-only" claims (RES-11 scoping)
------------------------------------------
Append-only here is a producer-side WRITER-API convention: this module never
rewrites prior rows. It is NOT a structural tamper-evidence guarantee for the
growing local file — a local process with write access can truncate or
rewrite it, and an unanchored per-row hash chain would not change that (the
same process recomputes the chain). The structural guarantees live elsewhere,
each at the layer where it can actually bind:

* once the log is minted into a bundle, its bytes are digest-pinned
  (manifest.files sha256 / DSSE set-closure) — post-mint truncation,
  rewrite, or reordering is a verifier REJECT;
* a bundle that needs pre-mint historical CONTINUITY as a verifiable claim
  carries C19 Layer A (extensions/c19/layer_a_counter.py): per-chain
  monotonic counters + prev-event hash chain + Merkle root, anchored via
  causal_chain so the chain is not locally recomputable, with
  verify_chain_integrity rejecting truncation/reordering/duplicates;
* absent Layer A, continuity is honestly UNCLAIMED: the open-tier ownership
  class for declared append-only files guarantees attribution-key coverage
  with producer-declared authority (integrity_ownership), never history.

See SECURITY.md §"Append-only logs and historical continuity".
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from audit_bundle.admission import admit_jsonl_file


_VALID_PROPERTY_NAMES: frozenset[str] = frozenset(
    {
        "issuer_identity_verified",
        "signed_artifact_present",
        "publication_class",
        "external_status_flags",
    }
)


@dataclass(frozen=True, slots=True)
class DecisionProvenance:
    """Immutable record of a source-property decision.

    decided_by convention: '<actor_kind>:<identifier>'
      e.g. 'human:max@nexi' | 'auto:issuer_verifier_v0.1'

    policy_version: SourceProperties.schema_version at decision time +
      verifier version, e.g. 'props_v0.1+iv_v0.1'

    prior_value: value before this decision (None if first-write)
    new_value:   value assigned by this decision
    evidence:    arbitrary supporting dict (e.g. {'allow_list_path': '...',
                 'matched_entry': '...'})
    """

    source_cid: str
    property_name: str  # one of _VALID_PROPERTY_NAMES
    decided_by: str  # '<actor_kind>:<identifier>'
    decided_at: str  # ISO-8601 UTC 'Z'
    policy_version: str  # e.g. 'props_v0.1+iv_v0.1'
    evidence: dict
    prior_value: object  # None on first-write
    new_value: object


def record_decision(jsonl_path: Path, provenance: DecisionProvenance) -> None:
    """Append provenance to a JSONL file in canonical form.

    Opens in append-binary mode and writes one JSON line (sort_keys=True,
    compact separators) followed by a newline byte. Prior rows are never
    touched — invariant mirrors audit_bundle.event_stream.append_event.

    Raises ValueError if property_name is not in the v1 set.
    """
    if provenance.property_name not in _VALID_PROPERTY_NAMES:
        raise ValueError(
            f"property_name {provenance.property_name!r} is not valid; "
            f"expected one of {sorted(_VALID_PROPERTY_NAMES)}"
        )
    row = dataclasses.asdict(provenance)
    line = (
        json.dumps(row, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    )
    with jsonl_path.open("ab") as fh:
        fh.write(line)


def read_decisions(
    jsonl_path: Path,
    source_cid: str | None = None,
) -> Iterator[DecisionProvenance]:
    """Yield DecisionProvenance objects from a JSONL file.

    Skips blank lines. Optionally filters to rows matching source_cid.

    The read is admission-bounded (admit_jsonl_file): this reader runs on the
    VERDICT PATH against a bundle-controlled file (the
    source_attributes_consistency plugin's replay-completeness leg), and the
    previous raw per-line ``json.loads`` over a file handle was exactly the
    iteration shape the package-wide admission ratchet documents as invisible
    to its AST scan — a depth-bomb line could drive the parser to
    RecursionError past the structured handler. Raises InputInadmissible
    (a ValueError) on size/depth/cardinality breach or a malformed line.
    """
    for obj in admit_jsonl_file(jsonl_path, check_name="decision_provenance"):
        prov = DecisionProvenance(
            source_cid=obj["source_cid"],
            property_name=obj["property_name"],
            decided_by=obj["decided_by"],
            decided_at=obj["decided_at"],
            policy_version=obj["policy_version"],
            evidence=obj.get("evidence", {}),
            prior_value=obj.get("prior_value"),
            new_value=obj["new_value"],
        )
        if source_cid is not None and prov.source_cid != source_cid:
            continue
        yield prov
