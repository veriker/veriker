"""examples/citation_integrity_minimal/build_bundle.py — L8 citation-integrity pilot.

Packages the (already-built, default-ON) L8 fragment-attestation engine into a
multi-citation demonstration. A "citation set" of ~4 synthetic citations quotes
two admitted source documents; each citation is emitted as a per-quote
``fragment_anchor`` (a locator + ``content_selector.exact``) bound to its source
snapshot. ``veriker/cli/verify.py``'s ``FragmentAttestationCheck`` re-derives every cited
span from the FROZEN snapshot bytes and asserts the quote matches under a
versioned text normalization (case/punctuation/whitespace-insensitive, NOT
byte-exact):

  - every quote matches its source       -> verify() PASS (FRAGMENTS_ATTESTED)
  - any one quote fabricated             -> FRAGMENT_MISQUOTE,            FAIL
  - any one offset past the snapshot end -> FRAGMENT_OFFSET_OUT_OF_BOUNDS, FAIL
  - a sentence anchor under a drifted segmenter -> SEGMENTER_MISMATCH,    FAIL
  - a citation whose source isn't bundled -> FRAGMENT_SOURCE_UNRESOLVABLE, FAIL

Two locked resolver kinds are exercised: byte-offset AND sentence-ID. No engine
code is touched — this module only emits anchors. ADR:
the internal design notes

HONEST CLAIM (see README): this proves citation INTEGRITY / re-derivability — the
quote matches the cited span under a versioned text normalization (case/punctuation/
whitespace-insensitive, NOT byte-exact), deterministically, no LLM, auditor-reproducible.
It does NOT prove the source is true, and does NOT mean "compliant". Same-snapshot
only: the W3C TextQuoteSelector prefix/suffix relocation fields are never exercised
(relocation across structure drift is deferred research, ADR D3.b).

The source passages below are synthetic, demo-only prose (NOT verbatim from any
real publication) so this pilot carries no named-firm or private content and is
safe on any surface — same posture as the single-citation rejection pilot.

Stdlib only.
"""

from __future__ import annotations

import sys

# Per the internal design notes — set FIRST.
sys.dont_write_bytecode = True

import hashlib  # noqa: E402
import json  # noqa: E402
from pathlib import Path  # noqa: E402

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parents[1]  # .../v-kernel-audit-bundle
sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.fragments.sentence_segmenter import (  # noqa: E402
    SEGMENTER_VERSION,
    resolve_sentence_id,
)
from audit_bundle.snapshots.snapshot_policy import (  # noqa: E402
    default_v1_policy,
    policy_to_canonical_dict,
)

# ---------------------------------------------------------------------------
# Two synthetic admitted-source documents (demo fixtures; not real publications).
# ---------------------------------------------------------------------------

SOURCE_A = (
    "A participant who fails to meet a mutual obligation requirement without a "
    "reasonable excuse may have their payment suspended. The Secretary must take "
    "into account the participant's personal circumstances before applying a "
    "financial penalty. A decision to suspend a payment is reviewable on its merits."
)

SOURCE_B = (
    "The provider must retain each decision record for no less than six years. "
    "An auditor may request the underlying evidence at any time during the "
    "retention period. Records that cannot be reproduced from source are treated "
    "as incomplete."
)

_SNAP_A_REL = "snapshots/src-welfare-001.txt"
_SNAP_B_REL = "snapshots/src-records-002.txt"


def _cid(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


CID_A = _cid(SOURCE_A)
CID_B = _cid(SOURCE_B)


def _byte_span(source: str, quote: str) -> tuple[int, int]:
    """Half-open UTF-8 byte range [start, end) of the genuine ``quote`` in ``source``."""
    src_bytes = source.encode("utf-8")
    start = src_bytes.index(quote.encode("utf-8"))
    return start, start + len(quote.encode("utf-8"))


# Genuine quotes (each byte-present in its source at the recorded span).
_Q_A1 = (
    "The Secretary must take into account the participant's personal "
    "circumstances before applying a financial penalty."
)
_Q_A2 = "A decision to suspend a payment is reviewable on its merits."
_Q_B1 = "The provider must retain each decision record for no less than six years."

# Genuine sentence-ID citation: index 1 of SOURCE_B's deterministic segmentation.
_SENT_B_INDEX = 1
_, _, _Q_B_SENT = resolve_sentence_id(SOURCE_B, _SENT_B_INDEX)

# A fabricated quote attributed to the SAME admitted source A — plausible, but NOT
# byte-present (the misquote class an admission walk alone misses).
_FABRICATED_A1 = (
    "The Secretary may suspend any payment immediately and without review "
    "whenever a participant misses an appointment."
)


def _genuine_anchors() -> dict[str, dict]:
    """The all-verbatim citation set: 3 byte-offset + 1 sentence-ID anchor."""
    a1_start, a1_end = _byte_span(SOURCE_A, _Q_A1)
    a2_start, a2_end = _byte_span(SOURCE_A, _Q_A2)
    b1_start, b1_end = _byte_span(SOURCE_B, _Q_B1)
    return {
        "cit-1": {
            "kind": "byte_offset",
            "source_cid": CID_A,
            "start": a1_start,
            "end": a1_end,
            "content_selector": {"type": "TextQuoteSelector", "exact": _Q_A1},
        },
        "cit-2": {
            "kind": "byte_offset",
            "source_cid": CID_A,
            "start": a2_start,
            "end": a2_end,
            "content_selector": {"type": "TextQuoteSelector", "exact": _Q_A2},
        },
        "cit-3": {
            "kind": "byte_offset",
            "source_cid": CID_B,
            "start": b1_start,
            "end": b1_end,
            "content_selector": {"type": "TextQuoteSelector", "exact": _Q_B1},
        },
        "cit-4": {
            "kind": "sentence_id",
            "source_cid": CID_B,
            "sentence_index": _SENT_B_INDEX,
            "segmenter_version": SEGMENTER_VERSION,
            "content_selector": {"type": "TextQuoteSelector", "exact": _Q_B_SENT},
        },
    }


# Valid faults, each mutating exactly one anchor from the all-genuine baseline.
_FAULTS = frozenset(
    {"fabricate", "offset_oob", "segmenter_drift", "source_unresolvable"}
)


def build_citation_bundle(
    bundle_dir: Path,
    fault: str | None = None,
    only: list[str] | None = None,
) -> Path:
    """Emit a citation-set bundle under ``bundle_dir``.

    ``fault`` (one of ``_FAULTS`` or ``None``) mutates exactly one anchor.
    ``only`` restricts the emitted anchors to the given citation keys (used to
    demonstrate a single genuine sentence-ID citation in isolation).
    """
    if fault is not None and fault not in _FAULTS:
        raise ValueError(f"unknown fault {fault!r}; expected one of {sorted(_FAULTS)}")

    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "snapshots").mkdir(parents=True, exist_ok=True)
    (bundle_dir / _SNAP_A_REL).write_text(SOURCE_A, encoding="utf-8")
    (bundle_dir / _SNAP_B_REL).write_text(SOURCE_B, encoding="utf-8")

    anchors = _genuine_anchors()
    if only is not None:
        anchors = {k: v for k, v in anchors.items() if k in only}

    if fault == "fabricate":
        anchors["cit-1"]["content_selector"]["exact"] = _FABRICATED_A1
    elif fault == "offset_oob":
        # Push the END past the snapshot length -> FRAGMENT_OFFSET_OUT_OF_BOUNDS.
        anchors["cit-1"]["end"] = len(SOURCE_A.encode("utf-8")) + 100
    elif fault == "segmenter_drift":
        # Stamp the sentence anchor with a segmenter that isn't the runtime's.
        anchors["cit-4"]["segmenter_version"] = "0.0-bogus-segmenter"
    elif fault == "source_unresolvable":
        # Point a citation at a source_cid not declared in manifest.snapshots.
        anchors["cit-3"]["source_cid"] = "sha256:" + ("00" * 32)

    a_bytes = SOURCE_A.encode("utf-8")
    b_bytes = SOURCE_B.encode("utf-8")
    manifest = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "citation-integrity-demo",
        "files": {
            _SNAP_A_REL: hashlib.sha256(a_bytes).hexdigest(),
            _SNAP_B_REL: hashlib.sha256(b_bytes).hexdigest(),
        },
        "spec_files": {},
        "cross_refs": {},
        "typed_checks": [],
        "snapshots": {CID_A: _SNAP_A_REL, CID_B: _SNAP_B_REL},
        "snapshot_policy": policy_to_canonical_dict(default_v1_policy()),
        "fragment_anchors": anchors,
    }
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return bundle_dir


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Build the genuine citation-integrity bundle (every quote verbatim) "
            "into --out-dir, ready for `python -m veriker.cli.verify --bundle-dir <out>`."
        )
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        required=True,
        help="Directory to write the bundle into (created if absent).",
    )
    args = parser.parse_args()
    out = build_citation_bundle(args.out_dir)
    print(f"Bundle written to {out}")
