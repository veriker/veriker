"""_build_bundle.py — build a deterministic scrabble_minimal audit bundle.

Writes a tournament-Scrabble dictionary-adjudication domain bundle into --out-dir:
  dictionaries/synthetic_csw_alpha.txt   (synthetic WESPA-INTL 2021-04-01 wordlist)
  dictionaries/synthetic_csw_beta.txt    (synthetic WESPA-INTL 2024-01-01 wordlist)
  dictionaries/synthetic_twl_v1.txt      (synthetic NASPA-NA 2006-03-01 wordlist)
  dictionaries/synthetic_twl_v2.txt      (synthetic NASPA-NA 2014-04-01 wordlist)
  editions/jurisdiction_timeline.json    (authority -> edition effective windows)
  disputes/D-0001.json                   (input dispute record)
  payload/ruling.json                    (adjudication ruling output)
  manifest.json

Exercises two V-Kernel extension points:
  OpaqueFragment(source_cid, kind_tag="lexical_entry", locator={...})
    — fragment anchor for the disputed word in its cited edition
  DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({
      "EDITION_RESOLVE", "MEMBERSHIP_LOOKUP", "COMPUTE"}))
    — admits two new op kinds for the (timeline -> wordlist) lookup chain

Usage (from v-kernel-audit-bundle root):
    python examples/scrabble_minimal/_build_bundle.py --out-dir /tmp/scrabble_bundle

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "scrabble-minimal-rc"
_CREATED_AT = "2026-05-08T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "scrabble_re_derivation",
    "dispatch_record_wellformed",
]

# --------------------------------------------------------------------------
# Synthetic dictionaries — deliberately tiny so the pilot is self-contained.
# Real CSW/TWL wordlists are commercially licensed by Collins/Hasbro; the
# substrate proof does not require real lexicons. The IP question is a
# downstream paper-prep concern, not a pilot blocker.
# --------------------------------------------------------------------------

# WESPA-INTL edition (2021-04-01 -> 2024-01-01)
_CSW_ALPHA: list[str] = [
    "ARFY", "ZARF", "QUOXY", "PRUM", "GLOZE",
    "SNARK", "WHEEN", "TANTO", "MIRZA", "VOLE",
]

# WESPA-INTL edition (2024-01-01 -> present)
# Adds: ZARFY, PHEEZE, QWERPS. Removes: ARFY.
_CSW_BETA: list[str] = [
    "ZARF", "QUOXY", "PRUM", "GLOZE", "SNARK",
    "WHEEN", "TANTO", "MIRZA", "VOLE",
    "ZARFY", "PHEEZE", "QWERPS",
]

# NASPA-NA edition (2006-03-01 -> 2014-04-01)
_TWL_V1: list[str] = [
    "ZARF", "PRUM", "SNARK", "TANTO", "VOLE",
    "GLITZ", "DAUNT", "TWIRP",
]

# NASPA-NA edition (2014-04-01 -> present)
# Adds: GLOZE, MIRZA.
_TWL_V2: list[str] = [
    "ZARF", "PRUM", "SNARK", "TANTO", "VOLE",
    "GLITZ", "DAUNT", "TWIRP",
    "GLOZE", "MIRZA",
]

# --------------------------------------------------------------------------
# Authority/edition timeline — single source of truth for which edition
# applies to which jurisdiction at which timestamp. EDITION_RESOLVE op
# reads this; MEMBERSHIP_LOOKUP op consults the resolved wordlist.
# --------------------------------------------------------------------------

_TIMELINE: dict = {
    "authorities": {
        "NASPA-NA": [
            {
                "edition": "synthetic_twl_v1",
                "wordlist_file": "dictionaries/synthetic_twl_v1.txt",
                "start": "2006-03-01T00:00:00Z",
                "end":   "2014-04-01T00:00:00Z",
            },
            {
                "edition": "synthetic_twl_v2",
                "wordlist_file": "dictionaries/synthetic_twl_v2.txt",
                "start": "2014-04-01T00:00:00Z",
                "end":   None,
            },
        ],
        "WESPA-INTL": [
            {
                "edition": "synthetic_csw_alpha",
                "wordlist_file": "dictionaries/synthetic_csw_alpha.txt",
                "start": "2021-04-01T00:00:00Z",
                "end":   "2024-01-01T00:00:00Z",
            },
            {
                "edition": "synthetic_csw_beta",
                "wordlist_file": "dictionaries/synthetic_csw_beta.txt",
                "start": "2024-01-01T00:00:00Z",
                "end":   None,
            },
        ],
    },
}

# --------------------------------------------------------------------------
# Dispute record — the input to be adjudicated.
# ZARFY is in csw_beta (legal under WESPA-INTL at 2024-08-15) but absent
# from twl_v2 (would be illegal under NASPA-NA at the same instant).
# --------------------------------------------------------------------------

_DISPUTE: dict = {
    "dispute_id": "D-0001",
    "word": "ZARFY",
    "jurisdiction": "WESPA-INTL",
    "timestamp": "2024-08-15T00:00:00Z",
    "claimed_ruling": "legal",
    "claimed_edition": "synthetic_csw_beta",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _wordlist_bytes(words: list[str]) -> bytes:
    """Render a wordlist file: sorted unique words, uppercased, one per line, LF-terminated."""
    lines = sorted({w.strip().upper() for w in words})
    return ("\n".join(lines) + "\n").encode("utf-8")


def build(out_dir: Path) -> None:
    # ------------------------------------------------------------------
    # Prepare artifact bytes
    # ------------------------------------------------------------------
    wordlists: dict[str, bytes] = {
        "synthetic_csw_alpha": _wordlist_bytes(_CSW_ALPHA),
        "synthetic_csw_beta":  _wordlist_bytes(_CSW_BETA),
        "synthetic_twl_v1":    _wordlist_bytes(_TWL_V1),
        "synthetic_twl_v2":    _wordlist_bytes(_TWL_V2),
    }

    timeline_bytes = (json.dumps(_TIMELINE, indent=2, sort_keys=True) + "\n").encode("utf-8")
    dispute_bytes = (json.dumps(_DISPUTE, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # ------------------------------------------------------------------
    # Compute the ruling deterministically (this is the "model output")
    # ------------------------------------------------------------------
    word_upper = _DISPUTE["word"].strip().upper()
    cited_edition_id = _DISPUTE["claimed_edition"]
    cited_wordlist_bytes = wordlists[cited_edition_id]
    is_member = word_upper in {
        line.strip()
        for line in cited_wordlist_bytes.decode("utf-8").splitlines()
        if line.strip()
    }

    # Locate the effective window for the cited edition under this jurisdiction
    eff_window = None
    for entry in _TIMELINE["authorities"][_DISPUTE["jurisdiction"]]:
        if entry["edition"] == cited_edition_id:
            eff_window = {"start": entry["start"], "end": entry["end"]}
            break
    assert eff_window is not None, (
        f"Dispute claims edition {cited_edition_id!r} not in timeline for "
        f"jurisdiction {_DISPUTE['jurisdiction']!r}"
    )

    ruling = {
        "dispute_id": _DISPUTE["dispute_id"],
        "word": word_upper,
        "jurisdiction": _DISPUTE["jurisdiction"],
        "timestamp": _DISPUTE["timestamp"],
        "ruling": "legal" if is_member else "illegal",
        "edition_cited": cited_edition_id,
        "edition_effective_window": eff_window,
        "membership_evidence": {
            "wordlist_sha256": _sha256(cited_wordlist_bytes),
            "lookup_method": "binary_membership",
        },
    }
    assert ruling["ruling"] == _DISPUTE["claimed_ruling"], (
        f"Synthesised ruling {ruling['ruling']!r} disagrees with claimed_ruling "
        f"{_DISPUTE['claimed_ruling']!r} — fixture inconsistency"
    )

    ruling_bytes = (json.dumps(ruling, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # ------------------------------------------------------------------
    # OpaqueFragment anchor — one per disputed word
    # ------------------------------------------------------------------
    cited_wordlist_cid = f"sha256:{_sha256(cited_wordlist_bytes)}"
    fragment_anchors: dict[str, dict] = {}

    frag = OpaqueFragment(
        source_cid=cited_wordlist_cid,
        kind_tag="lexical_entry",
        locator={
            "word": word_upper,
            "edition": cited_edition_id,
            "jurisdiction": _DISPUTE["jurisdiction"],
        },
    )
    fragment_anchors["disputed-word-anchor"] = fragment_to_canonical_dict(frag)

    assert len(fragment_anchors) >= 1, (
        f"Expected at least 1 OpaqueFragment anchor; got {len(fragment_anchors)}"
    )

    # ------------------------------------------------------------------
    # dispatch_records — EDITION_RESOLVE then MEMBERSHIP_LOOKUP.
    # ------------------------------------------------------------------
    dispatch_records = [
        {
            "schema_version": "0.1",
            "op": {
                "kind": "EDITION_RESOLVE",
                "name": "resolve_jurisdiction_edition_at_timestamp",
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
                "kind": "MEMBERSHIP_LOOKUP",
                "name": "wordlist_membership_check",
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
    # Emit via the reference-emitter SDK
    # ------------------------------------------------------------------
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "dictionaries/synthetic_csw_alpha.txt": wordlists["synthetic_csw_alpha"],
            "dictionaries/synthetic_csw_beta.txt": wordlists["synthetic_csw_beta"],
            "dictionaries/synthetic_twl_v1.txt": wordlists["synthetic_twl_v1"],
            "dictionaries/synthetic_twl_v2.txt": wordlists["synthetic_twl_v2"],
            "editions/jurisdiction_timeline.json": timeline_bytes,
            "disputes/D-0001.json": dispute_bytes,
            "payload/ruling.json": ruling_bytes,
        },
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "dispatch_records": dispatch_records,
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  dictionaries     : {len(wordlists)} synthetic editions")
    print(f"  manifest files   : 7")
    print(f"  fragment anchors : {len(fragment_anchors)} OpaqueFragment (kind_tag=lexical_entry)")
    print(f"  dispatch records : {len(dispatch_records)} (EDITION_RESOLVE + MEMBERSHIP_LOOKUP)")
    print(f"  ruling           : {ruling['word']} -> {ruling['ruling']} under {ruling['jurisdiction']}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic scrabble_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
