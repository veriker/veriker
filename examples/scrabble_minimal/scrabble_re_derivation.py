#!/usr/bin/env python3
"""scrabble_re_derivation.py — stdlib re-derivation pack for scrabble_minimal.

Verifies that a Scrabble adjudication ruling is derivable from the bundled
timeline + wordlists + dispute. the audit-bundle contract §C6 + AB4.

Reads from --bundle-dir:
  editions/jurisdiction_timeline.json     authority -> edition windows
  disputes/D-0001.json                    input dispute record
  payload/ruling.json                     adjudication ruling to re-derive
  dictionaries/<edition_id>.txt           wordlist files referenced by timeline

Five invariants checked in order; first failure -> exit 1 with a named
reason code on stderr.

  1. SCRABBLE_TIMELINE_MALFORMED   — timeline JSON is missing structure or
                                     references an unknown jurisdiction
  2. SCRABBLE_EDITION_MISMATCH     — payload's edition_cited disagrees with
                                     the edition the timeline resolves for
                                     (jurisdiction, timestamp)
  3. SCRABBLE_EFFECTIVE_WINDOW_MISMATCH
                                   — payload's edition_effective_window does
                                     not match the timeline entry
  4. SCRABBLE_WORDLIST_MISSING     — wordlist file referenced by timeline
                                     entry not present in the bundle
  5. SCRABBLE_MEMBERSHIP_MISMATCH  — payload ruling does not match the
                                     re-derived (word in wordlist) result

If any of editions/, disputes/, payload/ruling.json is absent, the bundle
opted out of Scrabble re-derivation -> exits 0.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _emit(reason_code: str, message: str) -> None:
    print(f"[{reason_code}] {message}", file=sys.stderr)


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp with trailing 'Z' to a tz-aware datetime."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def _load_json(path: Path, reason_code: str) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _emit(reason_code, f"{path}: JSON parse error: {exc}")
        return None


def _read_wordlist(path: Path) -> set[str]:
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scrabble adjudication re-derivation check for scrabble_minimal bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    timeline_path = bundle_dir / "editions" / "jurisdiction_timeline.json"
    dispute_path = bundle_dir / "disputes" / "D-0001.json"
    ruling_path = bundle_dir / "payload" / "ruling.json"

    # If any required input is absent, the bundle opted out — not a failure.
    if not timeline_path.exists() or not dispute_path.exists() or not ruling_path.exists():
        return 0

    timeline = _load_json(timeline_path, "SCRABBLE_TIMELINE_MALFORMED")
    if timeline is None:
        return 1
    dispute = _load_json(dispute_path, "SCRABBLE_DISPUTE_MALFORMED")
    if dispute is None:
        return 1
    ruling = _load_json(ruling_path, "SCRABBLE_RULING_MALFORMED")
    if ruling is None:
        return 1

    # ----- timeline structure --------------------------------------------------
    try:
        authorities = timeline["authorities"]
        if not isinstance(authorities, dict):
            raise TypeError("authorities must be a dict")
    except (KeyError, TypeError) as exc:
        _emit("SCRABBLE_TIMELINE_MALFORMED", f"jurisdiction_timeline.json: {exc}")
        return 1

    # ----- ruling fields --------------------------------------------------------
    try:
        word = str(ruling["word"]).strip().upper()
        jurisdiction = ruling["jurisdiction"]
        ts = _parse_iso(ruling["timestamp"])
        claimed_edition = ruling["edition_cited"]
        claimed_window = ruling["edition_effective_window"]
        claimed_ruling = ruling["ruling"]
    except (KeyError, TypeError, ValueError) as exc:
        _emit("SCRABBLE_RULING_MALFORMED", f"payload/ruling.json: {exc}")
        return 1

    # ----- jurisdiction must exist in timeline ---------------------------------
    if jurisdiction not in authorities:
        _emit(
            "SCRABBLE_TIMELINE_MALFORMED",
            f"jurisdiction {jurisdiction!r} not found in timeline; "
            f"known: {sorted(authorities.keys())}",
        )
        return 1

    # ----- resolve effective edition at timestamp ------------------------------
    resolved_entry = None
    for entry in authorities[jurisdiction]:
        try:
            start = _parse_iso(entry["start"])
            end = _parse_iso(entry["end"]) if entry["end"] is not None else None
            edition_id = entry["edition"]
        except (KeyError, TypeError, ValueError) as exc:
            _emit(
                "SCRABBLE_TIMELINE_MALFORMED",
                f"timeline entry under {jurisdiction!r} is malformed: {exc}",
            )
            return 1
        if start <= ts and (end is None or ts < end):
            resolved_entry = entry
            break

    if resolved_entry is None:
        _emit(
            "SCRABBLE_TIMELINE_MALFORMED",
            f"no edition active for jurisdiction={jurisdiction!r} at timestamp={ruling['timestamp']!r}",
        )
        return 1

    # Invariant 2 — claimed_edition must match resolved
    if claimed_edition != resolved_entry["edition"]:
        _emit(
            "SCRABBLE_EDITION_MISMATCH",
            f"payload claims edition_cited={claimed_edition!r} but timeline "
            f"resolves jurisdiction={jurisdiction!r} at "
            f"timestamp={ruling['timestamp']!r} -> edition={resolved_entry['edition']!r}",
        )
        return 1

    # Invariant 3 — effective window agreement
    expected_window = {"start": resolved_entry["start"], "end": resolved_entry["end"]}
    if claimed_window != expected_window:
        _emit(
            "SCRABBLE_EFFECTIVE_WINDOW_MISMATCH",
            f"payload edition_effective_window={claimed_window!r} disagrees with "
            f"timeline window={expected_window!r} for edition={claimed_edition!r}",
        )
        return 1

    # Invariant 4 — wordlist file present
    wordlist_rel = resolved_entry["wordlist_file"]
    wordlist_path = bundle_dir / wordlist_rel
    if not wordlist_path.exists():
        _emit(
            "SCRABBLE_WORDLIST_MISSING",
            f"wordlist file {wordlist_rel!r} for edition={claimed_edition!r} "
            f"not present in bundle",
        )
        return 1

    # Invariant 5 — re-derive (word in wordlist) and compare to claimed ruling
    wordset = _read_wordlist(wordlist_path)
    is_member = word in wordset
    rederived_ruling = "legal" if is_member else "illegal"
    if rederived_ruling != claimed_ruling:
        _emit(
            "SCRABBLE_MEMBERSHIP_MISMATCH",
            f"payload claims ruling={claimed_ruling!r} for word={word!r} under "
            f"edition={claimed_edition!r} but membership lookup re-derives "
            f"ruling={rederived_ruling!r} (word {'in' if is_member else 'not in'} wordlist)",
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
