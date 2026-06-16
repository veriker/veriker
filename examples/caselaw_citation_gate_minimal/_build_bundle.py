"""_build_bundle.py — build a deterministic caselaw_citation_gate_minimal audit bundle.

Case-law citation credibility-gate re-derivation pilot (Axis-2 spec-pinned dispatch).

An AI legal assistant (producer) asserts a set of supporting citations and a
gate decision (AUTO_APPROVE / ROUTE_TO_HUMAN). The bundle lets an auditor
re-derive that decision from committed evidence: each asserted reporter cite is
resolved against a rooted court-record corpus, and the quoted holding is screened
for verbatim membership in the resolved record's holding text. A cite that does
not resolve is UNRESOLVED (possible fabrication); a cite that resolves but whose
quote is not found is MISQUOTE (real source, fabricated/inverted quote); both
force ROUTE_TO_HUMAN.

This is the DEWR "real source / fabricated quote" rejection shape and the
scrabble_minimal "resolve-then-membership" shape, pointed at case law.

The honest fixture deliberately mixes:
  C-01 Alice (573 U.S. 208)            -> ROOTED      (quote matches)
  C-02 Thaler (43 F.4th 1207)          -> ROOTED      (quote matches)
  C-03 Recentive (134 F.4th 1205)      -> MISQUOTE    (cited for the OPPOSITE
                                          of its real holding: "eligible" vs the
                                          rooted "ineligible under section 101")
  C-04 Synapse AI (142 F.4th 880)      -> UNRESOLVED  (fabricated — no such case)
so the honest gate decision is ROUTE_TO_HUMAN, and that verdict re-derives.

Re-derivation primitive (one sentence):
  For each asserted citation, resolve its reporter cite against
  corpus/rooted_records.json and test the quoted holding for normalized
  substring membership in the rooted holding text; decision = AUTO_APPROVE iff
  every citation is ROOTED, else ROUTE_TO_HUMAN.

Trust-root note (honest framing):
  The auditor anchors the METHOD (resolve + misquote-check + comparator). That
  the corpus records are GENUINE court records is a trust-root concern (corpus
  genuineness, out of scope for the verifier's re-derivation).
  At v0.1 the corpus is a committed fixture of real, public U.S. patent
  cases; production replaces it with a trust-root resolver against a rooted
  authority (e.g. CourtListener / PACER). Bundle shape and protocol are identical.

Usage (from v-kernel-audit-bundle root):
    python examples/caselaw_citation_gate_minimal/_build_bundle.py --out-dir /tmp/clg_bundle

Exit codes:
  0  success
  1  assertion / computation failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Import the canonical compute function from the primitive module so the builder
# and the verifier share ONE definition and cannot drift.
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from caselaw_gate_recompute import (  # noqa: E402
    MISQUOTE,
    ROUTE_TO_HUMAN,
    UNRESOLVED,
    compute_gate_verdict,
)
from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "caselaw-citation-gate-minimal-rc"
_CREATED_AT = "2026-05-31T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
]

_OUTPUT_ID = "gate_verdict"
_TYPE_KEY = "caselaw_gate_verdict"

_CORPUS_SRC = _HERE / "corpus" / "rooted_records.json"
_ASSERTIONS_SRC = _HERE / "assertions" / "citation_assertions.json"
_SPEC_SRC = _HERE / "spec_pinned" / "caselaw_gate.spec.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Sweep __pycache__ before enumerating files (verifier-self-pollution guard)
    for pycache in out_dir.rglob("__pycache__"):
        if pycache.is_dir():
            shutil.rmtree(pycache, ignore_errors=True)

    # --- 1. Read committed evidence (frozen fixtures) ---
    corpus_bytes = _CORPUS_SRC.read_bytes()
    assertions_bytes = _ASSERTIONS_SRC.read_bytes()
    spec_bytes = _SPEC_SRC.read_bytes()
    spec_basename = _SPEC_SRC.name
    spec_sha = _sha256(spec_bytes)

    corpus = json.loads(corpus_bytes)
    assertions = json.loads(assertions_bytes)

    # --- 2. Compute the HONEST gate verdict (this is the producer's claim) ---
    verdict = compute_gate_verdict(corpus, assertions)

    # Sanity-check the fixture exercises all three statuses + the human route,
    # so the pilot demonstrably bites (a fixture where everything is ROOTED would
    # hide the misquote/fabrication detection that is the whole point).
    statuses = {c["status"] for c in verdict["citations"]}
    assert verdict["decision"] == ROUTE_TO_HUMAN, (
        f"Expected honest decision ROUTE_TO_HUMAN; got {verdict['decision']!r}. "
        "The fixture should contain at least one non-ROOTED citation."
    )
    assert MISQUOTE in statuses and UNRESOLVED in statuses, (
        f"Expected the fixture to exercise MISQUOTE and UNRESOLVED; got {sorted(statuses)!r}."
    )

    # --- 3. Build outputs/gate_verdict.json bytes (producer's claimed value) ---
    claim_bytes = (
        json.dumps({"value": verdict}, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- 4. Build outputs list for extra_manifest_fields ---
    outputs_list = [
        {
            "output_id": _OUTPUT_ID,
            "type": _TYPE_KEY,
            "conforms_to": f"spec/{spec_basename}",
        }
    ]

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest). ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "corpus/rooted_records.json": corpus_bytes,
            "assertions/citation_assertions.json": assertions_bytes,
            f"outputs/{_OUTPUT_ID}.json": claim_bytes,
        },
        spec_files={spec_basename: spec_bytes},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": {},
            "outputs": outputs_list,
        },
    )
    write_bundle(out_dir, content)

    n_rooted = sum(1 for c in verdict["citations"] if c["status"] == "ROOTED")
    print(f"Bundle written to {out_dir}")
    print(f"  rooted corpus    : {len(corpus)} court record(s)")
    print(f"  assertions       : {len(assertions)} cited authority(ies)")
    print(f"  gate verdict     : {verdict['decision']} ({n_rooted}/{len(assertions)} ROOTED)")
    for c in verdict["citations"]:
        print(f"    {c['id']}  {c['reporter_cite']:<16} -> {c['status']}")
    print(f"  output_id        : {_OUTPUT_ID}")
    print(f"  spec             : {spec_basename}  sha256={spec_sha[:16]}...")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic caselaw_citation_gate_minimal audit bundle"
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
    except (AssertionError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
