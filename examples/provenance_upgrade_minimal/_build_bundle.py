"""_build_bundle.py — build a deterministic provenance_upgrade_minimal audit bundle.

The canonical HONEST demonstration of the S1 mechanism end-to-end: a real,
verifier-signed, single-tier rigor-stamp upgrade that verifies cleanly through
the bare default verifier (veriker/cli/verify.py), AND the monotone-minimum
"weakest-link" aggregation that forbids trust-laundering.

Patent S1 ("Tamper-Evident Provenance Labeling by a Monotone-Minimum Rigor
Lattice with Signed Single-Tier Upgrades") was, prior to this pilot, exercised
only by unit tests and by the adversarial soak corpus (negative cases). No
honest shipped bundle carried a real stamp upgrade. This pilot closes that gap.

Story — a two-step AI extraction over a hash-pinned source table:

  Record 0  COMPUTE / extract_total
      The model extracted a `total` figure from the source table. It enters at
      COMPOSED_HYPOTHESIS (tier 1 — a model-composed value, not yet checked).
      The verifier evaluates a deterministic predicate: recompute the sum of
      the source line-items and check the extracted total equals it. The
      predicate HOLDS, so the verifier signs a single-tier upgrade
      COMPOSED_HYPOTHESIS -> TARGET (reason=predicate_satisfied), HMAC-bound to
      (bundle_id, record_idx=0, from_stamp, to_stamp). Only a verifier-signed
      record can raise a stamp; the producer cannot raise its own label.

  Record 1  COMPUTE / extract_footnote
      The model also extracted a prose footnote claim for which the verifier has
      no deterministic predicate. It stays at COMPOSED_HYPOTHESIS, un-upgraded.

  aggregate_stamp = min(effective) = min(TARGET, COMPOSED_HYPOTHESIS)
                  = COMPOSED_HYPOTHESIS

The aggregate is PINNED to the weakest un-upgraded row: even though one row was
legitimately upgraded, the bundle cannot be presented at the higher tier. That
is the S1 anti-laundering invariant shown positively.

Verifier key — per the S1 disclosure, the upgrade is signed under the VERIFIER
key (held by the verifier, NOT the producer). This script plays the verifier's
upgrade-signing step and reads VKERNEL_VERIFIER_HMAC_KEY from the environment,
exactly as veriker/cli/verify.py's _load_verifier_recheck_key() does, so the signature
re-verifies at verify time. The key is a disclosed synthetic demo secret
(Standing Order #9: NOT a real secret).

Usage (from v-kernel-audit-bundle root, with the demo verifier key exported):
    export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
    python examples/provenance_upgrade_minimal/_build_bundle.py \
        --out-dir examples/provenance_upgrade_minimal/bundle

Exit codes:
  0  success
  1  assertion failure or missing verifier key
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.discharge.verifier_signing import (  # noqa: E402
    VerifierSigningKey,
    sign_stamp_upgrade,
)
from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "provenance-upgrade-minimal-rc"
_CREATED_AT = "2026-05-30T00:00:00Z"
# Defense 7 (out-of-order timestamp): the verifier-signed upgrade must be
# timestamped at or before the bundle's sealed creation time. We pin it to
# created_at exactly (<= holds).
_UPGRADE_AT = _CREATED_AT

_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "dispatch_record_wellformed",
    "stamp_lattice",
]

# The hash-pinned source the extraction was derived from. The `total` claim is
# checkable against this (sum of line_items); the `footnote` claim is not.
_SOURCE_TABLE = {
    "source": "nexi:demo:Q1FinancialsTable",
    "period": "2026-Q1",
    "line_items": [
        {"label": "Subscriptions", "amount_usd": 412000},
        {"label": "Services", "amount_usd": 138500},
        {"label": "Other", "amount_usd": 24500},
    ],
    "footnote_text": (
        "Services revenue includes a one-time migration engagement recognized "
        "ratably over the contract term."
    ),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_verifier_key() -> VerifierSigningKey:
    """Construct the verifier signing key the SAME way veriker/cli/verify.py's
    _load_verifier_recheck_key() does: VKERNEL_VERIFIER_HMAC_KEY (UTF-8 bytes),
    default verifier_id 'v-kernel-default'. This guarantees the upgrade
    signature re-verifies at verify time."""
    secret = os.environ.get("VKERNEL_VERIFIER_HMAC_KEY")
    if not secret:
        raise AssertionError(
            "VKERNEL_VERIFIER_HMAC_KEY is not set. The S1 upgrade is "
            "VERIFIER-signed; export the same demo secret the verifier loads, "
            "e.g.\n"
            '  export VKERNEL_VERIFIER_HMAC_KEY='
            '"demo-vkernel-verifier-secret-0123456789abcdef"'
        )
    return VerifierSigningKey.from_secret_bytes(secret.encode("utf-8"))


def build(out_dir: Path) -> None:
    key = _load_verifier_key()

    # spec/ — the pinned source table + disclosed synthetic verifier-key id.
    source_bytes = json.dumps(_SOURCE_TABLE, indent=2, sort_keys=True).encode("utf-8")

    # --- The model's two extracted claims (the producer's output). -----------
    # extract_total: an HONEST extraction — equals the recomputed sum.
    recomputed_total = sum(li["amount_usd"] for li in _SOURCE_TABLE["line_items"])
    extracted_total = recomputed_total  # honest producer
    extractions = {
        "source_sha256": _sha256(source_bytes),
        "claims": [
            {
                "claim_id": "extract_total",
                "kind": "numeric",
                "value_usd": extracted_total,
            },
            {
                "claim_id": "extract_footnote",
                "kind": "prose",
                "text": _SOURCE_TABLE["footnote_text"],
            },
        ],
    }
    payload_bytes = json.dumps(extractions, indent=2).encode("utf-8")

    # Evidence copy of the source the verifier re-derives against (file-integrity
    # covered; spec/ copy is covered by spec_sha_pin). Byte-identical to spec/.
    evidence_bytes = source_bytes

    # --- The verifier's role: evaluate the predicate, then sign the upgrade. --
    # Record 0 enters at COMPOSED_HYPOTHESIS. The verifier recomputes the sum
    # and checks the producer's `total` equals it. ONLY if it holds does the
    # verifier sign the single-tier upgrade. This mirrors the real verifier
    # path: the upgrade is EARNED, not rubber-stamped.
    predicate_holds = extracted_total == recomputed_total
    assert predicate_holds, (
        "extract_total does not equal the recomputed source sum; the verifier "
        "would refuse to sign the upgrade (this build only ships an HONEST "
        "bundle where the predicate genuinely holds)"
    )

    record_0 = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "extract_total"},
        "inputs": [],
        "outputs": [],
        "effect": {},
        "locale": "en-US",
        "predicates": ["sum(line_items.amount_usd) == claim.value_usd"],
        "stamp_declared": "COMPOSED_HYPOTHESIS",
        "stamp_observed": "COMPOSED_HYPOTHESIS",
    }
    # Verifier signs the single-tier upgrade COMPOSED_HYPOTHESIS -> TARGET.
    record_0 = sign_stamp_upgrade(
        record_0,
        key=key,
        from_stamp="COMPOSED_HYPOTHESIS",
        to_stamp="TARGET",
        upgrade_reason="predicate_satisfied",
        discharge_obligation_sha="",  # empty for non-'discharged' reasons
        bundle_id=_BUNDLE_ID,
        record_idx=0,
        timestamp_utc=_UPGRADE_AT,
    )

    # Record 1 — no checkable predicate; stays at COMPOSED_HYPOTHESIS.
    record_1 = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "extract_footnote"},
        "inputs": [],
        "outputs": [],
        "effect": {},
        "locale": "en-US",
        "predicates": [],
        "stamp_declared": "COMPOSED_HYPOTHESIS",
        "stamp_observed": "COMPOSED_HYPOTHESIS",
    }

    dispatch_records = [record_0, record_1]

    # Aggregate = min over EFFECTIVE stamps (record 0 effective = TARGET via the
    # admitted upgrade; record 1 effective = COMPOSED_HYPOTHESIS). Weakest-link.
    effective = ["TARGET", "COMPOSED_HYPOTHESIS"]
    aggregate_stamp = "COMPOSED_HYPOTHESIS"  # min(effective) — pinned, not laundered

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest). ---
    # dispatch_records (with the verifier-signed S1 upgrade) and the weakest-link
    # aggregate_stamp are deterministic domain output, supplied as pilot-carried
    # manifest fields (no live time/causal-chain witness on this pilot).
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "evidence/source_table.json": evidence_bytes,
            "payload/extractions.json": payload_bytes,
        },
        spec_files={"source_table.json": source_bytes},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "dispatch_records": dispatch_records,
            "aggregate_stamp": aggregate_stamp,
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  source line-items   : {len(_SOURCE_TABLE['line_items'])}")
    print(f"  recomputed total    : ${recomputed_total:,}")
    print(f"  extracted total     : ${extracted_total:,}  (predicate holds: {predicate_holds})")
    print("  record 0 stamp      : COMPOSED_HYPOTHESIS --[verifier-signed]--> TARGET")
    print("  record 1 stamp      : COMPOSED_HYPOTHESIS  (no checkable predicate)")
    print(f"  aggregate_stamp     : {aggregate_stamp}  (min over effective; weakest-link)")
    print(f"  verifier_id         : {key.verifier_id}")
    print(f"  manifest            : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic provenance_upgrade_minimal audit bundle"
    )
    parser.add_argument("--out-dir", required=True, type=Path)
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
