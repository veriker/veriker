"""_build_bundle.py — build a deterministic climate_emission_minimal audit bundle.

Climate / ESG Scope-3 supply-chain emission attribution pilot: for each
supplier in a 4-tier synthetic chain, compute:

    attributed_kg_co2e = round(activity_amount * emission_factor_kg_co2e_per_unit, 6)

Sum per-supplier values to produce total_scope3_kg_co2e.

Re-derivation primitive (one sentence):
  For each supplier (sorted by tier then vendor_id), multiply
  activity_amount × emission_factor_kg_co2e_per_unit, round to 6 decimal
  places; sum the per-supplier values to total_scope3_kg_co2e; assert
  every per-supplier attributed_kg_co2e AND the total exactly match
  payload/emission_report.json.

Why this matters for climate:
  Corporate ESG / GHG Protocol Scope-3 disclosures require supply-chain
  emission attributions to be computationally reproducible: the auditor
  must be able to re-derive each supplier's attributed emissions from the
  exact activity data and emission factors the model saw, using only
  committed artifacts. The V-Kernel audit bundle is that receipt.
  This pilot demonstrates the substrate claim on synthetic but
  structurally realistic data; production integrators replace the
  synthetic suppliers with real procurement data + certified EF databases;
  the bundle shape and verification protocol are identical.

Fragment kind: OpaqueFragment(kind_tag="supplier_emission_anchor") —
one fragment per supplier × emission-factor-source pair. Substrate
validates shape only; semantic validation is the responsibility of
ClimateEmissionReDerivationCheck.

Usage (from v-kernel-audit-bundle root, or anywhere):
    python examples/climate_emission_minimal/_build_bundle.py
        # writes manifest + bundle artifacts into the pilot directory itself

    python examples/climate_emission_minimal/_build_bundle.py --out-dir /tmp/climate_bundle
        # writes into a fresh out-dir

Caveat:
  When --out-dir is specified, only the generated artifacts (inputs/, payload/,
  re_derive/pack copy, manifest.json) are written. The pilot's own source files
  (_build_bundle.py, verify.py, README.md, ClimateEmissionReDerivationCheck.py,
  tests/) are not copied. The in-place build (default) is the canonical mode
  used by cli/verify.py.

Exit codes:
  0  success
  1  assertion failure
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

from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "climate-emission-minimal-rc"
_CREATED_AT = "2026-05-18T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "re_derivation_invocation",
]

# ---------------------------------------------------------------------------
# Synthetic fixtures — 4-tier supplier chain (8 suppliers total)
# Emission factors are plausible but invented (not from a real EF database).
# Sorted by tier then vendor_id for deterministic ordering.
# ---------------------------------------------------------------------------

_SUPPLIER_CHAIN = [
    # Tier 1 — raw material extraction
    {
        "tier": 1,
        "vendor_id": "T1-ALUM-001",
        "vendor_name": "Alpine Aluminium Smelting Co.",
        "activity_amount": 4200.0,
        "activity_unit": "kg_aluminium",
        "emission_factor_kg_co2e_per_unit": 8.24,
        "factor_source": "synthetic-EF-v1.0/aluminium-primary",
    },
    {
        "tier": 1,
        "vendor_id": "T1-STEE-002",
        "vendor_name": "Boreal Steel Works",
        "activity_amount": 7800.0,
        "activity_unit": "kg_steel",
        "emission_factor_kg_co2e_per_unit": 1.89,
        "factor_source": "synthetic-EF-v1.0/steel-basic-oxygen",
    },
    # Tier 2 — component manufacturing
    {
        "tier": 2,
        "vendor_id": "T2-CAST-001",
        "vendor_name": "Cascade Components Ltd.",
        "activity_amount": 320.0,
        "activity_unit": "kwh_electricity",
        "emission_factor_kg_co2e_per_unit": 0.233,
        "factor_source": "synthetic-EF-v1.0/electricity-grid-avg",
    },
    {
        "tier": 2,
        "vendor_id": "T2-PACK-002",
        "vendor_name": "Meridian Packaging Solutions",
        "activity_amount": 1500.0,
        "activity_unit": "kg_cardboard",
        "emission_factor_kg_co2e_per_unit": 0.72,
        "factor_source": "synthetic-EF-v1.0/cardboard-recycled",
    },
    # Tier 3 — sub-assembly
    {
        "tier": 3,
        "vendor_id": "T3-ASMB-001",
        "vendor_name": "Northgate Sub-Assembly Inc.",
        "activity_amount": 980.0,
        "activity_unit": "kwh_electricity",
        "emission_factor_kg_co2e_per_unit": 0.411,
        "factor_source": "synthetic-EF-v1.0/electricity-coal-heavy",
    },
    {
        "tier": 3,
        "vendor_id": "T3-LOGX-002",
        "vendor_name": "Overland Express Freight",
        "activity_amount": 12000.0,
        "activity_unit": "tonne_km",
        "emission_factor_kg_co2e_per_unit": 0.096,
        "factor_source": "synthetic-EF-v1.0/road-freight-diesel",
    },
    # Tier 4 — final logistics / last-mile delivery
    {
        "tier": 4,
        "vendor_id": "T4-AIRX-001",
        "vendor_name": "Apex Air Cargo Ltd.",
        "activity_amount": 550.0,
        "activity_unit": "tonne_km",
        "emission_factor_kg_co2e_per_unit": 0.602,
        "factor_source": "synthetic-EF-v1.0/air-freight-long-haul",
    },
    {
        "tier": 4,
        "vendor_id": "T4-SHIP-002",
        "vendor_name": "Coastal Shipping Partners",
        "activity_amount": 45000.0,
        "activity_unit": "tonne_km",
        "emission_factor_kg_co2e_per_unit": 0.012,
        "factor_source": "synthetic-EF-v1.0/sea-freight-container",
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj) -> bytes:
    """Deterministic JSON: sort_keys + compact separators + trailing newline."""
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _compute_attributions(supplier_chain: list) -> tuple[list, float]:
    """Compute per-supplier attributed_kg_co2e and total.

    Re-derivation primitive:
        attributed_kg_co2e = round(activity_amount * emission_factor_kg_co2e_per_unit, 6)
    Suppliers processed in input order (already sorted by tier then vendor_id).
    Total = sum of per-supplier attributed values (exact Python float sum).
    """
    attributions = []
    for s in supplier_chain:
        attributed = round(
            float(s["activity_amount"]) * float(s["emission_factor_kg_co2e_per_unit"]),
            6,
        )
        attributions.append(
            {
                "vendor_id": s["vendor_id"],
                "tier": s["tier"],
                "activity_amount": s["activity_amount"],
                "activity_unit": s["activity_unit"],
                "emission_factor_kg_co2e_per_unit": s[
                    "emission_factor_kg_co2e_per_unit"
                ],
                "factor_source": s["factor_source"],
                "attributed_kg_co2e": attributed,
            }
        )
    total = round(sum(a["attributed_kg_co2e"] for a in attributions), 6)
    return attributions, total


def _build_fragment_anchors(
    supplier_chain: list,
    attributions: list,
    supplier_chain_cid: str,
) -> dict:
    """One OpaqueFragment(kind_tag="supplier_emission_anchor") per supplier.

    source_cid is the supplier_chain.json content CID. Locator carries
    vendor_id + factor_source — enough for an auditor to trace the emission
    factor to its synthetic-EF-v1.0 registry entry.
    """
    anchors: dict = {}
    for s in supplier_chain:
        key = f"{s['vendor_id']}-ef"
        anchors[key] = fragment_to_canonical_dict(
            OpaqueFragment(
                source_cid=supplier_chain_cid,
                kind_tag="supplier_emission_anchor",
                locator={
                    "vendor_id": s["vendor_id"],
                    "factor_source": s["factor_source"],
                    "tier": s["tier"],
                },
            )
        )
    return anchors


# ---------------------------------------------------------------------------
# Re-derivation pack source — written into re_derive/ inside the bundle.
# Kept as a module-level string so _build_bundle.py is self-contained.
# ---------------------------------------------------------------------------

_RE_DERIVE_PACK_SOURCE: str = '''#!/usr/bin/env python3
"""climate_emission_pack.py — stdlib re-derivation pack for climate emission domain.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don\'t-import):
no audit_bundle imports inside this script. Stdlib only.

Re-derivation primitive:
  For each supplier in inputs/supplier_chain.json (in list order):
    attributed_kg_co2e = round(activity_amount * emission_factor_kg_co2e_per_unit, 6)
  Sum all per-supplier attributed_kg_co2e → total_scope3_kg_co2e (round to 6dp).

Assertions against payload/emission_report.json:
  - same number of attribution records
  - per-record: vendor_id, tier, attributed_kg_co2e must all match exactly
  - top-level total_scope3_kg_co2e must match exactly (round to 6dp)
  - aggregation_method must be "sum"

Exit 0 on full match; exit 1 with [CEM_REDER_FAIL] <description> on stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _fail(msg: str) -> int:
    print(f"[CEM_REDER_FAIL] {msg}", file=sys.stderr)
    return 1


def _compute_attributions(supplier_chain: list) -> tuple:
    """Re-derive per-supplier attributed_kg_co2e and total from supplier_chain."""
    attributions = []
    for s in supplier_chain:
        attributed = round(
            float(s["activity_amount"]) * float(s["emission_factor_kg_co2e_per_unit"]),
            6,
        )
        attributions.append(
            {
                "vendor_id": s["vendor_id"],
                "tier": s["tier"],
                "attributed_kg_co2e": attributed,
            }
        )
    total = round(sum(a["attributed_kg_co2e"] for a in attributions), 6)
    return attributions, total


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Climate Scope-3 emission re-derivation check"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    supplier_chain_path = bundle_dir / "inputs" / "supplier_chain.json"
    report_path = bundle_dir / "payload" / "emission_report.json"
    for p in (supplier_chain_path, report_path):
        if not p.exists():
            return _fail(f"required file missing: {p}")

    try:
        supplier_chain = json.loads(supplier_chain_path.read_text(encoding="utf-8"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to load bundle inputs/payload: {exc}")

    if not isinstance(supplier_chain, list):
        return _fail("supplier_chain.json must be a JSON array")
    if not isinstance(report, dict):
        return _fail("emission_report.json must be a JSON object")

    bundled_attributions = report.get("attributions")
    if not isinstance(bundled_attributions, list):
        return _fail("emission_report.json missing \'attributions\' array")
    bundled_total = report.get("total_scope3_kg_co2e")
    if bundled_total is None:
        return _fail("emission_report.json missing \'total_scope3_kg_co2e\'")
    agg_method = report.get("aggregation_method")
    if agg_method != "sum":
        return _fail(
            f"emission_report.json aggregation_method must be \'sum\'; got {agg_method!r}"
        )

    recomputed, recomputed_total = _compute_attributions(supplier_chain)

    if len(recomputed) != len(bundled_attributions):
        return _fail(
            f"attribution count mismatch: recomputed={len(recomputed)} "
            f"bundled={len(bundled_attributions)}"
        )

    for i, (rec, exp) in enumerate(zip(recomputed, bundled_attributions)):
        if rec["vendor_id"] != exp.get("vendor_id"):
            return _fail(
                f"attribution[{i}] vendor_id mismatch: "
                f"recomputed={rec[\'vendor_id\']!r} bundled={exp.get(\'vendor_id\')!r}"
            )
        if rec["tier"] != exp.get("tier"):
            return _fail(
                f"attribution[{i}] tier mismatch for {rec[\'vendor_id\']!r}: "
                f"recomputed={rec[\'tier\']} bundled={exp.get(\'tier\')}"
            )
        rec_val = round(float(rec["attributed_kg_co2e"]), 6)
        exp_val = round(float(exp.get("attributed_kg_co2e", 0.0)), 6)
        if rec_val != exp_val:
            return _fail(
                f"attribution[{i}] attributed_kg_co2e mismatch for "
                f"{rec[\'vendor_id\']!r}: recomputed={rec_val} bundled={exp_val}"
            )

    bundled_total_rounded = round(float(bundled_total), 6)
    if recomputed_total != bundled_total_rounded:
        return _fail(
            f"total_scope3_kg_co2e mismatch: recomputed={recomputed_total} "
            f"bundled={bundled_total_rounded}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


# ---------------------------------------------------------------------------
# Manifest file enumeration (in-place build)
# ---------------------------------------------------------------------------


def _enumerate_pilot_files_for_manifest(pilot_dir: Path) -> dict:
    """Walk the pilot dir and return {rel_path: sha256} for every file.

    Excludes manifest.json itself, any __pycache__ tree, any .pyc artifacts,
    and any spec/ or snapshots/ trees.
    """
    files: dict[str, str] = {}
    _SKIP_TOP = frozenset({"spec", "snapshots", "__pycache__"})
    for fpath in sorted(pilot_dir.rglob("*")):
        if fpath.is_dir():
            continue
        rel = fpath.relative_to(pilot_dir).as_posix()
        if rel == "manifest.json":
            continue
        parts = rel.split("/")
        if parts[0] in _SKIP_TOP:
            continue
        if any(p == "__pycache__" for p in parts):
            continue
        if rel.endswith(".pyc"):
            continue
        files[rel] = _sha256(fpath.read_bytes())
    return files


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    inputs_dir = out_dir / "inputs"
    payload_dir = out_dir / "payload"
    re_derive_dir = out_dir / "re_derive"
    for d in (inputs_dir, payload_dir, re_derive_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Sweep __pycache__ before enumerating files (verifier-self-pollution guard)
    for pycache in out_dir.rglob("__pycache__"):
        if pycache.is_dir():
            import shutil as _shutil

            _shutil.rmtree(pycache, ignore_errors=True)

    # --- Write the re-derivation pack first ---
    pack_path = re_derive_dir / "climate_emission_pack.py"
    pack_path.write_bytes(_RE_DERIVE_PACK_SOURCE.encode("utf-8"))

    # --- Write supplier_chain.json ---
    # Sort by tier then vendor_id for deterministic ordering
    sorted_chain = sorted(_SUPPLIER_CHAIN, key=lambda s: (s["tier"], s["vendor_id"]))
    supplier_chain_bytes = _canonical_json_bytes(sorted_chain)
    (inputs_dir / "supplier_chain.json").write_bytes(supplier_chain_bytes)
    supplier_chain_cid = f"sha256:{_sha256(supplier_chain_bytes)}"

    # --- Compute attributions ---
    attributions, total = _compute_attributions(sorted_chain)
    assert len(attributions) == 8, (
        f"Expected exactly 8 supplier attributions; got {len(attributions)}."
    )

    # --- Write emission_report.json ---
    emission_report = {
        "aggregation_method": "sum",
        "attributions": attributions,
        "total_scope3_kg_co2e": total,
    }
    emission_report_bytes = _canonical_json_bytes(emission_report)
    (payload_dir / "emission_report.json").write_bytes(emission_report_bytes)

    # --- Fragment anchors (one OpaqueFragment per supplier) ---
    fragment_anchors = _build_fragment_anchors(
        sorted_chain, attributions, supplier_chain_cid
    )
    assert len(fragment_anchors) == 8, (
        f"Expected exactly 8 fragment anchors (one per supplier); got {len(fragment_anchors)}."
    )

    # --- Build manifest.files ---
    if out_dir.resolve() == _HERE.resolve():
        files = _enumerate_pilot_files_for_manifest(out_dir)
    else:
        files = {
            "inputs/supplier_chain.json": _sha256(supplier_chain_bytes),
            "payload/emission_report.json": _sha256(emission_report_bytes),
            "re_derive/climate_emission_pack.py": _sha256(
                _RE_DERIVE_PACK_SOURCE.encode("utf-8")
            ),
        }

    manifest = {
        "schema_version": _SCHEMA_VERSION,
        "bundle_id": _BUNDLE_ID,
        "created_at": _CREATED_AT,
        "files": files,
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": _TYPED_CHECKS,
        "fragment_anchors": fragment_anchors,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Bundle written to {out_dir}")
    print(f"  suppliers        : {len(sorted_chain)} (4 tiers)")
    print(f"  total_scope3     : {total:.6f} kg CO2e")
    print(f"  fragment anchors : {len(fragment_anchors)} OpaqueFragment")
    print(f"  manifest files   : {len(files)}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic climate_emission_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=False,
        type=Path,
        default=_HERE,
        help=(
            "Destination directory. Defaults to the pilot's own directory "
            "(in-place build) so cli/verify.py --bundle-dir <pilot-dir> Just Works. "
            "Pass an explicit --out-dir to write a standalone bundle."
        ),
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
