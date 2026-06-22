#!/usr/bin/env python3
"""pe_engineering_signoff_re_derivation.py — stdlib re-derivation pack for pe_engineering_signoff_minimal.

Re-computes the maximum bending stress, factor of safety, and structural verdict
for each cantilever-beam analysis in the bundle from bundled geometry + material +
load inputs. Compares against bundled payload/engineering_analyses.json.

Additionally re-verifies every HMAC-signed PE-stamp attestation in
payload/pe_stamp_provenance.jsonl against the synthetic key in
payload/attestation_key.hex.

the audit-bundle contract §C6 (domain-agnostic re-derivation) + AB4.

Re-derivation primitive (one sentence):
  Re-compute σ_max = (P * L) * c / I from bundled material + geometry + load
  inputs, re-derive factor_of_safety = yield_stress_Pa / σ_max, and verify the
  PE stamp's HMAC-SHA256 over the 8-field stamp payload binds each output to a
  specific licensed PE.

Exit codes:
  0  all invariants pass
  1  mismatch found — see stderr for [PE_ENGINEERING_REDERIVATION_MISMATCH] or
                       [PE_STAMP_INVALID]

Stdlib only: json, hmac, hashlib, argparse, pathlib, sys.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac as _hmac
import json
import sys
from pathlib import Path

# Float comparison tolerances
_STRESS_EPS = 1e-9  # Pa — absolute tolerance for max_bending_stress_Pa
_RATIO_EPS = 1e-6  # dimensionless — absolute tolerance for factor_of_safety


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def _load_analyses_inputs(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "inputs" / "analyses.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[PE_ENGINEERING_REDERIVATION_MISMATCH] inputs/analyses.json: "
            f"JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_analysis_outputs(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "payload" / "engineering_analyses.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[PE_ENGINEERING_REDERIVATION_MISMATCH] payload/engineering_analyses.json: "
            f"JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_provenance(bundle_dir: Path) -> list[dict] | None:
    p = bundle_dir / "payload" / "pe_stamp_provenance.jsonl"
    if not p.exists():
        return None
    rows = []
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(
                f"[PE_STAMP_INVALID] payload/pe_stamp_provenance.jsonl line {i}: "
                f"JSON parse error: {exc}",
                file=sys.stderr,
            )
            return None
    return rows


def _load_attestation_key(bundle_dir: Path) -> bytes | None:
    p = bundle_dir / "payload" / "attestation_key.hex"
    if not p.exists():
        print(
            "[PE_STAMP_INVALID] payload/attestation_key.hex not found in bundle",
            file=sys.stderr,
        )
        return None
    try:
        key_hex = p.read_text(encoding="utf-8").strip()
        return bytes.fromhex(key_hex)
    except ValueError as exc:
        print(
            f"[PE_STAMP_INVALID] payload/attestation_key.hex: invalid hex: {exc}",
            file=sys.stderr,
        )
        return None


# ---------------------------------------------------------------------------
# Re-derivation logic (mirrors _build_bundle.py — stdlib only)
# ---------------------------------------------------------------------------


def _compute_max_bending_stress(analysis: dict) -> float:
    """σ_max = (P * L) * c / I  for a rectangular cross section.

    c = height / 2 (distance from neutral axis to extreme fiber)
    I = (width * height^3) / 12  (second moment of area for rectangle)
    """
    P = analysis["load_N"]
    L = analysis["length_m"]
    h = analysis["cross_section"]["height_m"]
    w = analysis["cross_section"]["width_m"]
    c = h / 2.0
    I = (w * h**3) / 12.0
    return (P * L * c) / I


def _compute_factor_of_safety(analysis: dict, max_stress_pa: float) -> float:
    """FoS = yield_stress_Pa / sigma_max"""
    yield_stress_pa = analysis["material"]["yield_stress_MPa"] * 1e6
    return yield_stress_pa / max_stress_pa


def _compute_verdict(analysis: dict, fos: float) -> str:
    return "pass" if fos >= analysis["material"]["safety_factor"] else "fail"


def _compute_analysis_summary_hash(analysis_output: dict) -> str:
    """SHA-256 of the canonical JSON of the analysis output the PE stamp covers."""
    canonical = json.dumps(analysis_output, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compute_stamp_hmac(
    pe_license_id: str,
    state_board_code: str,
    license_expiration: str,
    analysis_id: str,
    analysis_summary_hash: str,
    stamp_verdict: str,
    limitations_list: list[str],
    stamp_timestamp: str,
    key: bytes,
) -> str:
    """HMAC-SHA256 of canonical-JSON of the 8-field stamp payload."""
    payload = {
        "analysis_id": analysis_id,
        "analysis_summary_hash": analysis_summary_hash,
        "license_expiration": license_expiration,
        "limitations_list": limitations_list,
        "pe_license_id": pe_license_id,
        "stamp_timestamp": stamp_timestamp,
        "stamp_verdict": stamp_verdict,
        "state_board_code": state_board_code,
    }
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _hmac.new(key, msg, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Main verification
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "PE engineering signoff re-derivation + HMAC attestation check "
            "for pe_engineering_signoff_minimal audit bundles"
        )
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # Load all inputs
    analyses_inputs = _load_analyses_inputs(bundle_dir)
    if analyses_inputs is None:
        if not (bundle_dir / "inputs" / "analyses.json").exists():
            return 0  # domain opted out
        return 1

    analysis_outputs = _load_analysis_outputs(bundle_dir)
    if analysis_outputs is None:
        if not (bundle_dir / "payload" / "engineering_analyses.json").exists():
            return 0
        return 1

    provenance = _load_provenance(bundle_dir)
    if provenance is None:
        return 1

    attestation_key = _load_attestation_key(bundle_dir)
    if attestation_key is None:
        return 1

    # -----------------------------------------------------------------------
    # Invariant 1: re-derive every analysis output and compare to bundled values
    # -----------------------------------------------------------------------
    bundled_by_id: dict[str, dict] = {d["analysis_id"]: d for d in analysis_outputs}

    for analysis in analyses_inputs:
        aid = analysis.get("analysis_id")
        if aid is None:
            print(
                "[PE_ENGINEERING_REDERIVATION_MISMATCH] analysis missing analysis_id",
                file=sys.stderr,
            )
            return 1

        bundled = bundled_by_id.get(aid)
        if bundled is None:
            print(
                f"[PE_ENGINEERING_REDERIVATION_MISMATCH] analysis_id={aid!r} "
                "not found in bundled engineering_analyses.json",
                file=sys.stderr,
            )
            return 1

        # Re-derive
        try:
            derived_stress = _compute_max_bending_stress(analysis)
            derived_fos = _compute_factor_of_safety(analysis, derived_stress)
            derived_verdict = _compute_verdict(analysis, derived_fos)
        except (KeyError, ZeroDivisionError, TypeError) as exc:
            print(
                f"[PE_ENGINEERING_REDERIVATION_MISMATCH] analysis_id={aid!r}: "
                f"computation error: {exc}",
                file=sys.stderr,
            )
            return 1

        # Compare stress (absolute tolerance)
        bundled_stress = bundled.get("max_bending_stress_Pa")
        if bundled_stress is None or abs(derived_stress - bundled_stress) > _STRESS_EPS:
            print(
                f"[PE_ENGINEERING_REDERIVATION_MISMATCH] analysis_id={aid!r}: "
                f"max_bending_stress_Pa mismatch — "
                f"derived={derived_stress:.6e} bundled={bundled_stress}",
                file=sys.stderr,
            )
            return 1

        # Compare factor_of_safety (absolute tolerance)
        bundled_fos = bundled.get("factor_of_safety")
        if bundled_fos is None or abs(derived_fos - bundled_fos) > _RATIO_EPS:
            print(
                f"[PE_ENGINEERING_REDERIVATION_MISMATCH] analysis_id={aid!r}: "
                f"factor_of_safety mismatch — "
                f"derived={derived_fos:.9f} bundled={bundled_fos}",
                file=sys.stderr,
            )
            return 1

        # Compare structural verdict (exact string match)
        bundled_verdict = bundled.get("structural_verdict")
        if derived_verdict != bundled_verdict:
            print(
                f"[PE_ENGINEERING_REDERIVATION_MISMATCH] analysis_id={aid!r}: "
                f"structural_verdict mismatch — "
                f"derived={derived_verdict!r} bundled={bundled_verdict!r}",
                file=sys.stderr,
            )
            return 1

    # -----------------------------------------------------------------------
    # Invariant 2: every bundled analysis output has a corresponding provenance row
    # -----------------------------------------------------------------------
    provenance_by_id: dict[str, dict] = {row["analysis_id"]: row for row in provenance}

    for output in analysis_outputs:
        aid = output["analysis_id"]
        if aid not in provenance_by_id:
            print(
                f"[PE_STAMP_INVALID] analysis_id={aid!r}: no provenance row found in "
                "payload/pe_stamp_provenance.jsonl",
                file=sys.stderr,
            )
            return 1

    # -----------------------------------------------------------------------
    # Invariant 3: re-verify every PE-stamp attestation HMAC
    # Also verify the analysis_summary_hash in each row matches the re-derived output
    # -----------------------------------------------------------------------
    for row in provenance:
        aid = row.get("analysis_id", "")
        pe_license_id = row.get("pe_license_id", "")
        state_board_code = row.get("state_board_code", "")
        license_expiration = row.get("license_expiration", "")
        analysis_summary_hash = row.get("analysis_summary_hash", "")
        stamp_verdict = row.get("stamp_verdict", "")
        limitations_list = row.get("limitations_list", [])
        stamp_timestamp = row.get("stamp_timestamp", "")
        stored_hmac = row.get("attestation_hmac", "")

        # Verify analysis_summary_hash commits to the correct analysis output
        bundled_output = bundled_by_id.get(aid)
        if bundled_output is not None:
            expected_summary_hash = _compute_analysis_summary_hash(bundled_output)
            if analysis_summary_hash != expected_summary_hash:
                print(
                    f"[PE_STAMP_INVALID] analysis_id={aid!r}: "
                    f"analysis_summary_hash mismatch — "
                    f"stored={analysis_summary_hash[:16]!r}... "
                    f"expected={expected_summary_hash[:16]!r}... "
                    "(analysis output may have been tampered)",
                    file=sys.stderr,
                )
                return 1

        # Re-compute HMAC
        expected_hmac = _compute_stamp_hmac(
            pe_license_id=pe_license_id,
            state_board_code=state_board_code,
            license_expiration=license_expiration,
            analysis_id=aid,
            analysis_summary_hash=analysis_summary_hash,
            stamp_verdict=stamp_verdict,
            limitations_list=limitations_list,
            stamp_timestamp=stamp_timestamp,
            key=attestation_key,
        )

        if not _hmac.compare_digest(expected_hmac, stored_hmac):
            print(
                f"[PE_STAMP_INVALID] analysis_id={aid!r} pe_license_id={pe_license_id!r}: "
                f"HMAC mismatch — stored={stored_hmac[:16]!r}... "
                f"expected={expected_hmac[:16]!r}... "
                "(stamp_verdict or other stamp field may have been tampered)",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
