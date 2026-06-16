"""PeEngineeringSignoffReDerivationCheck — TypedCheck plugin for PE engineering signoff (C6).

Wraps pe_engineering_signoff_re_derivation.py via subprocess.

Two checks in one plugin:
  1. Engineering re-derivation: re-computes max_bending_stress_Pa, factor_of_safety,
     and structural_verdict from bundled geometry + material + load inputs and asserts
     they match payload/engineering_analyses.json within bounded float tolerance
     (ε=1e-9 for stresses, ε=1e-6 for ratios).
  2. PE-stamp HMAC re-verification: for every row in payload/pe_stamp_provenance.jsonl,
     re-computes HMAC-SHA256 of the 8-field stamp payload
     (pe_license_id, state_board_code, license_expiration, analysis_id,
      analysis_summary_hash, stamp_verdict, limitations_list, stamp_timestamp)
     under the bundle's committed attestation key and asserts it matches the
     stored attestation_hmac.

Reason codes:
  PE_ENGINEERING_REDERIVED              — both invariants passed
  PE_ENGINEERING_REDERIVATION_MISMATCH  — bending-stress / FoS / verdict mismatch
  PE_STAMP_INVALID                      — HMAC verification failure
                                          (verdict tampered or HMAC tampered,
                                           even if file SHA re-aligned by attacker)

the audit-bundle contract §C6 (domain-agnostic re-derivation).
name='pe_engineering_signoff_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class PeEngineeringSignoffReDerivationCheck:
    name: str = "pe_engineering_signoff_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {
            "inputs/",
            "payload/engineering_analyses.json",
            "payload/pe_stamp_provenance.jsonl",
            "payload/attestation_key.hex",
        }
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "pe_engineering_signoff_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "pe_engineering_signoff_re_derivation.py not found alongside "
                    "PeEngineeringSignoffReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        analyses_path = bundle_dir / "payload" / "engineering_analyses.json"
        if not analyses_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/engineering_analyses.json absent — "
                    "no engineering analyses to re-derive"
                ),
                files_audited=(),
            )

        try:
            result = subprocess.run(
                [sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)],
                capture_output=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                ok=False,
                reason_code="PE_ENGINEERING_REDERIVATION_TIMEOUT",
                detail="pe_engineering_signoff_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(analyses_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="PE_ENGINEERING_REDERIVED",
                detail=(
                    "pe_engineering_signoff_re_derivation.py exited 0 — all engineering "
                    "re-derivation invariants verified (stress/FoS/verdict) and all PE "
                    "stamp HMAC attestations validated"
                ),
                files_audited=(str(analyses_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]

        # Distinguish PE_STAMP_INVALID from re-derivation mismatch based on stderr tag
        if "PE_STAMP_INVALID" in stderr_snippet:
            return PluginResult(
                ok=False,
                reason_code="PE_STAMP_INVALID",
                detail=stderr_snippet,
                files_audited=(str(analyses_path),),
            )

        return PluginResult(
            ok=False,
            reason_code="PE_ENGINEERING_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(analyses_path),),
        )


register_typed_check("pe_engineering_signoff_re_derivation")
