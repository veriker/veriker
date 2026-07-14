"""DCEmissionsMRVReDerivationCheck — TypedCheck plugin for data-center NSR + LCA.

Used by the pilot-local verify.py wrapper
(examples/dc_emissions_mrv_minimal/verify.py). The top-level cli/verify.py
instead auto-detects re_derive/dc_emissions_mrv_pack.py inside the bundle
and runs the substrate's ReDerivationInvocationCheck against it — same pack,
different plugin shell.

Wraps dc_emissions_mrv_pack.py via subprocess, mirroring the
re_derivation_invocation pattern from
audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C5 (auditor independence) + §C6 (deterministic
re-derivation).
name='dc_emissions_mrv_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class DCEmissionsMRVReDerivationCheck:
    name: str = "dc_emissions_mrv_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {
            "inputs/emission_sources.json",
            "inputs/embodied_carbon_inventory.json",
            "inputs/permit_thresholds.json",
            "payload/nsr_submission.json",
            "re_derive/dc_emissions_mrv_pack.py",
        }
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = bundle_dir / "re_derive" / "dc_emissions_mrv_pack.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "re_derive/dc_emissions_mrv_pack.py not found in bundle; "
                    "pilot opted out of re-derivation"
                ),
                files_audited=(),
            )

        submission_path = bundle_dir / "payload" / "nsr_submission.json"
        if not submission_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/nsr_submission.json absent — no submission to re-derive",
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
                reason_code="DC_EMISSIONS_MRV_REDERIVATION_TIMEOUT",
                detail="dc_emissions_mrv_pack.py exceeded 60 s timeout",
                files_audited=(str(submission_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="DC_EMISSIONS_MRV_REDERIVED",
                detail=(
                    "dc_emissions_mrv_pack.py exited 0 — every per-source tpy, "
                    "per-pollutant total, per-pollutant classification, "
                    "embodied-carbon total, and overall facility classification "
                    "re-derived deterministically from bundled inputs"
                ),
                files_audited=(str(submission_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="DC_EMISSIONS_MRV_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(submission_path),),
        )


register_typed_check("dc_emissions_mrv_re_derivation")
