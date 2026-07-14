"""ClimateEmissionReDerivationCheck — TypedCheck plugin for Scope-3 emission re-derivation.

This plugin is used by the pilot-local verify.py wrapper
(examples/climate_emission_minimal/verify.py). The top-level cli/verify.py
instead auto-detects re_derive/climate_emission_pack.py inside the bundle
and runs the substrate's ReDerivationInvocationCheck against it — same pack,
different plugin shell.

Wraps climate_emission_pack.py via subprocess, mirroring the
re_derivation_invocation pattern from audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C5 (auditor independence) + §C6 (deterministic re-derivation).
name='climate_emission_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class ClimateEmissionReDerivationCheck:
    name: str = "climate_emission_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {
            "inputs/supplier_chain.json",
            "payload/emission_report.json",
            "re_derive/climate_emission_pack.py",
        }
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = bundle_dir / "re_derive" / "climate_emission_pack.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "re_derive/climate_emission_pack.py not found in bundle; "
                    "pilot opted out of re-derivation"
                ),
                files_audited=(),
            )

        report_path = bundle_dir / "payload" / "emission_report.json"
        if not report_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/emission_report.json absent — no emission report to re-derive",
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
                reason_code="CLIMATE_EMISSION_REDERIVATION_TIMEOUT",
                detail="climate_emission_pack.py exceeded 60 s timeout",
                files_audited=(str(report_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="CLIMATE_EMISSION_REDERIVED",
                detail=(
                    "climate_emission_pack.py exited 0 — every supplier's "
                    "attributed_kg_co2e and total_scope3_kg_co2e re-derived "
                    "via deterministic multiplication + sum of bundled supply chain"
                ),
                files_audited=(str(report_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="CLIMATE_EMISSION_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(report_path),),
        )


register_typed_check("climate_emission_re_derivation")
