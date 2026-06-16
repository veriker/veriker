"""PandemicEligibilityReDerivationCheck — TypedCheck plugin for pandemic benefit eligibility.

Wraps pandemic_eligibility_rederivation.py via subprocess. The verifier independently
re-derives each applicant's eligibility verdict and weekly benefit amount from the pinned
rule set and attested attributes, then asserts it matches the bundled disbursement decision.

The load-bearing safety property: the verifier never trusts the disbursement system's
verdict — it re-derives it from first principles. An ineligible applicant marked APPROVED
(e.g. prior_income below the $5,000 floor, income not actually dropped) is caught here
even if the decision carries a valid signature and the file SHA is re-aligned.

Emits:
  PANDEMIC_ELIGIBILITY_REDERIVED           — all decisions match the verifier's re-derivation
  PANDEMIC_ELIGIBILITY_REDERIVATION_MISMATCH — one or more decisions do not re-derive

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate) + §C16 principle
that the verifier — never the disbursement system — sets the verdict.
name='pandemic_eligibility_rederivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class PandemicEligibilityReDerivationCheck:
    name: str = "pandemic_eligibility_rederivation"
    applies_to_files: frozenset[str] = frozenset(
        {"data/applicants.json", "payload/disbursement_decisions.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "pandemic_eligibility_rederivation.py"
        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail="pandemic_eligibility_rederivation.py not found alongside plugin; pilot opted out",
                files_audited=(),
            )

        decisions_path = bundle_dir / "payload" / "disbursement_decisions.json"
        applicants_path = bundle_dir / "data" / "applicants.json"
        if not decisions_path.exists() or not applicants_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="disbursement_decisions.json or applicants.json absent — nothing to re-derive",
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
                reason_code="PANDEMIC_ELIGIBILITY_TIMEOUT",
                detail="pandemic_eligibility_rederivation.py exceeded 60 s timeout",
                files_audited=(str(decisions_path), str(applicants_path)),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="PANDEMIC_ELIGIBILITY_REDERIVED",
                detail=(
                    "every disbursement decision signed and independently re-derived from the "
                    "published rule set and attested applicant attributes — the pre-payment check "
                    "that was skipped"
                ),
                files_audited=(str(decisions_path), str(applicants_path)),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        reason = (
            "PANDEMIC_ELIGIBILITY_REDERIVATION_MISMATCH"
            if "MISMATCH" in stderr_snippet
            else "PANDEMIC_ELIGIBILITY_FAIL"
        )
        return PluginResult(
            ok=False,
            reason_code=reason,
            detail=stderr_snippet,
            files_audited=(str(decisions_path), str(applicants_path)),
        )


register_typed_check("pandemic_eligibility_rederivation")
