"""run_upgrade_demo.py — prove the S1 signed-upgrade mechanism on the honest
provenance_upgrade_minimal bundle: one PASS plus four tamper scenarios.

Run (from v-kernel-audit-bundle root, with the demo verifier key exported):
    export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
    python examples/provenance_upgrade_minimal/_build_bundle.py \
        --out-dir examples/provenance_upgrade_minimal/bundle
    python examples/provenance_upgrade_minimal/demo/run_upgrade_demo.py

Each scenario constructs an in-memory manifest from the on-disk bundle, mutates
ONE thing, and runs the C14 stamp_lattice plugin. The honest bundle PASSes and
admits the upgrade; every tamper is rejected with a specific reason code.

Exit code 0 iff all scenarios behaved as expected.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[3]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.bundle_manifest import BundleManifest  # noqa: E402
from audit_bundle.plugins import _load_verifier_recheck_key  # noqa: E402
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck  # noqa: E402

_BUNDLE = _PKG_ROOT / "examples/provenance_upgrade_minimal/bundle"


def _manifest_from(raw: dict) -> BundleManifest:
    return BundleManifest(
        schema_version=raw["schema_version"],
        bundle_id=raw["bundle_id"],
        created_at=raw["created_at"],
        files=raw["files"],
        spec_files=raw["spec_files"],
        cross_refs=raw["cross_refs"],
        payload=raw["payload"],
        typed_checks=raw["typed_checks"],
        dispatch_records=tuple(raw["dispatch_records"]),
        aggregate_stamp=raw.get("aggregate_stamp"),
    )


def _run(raw: dict, *, key) -> tuple[bool, str, str]:
    r = StampLatticeCheck(recheck_key=key).check(_BUNDLE, _manifest_from(raw))
    return r.ok, r.reason_code, r.detail


def main() -> int:
    if not os.environ.get("VKERNEL_VERIFIER_HMAC_KEY"):
        print(
            "ERROR: export VKERNEL_VERIFIER_HMAC_KEY first "
            '(e.g. "demo-vkernel-verifier-secret-0123456789abcdef")',
            file=sys.stderr,
        )
        return 1
    if not (_BUNDLE / "manifest.json").exists():
        print("ERROR: build the bundle first (see module docstring)", file=sys.stderr)
        return 1

    key = _load_verifier_recheck_key()
    base = json.loads((_BUNDLE / "manifest.json").read_text(encoding="utf-8"))

    failures = 0

    # 0 — HONEST: the real verifier-signed upgrade is admitted.
    ok, code, detail = _run(copy.deepcopy(base), key=key)
    expect_pass = ok and code == "PASS" and "1 verifier-signed upgrade" in detail
    print(f"[0] honest signed upgrade           -> ok={ok} {code}")
    print(f"      {detail}")
    failures += 0 if expect_pass else 1

    # 1 — FAIL-CLOSED: no verifier key wired (recheck_key=None). Defense 4.
    rn = StampLatticeCheck(recheck_key=None).check(
        _BUNDLE, _manifest_from(copy.deepcopy(base))
    )
    okn, coden = rn.ok, rn.reason_code
    expect = (not okn) and coden == "STAMP_UPGRADE_FORGED"
    print(f"[1] no verifier key (fail-closed)    -> ok={okn} {coden}  (expect FORGED)")
    failures += 0 if expect else 1

    # 2 — FORGED: strip the signature from the upgrade. Defense 5.
    m = copy.deepcopy(base)
    del m["dispatch_records"][0]["stamp_upgrade"]["verifier_signature"]
    ok2, code2, _ = _run(m, key=key)
    expect = (not ok2) and code2 == "STAMP_UPGRADE_FORGED"
    print(f"[2] stripped signature               -> ok={ok2} {code2}  (expect FORGED)")
    failures += 0 if expect else 1

    # 3 — TIER-JUMP: forge a 2-tier body (CONFIRMED... ) without re-signing. The
    #     body no longer matches the signed payload -> HMAC fails. Defense 5/3.
    m = copy.deepcopy(base)
    m["dispatch_records"][0]["stamp_upgrade"]["to_stamp"] = "INTERNAL_BENCHMARK"
    ok3, code3, _ = _run(m, key=key)
    expect = (not ok3) and code3 == "STAMP_UPGRADE_FORGED"
    print(f"[3] tier-jump body tamper            -> ok={ok3} {code3}  (expect FORGED)")
    failures += 0 if expect else 1

    # 4 — ROUND-UP: launder the aggregate up to TARGET (the upgraded row's tier),
    #     hiding the weakest un-upgraded row. Rule 1 (monotone-minimum).
    m = copy.deepcopy(base)
    m["aggregate_stamp"] = "TARGET"
    ok4, code4, _ = _run(m, key=key)
    expect = (not ok4) and code4 == "STAMP_AGGREGATE_ROUNDUP_DETECTED"
    print(f"[4] aggregate round-up (laundering)  -> ok={ok4} {code4}  (expect ROUNDUP)")
    failures += 0 if expect else 1

    print()
    if failures == 0:
        print("ALL SCENARIOS BEHAVED AS EXPECTED (1 honest PASS + 4 tamper rejections)")
        return 0
    print(f"{failures} scenario(s) did NOT behave as expected")
    return 1


if __name__ == "__main__":
    sys.exit(main())
