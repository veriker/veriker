"""tests/test_acceptance_tolerance_authority_ratchet.py — the acceptance tolerance
is AUTHORITY-PINNED, and it gets a ratchet.

Why this exists
---------------
The load-bearing claim of a re-derivation pilot is that the auditor — not the
producer — owns the acceptance criterion: `a' = f_S(inputs)` is accepted iff
`compare(a', a) <= epsilon` under a comparator whose tolerance the PRODUCER
CANNOT LOOSEN. For a scalar_epsilon pilot that means the epsilon lives on the
verifier side (the auditor's committed `spec_pinned/<domain>.spec.json`), never
in a file the producer ships inside the bundle.

Some legacy example verifiers silently violated this: their `verify.py` read the
comparison tolerance from a producer-written in-bundle file (e.g. the float-ML
pilot's `weights/model.json`). A producer could set that value to 1e9, ship a
fabricated output with honest inputs, repair the in-bundle SHAs, and `verify.py`
printed PASS. The spec-pinned dispatch path was already correct; the *legacy*
`verify.py` path was the un-retired hole.

This ratchet locks the property two ways:

  A. STATIC — no example `*_re_derivation.py` / `*_recompute.py` may bind a
     value from an in-bundle dict keyed `epsilon`/`tolerance`/`atol`/`rtol` and
     use it as the RHS of a `>` acceptance comparison, UNLESS it also sources
     the acceptance tolerance from the auditor spec (`_auditor_epsilon` /
     `spec_pinned`). A regression that reverts the fix, or a NEW pilot that
     reads a producer tolerance without auditor-pinning it, fails here with the
     offending file named. (A value only fed into a recompute — e.g. a DP
     privacy budget → noise scale — never appears as `> VAR` and is not flagged.)

  B. BEHAVIORAL — for a public scalar_epsilon pilot that carries a
     producer-declared tolerance field, the concrete attack (loosen the
     in-bundle tolerance + fabricate the claimed output + repair every
     producer-controlled SHA) must FAIL closed through the pilot's own
     `verify.py`. (Partner-held pilots get the same behavioral leg in their own
     export-excluded ratchet file, so this file ships clean.)
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLES = _PKG_ROOT / "examples"

# The sweep fingerprint has TWO parts that must BOTH hold to be an offender:
#   (1) a variable is bound from an in-bundle dict value keyed epsilon/tolerance…
_PRODUCER_TOL_BIND_RE = re.compile(
    r"""\b([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=\n]+)?=\s*float\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\[\s*["'](?:epsilon|tolerance|atol|rtol)["']\s*\]\s*\)"""
)
#   (2) …AND that same variable is used as the RHS of a `>`/`>=` acceptance
#       comparison (`delta > VAR`). A value only fed into a recompute (e.g. the
#       DP Laplace privacy budget → scale) never appears as `> VAR` and is NOT
#       an acceptance tolerance — that is the dp_minimal false positive the
#       coarse form flagged.
# Evidence the module sources the acceptance tolerance from the auditor side.
_AUTHORITY_MARKERS = ("_auditor_epsilon", "spec_pinned")


def _binds_producer_acceptance_tolerance(src: str) -> bool:
    for m in _PRODUCER_TOL_BIND_RE.finditer(src):
        var = m.group(1)
        if re.search(rf">=?\s*{re.escape(var)}\b", src):
            return True
    return False


def _rederivation_modules() -> list[Path]:
    mods: list[Path] = []
    for pat in ("*_re_derivation.py", "*_recompute.py"):
        mods.extend(sorted(_EXAMPLES.glob(f"*/{pat}")))
    return mods


# ---------------------------------------------------------------------------
# A. STATIC RATCHET
# ---------------------------------------------------------------------------


def test_no_example_reads_acceptance_tolerance_from_the_bundle() -> None:
    """A module that binds a comparison tolerance from an in-bundle dict must
    also pin acceptance on the auditor side. Otherwise the producer owns the
    criterion → fail-open."""
    offenders: list[str] = []
    for mod in _rederivation_modules():
        src = mod.read_text(encoding="utf-8")
        if _binds_producer_acceptance_tolerance(src) and not any(
            m in src for m in _AUTHORITY_MARKERS
        ):
            rel = mod.relative_to(_PKG_ROOT)
            offenders.append(str(rel))
    assert not offenders, (
        "these example re-derivation modules bind a comparison tolerance from an "
        "in-bundle (producer-written) dict without pinning acceptance to the "
        "auditor's committed spec (no _auditor_epsilon / spec_pinned reference) — "
        "a producer can loosen the tolerance and pass a fabricated output:\n  "
        + "\n  ".join(offenders)
        + "\nRead the acceptance tolerance from spec_pinned/<domain>.spec.json "
        "(repo-side, next to the module), never from the bundle."
    )


# ---------------------------------------------------------------------------
# B. BEHAVIORAL RATCHET — the concrete attack must fail closed
# ---------------------------------------------------------------------------


def _repair_all_hashes(bundle: Path) -> None:
    mf = json.loads((bundle / "manifest.json").read_text())
    for group in ("files", "spec_files"):
        table = mf.get(group)
        if isinstance(table, dict):
            for rel in list(table):
                cand = bundle / rel
                if cand.exists():
                    table[rel] = hashlib.sha256(cand.read_bytes()).hexdigest()
    (bundle / "manifest.json").write_text(json.dumps(mf, indent=2))


def _verify_exit(pilot: str, bundle: Path) -> int:
    proc = subprocess.run(
        [
            sys.executable,
            str(_EXAMPLES / pilot / "verify.py"),
            "--bundle-dir",
            str(bundle),
        ],
        capture_output=True,
        text=True,
    )
    return proc.returncode


def _build(pilot: str, dest: Path) -> Path:
    subprocess.run(
        [
            sys.executable,
            str(_EXAMPLES / pilot / "_build_bundle.py"),
            "--out-dir",
            str(dest),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


def test_fp_ml_producer_tolerance_loosening_fails_closed(tmp_path: Path) -> None:
    bundle = _build("fp_ml_minimal", tmp_path / "b")
    assert _verify_exit("fp_ml_minimal", bundle) == 0, "honest bundle must PASS"
    # Attack: loosen the in-bundle tolerance, fabricate a logit, repair SHAs.
    mp = bundle / "weights" / "model.json"
    m = json.loads(mp.read_text())
    m["tolerance"] = 1e9
    mp.write_text(json.dumps(m, indent=2))
    pp = bundle / "payload" / "predictions.json"
    preds = json.loads(pp.read_text())
    preds[0]["logits"][0] += 999.0
    pp.write_text(json.dumps(preds, indent=2))
    _repair_all_hashes(bundle)
    assert _verify_exit("fp_ml_minimal", bundle) != 0, (
        "loosened producer tolerance + fabricated logit must FAIL closed"
    )
