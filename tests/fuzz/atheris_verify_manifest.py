"""Atheris harness: coverage-guided byte fuzz of the verifier parse boundary.

Targets BundleVerifier().verify() with raw bytes written to bundle/manifest.json.
The §C9 contract (verifier.py:163, 187-200) is that verify() NEVER raises:
every failure must surface as a collected VerifyFailure so an adversarial
manifest can neither crash the verifier (fail-stop / DoS) nor sneak past it
(fail-open). This harness is the coverage-guided complement to the
hand-found parametrized regressions in test_manifest_shape_contract.py.

Oracle (intentionally narrow):
  1. verify() returns a VerifyResult — does not raise any exception.
  2. The returned object's .ok and .failures attributes are accessible.

We deliberately do NOT cross-check verify()'s ok-verdict against an
independent "is this shape valid?" assessment — the production guard
(_validate_manifest_shape -> _validate_field_shapes) is single-source-of-truth,
and any independent re-implementation here would either drift from it or
just call it (tautological).

Run a bounded session:
    .venv/bin/python tests/fuzz/atheris_verify_manifest.py \
        -max_total_time=120 \
        tests/fuzz/corpus/manifest/

Atheris/libfuzzer flags after Setup() are passed through to libfuzzer; common ones:
    -max_total_time=N        seconds to fuzz before stopping
    -runs=N                  hard cap on iterations
    -artifact_prefix=PATH/   where to write crash/timeout/oom artifacts
    -print_final_stats=1     summary at exit
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from audit_bundle.bundle_manifest import (  # noqa: F401  (instrumented)
        MalformedManifest,
        _validate_field_shapes,
    )
    from audit_bundle.verifier import (  # noqa: F401  (instrumented)
        BundleVerifier,
        VerifyResult,
        _load_manifest,
        _validate_manifest_shape,
    )


# One reusable bundle dir + verifier; we rewrite manifest.json per iteration.
# Per-iteration mkdtemp would dominate the wall-clock and waste exec/sec budget.
_BUNDLE_DIR = Path(tempfile.mkdtemp(prefix="atheris_vk_bundle_"))
_MANIFEST_PATH = _BUNDLE_DIR / "manifest.json"
_VERIFIER = BundleVerifier()


def test_one(data: bytes) -> None:
    _MANIFEST_PATH.write_bytes(data)
    result = _VERIFIER.verify(_BUNDLE_DIR)
    # Sanity probe: the contract is .ok + .failures must be present and the
    # right shapes. AttributeError / TypeError here would mean verify() handed
    # back something that isn't a VerifyResult — also a contract break.
    assert isinstance(result, VerifyResult), (
        f"verify() returned {type(result).__name__}, expected VerifyResult"
    )
    assert isinstance(result.ok, bool), (
        f"VerifyResult.ok is {type(result.ok).__name__}, expected bool"
    )
    assert isinstance(result.failures, list), (
        f"VerifyResult.failures is {type(result.failures).__name__}, expected list"
    )


def main() -> None:
    atheris.Setup(sys.argv, test_one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
