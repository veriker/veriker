"""Round-trip integration test for examples/hyperframes_render_minimal/verify.py.

Test flow:
  1. Build a clean bundle by rendering the fixture composition.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True (ROUND-TRIP test).
  4. PRIMARY TAMPER: mutate source/index.html (replace the title string);
     re-align its SHA in manifest.files so FileIntegrityManySmall passes;
     assert HYPERFRAMES_REDERIVATION_MISMATCH because the re-rendered MP4 sha
     differs from the committed sha.
  5. SPEC TAMPER: append whitespace to spec/tooling.json without realigning
     manifest.spec_files; assert SPEC_SHA_MISMATCH from SpecShaPinCheck.

Skipped when node ≥ 22 or ffmpeg is not on PATH — the re-derivation pack
needs them to actually re-render. Sketch pilot, third-party tooling
dependency by design.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "hyperframes_render_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Tool-availability gate — skip module if external tools missing
# ---------------------------------------------------------------------------


def _have_tool(cmd: list[str]) -> bool:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_HAVE_NODE = _have_tool(["node", "--version"])
_HAVE_FFMPEG = _have_tool(["ffmpeg", "-version"])
_HAVE_NPX = _have_tool(["npx", "--version"])

pytestmark = pytest.mark.skipif(
    not (_HAVE_NODE and _HAVE_FFMPEG and _HAVE_NPX),
    reason="hyperframes_render_minimal needs node, npx, and ffmpeg on PATH",
)


# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.hyperframes_render_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from HyperFramesReDerivationCheck import HyperFramesReDerivationCheck  # noqa: E402


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        HyperFramesReDerivationCheck(),
    ])


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "hf_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True; failures: {result.failures}"
    )


def test_tamper_index_html_fails_rederivation(tmp_path: Path) -> None:
    """Mutating source/index.html with SHA-realignment must trigger
    HYPERFRAMES_REDERIVATION_MISMATCH.

    The fixture title 'V-Kernel + HyperFrames' is replaced with
    'V-Kernel and HyperFrames'. File integrity SHA is re-aligned so
    FileIntegrityManySmall does not fire first. Re-derivation re-renders
    from the mutated HTML, producing a different MP4 (different text →
    different pixel bytes → different sha256), and the bundled
    payload/output.mp4 (still from the original HTML) no longer matches.
    """
    bundle_dir = tmp_path / "hf_bundle_html_tamper"
    build(bundle_dir)

    # Tamper: edit source/index.html
    index_path = bundle_dir / "source" / "index.html"
    text = index_path.read_text(encoding="utf-8")
    mutated = text.replace("V-Kernel + HyperFrames", "V-Kernel and HyperFrames")
    assert mutated != text, "fixture title string not found — test fixture drift"
    index_path.write_text(mutated, encoding="utf-8")

    # Re-align manifest SHA so file_integrity_many_small does not fire first
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["source/index.html"] = _sha256_file(index_path)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after mutating source/index.html"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "HYPERFRAMES_REDERIVATION_MISMATCH" in combined, (
        f"expected HYPERFRAMES_REDERIVATION_MISMATCH in failures; "
        f"got: {result.failures}"
    )


def test_tamper_tooling_spec_fails_spec_sha(tmp_path: Path) -> None:
    """Appending whitespace to spec/tooling.json without realigning
    manifest.spec_files must trigger a spec-SHA failure from SpecShaPinCheck.

    json.loads ignores trailing whitespace so the parsed spec is unchanged
    and re-derivation could still succeed — but the bundle's integrity
    contract requires manifest-pinned SHAs to match on-disk bytes exactly.
    """
    bundle_dir = tmp_path / "hf_bundle_spec_tamper"
    build(bundle_dir)

    spec_path = bundle_dir / "spec" / "tooling.json"
    original = spec_path.read_text(encoding="utf-8")
    spec_path.write_text(original + "\n   \n", encoding="utf-8")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after appending whitespace to spec/tooling.json"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert (
        "SPEC_SHA_MISMATCH" in combined
        or "MISSING_SPEC_BLOB" in combined
        or ("SPEC" in combined and "SHA MISMATCH" in combined)
    ), (
        f"expected spec-SHA-mismatch indicator in failures; "
        f"got: {result.failures}"
    )
