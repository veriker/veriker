#!/usr/bin/env python3
"""_build_bundle.py — build a hyperframes_render_minimal audit bundle.

Renders a fixture HTML composition via `npx hyperframes render`, then assembles
a V-kernel canary4 audit bundle around the MP4 output. The bundle is structured
so that a verifier can re-run the same render against the bundled source +
pinned tooling and assert bit-identical MP4 bytes.

The render itself depends on Node ≥ 22, ffmpeg, and a Chrome headless shell
(downloaded into ~/.cache/hyperframes/chrome on first use). The Python wrapper
is stdlib-only per the internal design notes AB4.

Usage (from v-kernel-audit-bundle root):
    python examples/hyperframes_render_minimal/_build_bundle.py --out-dir /tmp/hf_bundle

Outputs:
  <out-dir>/source/index.html       (committed composition HTML)
  <out-dir>/source/hyperframes.json (committed project config)
  <out-dir>/source/package.json     (committed package manifest)
  <out-dir>/spec/tooling.json       (pinned tool versions — the re-derivation environment)
  <out-dir>/payload/output.mp4      (the rendered MP4, deterministic from source+tooling)
  <out-dir>/audit/render.log        (render stdout for traceability)
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  render failure or assertion failure
  2  Node/ffmpeg/Chrome missing on PATH
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parents[1]  # v-kernel-audit-bundle/
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, sha256, write_bundle  # noqa: E402

# Pin bundle_id + created_at so the manifest itself is deterministic across
# builds (mirrors audio_minimal pattern). tooling.json snapshots the LIVE
# environment because the spec must reflect the actual re-derivation
# environment, not a static placeholder.
_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "hyperframes-render-minimal-rc"
_CREATED_AT = "2026-05-27T00:00:00Z"
_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "hyperframes_re_derivation",
]
_SOURCE_FILES = ["index.html", "hyperframes.json", "package.json"]
_HYPERFRAMES_PIN = "0.6.52"
_FIXTURE_DIR = _HERE / "fixture"


def _run(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def _snapshot_tooling(project_dir: Path) -> dict:
    """Capture pinned versions of every tool that contributes to the render."""
    rc_n, node_ver, _ = _run(["node", "--version"], project_dir)
    rc_m, npm_ver, _ = _run(["npm", "--version"], project_dir)
    if rc_n != 0 or rc_m != 0:
        raise RuntimeError("node/npm not available on PATH")

    rc_f, ffmpeg_ver, _ = _run(["ffmpeg", "-version"], project_dir)
    if rc_f != 0:
        raise RuntimeError("ffmpeg not available on PATH")
    ffmpeg_match = re.match(r"ffmpeg version (\S+)", ffmpeg_ver)
    ffmpeg_short = ffmpeg_match.group(1) if ffmpeg_match else ffmpeg_ver.splitlines()[0]

    chrome_root = (
        Path.home() / ".cache" / "hyperframes" / "chrome" / "chrome-headless-shell"
    )
    chrome_ver = "unknown"
    # The headless-shell cache dir is named "<platform>-<version>" by
    # @puppeteer/browsers; <platform> is linux / mac / mac_arm / win32 / win64
    # depending on the build host. Match any of them rather than assuming linux
    # so the tooling snapshot is correct when the bundle is built off-Linux.
    _CHROME_PLATFORMS = ("linux", "mac_arm", "mac", "win64", "win32")
    if chrome_root.exists():
        for child in sorted(chrome_root.iterdir()):
            if not child.is_dir():
                continue
            for plat in _CHROME_PLATFORMS:
                if child.name.startswith(f"{plat}-"):
                    chrome_ver = child.name.split("-", 1)[1]
                    break
            if chrome_ver != "unknown":
                break

    gsap_url = None
    gsap_version = None
    index_text = (project_dir / "index.html").read_text(encoding="utf-8")
    gsap_match = re.search(
        r'src=["\']([^"\']*gsap@(\d+\.\d+\.\d+)[^"\']*)["\']', index_text
    )
    if gsap_match:
        gsap_url = gsap_match.group(1)
        gsap_version = gsap_match.group(2)

    import platform as _plat

    uname = _plat.uname()

    return {
        "schema": "hyperframes-tooling-v1",
        "hyperframes": _HYPERFRAMES_PIN,
        "node": node_ver.strip(),
        "npm": npm_ver.strip(),
        "ffmpeg": ffmpeg_short,
        "chrome_headless_shell": chrome_ver,
        "gsap_cdn": gsap_url,
        "gsap_version": gsap_version,
        "platform": f"{uname.system.lower()} {uname.machine}",
        "kernel": uname.release,
    }


def build(out_dir: Path) -> None:
    """Build a hyperframes_render_minimal bundle at out_dir.

    Steps:
      1. Copy fixture/* to a scratch render dir (kept under out_dir/_scratch/).
      2. Run `npx hyperframes render` from the scratch dir.
      3. Move the MP4 to payload/output.mp4.
      4. Copy fixture files to source/.
      5. Snapshot tooling versions to spec/tooling.json.
      6. Compute file SHAs and write manifest.json.

    Raises on tool absence or render failure.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch_dir = out_dir / "_scratch"
    if scratch_dir.exists():
        shutil.rmtree(scratch_dir)
    scratch_dir.mkdir(parents=True)

    # 1. populate scratch with fixture
    for name in _SOURCE_FILES:
        shutil.copy2(_FIXTURE_DIR / name, scratch_dir / name)

    # 2. run npx hyperframes render
    mp4_temp = scratch_dir / "output.mp4"
    rc, stdout, stderr = _run(
        [
            "npx",
            "-y",
            f"hyperframes@{_HYPERFRAMES_PIN}",
            "render",
            "--output",
            str(mp4_temp),
        ],
        cwd=scratch_dir,
    )
    if rc != 0:
        # surface render failure through stderr for the caller
        sys.stderr.write(stderr)
        raise RuntimeError(f"`npx hyperframes render` exited {rc}")
    if not mp4_temp.exists():
        raise RuntimeError(f"render did not produce MP4 at {mp4_temp}")

    # 3. read the rendered MP4 bytes
    # NB: we intentionally do NOT persist the render stdout/stderr to the
    # bundle — the log contains absolute scratch paths and progress-bar
    # carriage returns that vary across machines, which would either break
    # manifest-SHA stability (if hashed) or violate the file_integrity walk
    # contract (if unhashed). Re-derivation is the audit guarantee here, not
    # the log.
    mp4_bytes = mp4_temp.read_bytes()

    # 4. read source/ tree bytes from fixture
    source_bytes = {
        f"source/{name}": (_FIXTURE_DIR / name).read_bytes() for name in _SOURCE_FILES
    }

    # 5. snapshot tooling -> spec/tooling.json bytes
    tooling = _snapshot_tooling(_FIXTURE_DIR)
    # sort_keys for byte-stable spec hash across runs
    tooling_bytes = json.dumps(tooling, indent=2, sort_keys=True).encode("utf-8")

    # 6. emit via the reference-emitter SDK (scaffold + digests + manifest)
    mp4_sha = sha256(mp4_bytes)
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            **source_bytes,
            "payload/output.mp4": mp4_bytes,
        },
        spec_files={"tooling.json": tooling_bytes},
        payload={"output_mp4_sha256": mp4_sha},
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)

    # 7. cleanup scratch
    shutil.rmtree(scratch_dir, ignore_errors=True)

    print(f"Bundle written to {out_dir}")
    print(f"  schema_version : {_SCHEMA_VERSION}")
    print(f"  bundle_id      : {_BUNDLE_ID}")
    print(f"  output_mp4_sha : {mp4_sha[:16]}...")
    print(f"  manifest files : {len(manifest['files'])}")
    print(f"  spec_files     : {len(manifest['spec_files'])}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a hyperframes_render_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
