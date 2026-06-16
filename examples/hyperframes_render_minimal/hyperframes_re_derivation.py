#!/usr/bin/env python3
"""hyperframes_re_derivation.py — stdlib re-derivation pack for HyperFrames domain.

Re-renders the bundled HyperFrames composition using the pinned tool versions
in spec/tooling.json and asserts the resulting MP4 bytes hash to the committed
sha256 in manifest.payload.output_mp4_sha256.

the audit-bundle contract §C6 (re-derivation pack — domain-agnostic substrate).
AB4: stdlib only — subprocess, hashlib, json, tempfile, shutil, pathlib.

Reads:
  spec/tooling.json                  — pinned tool versions (schema "hyperframes-tooling-v1")
  source/index.html                  — committed composition HTML
  source/hyperframes.json            — committed project config
  source/package.json                — committed package manifest
  payload/output.mp4                 — bundled rendered output
  manifest.json (.payload.output_mp4_sha256) — committed sha256 of bundled MP4

Re-derivation:
  1. Validate spec.schema == "hyperframes-tooling-v1".
  2. Detect available tool versions on PATH (node, ffmpeg, hyperframes).
     If the LIVE versions differ from the pinned versions, exit 1 with
     [HYPERFRAMES_REDER_FAIL] HYPERFRAMES_TOOLCHAIN_MISMATCH — re-derivation
     would not be meaningful on a toolchain drift.
  3. Copy source/ tree into a scratch dir.
  4. Run `npx hyperframes@<pinned> render --output rederive.mp4` from scratch.
  5. Compute sha256(rederive.mp4) and compare to committed sha256.
  6. Exit 0 on match; exit 1 with [HYPERFRAMES_REDER_FAIL] HYPERFRAMES_REDERIVATION_MISMATCH.

Usage:
    python hyperframes_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def _detect_node_version(cwd: Path) -> str | None:
    rc, out, _ = _run(["node", "--version"], cwd)
    return out.strip() if rc == 0 else None


def _detect_ffmpeg_version(cwd: Path) -> str | None:
    rc, out, _ = _run(["ffmpeg", "-version"], cwd)
    if rc != 0:
        return None
    m = re.match(r"ffmpeg version (\S+)", out)
    return m.group(1) if m else out.splitlines()[0]


def _verify(bundle_dir: Path) -> str | None:
    """Return an error description on mismatch, or None on success."""
    spec_path = bundle_dir / "spec" / "tooling.json"
    index_path = bundle_dir / "source" / "index.html"
    hf_json_path = bundle_dir / "source" / "hyperframes.json"
    pkg_json_path = bundle_dir / "source" / "package.json"
    mp4_path = bundle_dir / "payload" / "output.mp4"
    manifest_path = bundle_dir / "manifest.json"

    for p, label in [
        (spec_path, "spec/tooling.json"),
        (index_path, "source/index.html"),
        (hf_json_path, "source/hyperframes.json"),
        (pkg_json_path, "source/package.json"),
        (mp4_path, "payload/output.mp4"),
        (manifest_path, "manifest.json"),
    ]:
        if not p.exists():
            return f"{label} absent from bundle_dir {bundle_dir}"

    # ---- 1. load + validate spec ----
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read spec/tooling.json: {exc}"
    if spec.get("schema") != "hyperframes-tooling-v1":
        return (
            f"spec schema mismatch: expected 'hyperframes-tooling-v1', "
            f"got {spec.get('schema')!r}"
        )

    pinned_hyperframes = spec.get("hyperframes")
    pinned_node = spec.get("node")
    pinned_ffmpeg = spec.get("ffmpeg")
    if not (pinned_hyperframes and pinned_node and pinned_ffmpeg):
        return (
            "spec/tooling.json missing one of hyperframes/node/ffmpeg "
            f"(got hf={pinned_hyperframes!r}, node={pinned_node!r}, ffmpeg={pinned_ffmpeg!r})"
        )

    # ---- 2. toolchain match check ----
    live_node = _detect_node_version(bundle_dir)
    if live_node is None:
        return "HYPERFRAMES_TOOLCHAIN_MISSING: node not on PATH"
    if live_node != pinned_node:
        return (
            f"HYPERFRAMES_TOOLCHAIN_MISMATCH: node "
            f"pinned={pinned_node!r}, live={live_node!r}"
        )

    live_ffmpeg = _detect_ffmpeg_version(bundle_dir)
    if live_ffmpeg is None:
        return "HYPERFRAMES_TOOLCHAIN_MISSING: ffmpeg not on PATH"
    if live_ffmpeg != pinned_ffmpeg:
        return (
            f"HYPERFRAMES_TOOLCHAIN_MISMATCH: ffmpeg "
            f"pinned={pinned_ffmpeg!r}, live={live_ffmpeg!r}"
        )

    # ---- 3. load committed sha ----
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read manifest.json: {exc}"
    committed_sha = (manifest.get("payload") or {}).get("output_mp4_sha256")
    if not committed_sha:
        return "manifest.payload.output_mp4_sha256 absent"

    # ---- 4-5. re-render in scratch and compare ----
    with tempfile.TemporaryDirectory(prefix="hf_rederive_") as scratch:
        scratch_path = Path(scratch)
        shutil.copy2(index_path,   scratch_path / "index.html")
        shutil.copy2(hf_json_path, scratch_path / "hyperframes.json")
        shutil.copy2(pkg_json_path, scratch_path / "package.json")

        rederive_mp4 = scratch_path / "rederive.mp4"
        rc, _stdout, stderr = _run(
            [
                "npx",
                "-y",
                f"hyperframes@{pinned_hyperframes}",
                "render",
                "--output",
                str(rederive_mp4),
            ],
            cwd=scratch_path,
        )
        if rc != 0:
            return (
                f"re-render failed (npx hyperframes exit {rc}); "
                f"stderr head: {stderr[:200]!r}"
            )
        if not rederive_mp4.exists():
            return "re-render produced no MP4"

        rederive_sha = _sha256_file(rederive_mp4)

    if rederive_sha != committed_sha:
        return (
            f"HYPERFRAMES_REDERIVATION_MISMATCH: re-derived sha "
            f"{rederive_sha[:16]}..., committed sha {committed_sha[:16]}..."
        )

    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HyperFrames render re-derivation check (V-kernel canary4)"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    error = _verify(bundle_dir)
    if error is None:
        return 0
    print(f"[HYPERFRAMES_REDER_FAIL] {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
