#!/usr/bin/env python3
"""totalsegmentator_re_derivation.py — re-derivation pack for TotalSegmentator medical-imaging domain.

Re-runs TotalSegmentator inference on the bundled CT volume using the pinned
tool versions in spec/tooling.json and asserts the resulting multi-label NIfTI
bytes hash to the committed sha256 in manifest.payload.segmentation_sha256.

the audit-bundle contract §C6 (re-derivation pack — domain-agnostic substrate).

Unlike hyperframes_re_derivation (stdlib-only; shells to `npx hyperframes`),
this pack imports torch + totalsegmentator. TotalSegmentator is a Python tool
with no equivalent CLI boundary that's deterministic from env vars alone —
torch.use_deterministic_algorithms(True) and torch.set_num_threads(1) must be
applied in-process before any torch op executes. Isolation is preserved by
running the pack as a separate subprocess from the verifier process (invoked
via TotalSegmentatorReDerivationCheck.py).

Reads:
  spec/tooling.json                            — pinned tool + model versions (schema "totalsegmentator-tooling-v1")
  source/phantom.nii.gz (or whatever the CT file is named) — committed input CT volume
  source/config.json                           — committed task/flags config
  payload/segmentation.nii.gz                  — bundled multi-label segmentation
  manifest.json (.payload.segmentation_sha256) — committed sha256 of bundled segmentation

Re-derivation:
  1. Validate spec.schema == "totalsegmentator-tooling-v1".
  2. Compare LIVE package versions (torch, torchvision, totalsegmentator,
     nnunetv2, nibabel, SimpleITK, python) to pinned. On any drift, exit 1
     with [TOTALSEGMENTATOR_REDER_FAIL] TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH.
  3. Compare LIVE model checkpoint sha256 to pinned. On drift or absence,
     exit 1 with [TOTALSEGMENTATOR_REDER_FAIL] TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH
     (or _MISSING for absent checkpoint).
  4. Copy source/ tree → scratch dir; run inference with full determinism
     incantation → rederive.nii.gz.
  5. Compute sha256(rederive) and compare to committed sha256.
  6. Exit 0 on match; exit 1 with [TOTALSEGMENTATOR_REDER_FAIL]
     TOTALSEGMENTATOR_REDERIVATION_MISMATCH on drift.

Usage:
    python totalsegmentator_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

# Determinism env vars MUST be set before torch is imported.
import os
os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"
os.environ["PYTHONHASHSEED"] = "0"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from importlib import metadata as _md
from pathlib import Path


_PINNED_TOOLS = (
    "totalsegmentator",
    "torch",
    "torchvision",
    "nnunetv2",
    "nibabel",
    "SimpleITK",
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _pkg_version(pkg: str) -> str | None:
    try:
        return _md.version(pkg)
    except _md.PackageNotFoundError:
        return None


def _checkpoint_path_from_spec(spec: dict) -> Path:
    """Resolve the on-disk checkpoint path from the spec's relpath."""
    home = Path.home()
    base = home / ".totalsegmentator" / "nnunet" / "results"
    relpath = spec.get("model", {}).get("checkpoint_relpath")
    if not relpath:
        raise RuntimeError("spec.model.checkpoint_relpath missing")
    return base / relpath


def _verify(bundle_dir: Path) -> str | None:
    """Return an error description on mismatch, or None on success."""
    spec_path = bundle_dir / "spec" / "tooling.json"
    config_path = bundle_dir / "source" / "config.json"
    manifest_path = bundle_dir / "manifest.json"

    # Find the CT input — first .nii.gz under source/ that isn't config.json
    src_dir = bundle_dir / "source"
    if not src_dir.exists():
        return f"source/ absent from bundle_dir {bundle_dir}"
    ct_candidates = sorted(src_dir.glob("*.nii.gz"))
    if not ct_candidates:
        return f"no *.nii.gz under {src_dir}"
    ct_path = ct_candidates[0]

    seg_path = bundle_dir / "payload" / "segmentation.nii.gz"
    for p, label in [
        (spec_path, "spec/tooling.json"),
        (config_path, "source/config.json"),
        (seg_path, "payload/segmentation.nii.gz"),
        (manifest_path, "manifest.json"),
    ]:
        if not p.exists():
            return f"{label} absent from bundle_dir {bundle_dir}"

    # ---- 1. load + validate spec ----
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read spec/tooling.json: {exc}"
    if spec.get("schema") != "totalsegmentator-tooling-v1":
        return (
            f"spec schema mismatch: expected 'totalsegmentator-tooling-v1', "
            f"got {spec.get('schema')!r}"
        )

    # ---- 2. live vs pinned package versions ----
    for pkg in _PINNED_TOOLS:
        pinned = spec.get(pkg)
        if pinned in (None, "missing"):
            return (
                f"TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH: spec missing pinned version for {pkg!r}"
            )
        live = _pkg_version(pkg)
        if live is None:
            return f"TOTALSEGMENTATOR_TOOLCHAIN_MISSING: {pkg!r} not installed"
        if live != pinned:
            return (
                f"TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH: {pkg!r} "
                f"pinned={pinned!r}, live={live!r}"
            )

    # Python major.minor.micro check
    pinned_py = spec.get("python")
    live_py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if pinned_py and pinned_py != live_py:
        return (
            f"TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH: python "
            f"pinned={pinned_py!r}, live={live_py!r}"
        )

    # ---- 3. live vs pinned model checkpoint sha ----
    try:
        chk_path = _checkpoint_path_from_spec(spec)
    except RuntimeError as exc:
        return f"TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH: {exc}"
    if not chk_path.exists():
        return (
            f"TOTALSEGMENTATOR_TOOLCHAIN_MISSING: model checkpoint not found "
            f"at {chk_path}; download via `TotalSegmentator --download_weights` "
            f"or run task=total fast=True once"
        )
    pinned_chk_sha = spec.get("model", {}).get("checkpoint_sha256")
    if not pinned_chk_sha:
        return "TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH: spec.model.checkpoint_sha256 absent"
    live_chk_sha = _sha256_file(chk_path)
    if live_chk_sha != pinned_chk_sha:
        return (
            f"TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH: checkpoint sha "
            f"pinned={pinned_chk_sha[:16]!r}..., live={live_chk_sha[:16]!r}..."
        )

    # ---- 4. load committed segmentation sha ----
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read manifest.json: {exc}"
    committed_sha = (manifest.get("payload") or {}).get("segmentation_sha256")
    if not committed_sha:
        return "manifest.payload.segmentation_sha256 absent"

    # ---- 5-6. re-run inference in scratch + compare ----
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read source/config.json: {exc}"

    # Apply determinism flags in-process
    import torch
    torch.manual_seed(0)
    torch.use_deterministic_algorithms(True, warn_only=True)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False
    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)
    try:
        from monai.utils import set_determinism as monai_set_determinism
        monai_set_determinism(seed=0)
    except Exception:
        pass

    from totalsegmentator.python_api import totalsegmentator

    with tempfile.TemporaryDirectory(prefix="ts_rederive_") as scratch:
        scratch_path = Path(scratch)
        scratch_ct = scratch_path / ct_path.name
        shutil.copy2(ct_path, scratch_ct)
        rederive_seg = scratch_path / "rederive.nii.gz"
        try:
            totalsegmentator(
                input=str(scratch_ct),
                output=str(rederive_seg),
                task=config["task"],
                fast=config["fast"],
                ml=config["ml"],
                device=config["device"],
                quiet=True,
                skip_saving=False,
            )
        except Exception as exc:
            return f"re-inference raised {type(exc).__name__}: {exc}"
        if not rederive_seg.exists():
            return "re-inference produced no segmentation"
        rederive_sha = _sha256_file(rederive_seg)

    if rederive_sha != committed_sha:
        return (
            f"TOTALSEGMENTATOR_REDERIVATION_MISMATCH: re-derived sha "
            f"{rederive_sha[:16]}..., committed sha {committed_sha[:16]}..."
        )

    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TotalSegmentator inference re-derivation check (V-kernel canary4)"
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
    print(f"[TOTALSEGMENTATOR_REDER_FAIL] {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
