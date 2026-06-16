#!/usr/bin/env python3
"""_build_bundle.py — build a totalsegmentator_minimal audit bundle.

Runs TotalSegmentator (Apache 2.0, wasserth/TotalSegmentator) on a deterministic
CT-like phantom (or a real CT volume passed via --ct-path) and assembles a
V-kernel canary4 audit bundle around the multi-label segmentation NIfTI. The
bundle is structured so that a verifier can re-run the same inference against
the bundled source + pinned tooling + pinned model weights and assert
bit-identical segmentation bytes.

The inference depends on torch (CPU-only), TotalSegmentator, nnUNetv2, nibabel,
and a downloaded model weight blob (~135 MB, fetched on first run from
github.com/wasserth/TotalSegmentator/releases). The bundle pins all of these
in spec/tooling.json; toolchain mismatch surfaces as
TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH at verify time, distinct from
TOTALSEGMENTATOR_REDERIVATION_MISMATCH (bytes drift with toolchain-pinned).

Usage (from v-kernel-audit-bundle root):
    python examples/totalsegmentator_minimal/_build_bundle.py --out-dir /tmp/ts_bundle
    python examples/totalsegmentator_minimal/_build_bundle.py --out-dir /tmp/ts_bundle --ct-path /path/to/real.nii.gz

Outputs:
  <out-dir>/source/phantom.nii.gz     (input CT volume — phantom or real)
  <out-dir>/source/config.json        (segmentation task name + flags)
  <out-dir>/spec/tooling.json         (pinned tool + model versions — the re-derivation environment)
  <out-dir>/payload/segmentation.nii.gz  (the multi-label segmentation, deterministic from source+tooling)
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  inference failure or assertion failure
  2  required tool/weight missing
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Determinism env vars MUST be set before torch is imported. Anything after
# `import torch` that flips a flag is too late for kernels that snapshot
# config at import time.
# ---------------------------------------------------------------------------
import os
os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"
os.environ["PYTHONHASHSEED"] = "0"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"

import argparse
import hashlib
import json
import platform
import shutil
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parents[1]  # v-kernel-audit-bundle/
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

# Pin bundle_id + created_at so the manifest itself is deterministic across
# builds (mirrors audio_minimal + hyperframes patterns). tooling.json
# snapshots the LIVE environment because the spec must reflect the actual
# re-derivation environment, not a static placeholder.
_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "totalsegmentator-minimal-rc"
_CREATED_AT = "2026-05-27T00:00:00Z"
_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "totalsegmentator_re_derivation",
]
_FIXTURE_DIR = _HERE / "fixture"
_DEFAULT_CT_NAME = "phantom.nii.gz"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _checkpoint_path(task_id: int = 297) -> Path:
    """Return the path to the TotalSegmentator nnUNetv2 checkpoint for task_id.

    task_id=297 is the 3mm "fast" model for task=total. Matches the
    libs.py layout (~/.totalsegmentator/nnunet/results/Dataset297_*/...).
    """
    home = Path.home()
    base = home / ".totalsegmentator" / "nnunet" / "results"
    dataset_dir = base / f"Dataset{task_id}_TotalSegmentator_total_3mm_1559subj"
    return (
        dataset_dir
        / "nnUNetTrainer_4000epochs_NoMirroring__nnUNetPlans__3d_fullres"
        / "fold_0"
        / "checkpoint_final.pth"
    )


def _snapshot_tooling() -> dict:
    """Capture pinned versions + model weight sha for the re-derivation environment."""
    from importlib import metadata as _md

    def ver(pkg: str) -> str:
        try:
            return _md.version(pkg)
        except _md.PackageNotFoundError:
            return "missing"

    chk_path = _checkpoint_path(297)
    if not chk_path.exists():
        raise RuntimeError(
            f"TotalSegmentator task-297 checkpoint not found at {chk_path}; "
            "run `TotalSegmentator --download_weights` or invoke once with task=total fast=True first"
        )
    chk_sha = _sha256_file(chk_path)

    return {
        "schema": "totalsegmentator-tooling-v1",
        "totalsegmentator": ver("TotalSegmentator"),
        "torch": ver("torch"),
        "torchvision": ver("torchvision"),
        "nnunetv2": ver("nnunetv2"),
        "nibabel": ver("nibabel"),
        "SimpleITK": ver("SimpleITK"),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": f"{platform.system().lower()} {platform.machine()}",
        "model": {
            "task": "total",
            "fast": True,
            "task_id": 297,
            "weights_url": (
                "https://github.com/wasserth/TotalSegmentator/releases/download/"
                "v2.0.0-weights/Dataset297_TotalSegmentator_total_3mm_1559subj.zip"
            ),
            "checkpoint_relpath": (
                "Dataset297_TotalSegmentator_total_3mm_1559subj/"
                "nnUNetTrainer_4000epochs_NoMirroring__nnUNetPlans__3d_fullres/"
                "fold_0/checkpoint_final.pth"
            ),
            "checkpoint_sha256": chk_sha,
        },
    }


def _apply_torch_determinism() -> None:
    """Apply in-process torch determinism flags. Idempotent across re-entry.

    torch.set_num_interop_threads(...) raises RuntimeError if called twice or
    after any parallel work has started — fine on first call, fatal on second
    when build() runs multiple times in one pytest process. We swallow the
    re-entry RuntimeError because the *first* successful set is what matters
    for determinism; later calls are no-ops by construction.
    """
    import torch
    torch.manual_seed(0)
    torch.use_deterministic_algorithms(True, warn_only=True)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False
    torch.set_num_threads(1)
    try:
        torch.set_num_interop_threads(1)
    except RuntimeError:
        pass
    try:
        from monai.utils import set_determinism as monai_set_determinism
        monai_set_determinism(seed=0)
    except Exception:
        pass


def _run_inference(input_ct: Path, out_seg: Path, config: dict) -> None:
    """Run TotalSegmentator with config flags, writing multi-label NIfTI to out_seg."""
    _apply_torch_determinism()
    from totalsegmentator.python_api import totalsegmentator

    out_seg.parent.mkdir(parents=True, exist_ok=True)
    totalsegmentator(
        input=str(input_ct),
        output=str(out_seg),
        task=config["task"],
        fast=config["fast"],
        ml=config["ml"],
        device=config["device"],
        quiet=True,
        skip_saving=False,
    )


def build(out_dir: Path, ct_path: Path | None = None) -> None:
    """Build a totalsegmentator_minimal bundle at out_dir.

    Steps:
      1. Stage source/ — copy phantom (or --ct-path file) + config.json from fixture/.
      2. Snapshot tooling versions + model checkpoint sha → spec/tooling.json.
      3. Run inference → payload/segmentation.nii.gz.
      4. Compute file SHAs and write manifest.json.

    Raises on tool absence, missing checkpoint, or inference failure.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- 1. source/ -----------------------------------------------------
    src_dst = out_dir / "source"
    src_dst.mkdir(parents=True, exist_ok=True)
    config_path = src_dst / "config.json"
    ct_dst = src_dst / _DEFAULT_CT_NAME

    if ct_path is None:
        shutil.copy2(_FIXTURE_DIR / _DEFAULT_CT_NAME, ct_dst)
    else:
        ct_path = ct_path.resolve()
        if not ct_path.exists():
            raise RuntimeError(f"--ct-path file not found: {ct_path}")
        shutil.copy2(ct_path, ct_dst)
    shutil.copy2(_FIXTURE_DIR / "config.json", config_path)

    # ---- 2. spec/tooling.json ------------------------------------------
    tooling = _snapshot_tooling()
    tooling_bytes = json.dumps(tooling, indent=2, sort_keys=True).encode("utf-8")

    # ---- 3. payload/segmentation.nii.gz --------------------------------
    # Inference writes the segmentation NIfTI directly to disk; read its bytes
    # back for the SDK emit (the bytes are whatever the original produced).
    payload_dst = out_dir / "payload"
    payload_dst.mkdir(parents=True, exist_ok=True)
    seg_path = payload_dst / "segmentation.nii.gz"

    config = json.loads(config_path.read_text(encoding="utf-8"))
    _run_inference(ct_dst, seg_path, config)
    if not seg_path.exists():
        raise RuntimeError(f"inference did not produce segmentation at {seg_path}")

    # ---- 4. emit via the reference-emitter SDK -------------------------
    # source/* are copied onto disk above; read their bytes back for the emit.
    seg_bytes = seg_path.read_bytes()
    files = {
        f"source/{_DEFAULT_CT_NAME}": ct_dst.read_bytes(),
        "source/config.json": config_path.read_bytes(),
        "payload/segmentation.nii.gz": seg_bytes,
    }
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files=files,
        spec_files={"tooling.json": tooling_bytes},
        payload={"segmentation_sha256": _sha256_file(seg_path)},
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  schema_version       : {_SCHEMA_VERSION}")
    print(f"  bundle_id            : {_BUNDLE_ID}")
    print(f"  segmentation_sha     : {manifest['files']['payload/segmentation.nii.gz'][:16]}...")
    print(f"  checkpoint_sha       : {tooling['model']['checkpoint_sha256'][:16]}...")
    print(f"  manifest files       : {len(manifest['files'])}")
    print(f"  spec_files           : {len(manifest['spec_files'])}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a totalsegmentator_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    parser.add_argument(
        "--ct-path",
        type=Path,
        default=None,
        help=(
            "Optional: path to a real CT NIfTI input (.nii.gz). "
            "Default: use the deterministic fixture phantom."
        ),
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve(), ct_path=args.ct_path)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
