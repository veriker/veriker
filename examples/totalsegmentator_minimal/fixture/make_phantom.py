"""Generate the committed fixture/phantom.nii.gz.

Run once to regenerate the deterministic 96^3 CT-like phantom volume that
ships in fixture/. Not invoked by _build_bundle.py at runtime — the build
script copies the already-generated phantom.nii.gz from fixture/ into
source/. This helper exists so the phantom can be regenerated (or its
parameters tuned) if the fixture ever needs to be refreshed.

Requires numpy + nibabel; this is fixture-prep tooling, not part of the
re-derivation contract.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import nibabel as nib
import numpy as np


def make_phantom(side: int = 96) -> np.ndarray:
    """Deterministic CT-like phantom: nested spherical shells + off-center blobs.

    HU values:
      -1000 air baseline
        -80 fat-like shell
         40 soft-tissue shell
        800 bone-like core
         60 liver-like blob
         30 spleen-like blob
       1200 vertebra-like dense blob

    All arithmetic is integer or value-preserving cast to int16. No randomness.
    Output is bit-identical across machines for the same (side,) input.
    """
    vol = np.full((side, side, side), -1000, dtype=np.int16)
    cx = cy = cz = side / 2.0
    z, y, x = np.indices((side, side, side))
    r = np.sqrt((x - cx) ** 2 + (y - cy) ** 2 + (z - cz) ** 2)
    vol[r <= side * 0.45] = 40
    vol[r <= side * 0.30] = -80
    vol[r <= side * 0.12] = 800
    for ox, oy, oz, radius, hu in [
        (0.65, 0.50, 0.50, 0.08, 60),
        (0.35, 0.55, 0.50, 0.06, 30),
        (0.50, 0.35, 0.55, 0.05, 1200),
    ]:
        bx, by, bz = ox * side, oy * side, oz * side
        rb = np.sqrt((x - bx) ** 2 + (y - by) ** 2 + (z - bz) ** 2)
        vol[rb <= (radius * side)] = hu
    return vol


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--side", default=96, type=int)
    parser.add_argument("--spacing", default=1.5, type=float)
    args = parser.parse_args()

    vol = make_phantom(args.side)
    affine = np.eye(4, dtype=np.float64)
    affine[0, 0] = args.spacing
    affine[1, 1] = args.spacing
    affine[2, 2] = args.spacing
    img = nib.Nifti1Image(vol, affine)
    nib.save(img, str(args.out))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
