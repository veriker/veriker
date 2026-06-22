"""Write-once content-addressed snapshot store.

Storage layer for the snapshot component per the audit-bundle contract §C8.
Layout: <root>/<scheme>/<digest[:2]>/<digest>
Writes are atomic (temp-file + os.replace) and write-once-idempotent.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .cid import CID, BadCID, compute_cid, parse_cid


class SnapshotMissing(KeyError):
    """Raised when a requested CID is not present in the store."""


class CIDCollision(RuntimeError):
    """Raised when the same CID maps to different byte content.

    Indicates SHA-256 collision or storage corruption — treated as fatal.
    """


class SnapshotStore:
    """Write-once, content-addressed file store.

    Layout: <root>/<scheme>/<digest[:2]>/<digest>
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def _path(self, cid: CID) -> Path:
        return self.root / cid.scheme / cid.digest[:2] / cid.digest

    def write(self, raw_bytes: bytes) -> CID:
        """Store raw_bytes and return its CID.

        Idempotent: writing the same bytes again is a no-op.
        Raises CIDCollision if the same CID maps to different bytes.
        """
        cid_str = compute_cid(raw_bytes)
        scheme, digest = parse_cid(cid_str)
        cid = CID(scheme=scheme, digest=digest)
        path = self._path(cid)

        if path.exists():
            existing = path.read_bytes()
            if existing != raw_bytes:
                raise CIDCollision(
                    f"CID {cid.as_string!r} already stored with different content "
                    f"(stored {len(existing)} bytes, incoming {len(raw_bytes)} bytes)"
                )
            return cid

        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: temp file in same directory, then os.replace
        fd, tmp_path = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw_bytes)
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        return cid

    def read(self, cid: CID) -> bytes:
        """Return stored bytes for cid; raises SnapshotMissing if absent."""
        path = self._path(cid)
        if not path.exists():
            raise SnapshotMissing(f"No snapshot stored for CID {cid.as_string!r}")
        return path.read_bytes()

    def exists(self, cid: CID) -> bool:
        """Return True if cid is present in the store."""
        return self._path(cid).exists()

    def manifest(self) -> dict[str, str]:
        """Return {cid_string: relative_posix_path} for every stored snapshot.

        Relative to self.root, using forward slashes — suitable for BundleManifest.files.
        Files that don't parse as valid CIDs are silently skipped.
        """
        result: dict[str, str] = {}
        if not self.root.exists():
            return result
        for dirpath, _dirnames, filenames in os.walk(self.root):
            for filename in filenames:
                abs_path = Path(dirpath) / filename
                rel = abs_path.relative_to(self.root)
                parts = rel.parts
                # Expected layout: <scheme>/<prefix2>/<digest>
                if len(parts) != 3:
                    continue
                scheme, _prefix, digest = parts
                cid_str = f"{scheme}:{digest}"
                try:
                    parse_cid(cid_str)
                except BadCID:
                    continue
                result[cid_str] = rel.as_posix()
        return result
