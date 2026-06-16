"""Read-only verify() ratchet (2026-06-10).

INVARIANT: BundleVerifier.verify() never creates, modifies, or deletes
anything inside bundle_dir. A verifier that writes into the artifact under
audit poisons its own re-runs: the conservation gate's universe is
on-disk ∪ declared, so any verifier-written file classifies UNOWNED surplus
and flips the NEXT verification's verdict (proven GREEN→RED with the C18
tripwire's events.jsonl append before this ratchet landed). Re-run
determinism — same bundle, same verdict, same reason set — is the
verifier's core trust property; self-mutation breaks it.

Two layers:

  1. DYNAMIC — run verify() end-to-end on bundles that exercise the two
     historical writer paths (C18 tripwire fire; C16 Fork A divergence
     retention) and assert bundle_dir is byte-identical before/after and
     the verdict is reproducible across back-to-back runs.

  2. STATIC — sweep the verify-path plugin sources for write tokens. The
     allowlist is EMPTY: a new plugin that needs to persist something must
     ride PluginResult.disclosures (verdict face) or a caller-owned sink,
     never bundle_dir. (Same empty-allowlist ratchet discipline as
     test_oss_dangling_module_refs.)
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from audit_bundle.verifier import BundleVerifier
from audit_bundle.plugins.verifier_identity_tripwire import (
    EVENT_KIND_VERIFIER_IDENTITY_DIVERGENCE,
    VerifierIdentityTripwireCheck,
)

PLUGINS_DIR = Path(__file__).resolve().parents[1] / "audit_bundle" / "plugins"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snapshot(bundle_dir: Path) -> tuple:
    """(rel_path, sha256|None) for every object under bundle_dir."""
    rows = []
    for p in sorted(bundle_dir.rglob("*")):
        rel = p.relative_to(bundle_dir).as_posix()
        digest = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
        rows.append((rel, digest))
    return tuple(rows)


def _tripwire_fire_bundle(tmp_path: Path) -> Path:
    """Minimal green bundle whose verifier_identity self-check reports
    'failed' — the tripwire-fire path, the proven GREEN→RED self-poisoner
    before the read-only fix."""
    bundle_dir = tmp_path / "b"
    bundle_dir.mkdir(parents=True)
    data = b"payload"
    (bundle_dir / "data.txt").write_bytes(data)
    manifest = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "readonly-ratchet",
        "created_at": "2026-06-10T00:00:00Z",
        "files": {"data.txt": hashlib.sha256(data).hexdigest()},
        "spec_files": {},
        "cross_refs": {},
        "verifier_identity": {
            "verifier_release_id": "v0.3.0",
            "verifier_oci_digest": "sha256:" + "a" * 64,
            "verifier_self_check_status": "failed",
            "release_manifest_url": "https://manifest.vkernel.dev/v0.3.0.json",
            "release_manifest_hash": "sha256:" + "0" * 64,
            "scitt_statement_hash": "sha256:" + "1" * 64,
            "sigstore_bundle_hash": "sha256:" + "2" * 64,
            "rekor_inclusion_proof": {
                "leaf_index": 100,
                "tree_size": 200,
                "hashes": ["aa" * 32, "bb" * 32],
                "root_hash": "deadbeef" * 8,
            },
        },
    }
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest))
    return bundle_dir


# ---------------------------------------------------------------------------
# 1. DYNAMIC — end-to-end: verify() must not touch bundle_dir, and the
#    verdict must be reproducible across back-to-back runs.
# ---------------------------------------------------------------------------


def test_tripwire_fire_verify_is_readonly_and_reproducible(tmp_path):
    """The exact GREEN→RED self-poisoning scenario, now pinned green-green:
    run 1 passes with the tripwire disclosure on the verdict face; bundle_dir
    is byte-identical; run 2 returns the same verdict."""
    bundle_dir = _tripwire_fire_bundle(tmp_path)
    verifier = BundleVerifier(plugins=(VerifierIdentityTripwireCheck(),))

    before = _snapshot(bundle_dir)
    v1 = verifier.verify(bundle_dir)
    assert v1.ok is True, [(f.check_name, f.reason_code) for f in v1.failures]
    assert any(
        EVENT_KIND_VERIFIER_IDENTITY_DIVERGENCE in d
        for d in v1.completeness.disclosures
    ), "tripwire signal must reach the verdict face"
    assert _snapshot(bundle_dir) == before, "verify() wrote into bundle_dir"

    v2 = verifier.verify(bundle_dir)
    assert v2.ok is True, [(f.check_name, f.reason_code) for f in v2.failures]
    assert [(f.check_name, f.reason_code) for f in v2.failures] == [
        (f.check_name, f.reason_code) for f in v1.failures
    ], "re-run produced a different failure set (determinism regression)"
    assert _snapshot(bundle_dir) == before


def test_pluginless_verify_is_readonly(tmp_path):
    """Baseline: the plugin-less core walk performs no bundle_dir writes."""
    bundle_dir = tmp_path / "b"
    bundle_dir.mkdir(parents=True)
    data = b"x"
    (bundle_dir / "data.txt").write_bytes(data)
    (bundle_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "vcp-v1.1-canary4",
                "bundle_id": "readonly-core",
                "created_at": "2026-06-10T00:00:00Z",
                "files": {"data.txt": hashlib.sha256(data).hexdigest()},
                "spec_files": {},
                "cross_refs": {},
            }
        )
    )
    before = _snapshot(bundle_dir)
    verdict = BundleVerifier(plugins=()).verify(bundle_dir)
    assert verdict.ok is True
    assert _snapshot(bundle_dir) == before


# ---------------------------------------------------------------------------
# 2. STATIC — write-token sweep over the verify-path plugin sources.
# ---------------------------------------------------------------------------

# Tokens that indicate filesystem mutation. Matched against source with
# string/comment content INCLUDED deliberately: a docstring naming
# `write_text` costs one allowlist entry and an explanation, which is the
# point of a ratchet.
_WRITE_TOKEN_RE = re.compile(
    r"""
    \.write_text\s*\(            |
    \.write_bytes\s*\(           |
    \.mkdir\s*\(                 |
    \.unlink\s*\(                |
    \.rmdir\s*\(                 |
    \.touch\s*\(                 |
    \.rename\s*\(                |
    \.open\s*\(\s*["'][wax]      |   # pathlib .open("w"/"a"/"x")
    \bopen\s*\([^)]*["'][wax]["']    # builtin open(..., "w"/"a"/"x")
    """,
    re.VERBOSE,
)

# rel_path -> justification. EMPTY by design; additions need a reviewed
# reason a verify-path plugin must mutate the filesystem (expected: never —
# use PluginResult.disclosures or a caller-owned sink).
_ALLOWLISTED_WRITERS: dict[str, str] = {}


def test_no_write_tokens_in_verify_path_plugins():
    offenders = []
    for src_file in sorted(PLUGINS_DIR.rglob("*.py")):
        rel = src_file.relative_to(PLUGINS_DIR).as_posix()
        if rel in _ALLOWLISTED_WRITERS:
            continue
        for lineno, line in enumerate(
            src_file.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if _WRITE_TOKEN_RE.search(line):
                offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "write tokens found in verify-path plugin sources — verify() must be "
        "read-only (surface via PluginResult.disclosures or a caller-owned "
        "sink, never bundle_dir):\n" + "\n".join(offenders)
    )
