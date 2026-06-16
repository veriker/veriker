"""Versioned normalization policy for source snapshots.

SnapshotPolicy documents exactly how raw bytes were captured and processed,
making the policy itself content-addressable and auditable.  Follows
SCOPING.md §Revised kernel item 1 (snapshot policy explicit).
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class SnapshotPolicy:
    """Immutable record of snapshot capture and normalization decisions.

    Every field is a versioned, named choice — not a flag.  This makes the
    policy a first-class spec doc that can be CID'd alongside the bundle.
    """

    policy_version: str
    raw_bytes_kept: bool
    rendered_text_extractor: str
    normalization_version: str
    dynamic_page_handling: str
    redirect_chain_captured: bool
    duplicate_detection: str


def default_v1_policy() -> SnapshotPolicy:
    """Return the W3 v1 snapshot policy.

    Values encode the invariants for the initial pilot:
    - raw bytes kept verbatim (C1 invariant)
    - rendered text is identity (no extraction transform yet)
    - normalization is whitespace-collapsing + NFC Unicode, version 0.1
    - SPAs and dynamic pages are out of scope; no crawler
    - redirect chains are captured and stored
    - dedup is CID equality at the store layer
    """
    return SnapshotPolicy(
        policy_version='0.1',
        raw_bytes_kept=True,
        rendered_text_extractor='identity',
        normalization_version='0.1',
        dynamic_page_handling='none',
        redirect_chain_captured=True,
        duplicate_detection='cid_equality',
    )


def policy_to_canonical_dict(policy: SnapshotPolicy) -> dict:
    """Serialize policy to a stable dict for inclusion in BundleManifest spec_files.

    The returned dict is JSON-serializable with stdlib json and is ordered
    deterministically (insertion order matches field declaration order) so
    that compute_cid over its JSON encoding is stable across runs.
    """
    return {
        'policy_version': policy.policy_version,
        'raw_bytes_kept': policy.raw_bytes_kept,
        'rendered_text_extractor': policy.rendered_text_extractor,
        'normalization_version': policy.normalization_version,
        'dynamic_page_handling': policy.dynamic_page_handling,
        'redirect_chain_captured': policy.redirect_chain_captured,
        'duplicate_detection': policy.duplicate_detection,
    }
