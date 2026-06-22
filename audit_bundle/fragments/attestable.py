"""audit_bundle/fragments/attestable.py — the shared attestability vocabulary.

ONE module answers three questions that MUST agree (RES-06 follow-up,
2026-06-11 — "quote-supported" must never reduce to "has a trusted CID label"
at ANY layer):

  * What is an ATTESTABLE anchor?  (`claimed_exact` — an anchor carrying
    `content_selector.exact` asserts "source S says 'X'", a falsifiable quote
    claim; a pure locator asserts nothing and is skipped everywhere.)
  * What is the versioned text canonicalization?  (`normalize_text` /
    `TEXT_CANONICALIZATION_VERSION` — ADR D7.d: NFC + casefold +
    punctuation-drop + whitespace-collapse + strip. A pure function, NOT a
    model.)
  * What is the content key that binds "this anchor was verified" to the
    exact present anchor bytes?  (`fragment_anchor_key` — same sha256
    canonical-JSON discipline as `cross_host_identity.cross_host_edge_key`,
    so a plugin cannot launder coverage of an anchor it did not see.)

Consumers:
  * `plugins/fragment_attestation.py` — the L8 keel re-derives each attestable
    anchor's span from the frozen snapshot and reports the keys it verified.
  * `BundleVerifier.verify()` — the coverage guard asserts present attestable
    keys − verified == ∅ (a present quote claim no wired plugin re-derived is
    could-not-conclude, never a silent OK).
  * `output_modes/ve_pipeline.py` — the producer-side VE post-processor uses
    the SAME canonicalization for its verbatim-containment check, so
    producer-side suppression and verifier-side attestation agree by
    construction.

Stdlib only (hashlib, json, re, unicodedata).
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata

#: Versioned text canonicalization (ADR D7.d). NFC + casefold + drop Unicode-P*
#: punctuation + collapse whitespace + strip. Pure-function, deterministic.
TEXT_CANONICALIZATION_VERSION = "0.1-nfc-casefold-droppunct-ws"

_WS_RE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """Apply the versioned, deterministic text canonicalization (ADR D7.d).

    Mirrors the span normalizer (5 rules) so every quote data-model renders
    the same verdict. NOT a model; a pure function of the input string.
    """
    text = unicodedata.normalize("NFC", text)
    text = text.casefold()
    text = "".join(ch for ch in text if not unicodedata.category(ch).startswith("P"))
    text = _WS_RE.sub(" ", text)
    return text.strip()


def claimed_exact(anchor_dict: dict) -> str | None:
    """Return the claimed quoted text (content_selector.exact) or None.

    None => the anchor is a pure locator (asserts no quote) and is not
    attestable. This predicate is THE definition of attestability — the L8
    plugin and the core coverage guard both consult it, so they can never
    disagree about which anchors carry a falsifiable claim.
    """
    selector = anchor_dict.get("content_selector")
    if not isinstance(selector, dict):
        return None
    exact = selector.get("exact")
    if isinstance(exact, str) and exact != "":
        return exact
    return None


def fragment_anchor_key(anchor_name: str, anchor_dict: dict) -> str:
    """Canonical content key for one fragment anchor.

    sha256 over canonical JSON (sorted keys, compact separators) of the
    (name, anchor) pair. The anchor comes from `json.loads(manifest.json)` so
    it is JSON-serialisable by construction. Binds "verified" to the exact
    present anchor bytes (the cross_host_edge_key discipline): a plugin that
    verified a DIFFERENT anchor — or the same name with different content —
    covers nothing.
    """
    canonical = json.dumps(
        {"name": anchor_name, "anchor": anchor_dict},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "fa:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def attestable_anchor_keys(anchors: object) -> frozenset[str]:
    """Key set for every ATTESTABLE anchor in a fragment_anchors mapping.

    Non-dict anchor values are skipped here (uncoverable by any plugin →
    the guard counts them separately and fails closed, mirroring the
    cross-host guard's non-dict-edge accounting). Pure locators are not
    attestable and impose no coverage obligation.
    """
    if not isinstance(anchors, dict):
        return frozenset()
    return frozenset(
        fragment_anchor_key(name, anchor)
        for name, anchor in anchors.items()
        if isinstance(anchor, dict) and claimed_exact(anchor) is not None
    )
