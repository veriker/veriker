"""audit_bundle/stamp_claims.py — canonical identity for dispatch-record and
aggregate-stamp claims.

Single source of truth for the keys that bind "this dispatch_records element /
this aggregate_stamp claim is present in the manifest" to "a wired plugin
verified THIS content". Both the verifier's stamp-claims coverage guard
(BundleVerifier._step_stamp_claims_guard) and the C14/C15 plugins compute the
keys from the SAME functions over the SAME values, so:

  present_record_keys − verified_record_keys == ∅   ⟺  every record was audited (C15)
  stamp_claim_key ∈ verified_stamp_claims           ⟺  the lattice claim was checked (C14)

Keys are content hashes (canonical JSON → sha256), NOT list indices: a plugin
cannot claim coverage of content whose exact bytes are not present, and the
check is order-independent and tamper-evident. The C14 key binds the FULL
records array plus the aggregate value (tribunal 2026-06-12, Q2 unanimous):
the C14 plugin reads every row to compute per-row effective stamps, so the key
attests to the entire context of the lattice decision — a stamp-relevant
projection would migrate C14 field knowledge into core (two-verifier drift)
and make a projection bug a soundness bug.

A value that cannot be canonically serialized (possible only for
directly-constructed manifests — wire-format records come from json.loads and
serialize by construction) yields key None: the guard counts it UNCOVERABLE
and fails closed, never silently covered.

Stdlib only (keeps the core verify() path import-light).
"""

from __future__ import annotations

import hashlib
import json


def _canonical(value: object) -> str | None:
    """Canonical JSON for a parsed-manifest value, or None when the value is
    not JSON-serializable (directly-constructed manifest carrying a non-JSON
    object — uncoverable, fails closed at the guard)."""
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    except (TypeError, ValueError):
        return None


def dispatch_record_key(record: object) -> str | None:
    """Canonical content key for one dispatch_records element (C15 coverage).

    Any JSON value is keyable — the C15 plugin's contract handles non-dict
    elements explicitly (None is skip-by-contract; other non-dicts reject as
    DISPATCH_RECORD_MALFORMED), so coverage means "the plugin read this exact
    element and disposed of it", not "this element is a dict".
    """
    canonical = _canonical(record)
    if canonical is None:
        return None
    return "dr:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def dispatch_record_keys(records) -> frozenset[str]:
    """Key set for a records sequence; unserializable elements are skipped
    (uncoverable → they remain outside any plugin's verified set and the
    guard's unkeyable count fails closed)."""
    keys = set()
    for record in records or ():
        key = dispatch_record_key(record)
        if key is not None:
            keys.add(key)
    return frozenset(keys)


def stamp_claim_key(aggregate_stamp: object, records) -> str | None:
    """Canonical content key for the bundle's ONE C14 lattice claim.

    The claim is global — aggregate_stamp must equal min(per-row effective
    stamp) over the whole row set — so the key binds the aggregate value AND
    the full records array as one object. A plugin reporting this key proves
    it evaluated the lattice over exactly these rows and exactly this
    aggregate; it cannot launder a row-set or aggregate it did not read.
    """
    canonical = _canonical(
        {"aggregate_stamp": aggregate_stamp, "dispatch_records": list(records or ())}
    )
    if canonical is None:
        return None
    return "sc:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
