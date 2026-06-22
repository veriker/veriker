"""C19 — Causal DAG + cross-host receipts + selective anchoring.

External framing: REFERENCE IMPLEMENTATION, soak-then-harden — NOT
production-Byzantine-safe at v0.3. v0.4 absorbs later hardening findings.

Three sub-modules under this package:

  layer_a_counter.py        -> SCITT-bound counter substrate
  cross_host_peerreview.py  -> PeerReview authenticator pairing
  tsa_roughtime_bls.py      -> per-batch RFC 3161 TSA + Roughtime quorum
                               + BLS aggregation

The shared `causal_chain` field in audit_bundle/bundle_manifest.py carries
discriminated-union sub-keys inside the dict — sub-modules write to those keys,
NOT the field declaration line.

Tests for this package live under `tests/extensions/c19/`, NOT colocated here:
in-package `test_*.py` would install into the wheel as importable
`audit_bundle.extensions.c19.test_*` modules.
"""
