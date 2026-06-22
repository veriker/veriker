"""Test fixtures for S19c — TSA + Roughtime + BLS aggregation.

All fixtures are CANNED (no live network). The live network path is only
exercised manually outside the test suite via
`audit_bundle.extensions.c19.tsa_roughtime_bls.live_poll_roughtime_roots`.

Mint helper: `mint_fixtures.py` — deterministic key generation + envelope
construction; tests monkeypatch the verifier's pinned constants with the
TEST keys for the duration of each test (production keys never reached).
"""
