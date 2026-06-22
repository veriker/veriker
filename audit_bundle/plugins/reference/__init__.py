"""audit_bundle.plugins.reference — packaged reference re-derivation plugins.

These TypedCheck plugins (and the stdlib re-derivation packs they invoke) were
relocated out of `examples/` so the open verifier (`veriker/cli/verify.py`) no longer
imports from the emitter-bearing example tree. They are verifier-side
re-derivation logic (recompute + compare), not emitter code, so they ship with
the open package. Each `*ReDerivationCheck` resolves its pack via
`Path(__file__).parent`, so the pack lives alongside the Check here.

The `examples/<pilot>/<Name>Check.py` files remain as thin re-exports of these
canonical modules so the standalone per-pilot demos (verify.py / demo.py) keep
working (AB4 duplicate-don't-import doctrine preserved for the demos).
"""
