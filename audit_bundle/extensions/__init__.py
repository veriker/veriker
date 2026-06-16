"""v0.3 substrate extension modules.

M0 stub allocated 2026-05-19 to enable 8-stream parallel build under worktree
isolation. Each module in this package is owned by exactly one stream:

  c9_1_append_only_files     -> S§C9.1   (schema reservation only at v0.3)
  c14v3_rigor_profile        -> S14v3-RES (schema reservation only at v0.3)
  c17_attested_serving       -> S17-RES  (schema reservation only at v0.3)
  c18_verifier_identity      -> S18      (production)
  c19/                       -> S19a + S19b + S19c (reference implementation,
                                soak-then-harden; sub-streams own separate files
                                inside the package)
  c20_semantic_fidelity      -> S20      (schema reservation only at v0.3)

Each extension stream owns ONLY its named module plus its allocated field in
audit_bundle/bundle_manifest.py — streams do not edit each other's modules.
"""
