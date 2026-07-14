"""audit_bundle/source_registry — Component 3: Source attributes and properties.

Implements the audit-bundle contract's source-attributes component
(Properties 1+2+4+5 at v1). Source
governance — a curated authoritative registry, publisher accountability, key
management, poison/vandalism resistance — is a SEPARATE substrate, explicitly
NOT provided by this open verifier.

Source attributes (replaces "attestations" per K3 renaming) are producer-declared
properties checked against provided inputs — never trust decisions the verifier makes:
  1. issuer identity (checked against a configured, non-authoritative allow-list)
  2. signed artifact present
  4. publication class (the producer's declared label, transcribed)
  5. status flags if supplied (producer-declared; the verifier maintains no feed)

Provenance recorded per source-property assignment (who/what/when/why/policy
version) — a transcript of an externally-made decision, not one made here.
Immutable once stamped; history tracked via DecisionProvenance.

Public API (re-exported once sibling modules land):
  - SourceProperties — immutable snapshot of source attributes
  - default_v1_property_set — default v1 baseline (all False/Unknown)
  - IssuerVerifier — structural validation for issuer identity
  - SignatureVerifier — structural validation for signed artifacts
  - DecisionProvenance — immutable provenance record for property decisions
  - record_decision — append decision to JSONL log

Imports from nexi_methodology.cache_integrity for chain integrity checks.
References bundled provenance_standard.md from the methodology package.

See README.md for scope details.
"""

from .decision_provenance import DecisionProvenance, read_decisions, record_decision
from .issuer_verifier import IssuerVerifier, default_v1_allow_list_path
from .properties import (
    PublicationClass,
    SourceProperties,
    default_v1_property_set,
)

# NOTE: signature_verifier is the only module in this package that imports
# `cryptography` (a non-stdlib dependency). It is reached on the core
# verification path solely because bundle_manifest imports
# `.source_registry.properties`, which triggers this package __init__. To keep
# the core verify() path (FIG 1 element 152 / Claim 1 "standard library only")
# genuinely stdlib-clean, SignatureVerifier / default_v1_signature_verifier are
# deferred via PEP 562: the package-level names stay importable, but the
# `cryptography` import is paid only when the signing path actually touches them.
# Direct submodule importers (`...source_registry.signature_verifier import X`)
# are unaffected. See S0_DIAGRAM_VS_IMPL_AUDIT.md finding H1.


def __getattr__(name: str):
    if name in ("SignatureVerifier", "default_v1_signature_verifier"):
        from . import signature_verifier as _sv

        return getattr(_sv, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "SourceProperties",
    "PublicationClass",
    "default_v1_property_set",
    "IssuerVerifier",
    "default_v1_allow_list_path",
    "SignatureVerifier",
    "default_v1_signature_verifier",
    "DecisionProvenance",
    "read_decisions",
    "record_decision",
]
