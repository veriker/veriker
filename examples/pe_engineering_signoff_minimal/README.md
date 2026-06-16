# pe_engineering_signoff_minimal

**Domain:** State-licensed Professional Engineer (PE) stamp on AI-assisted engineering analysis.

**Second-domain demonstration of the responsible-actor cryptographic binding claim line.**
The first domain is `prior_auth_minimal` (2026-05-19), which binds a healthcare provider's
NPI-shaped attestation to a prior-authorization decision. This pilot demonstrates the same
cryptographic binding primitive works for a *completely different credentialing context* —
state-licensed PE numbers tied to state engineering boards — and a *different verdict semantic*
— PE "stamping" assumes full professional liability for the analysis scope, not just an
approve/deny binary.

## Why this pair matters (patent portfolio)

The pair of (`prior_auth_minimal` + `pe_engineering_signoff_minimal`) establishes that the
responsible-actor cryptographic binding generalizes across:

- **(a) Federal vs state credentialing PKI:** prior_auth_minimal uses NPI (federally assigned,
  CMS-maintained namespace); this pilot uses state PE license numbers (CA-BPELSG, TX-TBPELS,
  FL-FBPE — three distinct state boards, three distinct credentialing authorities).
- **(b) Rule-tree vs numerical-engineering compute shapes:** prior_auth_minimal re-derives via
  a deterministic medical-necessity rule tree; this pilot re-derives via the cantilever bending
  formula `σ_max = (P * L) * c / I`.
- **(c) Approve/deny vs stamped-with-limitations verdict semantics:** prior_auth_minimal uses a
  binary `approve`/`deny`; this pilot introduces a richer enum (`stamped_unconditional`,
  `stamped_with_limitations`, `refused`) matching the professional-engineering standard-of-care
  concept of partial or conditional stamp acceptance.

Two domains is the threshold per V-Kernel's S0 enabling-disclosure pattern to convert a
"claim line" into a standalone claim candidate.

## Re-derivation primitive

```
σ_max = (P * L) * c / I
  where:
    P   = point load at tip (N)
    L   = cantilever length (m)
    c   = height / 2  (distance from neutral axis to extreme fiber, rectangular section)
    I   = (width * height^3) / 12  (second moment of area, rectangular section)

factor_of_safety = yield_stress_Pa / σ_max
verdict          = "pass" if FoS >= material.safety_factor else "fail"
```

Tolerances: `ε = 1e-9` for stresses (Pa), `ε = 1e-6` for ratios.

## Credential context

| License ID     | State Board  | Full Board Name |
|---|---|---|
| CA-PE-S12345   | CA-BPELSG    | California Board for Professional Engineers, Land Surveyors, and Geologists |
| TX-PE-E98765   | TX-TBPELS    | Texas Board of Professional Engineers and Land Surveyors |
| FL-PE-A45678   | FL-FBPE      | Florida Board of Professional Engineers |

Discipline prefixes in PE license IDs: `S` = structural, `E` = electrical, `A` = architectural.

## Stamp verdict states (all three fixturized)

| analysis_id  | stamp_verdict              | limitations_list |
|---|---|---|
| ANL-2026-001 | `stamped_unconditional`    | `[]` |
| ANL-2026-002 | `stamped_with_limitations` | 2 limitation strings |
| ANL-2026-003 | `refused`                  | 2 refusal reasons |

## Bundle layout

```
inputs/
  analyses.json                 3 cantilever-beam analysis inputs (geometry + load + material)
payload/
  engineering_analyses.json     computed max_bending_stress_Pa + FoS + structural_verdict
  pe_stamp_provenance.jsonl     one row per analysis; each row carries HMAC-bound PE-stamp fields
  attestation_key.hex           synthetic HMAC key committed to bundle for re-verification (demo only)
manifest.json                   schema_version=vcp-v1.1-canary4; decision_provenance_log set
```

## Quick start

```bash
cd veriker

# Build
python examples/pe_engineering_signoff_minimal/_build_bundle.py --out-dir /tmp/pe_engineering_signoff_bundle

# Verify (should print PASS)
python examples/pe_engineering_signoff_minimal/verify.py --bundle-dir /tmp/pe_engineering_signoff_bundle

# Test (happy-path + both tamper cases)
python -m pytest tests/test_pe_engineering_signoff_minimal.py -v
```

## Tamper tests

**Tamper A — re-derivation surface:**
Mutate `load_N` in `inputs/analyses.json` (changes computed σ_max and FoS),
re-align manifest SHA so `FileIntegrityManySmall` passes.
→ caught by `PeEngineeringSignoffReDerivationCheck` as `PE_ENGINEERING_REDERIVATION_MISMATCH`.

**Tamper B — PE-stamp HMAC surface:**
Flip `stamp_verdict` in a `pe_stamp_provenance.jsonl` row from `stamped_unconditional`
to `refused` WITHOUT recomputing its HMAC, then re-align manifest SHA.
→ `FileIntegrityManySmall` passes (SHA re-aligned), but
`PeEngineeringSignoffReDerivationCheck` fires `PE_STAMP_INVALID` because the
HMAC over the 8-field stamp payload no longer matches.

This is the key V-Kernel differentiator: an attacker who can mutate both the JSONL
and re-compute the file SHA still cannot forge a valid HMAC without the attestation key —
the provenance commitment is cryptographically stronger than file-integrity SHA alone.

## Production integration path

This demo uses a synthetic HMAC key committed to the bundle (`payload/attestation_key.hex`).
In production integration:

- The HMAC key would be replaced by the PE's **asymmetric signing key** issued by the
  state board (e.g., an RSA/ECDSA private key backed by NCEES Record + the relevant
  state-board-issued digital certificate).
- The `attestation_hmac` field would be replaced by a digital signature (e.g., ECDSA-P256
  over the canonical-JSON stamp payload), verifiable against the PE's public certificate
  without the private key being present in the bundle.
- The `pe_license_id` and `state_board_code` would be verified against the state board's
  licensee lookup API (e.g., CA-BPELSG license verification endpoint) at audit time.

The demo uses HMAC rather than asymmetric signing because the goal is to demonstrate the
responsible-actor binding shape (each verdict is cryptographically bound to a specific
credentialed PE), not to build production PKI infrastructure.

## V-Kernel extension surfaces exercised

| Surface | What this pilot contributes |
|---|---|
| `OpaqueFragment(kind_tag="engineering_assumption")` | Per-PE-confirmed assumption anchors (material properties, load model, boundary condition) |
| `decision_provenance_log` | PE-stamp HMAC attestation log — distinct from prior_auth's provider-NPI attestation shape |
| `DispatchRecordWellformedCheck(op_kinds_admitted={"FEA_SOLVE", "PE_STAMP", "COMPUTE"})` | Domain-specific op kinds for engineering compute + stamp binding |

## Relationship to prior_auth_minimal

`prior_auth_minimal` is the **first domain** demonstrating responsible-actor cryptographic
binding. Read its README for the healthcare-provider NPI credentialing context. The two
pilots are complementary demonstrations of the same V-Kernel primitive in different
professional-credentialing contexts; neither inflates the other's domain count.
