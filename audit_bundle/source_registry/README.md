# Component 3: Source Attributes (verifier-side property checks)

**Scope:** Re-derivable checks over *producer-supplied* source-property claims.
This component does **not** decide, admit, curate, or govern sources, and does
not establish that a source is trustworthy, authoritative, or genuine. Issuer /
publisher authority is an **exogenous input** — a configured, caller-supplied
allow-list plus producer-signed metadata — never decided here. Source governance
(a curated authoritative registry, key management, an accountability program,
poison / vandalism resistance) is a **separate substrate outside this open
verifier** and is not provided by it.

**V1 property checks (each re-derives a producer-declared claim against provided inputs):**
1. **Issuer identity** — checks a producer-supplied issuer signature against a
   *configured* key / allow-list. The allow-list is an injected, **non-authoritative**
   input (see the `CANARY-SCOPE` note in `allow_list_v0.json`), not a registry
   this verifier owns or curates.
2. **Signed artifact present** — a producer-*declared* property. The verifier-side
   check is **structural** (if declared present, a `signing_key_id` must be named);
   the core verdict does **not** re-run the source signature. The `SignatureVerifier`
   class is a build-time / SDK helper a producer may use to sign artifacts; where a
   signature is meant to constrain provenance, the `source_cid`↔bytes binding is
   established out of band via content-addressing (snapshot CID integrity), not by
   the signature. Verifier-enforced source-signature checking — over a
   canonical envelope binding source_cid / key_id / issuer / algorithm / purpose —
   is a v2 / W4 item, not provided at v1.
3. **Publication class** — records the producer's *declared* class label
   (peer-reviewed / press / regulatory / blog / unknown); the verifier transcribes
   the declared value, it does not adjudicate it.
4. **Status flags** — checks producer-*declared* status flags; the verifier does
   not maintain a retraction or sanctions feed.

**Provenance record:** who / what / when / why / policy-version recorded per
source-property assignment — a transcript of an *externally-made* decision. The
verifier records it; it does not make the admission decision.

**Why this matters:** source attributes here are *properties checked against
provided inputs*, never *truth claims* and never *trust decisions*. A producer
can declare a property; this component re-derives whether that declared property
is internally consistent with the bundle — it does not vouch that the source is
genuine, authoritative, or trustworthy.

**See also:**
- The audit-bundle contract §Revised kernel item 3 — design rationale and the governance split
- The audit-bundle contract §C3 — contracts and schema evolution
