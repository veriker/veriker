# Component 5: Retrieval Trace Capture

**Scope:** Retrieval trace capture per the audit-bundle contract §Compose-or-build component table (row 5), revised-kernel item 5.

Captures **retriever query** / **candidate set** / **rankings** / **selected chunks** / **context window injected** / **model/router version**. Captured even if not exposed in consumer UI. Three-set distinction (**retrieved** / **context_injected** / **quote_supporting**) enables retrieval-laundering detection and manifests the actual supporting substrate versus claimed sources.

**Why this matters:** Coverage attestation and synthesis audit require the full retrieval history. Capturing it now is cheap insurance against later "the kernel did not preserve the historical data." Distinguishing the three sets closes the retrieval-laundering attack vector — manifest shows reputable sources retrieved, but output is actually driven by model priors injected into the context window without retrieval support.

**See also:**
- The audit-bundle contract §Frontier-panel convergence (item 7) — retrieval-set vs support-set distinction
- The audit-bundle contract §C6 (Re-derivation pack) — how retrieval traces feed into manifest composition
