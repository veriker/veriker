# Output Post-Processor + VE/ES Modes

**Scope:** Output post-processor and dual output modes per the audit-bundle contract §Compose-or-build table row "Output post-processor + VE/ES modes"; output-mode policy locked 2026-04-27 (Option B).

**Option B decision (2026-04-27):** Two explicit output modes, never visually mixed:
- **Verified Extractive (VE):** quote-supported content only; default for new/unauthenticated users.
- **Exploratory Synthesis (ES):** freeform with hard-labeled unsupported sections; explicit opt-in.

**Mode-as-signed-field invariant:** The output mode is canonicalized into the bundle bytes, making it immutable after output freeze. Consumers verify mode matches the signed manifest.

**Two-pipeline UX:** Mode toggle is visually unmistakable — first-class output dimension (not a settings checkbox). Mode cannot be changed after output is frozen.

**Why this matters:** Mixed-mode-in-one-pane is a high-risk UX failure mode (per frontier panel review). Separating pipelines enforces trust boundaries and prevents silent synthesis creep.

**See also:**
- The audit-bundle contract §Output mode policy and §Implementation implications
- The audit-bundle contract §"Compose-or-build..." table (row 9)
