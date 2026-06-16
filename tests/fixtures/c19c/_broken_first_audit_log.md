# c19c-004 — broken-first audit log

**Date:** 2026-05-20
**Branch:** v0_3_c19c
**Pre-real-impl HEAD:** b1b66510 (c19c-003 [TESTS])
**Module under audit:** `audit_bundle/extensions/c19/tsa_roughtime_bls.py`

## Discipline

Per memory `the internal design notes` step 3:
verify the broken stand-in fails each test in the way the test expects — the
test runs to completion and reports the expected failure mode, not an
unexpected crash that masquerades as failure.

## Result

```
46 tests collected
46 failed
 0 passed
 0 errored
```

**All tests failed in the expected broken-stand-in mode.** Every failure
traceback ends at `AssertionError("V0_3_S19c_BROKEN_STAND_IN — must be
replaced by real impl in c19c-005; until then this function MUST fail every
adversarial test by construction")` raised from one of:

- `verify_per_batch_tsa_root` (line ~463 of `tsa_roughtime_bls.py`)
- `verify_per_event_roughtime_quorum` (line ~481)
- `enforce_anchor_window` (line ~493)
- `multi_tsa_quorum_required` (line ~501)

(`live_poll_roughtime_roots` not exercised by the verifier test path — it
is the emitter-side helper.)

## Diagnostic confirmations

- **(a)** Every failing test reached the broken function (no ImportError,
  AttributeError, NameError in the captures). The setup-phase `caplog`
  marker `"TEST FIXTURE OVERRIDES PINNED CONSTANTS — production keys never
  reached"` appears in every test's captured log, confirming the
  monkeypatch fixture executed before the verifier was invoked.
- **(b)** Zero tests passed. The broken stand-in has no body that
  accidentally satisfies any test's assertion.
- **(c)** Zero tests errored. Imports + fixture setup are clean; the only
  exception raised is the deliberate `V0_3_S19c_BROKEN_STAND_IN`
  AssertionError.

## Gate satisfied

- Test-collection count = 46 (≥40, matches c19c-003 `--collect-only`).
- Phrase "all tests failed in the expected broken-stand-in mode" present.
- Zero `PASSED` markers.
- Zero `ERROR` markers.

c19c-005 (REAL-IMPL) is cleared to start. Success criterion is binary:
46/46 tests turn green; no test loosened, no test skipped, no test
outside this stream's owned files added or modified.

## §Misbehavior pairwise fork-detection — opus_checkpoint reminder

The adversarial test suite at c19c-003 specifically encodes
fork-detection scenarios in BOTH directions:

- `TestVerifyPerEventRoughtimeQuorum::test_reject_pairwise_midp_radi_fork`
  (forking SREP listed last in the response array)
- `TestVerifyPerEventRoughtimeQuorum::test_reject_pairwise_midp_radi_fork_reverse_direction`
  (forking SREP listed first — pairwise check must catch regardless of
  iteration order)
- `TestPipelineDisciplineDoNotFallback::test_roughtime_fork_does_not_silent_fall_to_tsa`
  (forking Roughtime evidence + absent per_batch_tsa_root — verifier
  MUST raise `ROUGHTIME_FORK_DETECTED`, MUST NOT silently degrade)

c19c-005 real impl must derive the §Misbehavior pairwise interval-overlap
check from draft-19 §Misbehavior text directly. The substrate-level
invariant: for any two verified SREPs (i, j), the intervals
`[MIDP_i - RADI_i, MIDP_i + RADI_i]` and `[MIDP_j - RADI_j, MIDP_j + RADI_j]`
MUST overlap. Equivalently, both `MIDP_i - RADI_i <= MIDP_j + RADI_j` AND
`MIDP_j - RADI_j <= MIDP_i + RADI_i` must hold. ANY violation raises
`ROUGHTIME_FORK_DETECTED` — hard-fail, no fallback to TSA.
