"""effect_binding — translate dispatch_record.effect → Wasmtime Linker
import allowlist, grounded in the locked v0.1 effect-row vocabulary from
o_kernel/EFFECT_CALCULUS.md.

GRANULARITY DISCLOSURE (V15 panel review 2026-05-03 BUG 3):
  The allowlist is a frozenset of WASM Component Model IMPORT-MODULE
  names (e.g. `"wasi:sockets/tcp"`). When a dispatch record declares
  `effect={"net": []}`, the allowlist admits ALL function names under
  the `wasi:sockets/tcp` interface — including names the v0.2 reference
  toolchain doesn't emit (e.g. `wasi:sockets/tcp::exfiltrate_credentials`
  succeeds with a zero-returning host stub if the WASM module imports
  it). This is the v0.2 substrate's coarse granularity: effects bound
  observed effects at INTERFACE granularity, not function-name
  granularity. Function-name-granular enforcement (and per-function
  argument-shape policies) is deferred to v0.3 when the WIT toolchain
  is wired and a reference-implementation per interface enumerates
  the exact admissible function set.

The translation is the load-bearing piece of the V15 substrate: it is the
function `f` such that `f(declared_effects) = allowlist`, and the C15
plugin's enforcement claim is "observed effects ⊆ f(declared_effects)".
The function must be:

  - **Total over the locked set** — every label in {net, fs, model,
    llm_spend_usd, time_bound_ms, locale_bound} has an entry in
    `EFFECT_LABEL_TO_IMPORTS`. The import sets are non-overlapping
    where present, so a downstream consumer can reverse-map an observed
    import back to a single declared effect unambiguously. Two labels
    intentionally map to the EMPTY tuple (`time_bound_ms` enforced via
    Wasmtime epoch-interruption + fuel cap; `locale_bound` enforced
    out-of-band — at v0.2 deferred per Cumulative-pre-soak Patch 3,
    rejected at the C15 plugin when combined with `net`/`fs` as
    `WASM_LOCALE_BOUND_DEFERRED`). Reverse mapping is therefore only
    meaningful for the four import-bearing labels (`net`, `fs`,
    `model`, `llm_spend_usd`).
  - **Reject reserved labels under mode='wasm'** — labels {db, subprocess,
    random, clock, notify} are schema-tolerant in v0.1 advisory mode (per
    EFFECT_CALCULUS.md), but in v0.2 enforced mode they reject because
    no v0.2-enforcement story exists for them yet (the curator-review
    invariant from EFFECT_CALCULUS.md §"What v0.1 commits to" point 1).
  - **Reject unknown labels** — any label outside locked ∪ reserved is
    rejected; well-formedness is C15's domain (already enforced by
    dispatch_record_wellformed.py) so an unknown label arriving here is
    a contract violation upstream, not a translation problem.

The import-name format is the WASM Component Model interface form
`<namespace>:<package>/<interface>`, mirroring the WIT-imports the v0.3
toolchain will generate. v0.2 enforces the *shape* of the allowlist
(exact-match Linker imports) without requiring the WASI 0.2 generator
toolchain — this gives effect-containment without v0.3's port cost.
"""

from __future__ import annotations

from typing import Mapping


# ---------------------------------------------------------------------------
# Locked v0.2 substrate — effect labels and their import projections
# ---------------------------------------------------------------------------


# The locked v0.1 effect-row vocabulary (from o_kernel/EFFECT_CALCULUS.md
# §"v0.1 effect-row vocabulary (LOCKED)"). Mirrored here (not imported from
# the C15 plugin) to keep effect_runtime/ stand-alone — the plugin imports
# from us, not the other way round.
LOCKED_LABELS: frozenset[str] = frozenset({
    "net",
    "fs",
    "model",
    "llm_spend_usd",
    "time_bound_ms",
    "locale_bound",
})


# Reserved-set labels — schema-tolerant at v0.1 advisory; rejected at v0.2
# enforced. The rejection is the C15-v0.2 invariant: a dispatcher claiming
# mode='wasm' MUST migrate reserved labels to a locked label or to an
# explicit-empty effect (the locked vocabulary is closed under v0.2
# enforcement; reserved labels reopen it without a v0.2-enforcement story).
RESERVED_LABELS: frozenset[str] = frozenset({
    "db",
    "subprocess",
    "random",
    "clock",
    "notify",
})


# Effect label → tuple of WASM Component Model import names that the
# Wasmtime Linker will admit. The reverse map (import → declared effect)
# is computed lazily for trace-divergence detection in trace_attestation.
#
# The imports follow the WASI-0.2 / NEXI-defined Component naming
# convention `<namespace>:<package>/<interface>`. Values here are
# substrate-stable and survive the v0.3 toolchain switch — the WIT
# generator will emit imports under these exact names so v0.2 traces
# remain valid against v0.3 components without a re-binding.
EFFECT_LABEL_TO_IMPORTS: Mapping[str, tuple[str, ...]] = {
    "net": (
        "wasi:sockets/tcp",
        "wasi:sockets/udp",
        "wasi:sockets/ip-name-lookup",
    ),
    "fs": (
        "wasi:filesystem/preopens",
        "wasi:filesystem/types",
    ),
    "model": (
        "nexi:dispatch/model",
    ),
    "llm_spend_usd": (
        "nexi:dispatch/spend-meter",
    ),
    "time_bound_ms": (
        # `time_bound_ms` is enforced via a host-side wall-clock interrupt
        # (Wasmtime fuel cap + epoch-interruption) — it does NOT translate
        # to a WASI clock-read import. The empty tuple here records that
        # the host enforces it without exposing any guest-visible import.
    ),
    "locale_bound": (
        # Cumulative-pre-soak Patch 3 honest disclosure (Gate 1, 2026-05-04):
        # at v0.2, `locale_bound` enforcement is DEFERRED. The pre-fix
        # docstring claimed "enforced via host-side guard on outbound calls'
        # locale headers", but the generic host stub does NOT inspect call
        # arguments, so a WASM module declaring
        # {"net": [], "locale_bound": []} can make network calls
        # unconstrained by locale.
        #
        # v0.2 honest behavior — declaring `locale_bound` in combination
        # with any host-call effect (`net`, `fs`) is REJECTED at the C15
        # plugin level with reason code WASM_LOCALE_BOUND_DEFERRED.
        # Declaring `locale_bound` alone (or alongside non-host-call
        # effects like `model`, `llm_spend_usd`, `time_bound_ms`) is a
        # no-op and admitted.
        #
        # v0.3 work — implement effect-specific host shims that inspect
        # call arguments and validate locale headers; once landed,
        # remove the C15-level rejection and remove this caveat.
    ),
}


# Reverse map for trace-divergence detection. Built once at import time;
# import-name → effect-label that admits it. Imports outside this map
# are out-of-vocabulary syscalls (=> WASM_EFFECT_DIVERGENCE).
IMPORT_TO_EFFECT_LABEL: Mapping[str, str] = {
    imp: label
    for label, imports in EFFECT_LABEL_TO_IMPORTS.items()
    for imp in imports
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class EffectBindingError(ValueError):
    """Raised when a dispatch_record.effect cannot be translated to an
    allowlist (reserved label under mode='wasm', unknown label, or shape
    error). Never raised in mode='advisory' — the v0.1 plugin owns that
    code path and emits its own reason codes."""


# ---------------------------------------------------------------------------
# Translation
# ---------------------------------------------------------------------------


def translate_effects_to_allowlist(
    effect: object, *, mode: str = "wasm",
) -> frozenset[str]:
    """Translate a dispatch_record.effect dict to the WASM Component
    Model import allowlist that admits exactly those effects.

    Parameters
    ----------
    effect : dict-like
        A mapping from effect label to payload. The caller has typically
        already passed C15 well-formedness; if not, errors fire here as
        EffectBindingError. Empty effect ({}) translates to the empty
        allowlist (declared-pure dispatch).
    mode : str
        "wasm" (enforced) — reserved labels reject; this is the v0.2
        deliverable.
        "advisory" — reserved labels accepted (return empty import set
        for them). Provided for symmetry with the v0.1 plugin path; the
        primary V15 caller should always pass "wasm".

    Returns
    -------
    frozenset[str]
        The set of import names the Wasmtime Linker will admit. An empty
        frozenset means the dispatch is declared-pure under WASM
        enforcement (no host imports beyond core WebAssembly).
    """
    if not isinstance(effect, dict):
        raise EffectBindingError(
            f"effect must be a dict, got {type(effect).__name__}"
        )
    if mode not in ("wasm", "advisory"):
        raise EffectBindingError(
            f"mode must be 'wasm' or 'advisory', got {mode!r}"
        )

    allowlist: set[str] = set()
    for label in effect:
        if not isinstance(label, str):
            raise EffectBindingError(
                f"effect label must be str, got {type(label).__name__} "
                f"({label!r})"
            )
        if label in LOCKED_LABELS:
            allowlist.update(EFFECT_LABEL_TO_IMPORTS[label])
            continue
        if label in RESERVED_LABELS:
            if mode == "wasm":
                raise EffectBindingError(
                    f"reserved-set label {label!r} cannot be enforced "
                    "under mode='wasm' (no v0.2 enforcement story); "
                    "dispatcher must migrate to a locked label or to "
                    "explicit-empty effect, or stay on mode='advisory'"
                )
            # mode='advisory' — accept silently, no imports added.
            continue
        raise EffectBindingError(
            f"effect label {label!r} is not in the locked v0.1 vocabulary "
            f"({sorted(LOCKED_LABELS)}) or the reserved-forward set "
            f"({sorted(RESERVED_LABELS)})"
        )

    return frozenset(allowlist)


def reverse_map_import(import_name: str) -> str | None:
    """Given a WASM import name (e.g. 'wasi:sockets/tcp'), return the
    declared-effect label it would have come from (e.g. 'net'), or None
    if the import is not in the v0.2 vocabulary at all (out-of-vocab =>
    WASM_EFFECT_DIVERGENCE caller-side).
    """
    if not isinstance(import_name, str):
        return None
    return IMPORT_TO_EFFECT_LABEL.get(import_name)


def label_admits_import(label: str, import_name: str) -> bool:
    """True iff `import_name` is among the imports that effect label
    `label` translates to. Used by trace-divergence detection: a trace
    line tagged with an import is consistent with declared effects iff
    `label_admits_import(declared_label_for_import, import_name)`."""
    if not isinstance(label, str) or not isinstance(import_name, str):
        return False
    if label not in EFFECT_LABEL_TO_IMPORTS:
        return False
    return import_name in EFFECT_LABEL_TO_IMPORTS[label]
