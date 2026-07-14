"""audit_bundle/discharge/context_substitution.py — substitute concrete dispatch
values into a parsed refinement and emit a complete SMT-LIB script.

The script the runner sends to Z3 has the shape:

    (set-logic <logic>)
    (declare-const <symbol_1> <sort_1>)
    ...
    (declare-const <symbol_n> <sort_n>)
    (assert (not <refinement-formula-with-substitutions>))
    (check-sat)

We assert the negation: if Z3 returns ``unsat``, the refinement is universally
true given the context (the "discharged" outcome). ``sat`` means a counterexample
exists (the formula is false). ``unknown`` is timeout / decidability boundary.

Substitution rules:
  * If a free symbol has a concrete value in `context`, it's substituted as a
    literal at every occurrence in the formula.
  * If a free symbol has a sort declaration in `context["__sorts__"]`, it's
    declared as a `(declare-const <name> <sort>)` so Z3 can range over it.
  * If a free symbol has neither, ContextSubstitutionError is raised.

Concrete value forms supported (v0.2 enforced — Cumulative-pre-soak Patch 9
fix, Gate 1 2026-05-04):
  * bool                        -> 'true' / 'false'
  * int (excluding bool)        -> SMT-LIB integer literal
  * float (finite, no NaN/Inf)  -> SMT-LIB decimal literal
  * SmtLibLiteral wrapper       -> embedded text emitted verbatim; the
                                    wrapper's constructor routes through
                                    `parse_refinement` so the embedded text
                                    is fragment-checked (no SMT-LIB injection)

EXPLICITLY REJECTED (post V16 panel review BUG 6 fix, 2026-05-02):
  * raw `str`                   -> ContextSubstitutionError; callers must
                                    wrap as SmtLibLiteral so the text is
                                    parser-validated (closes the SMT-LIB
                                    injection vector that bare-string
                                    substitution opened)
  * raw `bytes`                 -> not supported; bitvector literals must
                                    be wrapped as SmtLibLiteral with the
                                    SMT-LIB `#b...` or `#x...` form

An earlier docstring promised raw str (as already-SMT-LIB) and bytes
support that the hardened `_format_literal` no longer admits. This is
aligned to the actual enforced surface.

List substitution (used by U1's sum-of-edge-attribution) is handled as a
sum reduction at substitution time — `(sum_of L)` is expanded into
`(+ l[0] l[1] ... l[n])` before the parser ever sees it. Tier U1 emits the
expansion at dispatch time, so the parser only sees fully-concrete sums.
"""

from __future__ import annotations

from dataclasses import dataclass

from .smtlib_parser import ParsedRefinement


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class ContextSubstitutionError(ValueError):
    """Raised when the dispatch context cannot supply a required symbol with the
    correct sort, or when a substitution value is out-of-range for its declared
    sort (e.g. negative value substituted into a Nat-shaped position)."""


class SubstrateInvalidSort(ContextSubstitutionError):
    """Raised when ``context["__sorts__"]`` carries a sort string outside the
    permitted allowlist. Gate 3a frontier-pair P1 (Opus 4.7 §a1, 2026-05-19):
    sort strings flow unsanitised into ``(declare-const <name> <sort>)`` lines
    in the discharge script. A dispatcher who supplies a sort like
    ``"Int) (assert false"`` lands an injected top-level form into the script
    that Z3 then accepts — the verifier reports DISCHARGED on a forgery. The
    hardening on ``_format_literal`` (BUG 6) only covered value substitution;
    the parallel sort-string path remained open until this fix."""


_PERMITTED_SORTS = frozenset({"Int", "Real", "Bool"}) | frozenset(
    f"(_ BitVec {n})" for n in (8, 16, 32, 64, 128)
)


@dataclass(frozen=True)
class SmtScript:
    """A complete SMT-LIB v2 script ready to feed to Z3.

    `text` is the script source. `free_symbols_resolved` is the set of symbols
    that were bound by context (used only for diagnostics).
    """

    text: str
    free_symbols_resolved: frozenset[str]
    declared_symbols: tuple[tuple[str, str], ...]  # (name, sort) pairs


@dataclass(frozen=True)
class SmtLibLiteral:
    """An SMT-LIB v2 sub-expression that has been parsed + fragment-checked.

    Used as an envelope for context values that aren't simple int/float/bool
    literals. Construction routes through `parse_refinement` so the embedded
    text is guaranteed to lie in QF_LIA + QF_BV + QF_LRA + QF_UF — emitting
    it into the discharge script is safe (no SMT-LIB injection).

    Per the V16 panel review BUG 6 (Sonnet 4.6 2026-05-02): bare `str`
    context values were emitted verbatim, enabling injection. Callers that
    need to pass a sub-expression now wrap via SmtLibLiteral.parse(text).
    """

    text: str

    @classmethod
    def parse(cls, text: str) -> "SmtLibLiteral":
        # Lazy import to keep context_substitution import-clean
        from .smtlib_parser import parse_refinement

        # parse_refinement raises FragmentOutOfScope or SmtLibParseError on bad
        # input; we propagate those — caller sees the same vocabulary they'd
        # see if the text were a refinement formula.
        parse_refinement(text)
        return cls(text=text)


# ---------------------------------------------------------------------------
# Logic selection helpers
# ---------------------------------------------------------------------------


_SUPPORTED_LOGICS = frozenset(
    {
        # The v0.1 fragment + sane unions. NIA / NRA / arrays / ALL are excluded
        # per the V16 panel review BUG 8 (Sonnet 4.6 2026-05-02): a dispatcher-
        # supplied __logic__ in recheck_context could request `(set-logic ALL)`
        # and trick Z3 into accepting nominally-out-of-fragment formulas.
        "QF_LIA",
        "QF_LRA",
        "QF_BV",
        "QF_UF",
        "QF_UFLIA",
        "QF_UFLRA",
        "QF_UFBV",
        "QF_UFLIRA",  # union of QF_UF + LIA + LRA — the default for mixed integer/real refinements
    }
)


def _format_literal(value) -> str:
    """Format a Python value as an SMT-LIB v2 literal.

    BUG 6 (panel review 2026-05-02): the prior implementation accepted `str`
    values verbatim, enabling SMT-LIB injection (e.g. a context value of
    `'(+ 1 1)) (assert false) (check-sat\\n;'` would inject extra assertions
    into the discharge script). String substitution is no longer admitted in
    the public API. Callers that genuinely need to substitute a parsed sub-
    expression should pass a `SmtLibLiteral` envelope (below) — that path
    routes through `parse_refinement` so the substituted text is fragment-
    checked before emission.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if value < 0:
            return f"(- {-value})"
        return str(value)
    if isinstance(value, float):
        if value != value:  # NaN
            raise ContextSubstitutionError(
                "NaN cannot be encoded as an SMT-LIB Real literal"
            )
        if value in (float("inf"), float("-inf")):
            raise ContextSubstitutionError(
                "Infinity cannot be encoded as an SMT-LIB Real literal"
            )
        if value < 0:
            return f"(- {-value})"
        # Force a decimal form: 1.0 / 0.5 / 3.14 — Z3 wants a dot.
        s = repr(value)
        if "." not in s and "e" not in s and "E" not in s:
            s = s + ".0"
        return s
    if isinstance(value, SmtLibLiteral):
        # Pre-parsed and fragment-checked at construction time; safe to emit.
        return value.text
    if isinstance(value, str):
        raise ContextSubstitutionError(
            "string-typed context values are not admitted (SMT-LIB injection risk; "
            "panel review 2026-05-02 BUG 6). Wrap parsed sub-expressions in "
            "SmtLibLiteral(...) which routes through parse_refinement for "
            "fragment-check before emission."
        )
    raise ContextSubstitutionError(
        f"unsupported substitution value type {type(value).__name__}"
    )


# ---------------------------------------------------------------------------
# Tree substitution
# ---------------------------------------------------------------------------


def _substitute_atoms(tree, value_map: dict[str, str]):
    """Recursively replace atoms named in value_map with their literal forms."""
    if isinstance(tree, str):
        return value_map.get(tree, tree)
    if isinstance(tree, tuple):
        return tuple(_substitute_atoms(child, value_map) for child in tree)
    return tree


def _emit_sexp(node) -> str:
    """Reverse the parser: serialise a tree back into SMT-LIB v2 text."""
    if isinstance(node, str):
        return node
    if isinstance(node, tuple):
        return "(" + " ".join(_emit_sexp(c) for c in node) + ")"
    raise ContextSubstitutionError(f"cannot emit node type {type(node).__name__}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def substitute(
    parsed: ParsedRefinement, context: dict, *, logic: str = "QF_UFLIRA"
) -> SmtScript:
    """Substitute dispatch-context values into the parsed formula and emit an
    SMT-LIB script.

    `context` keys:
      * <symbol-name> -> Python value (int/float/bool/str) — substituted as
        an SMT-LIB literal at every occurrence.
      * '__sorts__' -> dict[symbol-name, sort-string] — symbols to leave as
        free variables under a (declare-const) declaration.

    Symbols that appear in the formula but not in either context map raise
    ContextSubstitutionError.
    """
    if logic not in _SUPPORTED_LOGICS:
        raise ContextSubstitutionError(
            f"logic {logic!r} not supported; choose from {sorted(_SUPPORTED_LOGICS)}"
        )

    sort_map: dict[str, str] = {}
    if "__sorts__" in context:
        sort_map = dict(context["__sorts__"])

    value_map: dict[str, str] = {}
    declared: list[tuple[str, str]] = []
    resolved: set[str] = set()

    for sym in sorted(parsed.free_symbols):
        if sym in context and sym != "__sorts__":
            raw = context[sym]
            value_map[sym] = _format_literal(raw)
            resolved.add(sym)
            continue
        if sym in sort_map:
            sort = sort_map[sym]
            # Gate 3a frontier-pair P1 (Opus 4.7 §a1, 2026-05-19): the sort
            # string lands verbatim in the emitted `(declare-const <name> <sort>)`
            # line below. Without an allowlist a dispatcher who supplies a sort
            # like `"Int) (assert false"` injects an extra top-level assertion
            # that Z3 then evaluates — the assertion-set is jointly UNSAT and
            # the runner classifies a forgery as DISCHARGED. _format_literal's
            # str-rejection (BUG 6) closed the value-substitution path; this
            # closes the parallel sort-substitution path.
            if not isinstance(sort, str) or sort not in _PERMITTED_SORTS:
                raise SubstrateInvalidSort(
                    f"sort {sort!r} for symbol {sym!r} is not in the permitted "
                    f"allowlist {sorted(_PERMITTED_SORTS)} (Gate 3a P1, "
                    "SUBSTRATE_INVALID_SORT)"
                )
            declared.append((sym, sort))
            resolved.add(sym)
            continue
        raise ContextSubstitutionError(
            f"symbol {sym!r} appears in refinement but is not in context "
            "(neither concrete value nor sort declaration)"
        )

    substituted_tree = _substitute_atoms(parsed.tree, value_map)
    body_text = _emit_sexp(substituted_tree)

    lines = [f"(set-logic {logic})"]
    for name, sort in declared:
        lines.append(f"(declare-const {name} {sort})")
    lines.append(f"(assert (not {body_text}))")
    lines.append("(check-sat)")
    script_text = "\n".join(lines) + "\n"

    return SmtScript(
        text=script_text,
        free_symbols_resolved=frozenset(resolved),
        declared_symbols=tuple(declared),
    )
