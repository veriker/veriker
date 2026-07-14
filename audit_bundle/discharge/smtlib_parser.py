"""audit_bundle/discharge/smtlib_parser.py — SMT-LIB v2 fragment parser (V-Kernel v0.2).

Parses a single refinement formula (an SMT-LIB v2 expression) and walks the AST
to enforce v0.1 fragment lock per o_kernel/REFINEMENT_TYPES.md:

  IN  : QF_LIA, QF_BV, QF_LRA, QF_UF (the union)
  OUT : NIA (nonlinear arithmetic), QF_AX (arrays), QF_S (strings),
        quantifiers (forall/exists), recursive datatypes, sequences, regex.

Out-of-fragment input raises FragmentOutOfScope with .offending_token set so
the C16 plugin's error detail can name the violating construct.

Why hand-roll instead of using z3.parse_smt2_string:
  * z3.parse_smt2_string requires a complete script with declarations + assert,
    not a bare expression. We'd need to synthesize declarations from context,
    which is a different concern (see context_substitution.py).
  * We need fragment-membership decisions BEFORE Z3 ever sees the formula —
    out-of-fragment input must fail at parse time, not at solve time.
  * The parser is small (~250 LOC) and the SMT-LIB v2 sub-syntax we accept
    is narrow.

Linearity rule (the load-bearing nonlinear/linear distinction):
  Multiplication `(* a b)` is in-fragment iff at most one of a, b is a non-
  literal expression. `(* 3 x)` is linear (literal coefficient × variable);
  `(* x x)` and `(* a b)` (both variables) are nonlinear. Same rule for `*`
  with three+ args via left-associativity.
  Division `(/ a b)` is in-fragment iff `b` is a numeric literal. Integer
  `(div a b)` and `(mod a b)` are in QF_LIA iff `b` is a literal positive int.
  This matches Z3's own QF_LIA / QF_LRA acceptance.
"""

from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Public exceptions
# ---------------------------------------------------------------------------


class SmtLibParseError(ValueError):
    """Raised when the refinement string is not well-formed s-expression syntax."""


class FragmentOutOfScope(ValueError):
    """Raised when the parsed expression uses a feature outside QF_LIA + QF_BV +
    QF_LRA + QF_UF (e.g. quantifiers, arrays, nonlinear multiplication)."""

    def __init__(self, reason: str, offending_token: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.offending_token = offending_token


# ---------------------------------------------------------------------------
# Parsed-refinement value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedRefinement:
    """An s-expression representing the refinement formula.

    `tree` is a nested tuple of strings; leaves are atoms, branches are
    s-expressions like `('=', ('+', 'a', 'b'), 'total')`.

    `free_symbols` is the set of free symbols (atoms that aren't operators,
    sorts, or numeric / bitvector / boolean literals) — these are the symbols
    the dispatcher must supply via context_substitution.
    """

    text: str
    tree: tuple
    free_symbols: frozenset[str]


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------


_WHITESPACE = frozenset(" \t\r\n")


def _tokenize(text: str) -> list[str]:
    """Lex an SMT-LIB v2 expression into atoms, '(', ')'.

    Recognises double-quoted string literals (rejected at fragment-walk time)
    and the SMT-LIB v2 numeric-literal forms `#x..`, `#b..`, decimals.
    Comments (semicolon to end-of-line) are stripped.
    """
    tokens: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in _WHITESPACE:
            i += 1
            continue
        if c == ";":
            # comment to end of line
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "(":
            tokens.append("(")
            i += 1
            continue
        if c == ")":
            tokens.append(")")
            i += 1
            continue
        if c == '"':
            # double-quoted string literal; SMT-LIB v2 escapes "" as a single "
            j = i + 1
            buf = ['"']
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        buf.append('"')
                        buf.append('"')
                        j += 2
                        continue
                    buf.append('"')
                    j += 1
                    tokens.append("".join(buf))
                    break
                buf.append(text[j])
                j += 1
            else:
                raise SmtLibParseError(
                    f"unterminated string literal starting at index {i}"
                )
            i = j
            continue
        if c == "|":
            # quoted symbol |...|
            j = text.find("|", i + 1)
            if j < 0:
                raise SmtLibParseError(f"unterminated quoted symbol at index {i}")
            tokens.append(text[i : j + 1])
            i = j + 1
            continue
        # bare atom
        j = i
        while j < n and text[j] not in _WHITESPACE and text[j] not in '()";|':
            j += 1
        if j == i:
            raise SmtLibParseError(f"unexpected character {c!r} at index {i}")
        tokens.append(text[i:j])
        i = j
    return tokens


# ---------------------------------------------------------------------------
# S-expression parser
# ---------------------------------------------------------------------------


def _parse_sexp(tokens: list[str]) -> tuple:
    """Parse a list of tokens into a nested tuple. Atoms stay strings;
    s-expressions become tuples of children."""
    if not tokens:
        raise SmtLibParseError("empty token stream")
    pos = [0]

    def parse_one():
        if pos[0] >= len(tokens):
            raise SmtLibParseError("unexpected end of input")
        tok = tokens[pos[0]]
        pos[0] += 1
        if tok == "(":
            children = []
            while pos[0] < len(tokens) and tokens[pos[0]] != ")":
                children.append(parse_one())
            if pos[0] >= len(tokens):
                raise SmtLibParseError("unbalanced parentheses (missing close)")
            pos[0] += 1  # consume ")"
            return tuple(children)
        if tok == ")":
            raise SmtLibParseError("unbalanced parentheses (extra close)")
        return tok

    expr = parse_one()
    if pos[0] != len(tokens):
        raise SmtLibParseError(
            f"trailing tokens after expression: {tokens[pos[0] :]!r}"
        )
    return expr


# ---------------------------------------------------------------------------
# Fragment-membership walker
# ---------------------------------------------------------------------------


_QUANTIFIER_HEADS = frozenset({"forall", "exists"})

_DATATYPE_DECL_HEADS = frozenset(
    {
        "declare-datatype",
        "declare-datatypes",
        "declare-rec",
        "define-fun-rec",
        "define-funs-rec",
    }
)

_ARRAY_HEADS = frozenset({"select", "store"})

_ARRAY_SORTS = frozenset({"Array"})

_STRING_SORTS = frozenset({"String", "Seq", "RegLan"})

_BOOL_OPS = frozenset(
    {
        "not",
        "and",
        "or",
        "xor",
        "=>",
        "implies",
        "ite",
        "let",
    }
)

_EQ_OPS = frozenset({"=", "distinct"})

_REL_OPS = frozenset({"<", "<=", ">", ">="})

_INT_REAL_OPS = frozenset(
    {"+", "-", "abs"}
)  # `*` / `/` / `div` / `mod` are checked specially

_BV_OPS = frozenset(
    {
        "bvadd",
        "bvsub",
        "bvmul",
        "bvneg",
        "bvor",
        "bvand",
        "bvxor",
        "bvnot",
        "bvnand",
        "bvnor",
        "bvxnor",
        "bvshl",
        "bvlshr",
        "bvashr",
        "bvurem",
        "bvsrem",
        "bvsmod",
        "bvudiv",
        "bvsdiv",
        "bvule",
        "bvult",
        "bvuge",
        "bvugt",
        "bvsle",
        "bvslt",
        "bvsge",
        "bvsgt",
        "concat",
        "extract",
        "bvcomp",
        "zero_extend",
        "sign_extend",
        "rotate_left",
        "rotate_right",
        "repeat",
        "bv2nat",
        "nat2bv",
        "int2bv",
    }
)

_BUILTIN_SORTS = frozenset({"Int", "Real", "Bool", "BitVec"})

_LITERALS = frozenset({"true", "false"})

# Tokens that would otherwise look like operators but always take their
# arguments through `_` (the indexed-identifier marker).
_INDEXED_IDENTIFIER_HEAD = "_"

# Operator / sort / literal vocabulary — used to subtract from free_symbols.
_VOCAB: frozenset[str] = (
    _BOOL_OPS
    | _EQ_OPS
    | _REL_OPS
    | _INT_REAL_OPS
    | _BV_OPS
    | _BUILTIN_SORTS
    | _LITERALS
    | _ARRAY_HEADS
    | _ARRAY_SORTS
    | _STRING_SORTS
    | _QUANTIFIER_HEADS
    | _DATATYPE_DECL_HEADS
    | frozenset({"*", "/", "div", "mod", "_", "as", "let", "match"})
)


def _is_numeric_literal(atom: str) -> bool:
    if not atom:
        return False
    if atom in _LITERALS:
        return False  # 'true'/'false' are bool literals, not numeric
    if atom.startswith("#x"):
        return all(c in "0123456789abcdefABCDEF" for c in atom[2:]) and len(atom) > 2
    if atom.startswith("#b"):
        return all(c in "01" for c in atom[2:]) and len(atom) > 2
    # decimal — possibly with leading minus and dot
    s = atom
    if s.startswith("-"):
        s = s[1:]
    if not s:
        return False
    parts = s.split(".")
    if len(parts) > 2:
        return False
    return all(p.isdigit() for p in parts) and any(p for p in parts)


def _is_bool_literal(atom: str) -> bool:
    return atom in _LITERALS


def _is_constant_expr(expr) -> bool:
    """True iff `expr` evaluates to a constant under the v0.1 fragment.
    Atoms: numeric / bool literals.
    Compound: `(- <const>)`, `(+ <const> ...)`, `(- <const> <const> ...)`,
    `(* <const> ...)`. Used by the linearity check to recognise that
    `(- 1)`, `(- 1 2)`, etc. are constant coefficients."""
    if isinstance(expr, str):
        return _is_numeric_literal(expr) or _is_bool_literal(expr)
    if isinstance(expr, tuple) and expr:
        head = expr[0]
        if isinstance(head, str) and head in {"+", "-", "*"}:
            return all(_is_constant_expr(child) for child in expr[1:])
    return False


def _walk(expr, free: set[str]) -> None:
    """Walk an s-expression, raising FragmentOutOfScope on out-of-fragment use,
    and accumulating free symbols into `free`."""
    if isinstance(expr, str):
        atom = expr
        if _is_numeric_literal(atom):
            return
        if _is_bool_literal(atom):
            return
        if atom.startswith('"'):
            raise FragmentOutOfScope(
                "string literals are not in QF_LIA + QF_BV + QF_LRA + QF_UF (string theory deferred to v0.3)",
                offending_token="<string-literal>",
            )
        if atom in _VOCAB:
            return
        # bare atom — a free symbol
        free.add(atom)
        return

    if not isinstance(expr, tuple):
        raise SmtLibParseError(f"unexpected node type {type(expr).__name__}")

    if not expr:
        raise SmtLibParseError("empty s-expression ()")

    head = expr[0]

    # Indexed identifiers: (_ extract 7 0), (_ BitVec 32), etc. — by SMT-LIB
    # spec the index positions are integer literals or sort names. We walk
    # every child defensively so a malformed-but-parseable indexed identifier
    # (e.g. with a quantifier in an index position from hostile input) still
    # gets fragment-checked. Per the V16 panel review BUG 5 (Sonnet 4.6
    # 2026-05-02): the prior code returned without walking expr[2:] and let
    # out-of-fragment subexpressions through.
    if isinstance(head, str) and head == _INDEXED_IDENTIFIER_HEAD:
        if len(expr) < 2:
            raise SmtLibParseError("(_ ...) requires at least an operator name")
        op = expr[1]
        if isinstance(op, str):
            if op in _STRING_SORTS:
                raise FragmentOutOfScope(
                    f"string sort {op!r} is not in v0.1 fragment",
                    offending_token=op,
                )
        for child in expr[1:]:
            if isinstance(child, str):
                # Index args must be numeric literals or named operators / sorts;
                # free symbols are not legal here. We walk via _walk so any
                # out-of-fragment construct still raises.
                _walk(child, free)
            else:
                _walk(child, free)
        return

    # 'as' typed-coercion: (as <expr> <sort>) — inspect the sort for
    # Array/String, but ALWAYS walk the coerced expression so a quantifier /
    # array / string nested inside cannot escape the fragment check via a short
    # or malformed (as <expr>) form. Mirrors the indexed-identifier BUG 5 fix
    # above: the prior code only walked when len(expr) >= 3, so a 2-element
    # (as (exists ...)) returned without inspecting expr[1] — out of fragment,
    # silently admitted.
    if isinstance(head, str) and head == "as":
        if len(expr) >= 3:
            _check_sort(expr[2])
            _walk(expr[1], free)
            for extra in expr[3:]:  # malformed trailing operands — walk defensively
                _walk(extra, free)
        else:
            # short/malformed (as <expr>): no sort to inspect, but still
            # fragment-check every operand so nothing escapes via the truncation.
            for child in expr[1:]:
                _walk(child, free)
        return

    # Quantifier rejection
    if isinstance(head, str) and head in _QUANTIFIER_HEADS:
        raise FragmentOutOfScope(
            f"quantifier {head!r} is not in QF_LIA + QF_BV + QF_LRA + QF_UF (quantifier-free fragments only)",
            offending_token=head,
        )

    # Recursive datatype / function declarations
    if isinstance(head, str) and head in _DATATYPE_DECL_HEADS:
        raise FragmentOutOfScope(
            f"recursive datatype / function declaration {head!r} is not in v0.1 fragment",
            offending_token=head,
        )

    # Array operations
    if isinstance(head, str) and head in _ARRAY_HEADS:
        raise FragmentOutOfScope(
            f"array operation {head!r} (theory of arrays QF_AX) is not in v0.1 fragment",
            offending_token=head,
        )

    # String operations: anything starting with str. or seq. or re.
    if isinstance(head, str) and (
        head.startswith("str.") or head.startswith("seq.") or head.startswith("re.")
    ):
        raise FragmentOutOfScope(
            f"string / sequence / regex operation {head!r} is not in v0.1 fragment",
            offending_token=head,
        )

    # Multiplication linearity check.
    # A literal includes any constant-folding expression (e.g. `(- 1)` is the
    # SMT-LIB v2 negative-int literal). `_is_constant_expr` recurses.
    if isinstance(head, str) and head == "*":
        non_literal_count = 0
        for arg in expr[1:]:
            if _is_constant_expr(arg):
                continue
            non_literal_count += 1
        if non_literal_count >= 2:
            raise FragmentOutOfScope(
                "nonlinear multiplication (* of two or more non-literals) is not in QF_LIA + QF_LRA (NIA deferred to v0.3)",
                offending_token="*",
            )
        # walk children for nested fragment violations
        for arg in expr[1:]:
            _walk(arg, free)
        return

    # Real division: divisor must be a constant expression (LRA admits / by
    # literal only; `(- 1)` and similar count as constants).
    if isinstance(head, str) and head == "/":
        if len(expr) < 3:
            raise SmtLibParseError(f"too few args for `/`: {expr!r}")
        # `/` is variadic / left-associative: EVERY divisor (expr[2:]) must be a
        # constant (LRA admits division by literal only). Checking only expr[2]
        # let a non-constant — including an out-of-fragment quantifier / array /
        # string — ride in a later divisor slot (e.g. (/ x 2 (exists ...))).
        # _is_constant_expr is False for any such construct, so this fails closed.
        for divisor in expr[2:]:
            if not _is_constant_expr(divisor):
                raise FragmentOutOfScope(
                    "nonlinear division (/ x y) where a divisor is not a constant "
                    "is not in QF_LRA",
                    offending_token="/",
                )
        _walk(expr[1], free)
        return

    # Integer div / mod: every divisor must be a constant expression.
    if isinstance(head, str) and head in {"div", "mod"}:
        if len(expr) < 3:
            raise SmtLibParseError(f"too few args for {head!r}: {expr!r}")
        # As with `/`, check ALL of expr[2:], not just expr[2], so an
        # out-of-fragment construct in a later operand of a malformed/variadic
        # form cannot escape the fragment check.
        for divisor in expr[2:]:
            if not _is_constant_expr(divisor):
                raise FragmentOutOfScope(
                    f"nonlinear `{head}` (divisor must be a constant in QF_LIA) "
                    "is not in v0.1 fragment",
                    offending_token=head,
                )
        _walk(expr[1], free)
        return

    # `let` is in-fragment but binds local symbols; subtract them from free.
    # Per the V16 panel review BUGs 3+4 (Sonnet 4.6 2026-05-02):
    #   - reject malformed let where expr[1] is not a tuple of binders
    #   - walk every child after the binders, not just expr[2], so trailing
    #     siblings of the body don't escape fragment-check
    if isinstance(head, str) and head == "let":
        if len(expr) < 3:
            raise SmtLibParseError(
                f"`let` requires at least binders + body, got {len(expr) - 1} args"
            )
        if not isinstance(expr[1], tuple):
            raise SmtLibParseError(
                "`let` binders must be a list of (name value) pairs, "
                f"got {type(expr[1]).__name__}: {expr[1]!r}"
            )
        local_binders: set[str] = set()
        for binder in expr[1]:
            if not (
                isinstance(binder, tuple)
                and len(binder) == 2
                and isinstance(binder[0], str)
            ):
                raise SmtLibParseError(
                    f"`let` binder must be (name value), got {binder!r}"
                )
            local_binders.add(binder[0])
            _walk(binder[1], free)
        body_free: set[str] = set()
        for body_child in expr[2:]:
            _walk(body_child, body_free)
        free.update(body_free - local_binders)
        return

    # General case: walk head + all children
    _walk_atom_or_sort(head, free)
    for child in expr[1:]:
        _walk(child, free)


def _walk_atom_or_sort(head, free: set[str]) -> None:
    """Walk a head position — same as _walk for an atom, but with a sort check
    so `(Array Int Int)` as a head fails."""
    if isinstance(head, tuple):
        _walk(head, free)
        return
    if isinstance(head, str):
        _check_sort(head)
        if head in _VOCAB or _is_numeric_literal(head) or _is_bool_literal(head):
            return
        free.add(head)


def _check_sort(sort) -> None:
    """Reject Array, String, Seq, RegLan as sort heads. Recurse for compound sorts."""
    if isinstance(sort, str):
        if sort in _ARRAY_SORTS:
            raise FragmentOutOfScope(
                f"sort {sort!r} (theory of arrays) is not in v0.1 fragment",
                offending_token=sort,
            )
        if sort in _STRING_SORTS:
            raise FragmentOutOfScope(
                f"sort {sort!r} (string / sequence theory) is not in v0.1 fragment",
                offending_token=sort,
            )
        return
    if isinstance(sort, tuple) and sort:
        head = sort[0]
        if isinstance(head, str):
            if head in _ARRAY_SORTS:
                raise FragmentOutOfScope(
                    "compound Array sort is not in v0.1 fragment",
                    offending_token="Array",
                )
            if head in _STRING_SORTS:
                raise FragmentOutOfScope(
                    f"compound {head!r} sort is not in v0.1 fragment",
                    offending_token=head,
                )
        # Recurse into EVERY sort argument (and a tuple head) so an Array/String
        # nested ANYWHERE escapes the fragment check — not just sort[1] of an
        # indexed sort. The prior code inspected only sort[1], so a string/array
        # in a later index slot like (_ Foo String) / (_ Foo Array Int Int) or a
        # nested compound sort (_ Foo (Array Int Int)) slipped through. Numeric
        # index literals and (_ BitVec N) are unaffected: _check_sort is a no-op
        # on a numeric/non-array/non-string atom.
        if isinstance(head, tuple):
            _check_sort(head)
        for arg in sort[1:]:
            _check_sort(arg)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_refinement(text: str) -> ParsedRefinement:
    """Parse `text` as an SMT-LIB v2 refinement formula and verify fragment
    membership. Returns a ParsedRefinement on success; raises
    SmtLibParseError on malformed syntax or FragmentOutOfScope on out-of-
    fragment use."""
    if not isinstance(text, str):
        raise SmtLibParseError(
            f"refine value must be a string, got {type(text).__name__}"
        )
    if not text.strip():
        raise SmtLibParseError("refine value is empty")

    tokens = _tokenize(text)
    tree = _parse_sexp(tokens)

    free: set[str] = set()
    _walk(tree, free)

    return ParsedRefinement(
        text=text,
        tree=tree if isinstance(tree, tuple) else (tree,),
        free_symbols=frozenset(free),
    )
