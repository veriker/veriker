"""audit_bundle/rederivation/dispatch.py — core spec-pinned dispatch loop.

Implements design-note §3.5 orchestration + the §4a hardening. Per claimed
output O in manifest.outputs:

    binding  = anchored_spec_set.resolve(O.type)        # Axis 1 (auditor-anchored)
    value    = registry[binding.primitive_id].recompute(...)   # Axis 2 (value return)
    ok,_     = comparator[binding.comparator.kind](value, claimed, params)  # Axis 2 (split)

The verifier core ROUTES and AGGREGATES; the only domain-specific component is
the recompute primitive. Comparison is generic.

Fail-closed semantics (§4a.8): every per-output evaluation is wrapped so an
error becomes a RECORDED failure, never a crash and never a silent skip. Exactly
one result is recorded per declared output; a final cardinality assertion
(result-count == declared-output-count) guarantees `all([])` can never read True
on an empty or skipped set.

Coverage invariant (§4a.4 / C19): file-presence-triggered on outputs/ — the set
of output_ids declared in manifest.outputs must equal the set of output files
actually present (outputs/<output_id>.json). Otherwise "omit the check name"
just becomes "omit the output entry".

Stdlib-only (core verify() path).
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

from ..admission import admit_json_file
from ..plugin import ParsedInputs
from .comparators import (
    UnknownComparatorKind,
    UnknownComparatorParam,
    resolve_comparator,
)
from .registry import UnknownPrimitive, _ensure_primitives_loaded, resolve_primitive
from .spec_binding import (
    SpecAnchor,
    SpecBindingError,
    UnknownType,
    build_anchored_spec_set,
)


@dataclass(slots=True)
class DispatchFailure:
    check_name: str
    reason_code: str
    detail: str


# ---------------------------------------------------------------------------
# Non-finite (inf/nan) boundary — applies to EVERY comparator kind.
#
# A re-derivation primitive recomputes the producer's binary64 arithmetic
# faithfully (the MIRROR-the-producer doctrine: re-derivers reproduce the
# producer's exact numeric model, never a "safer" Decimal/fixed-point one).
# That faithfulness has a hard floor: a non-finite result (inf / -inf / nan)
# is never a meaningful compliance claim. It signals overflow or a degenerate
# input, it is not portably reproducible, and stdlib `json` will happily round-
# trip `Infinity`/`NaN` (a non-standard extension) so a producer can both
# OVERFLOW a committed input and CLAIM the overflowed value.
#
# Without this boundary the laundering succeeds comparator-by-comparator: the
# `exact` comparator returns True for `inf == inf` (and `structured` does the
# same for a non-finite field via `!=`), blessing "emissions = infinity" GREEN.
# `scalar_epsilon` already rejects non-finite operands in isolation; this lifts
# that defense to the dispatch chokepoint so it holds for ALL kinds uniformly,
# on BOTH the recomputed value and the producer's claimed value.
#
# The walk is iterative (explicit stack) so a deeply-nested adversarial claimed
# value drives a bounded loop, not a new RecursionError surface.
# ---------------------------------------------------------------------------


def _first_nonfinite_path(value: object) -> str | None:
    """Return a human path to the first non-finite float in `value` (walking
    nested lists/tuples/dicts), or None if every float is finite. bool/int are
    always finite; strings are opaque. Iterative to stay bounded on adversarial
    nesting."""
    stack: list[tuple[str, object]] = [("", value)]
    while stack:
        path, node = stack.pop()
        if isinstance(node, float):
            if not math.isfinite(node):
                return f"{path or '<root>'}={node!r}"
        elif isinstance(node, dict):
            for k, v in node.items():
                stack.append((f"{path}.{k}" if path else str(k), v))
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                stack.append((f"{path}[{i}]", v))
    return None


# output_id is interpolated into a filename (outputs/<output_id>.json) and used
# as a coverage stem. Constrain it to a single safe path segment so a hostile
# manifest cannot steer verifier-side reads outside outputs/ via traversal. The
# grammar forbids path separators ('/' and '\\') and a leading dot (so '.' and
# '..' are rejected); because no separator can appear, an embedded '..' can
# never form a parent-directory step. The allowed body chars ('.', '_', ':',
# '-' + alnum) cover every real output_id (e.g. 'P6.1_trust_in_ai__DE__2026Q3',
# 'energy-score-2026-04-28T23:00:00Z', 'E0008-2026-05').
_OUTPUT_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]*\Z")


def _outputs_dir(bundle_dir: Path) -> Path:
    return bundle_dir / "outputs"


def _enumerate_output_files(bundle_dir: Path) -> set[str]:
    """The output_ids actually present as outputs/<id>.json files."""
    odir = _outputs_dir(bundle_dir)
    if not odir.is_dir():
        return set()
    return {p.stem for p in odir.glob("*.json")}


def _check_coverage(
    bundle_dir: Path, declared_ids: list[str], failures: list[DispatchFailure]
) -> None:
    """§4a.4 coverage invariant. File-presence-triggered: only fires when an
    outputs/ directory exists. set(declared) must equal set(present)."""
    odir = _outputs_dir(bundle_dir)
    if not odir.is_dir():
        return  # inert when the bundle carries no outputs/ tree
    present = _enumerate_output_files(bundle_dir)
    declared = set(declared_ids)
    if declared == present:
        return
    missing_entry = present - declared  # file present, not declared (the omit attack)
    missing_file = declared - present  # declared, no file
    failures.append(
        DispatchFailure(
            check_name="spec_pinned_dispatch:coverage",
            reason_code="COVERAGE_MISMATCH",
            detail=(
                "manifest.outputs must cover exactly the outputs/ files "
                f"(§4a.4). present-but-undeclared={sorted(missing_entry)!r} "
                f"declared-but-absent={sorted(missing_file)!r}"
            ),
        )
    )


def run_spec_pinned_dispatch(
    bundle_dir: Path,
    manifest,
    anchor: SpecAnchor | None,
    role_policy: dict | None = None,
) -> list[DispatchFailure]:
    """Run spec-pinned dispatch over manifest.outputs. Returns collected
    failures (empty == all covered outputs re-derived and agreed).

    Engages ONLY when manifest.outputs is non-empty; otherwise returns [] so
    legacy bundles (0/56 carry outputs) are wholly unaffected.
    """
    outputs = list(getattr(manifest, "outputs", ()) or ())
    if not outputs:
        return []

    failures: list[DispatchFailure] = []

    # --- Build the auditor-anchored authoritative binding set (steps 3-5). ---
    # Any load-time failure (no anchor, malformed/ambiguous spec, monotone-
    # strictness violation) is terminal: record it and refuse to dispatch.
    try:
        anchored = build_anchored_spec_set(bundle_dir, manifest, anchor)
    except SpecBindingError as exc:
        failures.append(
            DispatchFailure(
                check_name="spec_pinned_dispatch:anchor",
                reason_code=type(exc).__name__,
                detail=str(exc),
            )
        )
        return failures

    _ensure_primitives_loaded()

    # --- Coverage invariant (§4a.4), file-presence-triggered. ---
    declared_ids = [
        o.get("output_id") if isinstance(o, dict) else None for o in outputs
    ]
    _check_coverage(
        bundle_dir, [d for d in declared_ids if isinstance(d, str)], failures
    )

    inputs = ParsedInputs(bundle_dir=bundle_dir)
    results: list[bool] = []  # exactly one per declared output (cardinality guard)

    for o in outputs:
        cn = "spec_pinned_dispatch"
        # --- Output entry shape ---
        if not isinstance(o, dict):
            failures.append(
                DispatchFailure(
                    cn, "OUTPUT_ENTRY_MALFORMED", f"output entry not an object: {o!r}"
                )
            )
            results.append(False)
            continue
        output_id = o.get("output_id")
        type_key = o.get("type")
        conforms_to = o.get("conforms_to")
        cn = f"spec_pinned_dispatch:{output_id}"
        if not isinstance(output_id, str) or not output_id:
            failures.append(
                DispatchFailure(
                    cn,
                    "OUTPUT_ENTRY_MALFORMED",
                    f"output_id not a non-empty string: {output_id!r}",
                )
            )
            results.append(False)
            continue
        if not _OUTPUT_ID_RE.match(output_id):
            failures.append(
                DispatchFailure(
                    cn,
                    "OUTPUT_ID_UNSAFE",
                    f"output_id {output_id!r} is not a safe filename segment "
                    "(grammar: [A-Za-z0-9][A-Za-z0-9._:-]*) — it is interpolated "
                    "into outputs/<output_id>.json, so path separators and "
                    "traversal are refused to keep verifier-side reads inside "
                    "outputs/.",
                )
            )
            results.append(False)
            continue
        if not isinstance(type_key, str) or not type_key:
            failures.append(
                DispatchFailure(
                    cn,
                    "OUTPUT_ENTRY_MALFORMED",
                    f"output {output_id!r}: type not a non-empty string",
                )
            )
            results.append(False)
            continue
        # conforms_to is a non-load-bearing cross-check hint (§4a.2 option b:
        # resolution is by anchored-search, not by following this pointer). It
        # must be a string if present; it cannot redirect dispatch.
        if conforms_to is not None and not isinstance(conforms_to, str):
            failures.append(
                DispatchFailure(
                    cn,
                    "OUTPUT_ENTRY_MALFORMED",
                    f"output {output_id!r}: conforms_to not a string",
                )
            )
            results.append(False)
            continue

        # --- Type-substitution role policy (§4a.3, auditor-supplied). ---
        if role_policy:
            required = role_policy.get(output_id)
            if required is not None and required != type_key:
                failures.append(
                    DispatchFailure(
                        cn,
                        "ROLE_POLICY_VIOLATION",
                        f"output {output_id!r} claims type {type_key!r} but the "
                        f"auditor role policy requires {required!r} — a weaker/other "
                        "type was substituted; fail-closed (§4a.3).",
                    )
                )
                results.append(False)
                continue

        # --- Resolve binding (Axis 1, auditor-anchored). ---
        try:
            binding = anchored.resolve(type_key)
        except UnknownType as exc:
            failures.append(DispatchFailure(cn, "UNKNOWN_TYPE", str(exc)))
            results.append(False)
            continue

        # --- Load the producer's claimed value (outputs/<id>.json {"value":…}). ---
        claimed_path = _outputs_dir(bundle_dir) / f"{output_id}.json"
        # Defense in depth: the grammar above already forbids separators and
        # traversal, but assert the resolved path stays inside outputs/ so even
        # a symlink under outputs/ or a platform-specific path quirk (e.g. a
        # Windows drive-relative segment) cannot steer the read outside it.
        outputs_root = _outputs_dir(bundle_dir).resolve()
        try:
            claimed_path.resolve().relative_to(outputs_root)
        except ValueError:
            failures.append(
                DispatchFailure(
                    cn,
                    "OUTPUT_ID_UNSAFE",
                    f"output {output_id!r}: claimed-value path resolves outside "
                    "outputs/ — refusing the read.",
                )
            )
            results.append(False)
            continue
        if not claimed_path.is_file():
            failures.append(
                DispatchFailure(
                    cn,
                    "CLAIMED_VALUE_MISSING",
                    f"output {output_id!r}: no outputs/{output_id}.json claimed-value file",
                )
            )
            results.append(False)
            continue
        try:
            # Admission-bounded load (RES-02): size-reject BEFORE allocation,
            # depth-scan BEFORE parse — the producer-claimed value is the most
            # bundle-controlled read on the dispatch path and must clear the
            # same gate as every other bundle JSON. InputInadmissible is a
            # ValueError, so a breach lands in the except arm below and keeps
            # the CLAIMED_VALUE_MALFORMED reason code (sweep convention).
            claimed_doc = admit_json_file(
                claimed_path, check_name="claimed_value_admission"
            )
            if not isinstance(claimed_doc, dict) or "value" not in claimed_doc:
                raise ValueError(
                    "claimed-value file must be a JSON object with a 'value' key"
                )
            claimed = claimed_doc["value"]
        except (
            json.JSONDecodeError,
            ValueError,
            UnicodeDecodeError,
            OSError,
            RecursionError,  # belt-and-suspenders; admission pre-empts the parser
        ) as exc:
            failures.append(
                DispatchFailure(
                    cn, "CLAIMED_VALUE_MALFORMED", f"output {output_id!r}: {exc}"
                )
            )
            results.append(False)
            continue

        # --- Resolve primitive + comparator (fail-closed on unknown). ---
        try:
            primitive = resolve_primitive(binding.primitive_id)
        except UnknownPrimitive as exc:
            failures.append(DispatchFailure(cn, "UNKNOWN_PRIMITIVE", str(exc)))
            results.append(False)
            continue
        try:
            comparator = resolve_comparator(binding.comparator_kind)
        except (UnknownComparatorKind, UnknownComparatorParam) as exc:
            failures.append(DispatchFailure(cn, "UNKNOWN_COMPARATOR_KIND", str(exc)))
            results.append(False)
            continue

        # --- Recompute (Axis 2; try/except -> recorded failure, §4a.8). ---
        pack_section = {
            "output_id": output_id,
            "type": type_key,
            "params": dict(binding.comparator_params),
        }
        try:
            recomputed = primitive.recompute(inputs, pack_section)
        except Exception as exc:  # noqa: BLE001 — any primitive error is fail-closed
            failures.append(
                DispatchFailure(
                    cn,
                    "RECOMPUTE_ERROR",
                    f"output {output_id!r}: primitive {binding.primitive_id!r} "
                    f"raised {type(exc).__name__}: {exc}",
                )
            )
            results.append(False)
            continue

        # --- Non-finite boundary (every comparator kind). A non-finite value
        #     on either side is a fail-closed REJECT, BEFORE the comparator runs,
        #     so `inf == inf` / a non-finite structured field can never be
        #     blessed GREEN by exact/set/structured (scalar_epsilon already
        #     guards in isolation). Recomputed side first (verifier saw it), then
        #     the producer's claimed side. ---
        nf = _first_nonfinite_path(recomputed.value)
        side = "recomputed"
        if nf is None:
            nf = _first_nonfinite_path(claimed)
            side = "claimed"
        if nf is not None:
            failures.append(
                DispatchFailure(
                    cn,
                    "NON_FINITE_VALUE",
                    f"output {output_id!r} (type {type_key!r}): non-finite "
                    f"{side} value at {nf} — a non-finite (inf/nan) result is "
                    f"never a verifiable claim (overflow/degenerate input)",
                )
            )
            results.append(False)
            continue

        # --- Compare (Axis 2; wrapped so a comparator that DOES raise is a
        #     recorded fail-closed REJECT, never an uncaught crash that
        #     escalates to a could-not-conclude verdict). The comparator
        #     contract is "never raises", but a deeply-nested claimed value read
        #     from outputs/<id>.json can drive _freeze/_cmp_* into RecursionError;
        #     this boundary enforces the contract for the whole verify path the
        #     same way the recompute call above is wrapped (§4a.8). ---
        try:
            ok, detail = comparator(
                recomputed.value, claimed, binding.comparator_params
            )
        except Exception as exc:  # noqa: BLE001 — any comparator error is fail-closed
            failures.append(
                DispatchFailure(
                    cn,
                    "COMPARATOR_ERROR",
                    f"output {output_id!r} (type {type_key!r}, comparator "
                    f"{binding.comparator_kind!r}): comparator raised "
                    f"{type(exc).__name__}: {exc}",
                )
            )
            results.append(False)
            continue
        if not ok:
            failures.append(
                DispatchFailure(
                    cn,
                    "REDERIVATION_MISMATCH",
                    f"output {output_id!r} (type {type_key!r}, "
                    f"primitive {binding.primitive_id!r}, comparator "
                    f"{binding.comparator_kind!r}): {detail}"
                    + (f" | {recomputed.detail}" if recomputed.detail else ""),
                )
            )
            results.append(False)
            continue

        results.append(True)

    # --- Cardinality guard (§4a.8): one result per declared output. ---
    if len(results) != len(outputs):
        failures.append(
            DispatchFailure(
                "spec_pinned_dispatch:cardinality",
                "CARDINALITY_VIOLATION",
                f"evaluated {len(results)} result(s) for {len(outputs)} declared "
                "output(s) — refusing to let an incomplete set aggregate to PASS.",
            )
        )

    return failures
