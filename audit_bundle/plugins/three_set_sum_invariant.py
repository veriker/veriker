"""audit_bundle/plugins/three_set_sum_invariant.py — TypedCheck: three-set sum invariant.

Follows the audit-bundle contract §C9 typed-check pattern (three-set manifest invariant).
Three checks over manifest.per_output_manifests:
  1. Subset chain: quote_supporting ⊆ context_injected ⊆ retrieved (via three_set_sum_invariant_check).
  2. Determinism: every set list in the canonical dict is sorted.
  3. Closure: every CID appearing in any set is reachable in manifest.snapshots or manifest.source_attributes.
"""

from __future__ import annotations

from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult
from audit_bundle.retrieval.three_set import ThreeSetView, three_set_sum_invariant_check


def _is_sorted(lst: list) -> bool:
    return all(lst[i] <= lst[i + 1] for i in range(len(lst) - 1))


class ThreeSetSumInvariantCheck:
    name: str = "three_set_sum_invariant"
    # exact-path-only: the former {"per_output_manifests/"} trailing-slash
    # pseudo-prefix was inert (consumed by exact match, never matched). Dropped.
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        """Walk manifest.per_output_manifests and enforce three invariants."""
        poms: tuple[dict, ...] = manifest.per_output_manifests
        checked = 0

        # Hoist the known-CID set out of the loop — manifest.snapshots and
        # manifest.source_attributes don't change per output, and on a mesh
        # bundle (the mesh pilot: 7145+7145 entries × 814 outputs) the
        # inner-loop reconstruction was ~990ms / 80% of verifier wall-time.
        known_cids: set[str] = set(manifest.snapshots) | set(manifest.source_attributes)

        for entry in poms:
            output_id = (
                entry.get("output_id", "<unknown>")
                if isinstance(entry, dict)
                else "<unknown>"
            )
            three_set = entry.get("three_set", {}) if isinstance(entry, dict) else {}

            # Fail-closed type guards: three_set and its three set fields are
            # bundle-controlled and never type-validated at parse. A non-dict
            # three_set (.get -> AttributeError), a non-list field
            # (list() -> TypeError), unhashable elements (set() -> TypeError
            # in the chain check), or mutually-unorderable elements
            # (_is_sorted -> TypeError) would otherwise escape the plugin and
            # degrade the run to a VERIFIER_INTERNAL_ERROR crash instead of a
            # recorded REJECT.
            if not isinstance(three_set, dict):
                return PluginResult(
                    ok=False,
                    reason_code="THREE_SET_MALFORMED",
                    detail=(
                        f"output_id={output_id!r}: three_set must be a JSON "
                        f"object, got {type(three_set).__name__!r}"
                    ),
                    files_audited=(),
                )
            for set_name in ("retrieved", "context_injected", "quote_supporting"):
                val = three_set.get(set_name, [])
                if not isinstance(val, list):
                    return PluginResult(
                        ok=False,
                        reason_code="THREE_SET_MALFORMED",
                        detail=(
                            f"output_id={output_id!r}: three_set[{set_name!r}] "
                            f"must be a list, got {type(val).__name__!r}"
                        ),
                        files_audited=(),
                    )

            retrieved = list(three_set.get("retrieved", []))
            context_injected = list(three_set.get("context_injected", []))
            quote_supporting = list(three_set.get("quote_supporting", []))

            # 1. Subset chain invariant
            view = ThreeSetView(
                retrieved=tuple(retrieved),
                context_injected=tuple(context_injected),
                quote_supporting=tuple(quote_supporting),
            )
            try:
                ok, reason_code = three_set_sum_invariant_check(view)
            except TypeError as exc:
                # set() over unhashable elements (e.g. nested lists/dicts).
                return PluginResult(
                    ok=False,
                    reason_code="THREE_SET_MALFORMED",
                    detail=(
                        f"output_id={output_id!r}: three_set contains "
                        f"unhashable elements; cannot evaluate the subset "
                        f"chain: {exc}"
                    ),
                    files_audited=(),
                )
            if not ok:
                return PluginResult(
                    ok=False,
                    reason_code=reason_code,
                    detail=(
                        f"output_id={output_id!r}: three-set subset chain violated "
                        f"({reason_code})"
                    ),
                    files_audited=(),
                )

            # 2. Determinism: all three set lists must be sorted
            for set_name, lst in (
                ("retrieved", retrieved),
                ("context_injected", context_injected),
                ("quote_supporting", quote_supporting),
            ):
                try:
                    is_sorted = _is_sorted(lst)
                except TypeError as exc:
                    # Mutually-unorderable elements (e.g. [1, "a"]) — hashable
                    # enough to pass the chain check, but '<=' raises.
                    return PluginResult(
                        ok=False,
                        reason_code="THREE_SET_MALFORMED",
                        detail=(
                            f"output_id={output_id!r}: three_set[{set_name!r}] "
                            f"contains mutually-unorderable elements; sorted-"
                            f"order is undecidable: {exc}"
                        ),
                        files_audited=(),
                    )
                if not is_sorted:
                    return PluginResult(
                        ok=False,
                        reason_code="THREE_SET_NOT_SORTED",
                        detail=(
                            f"output_id={output_id!r}: three_set[{set_name!r}] is not "
                            f"in sorted order — canonical dict is non-deterministic"
                        ),
                        files_audited=(),
                    )

            # 3. Closure: every CID in any set must be reachable
            #    (known_cids hoisted above the loop)
            all_cids = set(retrieved) | set(context_injected) | set(quote_supporting)
            orphans = all_cids - known_cids
            if orphans:
                first_orphan = sorted(orphans)[0]
                return PluginResult(
                    ok=False,
                    reason_code="THREE_SET_ORPHAN_CID",
                    detail=(
                        f"output_id={output_id!r}: CID {first_orphan!r} appears in the "
                        f"three-set but is not present in manifest.snapshots or "
                        f"manifest.source_attributes"
                    ),
                    files_audited=(),
                )

            checked += 1

        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=(
                f"all {checked} per_output_manifest"
                f"{'s' if checked != 1 else ''} passed three-set invariant checks"
            ),
            files_audited=(),
        )


register_typed_check("three_set_sum_invariant")
