"""audit_bundle/output_modes/es_pipeline.py — ES-mode failure_modes lint rails.

Exploratory Synthesis (ES) mode post-processor. ES-mode is NOT 'mixed-mode' — it
is exploratory synthesis with hard-labeled unsupported sections. Specifically:

- The K1 Option C 'mixed mode with sentence-level discipline' is far-future (not v1).
- ES bundles ARE permitted to contain non-stamped synthesis (this is the difference
  from VE-mode, which suppresses unsupported synthesis outright at generation time).
- The synthesis IS lint-checked against the failure-mode taxonomy; any output span
  that references an unknown failure-mode ID is hard-labeled with the markdown
  unsupported-marker convention: ``[unsupported: <failure_mode_id>] <failure_mode_id>``.
- Mixed-mode-in-one-pane is still forbidden: ES mode is the explicit opt-in mode;
  the per-pane mode lock ensures the consumer always knows they are in ES.

Dependency: nexi_methodology.failure_modes (B.3, Apache-2.0). Stdlib + nexi_methodology only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from audit_bundle.output_modes.mode import ModeSignal, OutputMode
from audit_bundle.retrieval.three_set import ThreeSetView

if TYPE_CHECKING:
    # Type-only import: resolves the FailureModeTaxonomy annotations for static
    # analysis without requiring the optional package at runtime (it is loaded
    # lazily via _load_failure_modes()). Under `from __future__ import
    # annotations` these annotations are never evaluated at runtime.
    from nexi_methodology.failure_modes import FailureModeTaxonomy


def _load_failure_modes():
    """Lazily import the optional ``nexi_methodology`` failure-mode API.

    ES post-processing needs it, but importing this module (and the rest of
    ``audit_bundle.output_modes`` / the core verifier) must NOT require it — it
    is an OPTIONAL dependency: the separate (currently source-only)
    ``nexi-methodology`` package. Deferring the import keeps the open verifier
    importable without that package present.
    """
    try:
        from nexi_methodology.failure_modes import FailureModeTaxonomy, lint_text
    except ModuleNotFoundError as exc:  # pragma: no cover - needs nexi-methodology
        raise RuntimeError(
            "ESPipeline requires the optional 'nexi-methodology' package "
            "(install it from source until it is published). It is not needed to "
            "import audit_bundle or run the core verifier."
        ) from exc
    return FailureModeTaxonomy, lint_text


class ESPipeline:
    """Exploratory Synthesis mode post-processor with failure-mode lint rails.

    Parameters
    ----------
    taxonomy:
        FailureModeTaxonomy to lint against. When None, an empty taxonomy is used
        (no lint hits possible — wire in the failure_modes.yaml at
        integration time via ``load_taxonomy(path)`` and pass the result here).
    rails_active:
        Tuple of failure-mode IDs actively monitored at runtime. Defaults to all
        mode IDs in the taxonomy (sorted). Must be non-empty to call emit_signal().
    """

    def __init__(
        self,
        taxonomy: FailureModeTaxonomy | None = None,
        rails_active: tuple[str, ...] | None = None,
    ) -> None:
        # PRD calls for load_taxonomy() (no-arg) against a bundled B.3 taxonomy;
        # nexi_methodology v0.1 requires an explicit yaml_path argument. Default to
        # an empty taxonomy until the bundled YAML is wired in at integration time.
        FailureModeTaxonomy, _ = _load_failure_modes()
        self.taxonomy: FailureModeTaxonomy = taxonomy or FailureModeTaxonomy(
            version="0.0-empty", modes=[], candidates=[]
        )
        self.rails_active: tuple[str, ...] = rails_active or tuple(
            sorted(fm.id for fm in self.taxonomy.modes)
        )

    def post_process(self, raw_output: str, three_set: ThreeSetView) -> str:
        """Lint raw_output and hard-label any unsupported failure-mode references.

        ES-mode does not promise quote-support (unlike VE-mode). The lint context
        acknowledges this: ``three_set.context_injected`` records which sources were
        available to the model, but unsupported synthesis across those sources is
        permitted and labeled rather than suppressed. ES-mode CAN still flag specific
        failure modes — hedge-out, fabrication, sycophancy, etc. — that appear as
        explicit Mode-N / Candidate-N citations in the output prose.

        For each body-text lint hit (an unknown failure-mode ID reference), the
        offending span is wrapped with:
            ``[unsupported: <failure_mode_id>] <failure_mode_id>``

        Front-matter hits (unknown IDs in ``failure_modes_cited`` /
        ``failure_modes_observed`` fields) are not modified — front-matter is
        metadata, not output prose.

        Parameters
        ----------
        raw_output:
            Raw output text to post-process.
        three_set:
            Three-set view for this output. ``context_injected`` is used as lint
            context: ES bundles do not promise quote-support, but the injected
            source set is available for attribution purposes.
        """
        # three_set.context_injected informs the lint context: ES-mode does not
        # promise quote-supported output, but failure modes can still be cited and
        # must reference valid taxonomy IDs.
        _ = three_set.context_injected  # lint context acknowledgment (ES ≠ VE)

        _, lint_text = _load_failure_modes()
        errors = lint_text(raw_output, self.taxonomy)
        if not errors:
            return raw_output

        lines = raw_output.splitlines(keepends=True)
        for error in errors:
            # Apply unsupported marker only to body-text hits (line_number present,
            # no front-matter field). Replace first occurrence per line to avoid
            # double-labeling if the same ID appears multiple times.
            if error.line_number is not None and error.field is None:
                idx = error.line_number - 1
                if 0 <= idx < len(lines):
                    cited = error.cited_id
                    lines[idx] = lines[idx].replace(
                        cited, f"[unsupported: {cited}] {cited}", 1
                    )

        return "".join(lines)

    def emit_signal(self) -> ModeSignal:
        """Return a ModeSignal locking this output as ES-mode with active rails.

        Raises
        ------
        ModeMisconfiguration
            If ``self.rails_active`` is empty. ModeSignal invariant: ES-mode
            requires at least one active rail. Wire in a non-empty taxonomy first.
        """
        return ModeSignal(mode=OutputMode.ES, rails_active=self.rails_active)
