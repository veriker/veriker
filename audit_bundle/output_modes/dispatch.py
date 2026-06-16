"""audit_bundle/output_modes/dispatch.py — two-pipeline UX dispatcher.

Routes output through VEPipeline or ESPipeline based on the requested OutputMode.

K1 lock (SCOPING.md §Output mode policy): MIXED MODE IS FORBIDDEN.  The
dispatcher does NOT allow per-segment mode selection within a single output.
The caller decides which mode based on user authentication context; this
module only enforces the routing, not the authentication gate.

Default user posture (policy_default_mode_for):
  - VE for new / unauthenticated users.
  - VE for authenticated users without explicit ES opt-in.
  - ES only on authenticated + explicit opt-in.
"""

from __future__ import annotations

from typing import Callable

from audit_bundle.output_modes.mode import ModeSignal, OutputMode
from audit_bundle.output_modes.ve_pipeline import VEPipeline
from audit_bundle.output_modes.es_pipeline import ESPipeline
from audit_bundle.retrieval.three_set import ThreeSetView


class ModeDispatcher:
    """Routes raw output through the correct pipeline (VE or ES).

    Parameters
    ----------
    ve_pipeline:
        VEPipeline instance to use. Defaults to a freshly constructed one.
    es_pipeline:
        ESPipeline instance to use. Defaults to a freshly constructed one.
    """

    def __init__(
        self,
        ve_pipeline: VEPipeline | None = None,
        es_pipeline: ESPipeline | None = None,
    ) -> None:
        self.ve: VEPipeline = ve_pipeline or VEPipeline()
        self.es: ESPipeline = es_pipeline or ESPipeline()

    def dispatch(
        self,
        mode: OutputMode,
        raw_output: str,
        three_set: ThreeSetView,
        source_text_lookup: Callable[[str], str] | None = None,
    ) -> tuple[str, ModeSignal]:
        """Route raw_output through the appropriate pipeline and return results.

        MIXED MODE IS FORBIDDEN: the dispatcher does not allow per-segment
        mode selection within a single output (K1 lock).

        Parameters
        ----------
        mode:
            The OutputMode to apply (VE or ES).
        raw_output:
            Raw model output to post-process.
        three_set:
            ThreeSetView for this output; drives suppression (VE) or lint
            context (ES).
        source_text_lookup:
            Optional callable from source_cid → source text.  Required by
            VEPipeline subclasses that perform additional verification;
            the base VEPipeline does not invoke it, so None is safe for the
            canary / default case.

        Returns
        -------
        tuple[str, ModeSignal]
            (post_processed_output, mode_signal) — the processed text and the
            ModeSignal that locks this output's mode into the bundle manifest.
        """
        if mode is OutputMode.VE:
            lookup: Callable[[str], str] = source_text_lookup or (lambda _cid: "")
            processed = self.ve.post_process(raw_output, three_set, lookup)
            signal = self.ve.emit_signal()
            return processed, signal

        if mode is OutputMode.ES:
            processed = self.es.post_process(raw_output, three_set)
            signal = self.es.emit_signal()
            return processed, signal

        # Unreachable for valid OutputMode values; guards against future enum
        # extensions before the dispatcher is updated.
        raise ValueError(f"Unhandled OutputMode: {mode!r}")  # pragma: no cover


def policy_default_mode_for(
    user_authenticated: bool,
    explicit_opt_in_to_es: bool,
) -> OutputMode:
    """Encode the K1 default-VE / explicit-opt-in-ES rule.

    Decision table
    --------------
    authenticated=False, opt_in=*    → VE  (unauthenticated always get VE)
    authenticated=True,  opt_in=False → VE  (authenticated default is still VE)
    authenticated=True,  opt_in=True  → ES  (only valid ES path)

    Parameters
    ----------
    user_authenticated:
        Whether the requesting user has been authenticated.
    explicit_opt_in_to_es:
        Whether the user has explicitly opted in to Exploratory Synthesis mode.

    Returns
    -------
    OutputMode
        The mode to apply for this request.
    """
    if user_authenticated and explicit_opt_in_to_es:
        return OutputMode.ES
    return OutputMode.VE
