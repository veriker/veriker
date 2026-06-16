"""audit_bundle/output_modes — Output post-processor + VE/ES modes.

Implements the audit-bundle contract's output post-processor (VE/ES modes,
Option B).

Output mode policy (Option B): Two explicit output modes, never visually mixed.
- Verified Extractive (VE): quote-supported content only; default for new/unauthenticated.
- Exploratory Synthesis (ES): freeform with hard-labeled unsupported sections; explicit opt-in.

Mode is canonicalized into the bundle bytes (cross-product extension to v-kernel/bundle/schema.py).
Two-pipeline UX: mode toggle visually unmistakable (first-class output dimension, not settings checkbox).

Public API (re-exported once sibling modules land):
- OutputMode — enum of available output modes (VE, ES)
- ModeDispatcher — router between VE and ES pipelines per mode selection
- VEPipeline — Verified Extractive mode processor (quote-supported only)
- ESPipeline — Exploratory Synthesis mode processor (freeform + hard-labels)
- mode_to_canonical_dict — convert OutputMode to canonical dict for bundle signing

See README.md for scope and design rationale.
"""

from enum import Enum

__all__ = [
    "OutputMode",
    "ModeDispatcher",
    "VEPipeline",
    "ESPipeline",
    "mode_to_canonical_dict",
]


class OutputMode(str, Enum):
    """Available output modes per SCOPING.md §Output mode policy Option B."""

    VE = "verified_extractive"
    ES = "exploratory_synthesis"

    def __str__(self) -> str:
        return self.value


def mode_to_canonical_dict(mode: OutputMode) -> dict:
    """Convert OutputMode to canonical dict for bundle signing.

    The output mode is signed as part of the bundle manifest,
    making it immutable after output freeze.

    Parameters
    ----------
    mode
        The OutputMode (VE or ES).

    Returns
    -------
    dict
        Canonical representation: {"mode": "<mode_value>", "canonical_name": "<friendly_name>"}
    """
    canonical_names = {
        OutputMode.VE: "Verified Extractive",
        OutputMode.ES: "Exploratory Synthesis",
    }
    return {
        "mode": mode.value,
        "canonical_name": canonical_names[mode],
    }


class ModeDispatcher:
    """Router between VE and ES pipelines per mode selection.

    Dispatches output through the appropriate post-processor based on
    the selected OutputMode. Not instantiated; use class methods directly.
    """

    pass


class VEPipeline:
    """Verified Extractive mode processor.

    Constraints:
    - Output is constrained to quote-supported content.
    - No unsupported synthesis allowed.
    - Default mode for new/unauthenticated users.

    See SCOPING.md §Output mode policy + §Implementation implications.
    """

    pass


class ESPipeline:
    """Exploratory Synthesis mode processor.

    Constraints:
    - Freeform synthesis allowed.
    - Hard-labeled unsupported sections required.
    - Explicit opt-in by user; never default.

    See SCOPING.md §Output mode policy + §Implementation implications.
    """

    pass
