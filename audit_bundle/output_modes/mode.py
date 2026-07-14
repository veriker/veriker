"""audit_bundle/output_modes/mode.py — OutputMode enum + canonical encoding.

ModeSignal is the signed record that travels inside each bundle manifest,
locking the VE/ES choice and its active constraints at output-freeze time.
"""

import dataclasses
import enum


class OutputMode(str, enum.Enum):
    VE = 'verified_extractive'
    ES = 'exploratory_synthesis'


class BadOutputMode(ValueError):
    """Missing required field or unknown OutputMode value in a mode dict."""


class ModeMisconfiguration(ValueError):
    """ModeSignal is internally inconsistent (missing required constraints/rails)."""


@dataclasses.dataclass(frozen=True)
class ModeSignal:
    mode: OutputMode
    policy_version: str = '0.1'
    rails_active: tuple[str, ...] = ()
    generation_constraints: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode is OutputMode.VE and not self.generation_constraints:
            raise ModeMisconfiguration(
                "VE-mode ModeSignal requires non-empty generation_constraints"
            )
        if self.mode is OutputMode.ES and not self.rails_active:
            raise ModeMisconfiguration(
                "ES-mode ModeSignal requires non-empty rails_active"
            )


def mode_to_canonical_dict(signal: ModeSignal) -> dict:
    """Return a JCS-canonicalizable dict for the given ModeSignal.

    Keys are in lexicographic order; list values are sorted so the
    byte representation is deterministic regardless of insertion order.
    """
    return {
        'generation_constraints': sorted(signal.generation_constraints),
        'mode': signal.mode.value,
        'policy_version': signal.policy_version,
        'rails_active': sorted(signal.rails_active),
    }


def mode_from_dict(d: dict) -> ModeSignal:
    """Reconstruct a ModeSignal from a canonical dict (round-trip).

    Raises
    ------
    BadOutputMode
        If 'mode' or 'policy_version' are absent, or the mode value is unknown.
    ModeMisconfiguration
        If the reconstructed signal violates VE/ES invariants.
    """
    if 'mode' not in d:
        raise BadOutputMode("missing required field: 'mode'")
    if 'policy_version' not in d:
        raise BadOutputMode("missing required field: 'policy_version'")
    try:
        mode = OutputMode(d['mode'])
    except ValueError:
        raise BadOutputMode(f"unknown OutputMode value: {d['mode']!r}")

    rails_active = tuple(sorted(d.get('rails_active', ())))
    generation_constraints = tuple(sorted(d.get('generation_constraints', ())))

    return ModeSignal(
        mode=mode,
        policy_version=d['policy_version'],
        rails_active=rails_active,
        generation_constraints=generation_constraints,
    )
