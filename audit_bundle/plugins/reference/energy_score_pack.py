#!/usr/bin/env python3
"""
energy_score_pack.py — Best-effort Energy Score re-derivation from a wearable
device's sensor traces (ring + smartwatch + phone fusion log).

Energy Score algorithm is proprietary; this pack uses a published-spec
approximation. Do not claim parity with the vendor's actual numbers.

Derived from: a wearable vendor's Health API public documentation (v2.1).
Methodology spec: methodology/ENERGY_SCORE_SPEC.md (SHA-stamped at bundle creation).

Usage:
    python energy_score_pack.py --bundle-dir <path>

Reads from <bundle-dir>:
    raw_traces/ring_*.jsonl
    raw_traces/watch_*.jsonl
    raw_traces/phone_fusion_log_*.jsonl

Outputs computed result as JSON to stdout (includes derived_from_public_docs: true).

If derived/energy_score.json exists, compares value_float within tolerance 1e-3.
  Exit 0 → match
  Exit 1 → mismatch or withheld
  Exit 2 → reference file missing or malformed
"""

import argparse
import json
import math
import pathlib
import sys

# ──────────────────────────────────────────────────────────────────────────────
# Constants — per ENERGY_SCORE_SPEC.md §Step 1 normalisation bounds
# ──────────────────────────────────────────────────────────────────────────────

TOLERANCE = 1e-3
DERIVED_FROM_PUBLIC_DOCS = True

HR_MIN, HR_MAX = 40.0, 120.0          # bpm
HRV_MIN, HRV_MAX = 20.0, 200.0        # RMSSD ms
DEEP_FRAC_MAX = 0.35                   # fraction of total sleep
REM_FRAC_MAX = 0.25
SLEEP_WINDOW_MAX_MIN = 600.0           # 10-hour normalisation cap
ACTIVITY_KCAL_MAX = 1200.0             # kcal / 24 h
STEP_MAX = 20000.0                     # daily step normalisation cap

# Sleep stage heuristic: minutes below this HR percentile = "deep"
_DEEP_PERCENTILE = 0.20
# Minutes at or above this HR percentile = "REM proxy"
_REM_PERCENTILE = 0.80

# Respiratory rate proxy range derived from Watch BIA quality score
_RESP_RATE_LO, _RESP_RATE_HI = 12.0, 20.0   # resp/min

# Assumed sleep-onset latency (synthesized data has no explicit sleep-onset ts)
_DEFAULT_LATENCY_MIN = 15.0

# kcal per step approximation (walking, published dietary guidelines)
_KCAL_PER_STEP = 0.05

# Ring off-finger fraction threshold beyond which score is withheld
_UNWORN_THRESHOLD = 0.30


# ──────────────────────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────────────────────

def _clip(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def _norm(v: float, lo: float, hi: float) -> float:
    return _clip((v - lo) / (hi - lo), 0.0, 1.0)


def _mean(xs: list) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _rmssd_from_hr_per_second(hr_samples: list) -> float:
    """Approximate RMSSD (ms) from per-second HR via RR-interval proxy.

    RR_i = 60000 / hr_bpm_i.  RMSSD = sqrt(mean(delta_RR^2)).
    This is a coarser proxy than true beat-to-beat RMSSD but uses only the
    available per-second data (no raw ECG).
    """
    rr = [60000.0 / h for h in hr_samples if h and h > 0]
    if len(rr) < 2:
        return 0.0
    sq = [(rr[i + 1] - rr[i]) ** 2 for i in range(len(rr) - 1)]
    return math.sqrt(sum(sq) / len(sq))


def _load_jsonl(path: pathlib.Path) -> list:
    return _admitted_jsonl(path)


# ---------------------------------------------------------------------------
# Admission-bounded JSON loading — duplicated, not imported (this file is a
# stdlib-only / standalone reference verifier; see module docstring). Mirrors
# audit_bundle.admission's discipline (RES-02, 2026-06-11): size-reject BEFORE
# allocation, bracket-depth scan BEFORE json.loads so a hostile depth bomb is
# a clean ValueError, never a RecursionError out of the parser.
# ---------------------------------------------------------------------------

_ADMIT_MAX_BYTES = 16 * 1024 * 1024
_ADMIT_MAX_DEPTH = 64


def _admit_depth_scan(raw, name):
    """Reject (ValueError) if raw's bracket/brace nesting outside JSON string
    literals exceeds _ADMIT_MAX_DEPTH — a structural upper bound on the
    recursion json.loads would perform."""
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # closing quote
                in_string = False
            continue
        if byte == 0x22:  # opening quote
            in_string = True
        elif byte in b"[{":
            depth += 1
            if depth > _ADMIT_MAX_DEPTH:
                raise ValueError(
                    f"{name}: JSON nesting exceeds max depth {_ADMIT_MAX_DEPTH}"
                )
        elif byte in b"]}":
            if depth > 0:
                depth -= 1


def _admitted_json(path):
    """Size- and depth-bounded replacement for json.loads(path.read_text())."""
    size = path.stat().st_size
    if size > _ADMIT_MAX_BYTES:
        raise ValueError(f"{path.name}: {size} bytes exceeds max {_ADMIT_MAX_BYTES}")
    raw = path.read_bytes()
    _admit_depth_scan(raw, path.name)
    return json.loads(raw)


def _admitted_jsonl(path):
    """Size- and per-line-depth-bounded replacement for a raw JSONL read."""
    size = path.stat().st_size
    if size > _ADMIT_MAX_BYTES:
        raise ValueError(f"{path.name}: {size} bytes exceeds max {_ADMIT_MAX_BYTES}")
    rows = []
    with open(path, "rb") as fh:
        for line in fh:
            s = line.strip()
            if not s:
                continue
            _admit_depth_scan(s, path.name)
            rows.append(json.loads(s))
    return rows



# ──────────────────────────────────────────────────────────────────────────────
# Core computation
# ──────────────────────────────────────────────────────────────────────────────

def compute(bundle_dir: pathlib.Path) -> dict:
    """Return the energy-score result dict (always includes derived_from_public_docs)."""
    raw = bundle_dir / "raw_traces"

    ring_files = sorted(raw.glob("ring_*.jsonl"))
    watch_files = sorted(raw.glob("watch_*.jsonl"))
    fusion_files = sorted(raw.glob("phone_fusion_log_*.jsonl"))

    if not ring_files or not watch_files or not fusion_files:
        raise FileNotFoundError(f"Expected ring/watch/fusion_log JSONL under {raw}")

    ring_rows = _load_jsonl(ring_files[0])
    watch_rows = _load_jsonl(watch_files[0])
    fusion_rows = _load_jsonl(fusion_files[0])

    # ── Worn-fraction gate ────────────────────────────────────────────────────
    total_s = len(ring_rows)
    off_s = sum(1 for r in ring_rows if not r.get("on_finger"))
    off_frac = off_s / total_s if total_s else 1.0

    if off_frac > _UNWORN_THRESHOLD:
        return {
            "derived_from_public_docs": DERIVED_FROM_PUBLIC_DOCS,
            "row_id": "energy_score_withheld",
            "value": None,
            "value_float": None,
            "withheld_reason": "device_unworn",
            "off_finger_fraction": round(off_frac, 6),
        }

    # ── Fused per-minute HR (ring primary → watch fallback) ──────────────────
    fused_hr: list[float] = []
    for fr in fusion_rows:
        fi = fr["fusion_inputs"]
        if fi.get("ring_available") and fi.get("hr_bpm_ring") is not None:
            fused_hr.append(float(fi["hr_bpm_ring"]))
        elif fi.get("hr_bpm_watch") is not None:
            fused_hr.append(float(fi["hr_bpm_watch"]))

    mean_hr = _mean(fused_hr)
    hr_norm = _norm(mean_hr, HR_MIN, HR_MAX)

    # ── HRV: RMSSD from per-second on-finger ring HR ─────────────────────────
    ring_hr_on = [
        float(r["hr_bpm"])
        for r in ring_rows
        if r.get("on_finger") and r.get("hr_bpm") is not None
    ]
    hrv_ms = _rmssd_from_hr_per_second(ring_hr_on)
    hrv_norm = _norm(hrv_ms, HRV_MIN, HRV_MAX)

    # ── Respiratory rate proxy from Watch BIA quality ────────────────────────
    # BIA quality 0-100 maps to resp_rate 12-20 resp/min (heuristic from
    # the vendor's wrist-PPG respiratory-inference research).
    watch_bia = [float(r["bia_quality"]) for r in watch_rows if r.get("bia_quality") is not None]
    mean_bia = _mean(watch_bia)
    resp_rate = _RESP_RATE_LO + (mean_bia / 100.0) * (_RESP_RATE_HI - _RESP_RATE_LO)
    resp_norm = _norm(resp_rate, _RESP_RATE_LO, _RESP_RATE_HI)

    # ── Sleep stage heuristics from per-minute fused HR ──────────────────────
    window_min = len(fusion_rows)
    if fused_hr:
        sh = sorted(fused_hr)
        n = len(sh)
        deep_thresh = sh[int(n * _DEEP_PERCENTILE)]
        rem_thresh = sh[int(n * _REM_PERCENTILE)]
        deep_min = sum(1 for h in fused_hr if h <= deep_thresh)
        rem_min = sum(1 for h in fused_hr if h >= rem_thresh)
    else:
        deep_min = rem_min = 0

    deep_frac = deep_min / window_min if window_min else 0.0
    rem_frac = rem_min / window_min if window_min else 0.0
    deep_norm = _norm(deep_frac, 0.0, DEEP_FRAC_MAX)
    rem_norm = _norm(rem_frac, 0.0, REM_FRAC_MAX)
    dur_norm = _clip(window_min / SLEEP_WINDOW_MAX_MIN, 0.0, 1.0)
    latency_norm = _clip(1.0 - (_DEFAULT_LATENCY_MIN / 60.0), 0.0, 1.0)

    # ── Activity from phone fusion log ────────────────────────────────────────
    total_steps = sum(fr["energy_score_step"]["step_count"] for fr in fusion_rows)
    kcal = total_steps * _KCAL_PER_STEP
    kcal_norm = _norm(kcal, 0.0, ACTIVITY_KCAL_MAX)
    step_norm = _norm(float(total_steps), 0.0, STEP_MAX)

    # ── Sub-scores per ENERGY_SCORE_SPEC.md ──────────────────────────────────
    sleep_quality = (
        0.4 * deep_norm
        + 0.3 * rem_norm
        + 0.2 * dur_norm
        + 0.1 * latency_norm
    )
    cardio_score = (
        0.5 * (1.0 - hr_norm)
        + 0.3 * hrv_norm
        + 0.2 * resp_norm
    )
    activity_score = 0.6 * kcal_norm + 0.4 * step_norm

    raw_score = (
        0.4 * sleep_quality
        + 0.35 * cardio_score
        + 0.25 * activity_score
    )

    value_float = _clip(raw_score * 100.0, 0.0, 100.0)
    value_int = round(value_float)

    return {
        "derived_from_public_docs": DERIVED_FROM_PUBLIC_DOCS,
        "row_id": "energy_score_2026_04_29",
        "value": value_int,
        "value_float": round(value_float, 6),
        "withheld_reason": None,
        "off_finger_fraction": round(off_frac, 6),
        "components": {
            "mean_hr_bpm": round(mean_hr, 4),
            "hr_norm": round(hr_norm, 6),
            "hrv_rmssd_ms": round(hrv_ms, 4),
            "hrv_norm": round(hrv_norm, 6),
            "resp_rate_bpm": round(resp_rate, 4),
            "resp_norm": round(resp_norm, 6),
            "deep_frac": round(deep_frac, 6),
            "deep_norm": round(deep_norm, 6),
            "rem_frac": round(rem_frac, 6),
            "rem_norm": round(rem_norm, 6),
            "sleep_dur_norm": round(dur_norm, 6),
            "sleep_latency_norm": round(latency_norm, 6),
            "sleep_quality": round(sleep_quality, 6),
            "total_steps": total_steps,
            "activity_kcal": round(kcal, 4),
            "kcal_norm": round(kcal_norm, 6),
            "step_norm": round(step_norm, 6),
            "cardio_score": round(cardio_score, 6),
            "activity_score": round(activity_score, 6),
            "raw_score": round(raw_score, 6),
        },
    }


# ──────────────────────────────────────────────────────────────────────────────
# Comparison
# ──────────────────────────────────────────────────────────────────────────────

def compare(result: dict, ref_path: pathlib.Path) -> int:
    """Return 0 on match within TOLERANCE, 1 on mismatch, 2 on ref error."""
    if result.get("value_float") is None:
        print("[energy_score_pack] score withheld — cannot compare", file=sys.stderr)
        return 1

    if not ref_path.exists():
        print(f"[energy_score_pack] reference not found: {ref_path}", file=sys.stderr)
        return 2

    try:
        with open(ref_path, encoding="utf-8") as fh:
            ref = json.load(fh)
    except Exception as exc:
        print(f"[energy_score_pack] reference parse error: {exc}", file=sys.stderr)
        return 2

    ref_float = ref.get("value_float")
    if ref_float is None:
        print("[energy_score_pack] reference missing value_float", file=sys.stderr)
        return 2

    computed = result["value_float"]
    diff = abs(computed - ref_float)
    if diff <= TOLERANCE:
        print(
            f"[energy_score_pack] MATCH  computed={computed:.6f} ref={ref_float:.6f}"
            f" |diff|={diff:.2e} <= {TOLERANCE:.0e}",
            file=sys.stderr,
        )
        return 0
    else:
        print(
            f"[energy_score_pack] MISMATCH computed={computed:.6f} ref={ref_float:.6f}"
            f" |diff|={diff:.2e} > {TOLERANCE:.0e}",
            file=sys.stderr,
        )
        return 1


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Energy Score re-derivation pack (best-effort approximation from public docs)"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        help="Path to the mesh pilot bundle directory",
    )
    args = parser.parse_args()

    bundle_dir = pathlib.Path(args.bundle_dir).resolve()

    try:
        result = compute(bundle_dir)
    except FileNotFoundError as exc:
        print(json.dumps({"error": str(exc), "derived_from_public_docs": DERIVED_FROM_PUBLIC_DOCS}))
        sys.exit(2)

    print(json.dumps(result, indent=2))

    ref_path = bundle_dir / "derived" / "energy_score.json"
    code = compare(result, ref_path)
    sys.exit(code)


if __name__ == "__main__":
    main()
