#!/usr/bin/env python3
"""healthcare_diagnosis_pack.py — stdlib re-derivation pack for healthcare diagnosis domain.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don't-import):
no audit_bundle imports inside this script. Stdlib only.

Re-derivation steps:
  1. Load inputs/symptoms.json   — list of {symptom_id, name, severity}
  2. Load inputs/rules.json      — list of {rule_id, icd10_code, conditions[],
                                    confidence_weight, description}
  3. Load payload/diagnosis.json — list of {icd10_code, description, confidence,
                                    matched_symptom_ids, rule_id, rule_path}
  4. Re-traverse the decision tree using the same deterministic rule engine
     used at build time:
       for each rule (sorted by rule_id):
         for each condition: symptom must exist and severity >= min_severity
         if all conditions match: confidence = sum(severity[matched_ids]) * weight
     Round confidence to 6 decimal places.
  5. Compare the re-derived candidate list to payload/diagnosis.json:
       - same number of candidates (count, order)
       - per-candidate: icd10_code, description, rule_id all equal
       - per-candidate: confidence equal to 6 decimal places
       - per-candidate: matched_symptom_ids set-equal
       - per-candidate: rule_path equal
  6. Exit 0 on full match; exit 1 with [HCD_REDER_FAIL] <description> on stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _fail(msg: str) -> int:
    print(f"[HCD_REDER_FAIL] {msg}", file=sys.stderr)
    return 1


def _eval_condition(symptom_map, cond) -> bool:
    s = symptom_map.get(cond["symptom_id"])
    if s is None:
        return False
    return int(s["severity"]) >= int(cond["min_severity"])


def _derive_candidates(symptoms, rules):
    symptom_map = {s["symptom_id"]: s for s in symptoms}
    out = []
    for rule in sorted(rules, key=lambda r: r["rule_id"]):
        matched = []
        fired = True
        for cond in rule["conditions"]:
            if _eval_condition(symptom_map, cond):
                matched.append(cond["symptom_id"])
            else:
                fired = False
                break
        if not fired:
            continue
        severity_sum = sum(int(symptom_map[sid]["severity"]) for sid in matched)
        confidence = round(severity_sum * float(rule["confidence_weight"]), 6)
        rule_path = {
            "rule_id": rule["rule_id"],
            "conditions_visited": [
                {"symptom_id": c["symptom_id"], "min_severity": c["min_severity"]}
                for c in rule["conditions"]
            ],
        }
        out.append(
            {
                "icd10_code": rule["icd10_code"],
                "description": rule["description"],
                "confidence": confidence,
                "matched_symptom_ids": matched,
                "rule_id": rule["rule_id"],
                "rule_path": rule_path,
            }
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Healthcare-diagnosis ICD-10 re-derivation check"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    symptoms_path = bundle_dir / "inputs" / "symptoms.json"
    rules_path = bundle_dir / "inputs" / "rules.json"
    diagnosis_path = bundle_dir / "payload" / "diagnosis.json"
    for p in (symptoms_path, rules_path, diagnosis_path):
        if not p.exists():
            return _fail(f"required file missing: {p}")

    try:
        symptoms = json.loads(symptoms_path.read_text(encoding="utf-8"))
        rules = json.loads(rules_path.read_text(encoding="utf-8"))
        bundled = json.loads(diagnosis_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to load bundle inputs/payload: {exc}")

    if not isinstance(symptoms, list) or not isinstance(rules, list) or not isinstance(bundled, list):
        return _fail("symptoms.json, rules.json, diagnosis.json must each be JSON arrays")

    recomputed = _derive_candidates(symptoms, rules)

    if len(recomputed) != len(bundled):
        return _fail(
            f"candidate count mismatch: recomputed={len(recomputed)} bundled={len(bundled)}"
        )

    for i, (rec, exp) in enumerate(zip(recomputed, bundled)):
        for field in ("icd10_code", "description", "rule_id"):
            if rec[field] != exp.get(field):
                return _fail(
                    f"candidate[{i}] {field} mismatch: "
                    f"recomputed={rec[field]!r} bundled={exp.get(field)!r}"
                )
        rec_conf = round(float(rec["confidence"]), 6)
        exp_conf = round(float(exp.get("confidence", 0.0)), 6)
        if rec_conf != exp_conf:
            return _fail(
                f"candidate[{i}] confidence mismatch for {rec['icd10_code']!r}: "
                f"recomputed={rec_conf} bundled={exp_conf}"
            )
        if sorted(rec["matched_symptom_ids"]) != sorted(exp.get("matched_symptom_ids", [])):
            return _fail(
                f"candidate[{i}] matched_symptom_ids mismatch for {rec['icd10_code']!r}: "
                f"recomputed={rec['matched_symptom_ids']!r} "
                f"bundled={exp.get('matched_symptom_ids')!r}"
            )
        if rec["rule_path"] != exp.get("rule_path"):
            return _fail(
                f"candidate[{i}] rule_path mismatch for {rec['icd10_code']!r}: "
                f"recomputed={rec['rule_path']!r} bundled={exp.get('rule_path')!r}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
