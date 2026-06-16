"""Per-plugin happy-path and tamper tests for all 5 reference TypedCheck plugins.

Each plugin class gets its own test class with:
  - A happy-path synthetic bundle asserting ok=True with expected reason_code
  - Tampered variants asserting ok=False with the EXPECTED reason_code
  - Edge-case and boundary tests

All tests use tmp_path. Stdlib only — no live network, no live git.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


from audit_bundle.plugins.falsification_negative_test import (
    FalsificationNegativeTestCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.monotone_growth import MonotoneGrowthCheck
from audit_bundle.plugins.re_derivation_invocation import ReDerivationInvocationCheck
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Manifest:
    """Minimal manifest stub; only carries fields plugins actually read.

    Carries ``snapshots`` and ``append_only_files`` too: file_integrity_many_
    small's Pass-3 sweep now derives surplus-membership from the integrity-
    ownership map (classify_path), which reads ``snapshots`` directly and
    ``append_only_files`` via getattr — mirroring the real BundleManifest,
    whose every instance has these fields.
    """

    def __init__(
        self,
        files=None,
        spec_files=None,
        typed_checks=None,
        snapshots=None,
        append_only_files=(),
    ):
        self.files = files or {}
        self.spec_files = spec_files or {}
        self.typed_checks = typed_checks or []
        self.snapshots = snapshots or {}
        self.append_only_files = append_only_files


def _write_jsonl(path: Path, case_ids: list[str]) -> None:
    """Write a corpus.jsonl file with the given case IDs (one JSON object per line)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = "\n".join(json.dumps({"id": cid}) for cid in case_ids)
    path.write_text(lines + "\n" if lines else "", encoding="utf-8")


# ============================================================================
# SpecShaPinCheck
# ============================================================================


class TestSpecShaPinCheck:
    """Tests for audit_bundle/plugins/spec_sha_pin.py."""

    _PLUGIN = SpecShaPinCheck

    def _setup_spec(
        self,
        bundle_dir: Path,
        filename: str,
        content: bytes,
        manifest_sha: str | None = None,
    ) -> _Manifest:
        """Write spec/<filename> with content; return manifest using actual or overridden SHA."""
        spec_dir = bundle_dir / "spec"
        spec_dir.mkdir(exist_ok=True)
        (spec_dir / filename).write_bytes(content)
        sha = manifest_sha if manifest_sha is not None else _sha256(content)
        return _Manifest(spec_files={filename: sha})

    # -----------------------------------------------------------------------
    # Happy path
    # -----------------------------------------------------------------------

    def test_matching_spec_returns_pass(self, tmp_path: Path) -> None:
        manifest = self._setup_spec(tmp_path, "example.md", b"the spec body")
        result = self._PLUGIN().check(tmp_path, manifest)
        assert result.ok is True
        assert result.reason_code == "PASS"

    def test_empty_spec_files_returns_pass(self, tmp_path: Path) -> None:
        result = self._PLUGIN().check(tmp_path, _Manifest(spec_files={}))
        assert result.ok is True
        assert result.reason_code == "PASS"

    def test_pass_files_audited_contains_spec_path(self, tmp_path: Path) -> None:
        manifest = self._setup_spec(tmp_path, "spec.md", b"content")
        result = self._PLUGIN().check(tmp_path, manifest)
        assert any("spec.md" in f for f in result.files_audited)

    def test_multiple_specs_all_matching(self, tmp_path: Path) -> None:
        (tmp_path / "spec").mkdir()
        files = {"a.md": b"content-a", "b.md": b"content-b", "c.md": b"content-c"}
        for name, content in files.items():
            (tmp_path / "spec" / name).write_bytes(content)
        manifest = _Manifest(spec_files={n: _sha256(c) for n, c in files.items()})
        result = self._PLUGIN().check(tmp_path, manifest)
        assert result.ok is True
        assert result.reason_code == "PASS"

    # -----------------------------------------------------------------------
    # Tampered: SHA mismatch
    # -----------------------------------------------------------------------

    def test_sha_mismatch_returns_spec_sha_mismatch(self, tmp_path: Path) -> None:
        manifest = self._setup_spec(tmp_path, "doc.md", b"real content", "dead" * 16)
        result = self._PLUGIN().check(tmp_path, manifest)
        assert result.ok is False
        assert result.reason_code == "SPEC_SHA_MISMATCH"

    def test_sha_mismatch_detail_names_spec_file(self, tmp_path: Path) -> None:
        manifest = self._setup_spec(tmp_path, "important.md", b"real", "dead" * 16)
        result = self._PLUGIN().check(tmp_path, manifest)
        assert "important.md" in result.detail

    # -----------------------------------------------------------------------
    # Tampered: missing file
    # -----------------------------------------------------------------------

    def test_missing_spec_file_returns_spec_sha_mismatch(self, tmp_path: Path) -> None:
        (tmp_path / "spec").mkdir()
        manifest = _Manifest(spec_files={"ghost.md": "a" * 64})
        result = self._PLUGIN().check(tmp_path, manifest)
        assert result.ok is False
        assert result.reason_code == "SPEC_SHA_MISMATCH"

    def test_missing_spec_file_detail_names_file(self, tmp_path: Path) -> None:
        (tmp_path / "spec").mkdir()
        manifest = _Manifest(spec_files={"ghost.md": "a" * 64})
        result = self._PLUGIN().check(tmp_path, manifest)
        assert "ghost.md" in result.detail

    # -----------------------------------------------------------------------
    # Tampered: multiple specs — one mismatch causes failure
    # -----------------------------------------------------------------------

    def test_one_mismatch_among_many_returns_fail(self, tmp_path: Path) -> None:
        (tmp_path / "spec").mkdir()
        (tmp_path / "spec" / "good.md").write_bytes(b"good")
        (tmp_path / "spec" / "bad.md").write_bytes(b"content-b")
        manifest = _Manifest(
            spec_files={
                "good.md": _sha256(b"good"),
                "bad.md": "wrong" + "0" * 59,  # 64 chars total, wrong SHA
            }
        )
        result = self._PLUGIN().check(tmp_path, manifest)
        assert result.ok is False
        assert result.reason_code == "SPEC_SHA_MISMATCH"

    # -----------------------------------------------------------------------
    # Edge: hash comparison is case-insensitive
    # -----------------------------------------------------------------------

    def test_uppercase_sha_in_manifest_is_accepted(self, tmp_path: Path) -> None:
        content = b"spec body"
        (tmp_path / "spec").mkdir()
        (tmp_path / "spec" / "doc.md").write_bytes(content)
        upper_sha = _sha256(content).upper()
        manifest = _Manifest(spec_files={"doc.md": upper_sha})
        result = self._PLUGIN().check(tmp_path, manifest)
        assert result.ok is True


# ============================================================================
# FileIntegrityManySmall
# ============================================================================


class TestFileIntegrityManySmall:
    """Tests for audit_bundle/plugins/file_integrity_many_small.py."""

    _PLUGIN = FileIntegrityManySmall

    def _check(self, bundle_dir, manifest):
        """Direct check() with the conservation result the D5 Pass-3 shim
        consumes bound first (verify()'s orchestration in miniature — an
        unbound direct invocation hard-errors by design)."""
        from audit_bundle.conservation import run_conservation

        plugin = self._PLUGIN()
        plugin.bind_conservation(
            run_conservation(bundle_dir, manifest, frozenset(), sealed=False)
        )
        return plugin.check(bundle_dir, manifest)

    # -----------------------------------------------------------------------
    # Happy path
    # -----------------------------------------------------------------------

    def test_matching_files_returns_pass(self, tmp_path: Path) -> None:
        content = b"payload bytes"
        (tmp_path / "payload").mkdir()
        (tmp_path / "payload" / "out.txt").write_bytes(content)
        manifest = _Manifest(files={"payload/out.txt": _sha256(content)})
        result = self._check(tmp_path, manifest)
        assert result.ok is True
        assert result.reason_code == "PASS"

    def test_empty_manifest_no_extra_files_returns_pass(self, tmp_path: Path) -> None:
        (tmp_path / "manifest.json").write_text("{}", encoding="utf-8")
        result = self._check(tmp_path, _Manifest(files={}))
        assert result.ok is True

    def test_multiple_files_all_matching(self, tmp_path: Path) -> None:
        (tmp_path / "payload").mkdir()
        files = {"payload/a.txt": b"alpha", "payload/b.txt": b"beta"}
        for path, content in files.items():
            (tmp_path / path).write_bytes(content)
        manifest = _Manifest(files={p: _sha256(c) for p, c in files.items()})
        result = self._check(tmp_path, manifest)
        assert result.ok is True

    # -----------------------------------------------------------------------
    # Pass 1 tamper: MISSING_FILE
    # -----------------------------------------------------------------------

    def test_missing_file_returns_missing_file(self, tmp_path: Path) -> None:
        manifest = _Manifest(files={"payload/ghost.txt": "a" * 64})
        result = self._check(tmp_path, manifest)
        assert result.ok is False
        assert result.reason_code == "MISSING_FILE"

    def test_missing_file_detail_names_path(self, tmp_path: Path) -> None:
        manifest = _Manifest(files={"payload/ghost.txt": "a" * 64})
        result = self._check(tmp_path, manifest)
        assert "payload/ghost.txt" in result.detail

    # -----------------------------------------------------------------------
    # Pass 2 tamper: BAD_FILE_SHA
    # -----------------------------------------------------------------------

    def test_sha_mismatch_returns_bad_file_sha(self, tmp_path: Path) -> None:
        content = b"real content"
        (tmp_path / "payload").mkdir()
        (tmp_path / "payload" / "out.txt").write_bytes(content)
        manifest = _Manifest(files={"payload/out.txt": "dead" * 16})
        result = self._check(tmp_path, manifest)
        assert result.ok is False
        assert result.reason_code == "BAD_FILE_SHA"

    def test_sha_mismatch_detail_contains_both_hashes(self, tmp_path: Path) -> None:
        content = b"data"
        (tmp_path / "payload").mkdir()
        (tmp_path / "payload" / "out.txt").write_bytes(content)
        wrong_sha = "dead" * 16
        manifest = _Manifest(files={"payload/out.txt": wrong_sha})
        result = self._check(tmp_path, manifest)
        assert wrong_sha in result.detail

    # -----------------------------------------------------------------------
    # Pass 3 tamper: EXTRA_FILE_NOT_IN_MANIFEST
    # -----------------------------------------------------------------------

    def test_extra_file_returns_extra_file_not_in_manifest(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "payload").mkdir()
        (tmp_path / "payload" / "extra.txt").write_bytes(b"extra")
        result = self._check(tmp_path, _Manifest(files={}))
        assert result.ok is False
        assert result.reason_code == "EXTRA_FILE_NOT_IN_MANIFEST"

    # -----------------------------------------------------------------------
    # Exemptions: spec/ and manifest.json are never flagged as EXTRA
    # -----------------------------------------------------------------------

    def test_spec_dir_files_are_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "spec").mkdir()
        (tmp_path / "spec" / "hidden.md").write_bytes(b"spec body")
        result = self._check(tmp_path, _Manifest(files={}))
        assert result.ok is True

    def test_manifest_json_is_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "manifest.json").write_bytes(b"{}")
        result = self._check(tmp_path, _Manifest(files={}))
        assert result.ok is True

    # -----------------------------------------------------------------------
    # Pass ordering: pass 1 wins over pass 2
    # -----------------------------------------------------------------------

    def test_missing_file_detected_before_sha_mismatch(self, tmp_path: Path) -> None:
        """Pass 1 (MISSING_FILE) must win over pass 2 (BAD_FILE_SHA)."""
        content = b"exists"
        (tmp_path / "payload").mkdir()
        (tmp_path / "payload" / "exists.txt").write_bytes(content)
        # "payload/absent.txt" < "payload/exists.txt" alphabetically → checked first in pass 1
        manifest = _Manifest(
            files={
                "payload/absent.txt": "a" * 64,  # triggers pass 1
                "payload/exists.txt": "b"
                * 64,  # triggers pass 2 — but pass 1 fires first
            }
        )
        result = self._check(tmp_path, manifest)
        assert result.ok is False
        assert result.reason_code == "MISSING_FILE"

    # -----------------------------------------------------------------------
    # files_audited coverage
    # -----------------------------------------------------------------------

    def test_pass_files_audited_lists_all_manifest_files(self, tmp_path: Path) -> None:
        (tmp_path / "payload").mkdir()
        files = {"payload/a.txt": b"a", "payload/b.txt": b"b"}
        for path, content in files.items():
            (tmp_path / path).write_bytes(content)
        manifest = _Manifest(files={p: _sha256(c) for p, c in files.items()})
        result = self._check(tmp_path, manifest)
        assert result.ok is True
        assert len(result.files_audited) == 2


# ============================================================================
# MonotoneGrowthCheck
# ============================================================================


class TestMonotoneGrowthCheck:
    """Tests for audit_bundle/plugins/monotone_growth.py."""

    # -----------------------------------------------------------------------
    # Happy path: current ⊇ prior
    # -----------------------------------------------------------------------

    def test_strict_superset_returns_pass(self, tmp_path: Path) -> None:
        _write_jsonl(tmp_path / "corpus" / "2.0" / "corpus.jsonl", ["c1", "c2"])
        _write_jsonl(tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl", ["c1"])
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert result.ok is True
        assert result.reason_code == "PASS"

    def test_equal_sets_returns_pass(self, tmp_path: Path) -> None:
        _write_jsonl(tmp_path / "corpus" / "2.0" / "corpus.jsonl", ["c1", "c2"])
        _write_jsonl(
            tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl", ["c1", "c2"]
        )
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert result.ok is True

    def test_pass_detail_reports_case_counts(self, tmp_path: Path) -> None:
        _write_jsonl(tmp_path / "corpus" / "2.0" / "corpus.jsonl", ["c1", "c2"])
        _write_jsonl(tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl", ["c1"])
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert "2" in result.detail and "1" in result.detail

    # -----------------------------------------------------------------------
    # Tampered: corpus shrank
    # -----------------------------------------------------------------------

    def test_shrunk_corpus_returns_adversarial_corpus_shrank(
        self, tmp_path: Path
    ) -> None:
        _write_jsonl(tmp_path / "corpus" / "2.0" / "corpus.jsonl", ["c1"])
        _write_jsonl(
            tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl", ["c1", "c2"]
        )
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "ADVERSARIAL_CORPUS_SHRANK"

    def test_shrink_detail_names_removed_cases(self, tmp_path: Path) -> None:
        _write_jsonl(tmp_path / "corpus" / "2.0" / "corpus.jsonl", ["c1"])
        _write_jsonl(
            tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl",
            ["c1", "case-removed"],
        )
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert "case-removed" in result.detail

    # -----------------------------------------------------------------------
    # Missing corpus files
    # -----------------------------------------------------------------------

    def test_missing_current_corpus_returns_fail(self, tmp_path: Path) -> None:
        _write_jsonl(tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl", ["c1"])
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "ADVERSARIAL_CORPUS_SHRANK"

    def test_missing_prior_corpus_returns_fail(self, tmp_path: Path) -> None:
        _write_jsonl(tmp_path / "corpus" / "2.0" / "corpus.jsonl", ["c1"])
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "ADVERSARIAL_CORPUS_SHRANK"

    # -----------------------------------------------------------------------
    # HARD-ENFORCED: no bundle-supplied escape hatch unlocks a removal.
    # (Regression for the false-green: an unsigned removal_authorization.json +
    # bundle-controlled "2.x"/"1.x" corpus filenames used to return PASS on a
    # shrunk corpus. Both signals are bundle-controlled, so neither can authorize
    # a removal — any removal now fails closed.)
    # -----------------------------------------------------------------------

    def test_unsigned_removal_authorization_does_not_unlock_pass(
        self, tmp_path: Path
    ) -> None:
        """A bundle naming its corpus 2.0/1.0 and shipping an unsigned reviewer
        assertion must NOT ride exit 0 on a shrunk corpus (the M2 false-green)."""
        _write_jsonl(tmp_path / "corpus" / "2.0" / "corpus.jsonl", ["c1"])
        _write_jsonl(
            tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl", ["c1", "c2"]
        )
        auth = {"reviewer": "anyone", "reason": "v2 scope narrowing"}
        (tmp_path / "removal_authorization.json").write_text(
            json.dumps(auth), encoding="utf-8"
        )
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "ADVERSARIAL_CORPUS_SHRANK"

    def test_major_version_removal_without_auth_returns_fail(
        self, tmp_path: Path
    ) -> None:
        """v1→v2 removal (no authorization file) is blocked."""
        _write_jsonl(tmp_path / "corpus" / "2.0" / "corpus.jsonl", ["c1"])
        _write_jsonl(
            tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl", ["c1", "c2"]
        )
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "ADVERSARIAL_CORPUS_SHRANK"

    def test_minor_version_removal_is_always_blocked(self, tmp_path: Path) -> None:
        """Minor-version bump never authorizes corpus removals."""
        _write_jsonl(tmp_path / "corpus" / "1.1" / "corpus.jsonl", ["c1"])
        _write_jsonl(
            tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl", ["c1", "c2"]
        )
        # Even with an auth file present, removals are not exempt.
        auth = {"reviewer": "Anyone"}
        (tmp_path / "removal_authorization.json").write_text(
            json.dumps(auth), encoding="utf-8"
        )
        result = MonotoneGrowthCheck("1.1", "1.0").check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "ADVERSARIAL_CORPUS_SHRANK"

    def test_removal_detail_names_removed_ids_not_reviewer(
        self, tmp_path: Path
    ) -> None:
        """The fail detail reports the removed case IDs; a bundle-supplied
        reviewer name is irrelevant to the verdict and is not what's reported."""
        _write_jsonl(tmp_path / "corpus" / "2.0" / "corpus.jsonl", ["c1"])
        _write_jsonl(
            tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl", ["c1", "c2"]
        )
        (tmp_path / "removal_authorization.json").write_text(
            json.dumps({"reviewer": "Jared"}), encoding="utf-8"
        )
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert result.ok is False
        assert "c2" in result.detail
        assert "Jared" not in result.detail

    # -----------------------------------------------------------------------
    # Case ID field variants (id / case_id / first value)
    # -----------------------------------------------------------------------

    def test_case_id_field_variants(self, tmp_path: Path) -> None:
        """_load_case_ids accepts 'id', 'case_id', or first object value."""
        current_path = tmp_path / "corpus" / "2.0" / "corpus.jsonl"
        current_path.parent.mkdir(parents=True)
        current_path.write_text(
            json.dumps({"id": "a"})
            + "\n"
            + json.dumps({"case_id": "b"})
            + "\n"
            + json.dumps({"other_field": "c"})
            + "\n",
            encoding="utf-8",
        )
        _write_jsonl(
            tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl",
            ["a", "b", "c"],
        )
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert result.ok is True

    def test_empty_lines_in_jsonl_are_ignored(self, tmp_path: Path) -> None:
        current_path = tmp_path / "corpus" / "2.0" / "corpus.jsonl"
        current_path.parent.mkdir(parents=True)
        current_path.write_text(
            "\n" + json.dumps({"id": "c1"}) + "\n\n",
            encoding="utf-8",
        )
        _write_jsonl(tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl", ["c1"])
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert result.ok is True

    # -----------------------------------------------------------------------
    # files_audited always references both corpus files
    # -----------------------------------------------------------------------

    def test_files_audited_contains_both_corpus_paths(self, tmp_path: Path) -> None:
        _write_jsonl(tmp_path / "corpus" / "2.0" / "corpus.jsonl", ["c1"])
        _write_jsonl(tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl", ["c1"])
        result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())
        assert len(result.files_audited) >= 2


# ============================================================================
# FalsificationNegativeTestCheck
# ============================================================================


class TestFalsificationNegativeTestCheck:
    """Tests for audit_bundle/plugins/falsification_negative_test.py."""

    _PLUGIN = FalsificationNegativeTestCheck

    def _rules_dir(self, bundle_dir: Path) -> Path:
        d = bundle_dir / "falsification_rules"
        d.mkdir(exist_ok=True)
        return d

    def _write_rule(
        self,
        rules_dir: Path,
        name: str,
        trigger: str,
        falsify_if: str,
    ) -> None:
        rule = {"trigger_expression": trigger, "falsify_if": falsify_if}
        (rules_dir / name).write_text(json.dumps(rule), encoding="utf-8")

    # -----------------------------------------------------------------------
    # Happy path: no rules or all rules pass NEGATIVE TEST
    # -----------------------------------------------------------------------

    def test_no_rules_dir_returns_pass(self, tmp_path: Path) -> None:
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True
        assert result.reason_code == "PASS"

    def test_empty_rules_dir_returns_pass(self, tmp_path: Path) -> None:
        self._rules_dir(tmp_path)
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True

    def test_valid_rule_returns_pass(self, tmp_path: Path) -> None:
        # "x > 0" is True for x in {1, 2} over bounded vals → NOT tautological → PASS
        rd = self._rules_dir(tmp_path)
        self._write_rule(rd, "rule_001.json", "x > -2", "x > 0")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True
        assert result.reason_code == "PASS"

    def test_multiple_valid_rules_returns_pass(self, tmp_path: Path) -> None:
        rd = self._rules_dir(tmp_path)
        self._write_rule(rd, "rule_001.json", "x > 0", "x > 0")
        self._write_rule(rd, "rule_002.json", "y > 0", "y != 0")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True
        assert result.reason_code == "PASS"

    def test_always_true_falsify_if_is_not_tautological(self, tmp_path: Path) -> None:
        """falsify_if that always evaluates True means the rule CAN fire → not tautological."""
        rd = self._rules_dir(tmp_path)
        # "x == x or x != x" is always True — meaning the rule fires for all inputs
        self._write_rule(rd, "rule_001.json", "x > 0", "x == x or x != x")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True

    # -----------------------------------------------------------------------
    # Tampered: unfalsifiable rule → FALSIFICATION_TAUTOLOGICAL
    # -----------------------------------------------------------------------

    def test_always_false_falsify_if_returns_tautological(self, tmp_path: Path) -> None:
        # "x > 100" is always False over bounded vals (-2,-1,0,1,2) → tautological
        rd = self._rules_dir(tmp_path)
        self._write_rule(rd, "rule_001.json", "x > 0", "x > 100")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "FALSIFICATION_TAUTOLOGICAL"

    def test_tautological_detail_identifies_rule_id(self, tmp_path: Path) -> None:
        rd = self._rules_dir(tmp_path)
        self._write_rule(rd, "rule_007.json", "x > 0", "x > 100")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert "007" in result.detail

    def test_one_tautological_among_valid_rules_blocks(self, tmp_path: Path) -> None:
        """A single unfalsifiable rule blocks the whole check."""
        rd = self._rules_dir(tmp_path)
        self._write_rule(rd, "rule_001.json", "x > 0", "x > 0")  # valid
        self._write_rule(rd, "rule_002.json", "x > 0", "x > 100")  # tautological
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "FALSIFICATION_TAUTOLOGICAL"

    def test_constant_false_expression_is_tautological(self, tmp_path: Path) -> None:
        """A falsify_if with no variables that evaluates to False is tautological."""
        rd = self._rules_dir(tmp_path)
        self._write_rule(rd, "rule_001.json", "1 > 0", "0 > 1")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "FALSIFICATION_TAUTOLOGICAL"

    # -----------------------------------------------------------------------
    # Out-of-grammar rules FAIL CLOSED (M6 regression: the earlier
    # PROCEED_WITH_CAVEAT ok=True made the NEGATIVE TEST evadable by using
    # one unsupported operator)
    # -----------------------------------------------------------------------

    def test_unsupported_grammar_in_falsify_if_fails_closed(
        self, tmp_path: Path
    ) -> None:
        # "len(x) > 0" uses a function call — outside the v1 bounded grammar.
        # Undecidable falsifiability must not ride a green verdict.
        rd = self._rules_dir(tmp_path)
        self._write_rule(rd, "rule_001.json", "x > 0", "len(x) > 0")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "FALSIFICATION_FRAGMENT_OUT_OF_SCOPE"

    def test_unsupported_trigger_grammar_fails_closed(self, tmp_path: Path) -> None:
        # Out-of-grammar trigger_expression → domain unknown → fail closed
        rd = self._rules_dir(tmp_path)
        self._write_rule(rd, "rule_001.json", "foo(x)", "x > 0")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "FALSIFICATION_FRAGMENT_OUT_OF_SCOPE"

    def test_unfalsifiable_rule_cannot_evade_via_unsupported_operator(
        self, tmp_path: Path
    ) -> None:
        # The M6 attack: a rule that can never fire ("x != x and ...")
        # dressed in an out-of-grammar token so the v1 evaluator cannot
        # prove it tautological. Pre-fix this rode ok=True; now fail-closed.
        rd = self._rules_dir(tmp_path)
        self._write_rule(rd, "rule_001.json", "x > 0", "x != x and len(x) > 0")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "FALSIFICATION_FRAGMENT_OUT_OF_SCOPE"

    def test_unparseable_trigger_fails_closed(self, tmp_path: Path) -> None:
        rd = self._rules_dir(tmp_path)
        self._write_rule(rd, "rule_001.json", "x >", "x > 0")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "FALSIFICATION_FRAGMENT_OUT_OF_SCOPE"

    # -----------------------------------------------------------------------
    # Error cases
    # -----------------------------------------------------------------------

    def test_invalid_json_returns_parse_error(self, tmp_path: Path) -> None:
        rd = self._rules_dir(tmp_path)
        (rd / "rule_001.json").write_text("not valid json {{", encoding="utf-8")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "FALSIFICATION_RULE_PARSE_ERROR"

    def test_non_string_fields_return_schema_error(self, tmp_path: Path) -> None:
        rd = self._rules_dir(tmp_path)
        rule = {"trigger_expression": 123, "falsify_if": 456}
        (rd / "rule_001.json").write_text(json.dumps(rule), encoding="utf-8")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "FALSIFICATION_RULE_SCHEMA_ERROR"

    # -----------------------------------------------------------------------
    # files_audited lists the rule files examined
    # -----------------------------------------------------------------------

    def test_files_audited_lists_rule_files(self, tmp_path: Path) -> None:
        rd = self._rules_dir(tmp_path)
        self._write_rule(rd, "rule_001.json", "x > 0", "x > 0")
        self._write_rule(rd, "rule_002.json", "y > 0", "y > 0")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert len(result.files_audited) == 2


# ============================================================================
# ReDerivationInvocationCheck
# ============================================================================


class TestReDerivationInvocationCheck:
    """Tests for audit_bundle/plugins/re_derivation_invocation.py."""

    # -----------------------------------------------------------------------
    # Happy path: no pack → domain opted out
    # -----------------------------------------------------------------------

    def test_no_rederive_dir_returns_no_pack(self, tmp_path: Path) -> None:
        result = ReDerivationInvocationCheck("pack.py", permit_execution=True).check(
            tmp_path, _Manifest()
        )
        assert result.ok is True
        assert result.reason_code == "NO_PACK"

    def test_rederive_dir_exists_but_no_pack_returns_no_pack(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "re_derive").mkdir()
        result = ReDerivationInvocationCheck("missing.py", permit_execution=True).check(
            tmp_path, _Manifest()
        )
        assert result.ok is True
        assert result.reason_code == "NO_PACK"

    def test_no_pack_files_audited_is_empty(self, tmp_path: Path) -> None:
        result = ReDerivationInvocationCheck("absent.py", permit_execution=True).check(
            tmp_path, _Manifest()
        )
        assert result.files_audited == ()

    # -----------------------------------------------------------------------
    # Happy path: pack present and exits 0 → RE_DERIVED
    # -----------------------------------------------------------------------

    def test_pack_exits_zero_returns_re_derived(self, tmp_path: Path) -> None:
        rederive_dir = tmp_path / "re_derive"
        rederive_dir.mkdir()
        (rederive_dir / "pack.py").write_text(
            "import sys; sys.exit(0)\n", encoding="utf-8"
        )
        result = ReDerivationInvocationCheck("pack.py", permit_execution=True).check(
            tmp_path, _Manifest()
        )
        assert result.ok is True
        assert result.reason_code == "RE_DERIVED"

    def test_pack_exits_zero_files_audited_contains_pack_path(
        self, tmp_path: Path
    ) -> None:
        rederive_dir = tmp_path / "re_derive"
        rederive_dir.mkdir()
        (rederive_dir / "run.py").write_text(
            "import sys; sys.exit(0)\n", encoding="utf-8"
        )
        result = ReDerivationInvocationCheck("run.py", permit_execution=True).check(
            tmp_path, _Manifest()
        )
        assert any("run.py" in f for f in result.files_audited)

    # -----------------------------------------------------------------------
    # Tampered: pack exits non-zero → RE_DERIVATION_MISMATCH
    # -----------------------------------------------------------------------

    def test_pack_exits_nonzero_returns_re_derivation_mismatch(
        self, tmp_path: Path
    ) -> None:
        rederive_dir = tmp_path / "re_derive"
        rederive_dir.mkdir()
        script = (
            "import sys\nprint('derivation failed', file=sys.stderr)\nsys.exit(1)\n"
        )
        (rederive_dir / "check.py").write_text(script, encoding="utf-8")
        result = ReDerivationInvocationCheck("check.py", permit_execution=True).check(
            tmp_path, _Manifest()
        )
        assert result.ok is False
        assert result.reason_code == "RE_DERIVATION_MISMATCH"

    def test_pack_nonzero_detail_contains_stderr_output(self, tmp_path: Path) -> None:
        rederive_dir = tmp_path / "re_derive"
        rederive_dir.mkdir()
        script = (
            "import sys\n"
            "print('CHECKSUM_MISMATCH_SENTINEL', file=sys.stderr)\n"
            "sys.exit(2)\n"
        )
        (rederive_dir / "check.py").write_text(script, encoding="utf-8")
        result = ReDerivationInvocationCheck("check.py", permit_execution=True).check(
            tmp_path, _Manifest()
        )
        assert "CHECKSUM_MISMATCH_SENTINEL" in result.detail

    def test_pack_exit_code_2_also_fails(self, tmp_path: Path) -> None:
        """Any non-zero return code is a mismatch, not only exit(1)."""
        rederive_dir = tmp_path / "re_derive"
        rederive_dir.mkdir()
        (rederive_dir / "pack.py").write_text(
            "import sys; sys.exit(42)\n", encoding="utf-8"
        )
        result = ReDerivationInvocationCheck("pack.py", permit_execution=True).check(
            tmp_path, _Manifest()
        )
        assert result.ok is False
        assert result.reason_code == "RE_DERIVATION_MISMATCH"

    # -----------------------------------------------------------------------
    # Pack receives expected CLI arguments
    # -----------------------------------------------------------------------

    def test_pack_receives_bundle_dir_argument(self, tmp_path: Path) -> None:
        """The pack receives --bundle-dir <bundle_dir> and can read it."""
        rederive_dir = tmp_path / "re_derive"
        rederive_dir.mkdir()
        sentinel = tmp_path / "sentinel.txt"
        script = (
            "import sys, pathlib\n"
            "args = sys.argv\n"
            "bd_index = args.index('--bundle-dir') + 1\n"
            "bd = pathlib.Path(args[bd_index])\n"
            "(bd / 'sentinel.txt').write_text('ok', encoding='utf-8')\n"
            "sys.exit(0)\n"
        )
        (rederive_dir / "probe.py").write_text(script, encoding="utf-8")
        result = ReDerivationInvocationCheck("probe.py", permit_execution=True).check(
            tmp_path, _Manifest()
        )
        assert result.ok is True
        assert sentinel.exists(), "pack did not receive --bundle-dir correctly"
