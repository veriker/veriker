"""tests/test_verifier_recheck_key_source.py — verifier recheck-key source safety.

Redteam regression: the verifier HMAC recheck key must come only from the
process environment or from an ABSOLUTE operator-named dotenv file — never from a
working-directory-relative path. The old fallback hardcoded a Windows
drive-rooted path literal (``Path("<drive>:/.../MASTER.env")``); such a literal
is NOT absolute on POSIX — pathlib parses ``<drive>:`` as a directory name under
the cwd — so an attacker who plants that directory tree under the working
directory could supply the verifier signing/recheck key.

These tests run on any platform (the planted ``<drive>:`` directory is just a
normal directory name on POSIX, which is exactly the attack surface).
"""

from __future__ import annotations

import re
from pathlib import Path

from audit_bundle.plugins import _load_verifier_recheck_key

_ENV = "VKERNEL_VERIFIER_HMAC_KEY"
_FILE_ENV = "VKERNEL_VERIFIER_HMAC_KEY_FILE"
_SECRET = "redteam-recheck-secret-deadbeef"


def _write_dotenv(path: Path, secret: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'# dotenv\nSOME_OTHER=1\nVKERNEL_VERIFIER_HMAC_KEY="{secret}"\nTRAILING=2\n',
        encoding="utf-8",
    )


def _clear(monkeypatch) -> None:
    monkeypatch.delenv(_ENV, raising=False)
    monkeypatch.delenv(_FILE_ENV, raising=False)


# ---------------------------------------------------------------------------
# The core regression: a cwd-relative drive-rooted MASTER.env is ignored
# ---------------------------------------------------------------------------


def test_cwd_planted_master_env_does_not_supply_key(tmp_path, monkeypatch):
    _clear(monkeypatch)
    # Reproduce the bug shape: a "<drive>:/.../.env/MASTER.env" path is parsed by
    # pathlib as a cwd-relative directory named "<drive>:" on POSIX. Plant exactly
    # that tree under the cwd.
    planted = tmp_path / "C:" / "internal" / ".env" / "MASTER.env"
    _write_dotenv(planted, _SECRET)
    monkeypatch.chdir(tmp_path)
    # No env var, no key-file env → the planted cwd file must NOT be read.
    assert _load_verifier_recheck_key() is None


def test_relative_key_file_env_is_refused(tmp_path, monkeypatch):
    _clear(monkeypatch)
    _write_dotenv(tmp_path / "local.env", _SECRET)
    monkeypatch.chdir(tmp_path)
    # A relative key-file path must be refused even though the file exists in cwd.
    monkeypatch.setenv(_FILE_ENV, "local.env")
    assert _load_verifier_recheck_key() is None


# ---------------------------------------------------------------------------
# Legitimate sources still work
# ---------------------------------------------------------------------------


def test_process_env_supplies_key(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv(_ENV, _SECRET)
    key = _load_verifier_recheck_key()
    assert key is not None


def test_absolute_key_file_supplies_key(tmp_path, monkeypatch):
    _clear(monkeypatch)
    abs_dotenv = tmp_path / "secrets" / "MASTER.env"
    _write_dotenv(abs_dotenv, _SECRET)
    assert abs_dotenv.is_absolute()
    monkeypatch.setenv(_FILE_ENV, str(abs_dotenv))
    key = _load_verifier_recheck_key()
    assert key is not None


def test_absent_everything_is_fail_closed_none(tmp_path, monkeypatch):
    _clear(monkeypatch)
    monkeypatch.chdir(tmp_path)
    assert _load_verifier_recheck_key() is None


def test_env_var_takes_precedence_over_key_file(tmp_path, monkeypatch):
    _clear(monkeypatch)
    # An absolute key-file with a DIFFERENT secret must not override the env var.
    other = tmp_path / "secrets" / "MASTER.env"
    _write_dotenv(other, "file-secret-should-not-win")
    monkeypatch.setenv(_FILE_ENV, str(other))
    monkeypatch.setenv(_ENV, _SECRET)
    got = _load_verifier_recheck_key()
    assert got is not None
    # The actual key bytes must be the ENV secret, not the file secret —
    # discriminates which source won.
    assert got.secret == _SECRET.encode("utf-8")
    assert got.secret != b"file-secret-should-not-win"


# ---------------------------------------------------------------------------
# The hardcoded internal path is gone from the module
# ---------------------------------------------------------------------------


def test_no_hardcoded_internal_path_literal():
    import audit_bundle.plugins as plugins_mod

    assert not hasattr(plugins_mod, "_MASTER_ENV_PATH")
    src = Path(plugins_mod.__file__).read_text(encoding="utf-8")
    # No hardcoded drive-rooted path literal (e.g. Path("X:/...")) as a key source.
    assert not re.search(r"""Path\(\s*['"][A-Za-z]:/""", src)
