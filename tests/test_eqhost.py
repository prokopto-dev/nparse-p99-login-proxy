"""Tests for the one file in the EQ install this plugin ever writes to.

These run against the real ``nparseplus.core.eqini`` when the host app is
installed and against a faithful stub otherwise — see ``conftest.py`` for why
that choice exists and what each backend does and does not prove.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from p99_login_proxy import eqhost
from p99_login_proxy.eqhost import EqHostError, EqHostStatus


def read(path: Path) -> str:
    return path.read_text()


def eqhost_file(eq_dir: Path) -> Path:
    return eq_dir / "eqhost.txt"


def backup_file(eq_dir: Path) -> Path:
    return eq_dir / eqhost.BACKUP_DIR_NAME / "eqhost.txt"


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------


def test_a_stock_install_reads_as_direct(eq_dir: Path):
    state = eqhost.read_state(eq_dir)
    assert state.status is EqHostStatus.DIRECT
    assert state.host == "login.eqemulator.net"
    assert state.port == 5998
    assert not state.is_proxied
    assert state.can_apply


def test_no_eq_directory_is_a_status_not_an_error():
    """None is the normal first-run state of nParse+, not a failure."""
    state = eqhost.read_state(None)
    assert state.status is EqHostStatus.NO_EQ_DIR
    assert state.reason


def test_a_directory_that_is_not_an_install_is_refused(tmp_path: Path):
    state = eqhost.read_state(tmp_path)
    assert state.status is EqHostStatus.NOT_AN_INSTALL
    assert not state.can_apply


def test_a_missing_eqhost_is_distinguished_from_an_unreadable_one(eq_dir: Path):
    eqhost_file(eq_dir).unlink()
    assert eqhost.read_state(eq_dir).status is EqHostStatus.MISSING

    eqhost_file(eq_dir).write_text("[LoginServer]\n")
    assert eqhost.read_state(eq_dir).status is EqHostStatus.UNREADABLE


@pytest.mark.parametrize("port", [5998, 5999, 1234])
def test_the_port_is_read_from_the_file_not_assumed(eq_dir: Path, port: int):
    eqhost_file(eq_dir).write_bytes(f"[LoginServer]\nHost=login.eqemulator.net:{port}\n".encode())
    assert eqhost.read_state(eq_dir).port == port

    eqhost.apply(eq_dir)
    state = eqhost.read_state(eq_dir)
    assert state.is_proxied
    assert state.port == port, "a custom port survives the edit"
    assert state.upstream_port == port


# --------------------------------------------------------------------------
# Applying
# --------------------------------------------------------------------------


def test_apply_backs_up_first_then_points_at_localhost(eq_dir: Path):
    assert eqhost.apply(eq_dir) is True

    assert "Host=127.0.0.1:5998" in read(eqhost_file(eq_dir))
    assert "login.eqemulator.net" in read(backup_file(eq_dir)), "the original is preserved"

    state = eqhost.read_state(eq_dir)
    assert state.status is EqHostStatus.PROXIED
    assert state.upstream_host == "login.eqemulator.net"
    assert state.upstream_port == 5998
    assert not state.upstream_is_default


def test_apply_is_idempotent(eq_dir: Path):
    assert eqhost.apply(eq_dir) is True
    after_first = eqhost_file(eq_dir).read_bytes()

    assert eqhost.apply(eq_dir) is False, "a second apply writes nothing"
    assert eqhost_file(eq_dir).read_bytes() == after_first
    assert "login.eqemulator.net" in read(backup_file(eq_dir))


def test_apply_preserves_other_sections_and_keys(eq_dir: Path):
    eqhost_file(eq_dir).write_bytes(
        b"; a comment\n"
        b"[LoginServer]\n"
        b"Host=login.eqemulator.net:5998\n"
        b"\n"
        b"[Other]\n"
        b"Keep=me\n"
        b"AlsoKeep=this\n"
    )
    eqhost.apply(eq_dir)

    text = read(eqhost_file(eq_dir))
    assert "Host=127.0.0.1:5998" in text
    assert "[Other]" in text
    assert "Keep=me" in text
    assert "AlsoKeep=this" in text
    assert "; a comment" in text


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_apply_preserves_the_files_newline_style(eq_dir: Path, newline: bytes):
    body = newline.join([b"[LoginServer]", b"Host=login.eqemulator.net:5998", b""])
    eqhost_file(eq_dir).write_bytes(body)

    eqhost.apply(eq_dir)

    written = eqhost_file(eq_dir).read_bytes()
    if newline == b"\r\n":
        assert b"\r\n" in written
        assert b"\r\r" not in written
    else:
        assert b"\r" not in written


def test_apply_refuses_when_already_localhost_with_no_backup(eq_dir: Path):
    """The trap that makes a revert restore the very change it should undo.

    ``backup_once`` keeps the FIRST copy it is given. Taking one now would
    enshrine the already-modified file as the pristine original.
    """
    eqhost_file(eq_dir).write_bytes(b"[LoginServer]\nHost=127.0.0.1:5998\n")
    assert not backup_file(eq_dir).exists()

    with pytest.raises(EqHostError, match="no backup"):
        eqhost.apply(eq_dir)

    assert not backup_file(eq_dir).exists(), "and it still did not take one"


def test_apply_refuses_without_an_eq_directory():
    with pytest.raises(EqHostError):
        eqhost.apply(None)


def test_an_already_localhost_file_without_a_backup_reports_the_default_upstream(eq_dir: Path):
    eqhost_file(eq_dir).write_bytes(b"[LoginServer]\nHost=localhost:5998\n")
    state = eqhost.read_state(eq_dir)
    assert state.is_proxied
    assert state.upstream_is_default
    assert state.upstream_host == "login.eqemulator.net"
    assert state.reason and "no backup" in state.reason


# --------------------------------------------------------------------------
# Reverting
# --------------------------------------------------------------------------


def test_revert_restores_the_backup_byte_for_byte(eq_dir: Path):
    original = eqhost_file(eq_dir).read_bytes()
    eqhost.apply(eq_dir)
    assert eqhost_file(eq_dir).read_bytes() != original

    assert eqhost.revert(eq_dir) is True
    assert eqhost_file(eq_dir).read_bytes() == original


def test_revert_restores_a_custom_login_server_not_a_hardcoded_default(eq_dir: Path):
    """EQTool writes login.eqemulator.net back unconditionally, destroying this."""
    custom = b"[LoginServer]\nHost=login.mycustomserver.example:1234\n"
    eqhost_file(eq_dir).write_bytes(custom)

    eqhost.apply(eq_dir)
    assert "Host=127.0.0.1:1234" in read(eqhost_file(eq_dir))

    eqhost.revert(eq_dir)
    assert eqhost_file(eq_dir).read_bytes() == custom
    assert b"eqemulator" not in eqhost_file(eq_dir).read_bytes()


def test_revert_is_idempotent(eq_dir: Path):
    original = eqhost_file(eq_dir).read_bytes()
    eqhost.apply(eq_dir)

    assert eqhost.revert(eq_dir) is True
    assert eqhost.revert(eq_dir) is False, "already reverted; nothing to write"
    assert eqhost_file(eq_dir).read_bytes() == original


def test_revert_without_a_backup_says_so_rather_than_guessing(eq_dir: Path):
    with pytest.raises(EqHostError, match="No backup"):
        eqhost.revert(eq_dir)


def test_apply_revert_apply_round_trips(eq_dir: Path):
    original = eqhost_file(eq_dir).read_bytes()
    for _ in range(3):
        eqhost.apply(eq_dir)
        assert eqhost.read_state(eq_dir).is_proxied
        eqhost.revert(eq_dir)
        assert eqhost_file(eq_dir).read_bytes() == original


def test_the_backup_is_never_overwritten_by_a_modified_file(eq_dir: Path):
    original = eqhost_file(eq_dir).read_bytes()
    eqhost.apply(eq_dir)
    # Simulate a re-apply after something else touched the file.
    eqhost_file(eq_dir).write_bytes(b"[LoginServer]\nHost=127.0.0.1:5998\n")
    eqhost.apply(eq_dir)
    assert backup_file(eq_dir).read_bytes() == original


def test_nothing_outside_eqhost_is_touched(eq_dir: Path):
    (eq_dir / "eqclient.ini").write_text("do not touch")
    (eq_dir / "uifiles" / "thing.xml").write_text("nor this")

    eqhost.apply(eq_dir)
    eqhost.revert(eq_dir)

    assert (eq_dir / "eqclient.ini").read_text() == "do not touch"
    assert (eq_dir / "uifiles" / "thing.xml").read_text() == "nor this"
    assert (eq_dir / "eqgame.exe").read_text() == "stub"
