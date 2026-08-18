"""Reading and rewriting ``eqhost.txt``, the one file this plugin ever touches.

``eqhost.txt`` lives in the EverQuest install root next to ``eqgame.exe`` and is
ini-shaped. For Project 1999 it is two lines::

    [LoginServer]
    Host=login.eqemulator.net:5998

Pointing that at the local proxy is the whole user-facing change:
``Host=127.0.0.1:5998``.

Every edit goes through :mod:`nparseplus_sdk.eqfiles`, which re-exports the host
app's own install-file helpers, rather than hand-rolling ini handling. That is
not ceremony — those helpers carry the three guarantees anything writing into
someone's game directory owes them: check it really is an install before
writing, keep a pristine copy of the *first* version seen, and leave every byte
outside the edited section alone. ``eqhost.txt`` is nominally single-section, but
"nominally" is not a reason to clobber whatever else a player put there.

Two behaviours here differ from EQTool's equivalent, both deliberately:

- **Revert restores the backup, not a hardcoded default.** EQTool writes
  ``login.eqemulator.net:5998`` back unconditionally, which silently destroys
  the setting of anyone pointed at a different login server.
- **The upstream target is read from the backup too**, so those same players
  keep working *through* the proxy rather than being quietly relocated to the
  public login server.
"""

from __future__ import annotations

import dataclasses
import enum
import shutil
from pathlib import Path

from nparseplus_sdk import eqfiles

from .proxy import DEFAULT_LOGIN_HOST, DEFAULT_LOGIN_PORT, LISTEN_HOST

__all__ = [
    "BACKUP_DIR_NAME",
    "EQHOST_FILENAME",
    "EqHostState",
    "EqHostStatus",
    "apply",
    "read_state",
    "revert",
]

EQHOST_FILENAME = "eqhost.txt"
SECTION = "LoginServer"
KEY = "Host"

#: Created inside the EQ install directory. Named for the plugin so it is
#: obvious what put it there and safe to leave behind after an uninstall.
BACKUP_DIR_NAME = "p99_login_proxy_backup"

#: Host spellings that mean "this machine". A file pointing at any of these is
#: already routed through a local proxy.
LOCALHOST_NAMES = frozenset({"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0"})


class EqHostStatus(enum.Enum):
    """What ``eqhost.txt`` currently says, and whether we can act on it."""

    NO_EQ_DIR = "no_eq_dir"
    NOT_AN_INSTALL = "not_an_install"
    MISSING = "missing"
    UNREADABLE = "unreadable"
    #: Points at a remote login server: the proxy is not in the path.
    DIRECT = "direct"
    #: Points at localhost: the proxy is in the path and must be running.
    PROXIED = "proxied"


@dataclasses.dataclass(frozen=True)
class EqHostState:
    """A snapshot of ``eqhost.txt``, everything the UI and the proxy need."""

    status: EqHostStatus
    #: Host currently configured in the file, if it could be read.
    host: str | None = None
    #: Port currently configured in the file, if it could be read.
    port: int | None = None
    #: Where the proxy should forward to: the backup's host, or the default.
    upstream_host: str = DEFAULT_LOGIN_HOST
    upstream_port: int = DEFAULT_LOGIN_PORT
    #: True when the upstream above is a guess because no backup exists.
    upstream_is_default: bool = True
    #: Human-readable detail, set for every failure status.
    reason: str | None = None

    @property
    def is_proxied(self) -> bool:
        return self.status is EqHostStatus.PROXIED

    @property
    def can_apply(self) -> bool:
        return self.status in (EqHostStatus.DIRECT, EqHostStatus.PROXIED)


def eqhost_path(eq_dir: Path) -> Path:
    return Path(eq_dir) / EQHOST_FILENAME


def backup_path(eq_dir: Path) -> Path:
    return Path(eq_dir) / BACKUP_DIR_NAME / EQHOST_FILENAME


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------


def _parse_host_line(lines: list[str]) -> tuple[str, int] | None:
    """Pull ``Host=<host>:<port>`` out of the ``[LoginServer]`` section."""
    for line in eqfiles.section_body(lines, SECTION):
        pair = eqfiles.split_key_value(line)
        if pair is None:
            continue
        key, value = pair
        if key.lower() != KEY.lower():
            continue
        host, sep, port_text = value.rpartition(":")
        if not sep:
            # No port at all. The client would not accept this either, but we
            # can still name the host in the UI rather than claiming the file
            # is unreadable.
            return value.strip(), DEFAULT_LOGIN_PORT
        try:
            return host.strip(), int(port_text.strip())
        except ValueError:
            return None
    return None


def _read_pair(path: Path) -> tuple[str, int] | None:
    # `read_lines` answers [] for any OSError, so a missing file and an empty
    # one are indistinguishable through it. Check existence explicitly.
    if not path.is_file():
        return None
    return _parse_host_line(eqfiles.read_lines(path))


def read_state(eq_dir: Path | None) -> EqHostState:
    """Inspect the install and report what the proxy and the UI should do.

    Never raises: ``eq_dir is None`` is the normal first-run state of nParse+,
    not an error, and every other failure is a status the settings page renders.
    """
    if eq_dir is None:
        return EqHostState(
            status=EqHostStatus.NO_EQ_DIR,
            reason="Set the EverQuest install directory in nParse+ settings first.",
        )

    reason = eqfiles.preflight(eq_dir)
    if reason is not None:
        return EqHostState(status=EqHostStatus.NOT_AN_INSTALL, reason=reason)

    path = eqhost_path(eq_dir)
    if not path.is_file():
        return EqHostState(
            status=EqHostStatus.MISSING,
            reason=f"No {EQHOST_FILENAME} in {eq_dir}.",
        )

    current = _parse_host_line(eqfiles.read_lines(path))
    if current is None:
        return EqHostState(
            status=EqHostStatus.UNREADABLE,
            reason=f"Could not find a [{SECTION}] {KEY}= line in {EQHOST_FILENAME}.",
        )

    host, port = current
    backed_up = _read_pair(backup_path(eq_dir))

    if host.lower() in LOCALHOST_NAMES:
        # Already proxied. Upstream must come from the backup — the current file
        # no longer records where this player was actually pointed.
        if backed_up is not None:
            return EqHostState(
                status=EqHostStatus.PROXIED,
                host=host,
                port=port,
                upstream_host=backed_up[0],
                upstream_port=backed_up[1],
                upstream_is_default=False,
            )
        return EqHostState(
            status=EqHostStatus.PROXIED,
            host=host,
            port=port,
            upstream_is_default=True,
            reason=(
                f"{EQHOST_FILENAME} already points at {host} but no backup exists, "
                f"so the original login server is unknown; assuming "
                f"{DEFAULT_LOGIN_HOST}:{DEFAULT_LOGIN_PORT}."
            ),
        )

    # Not proxied: the file itself names the upstream.
    return EqHostState(
        status=EqHostStatus.DIRECT,
        host=host,
        port=port,
        upstream_host=host,
        upstream_port=port,
        upstream_is_default=False,
    )


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------


class EqHostError(Exception):
    """An edit to ``eqhost.txt`` could not be performed."""


def apply(eq_dir: Path | None) -> bool:
    """Point ``eqhost.txt`` at the local proxy. Returns True if it wrote.

    Backup-first and preflight-gated, in the order the SDK prescribes. The
    original port is carried over rather than assumed, so a player on a custom
    port keeps it.

    Idempotent: applying twice writes once.
    """
    state = read_state(eq_dir)
    if not state.can_apply:
        raise EqHostError(state.reason or f"Cannot edit {EQHOST_FILENAME}.")
    assert eq_dir is not None and state.port is not None

    path = eqhost_path(eq_dir)

    if state.is_proxied:
        if state.upstream_is_default:
            # Refuse rather than take a backup now. `backup_once` keeps the
            # FIRST copy it is given, so snapshotting an already-modified file
            # would enshrine the edit as the "pristine" original and a later
            # revert would restore the very change it was meant to undo.
            raise EqHostError(
                f"{EQHOST_FILENAME} already points at {state.host} but there is no "
                f"backup of the original. Restore it by hand (the usual value is "
                f"{DEFAULT_LOGIN_HOST}:{DEFAULT_LOGIN_PORT}) before enabling the proxy, "
                f"so a revert has something true to go back to."
            )
        return False  # already applied, and the backup is intact

    eqfiles.backup_once(path, BACKUP_DIR_NAME)

    newline = eqfiles.detect_newline(path)
    lines = eqfiles.replace_section(
        eqfiles.read_lines(path), SECTION, [f"{KEY}={LISTEN_HOST}:{state.port}"]
    )
    eqfiles.write_lines(path, lines, newline=newline)
    return True


def revert(eq_dir: Path | None) -> bool:
    """Restore ``eqhost.txt`` from the backup. Returns True if it wrote.

    Restores the backed-up bytes verbatim rather than writing a default, so a
    player pointed at a non-standard login server gets *their* setting back.
    Idempotent, and a no-op when the file already matches the backup.
    """
    if eq_dir is None:
        raise EqHostError("Set the EverQuest install directory in nParse+ settings first.")

    reason = eqfiles.preflight(eq_dir)
    if reason is not None:
        raise EqHostError(reason)

    backup = backup_path(eq_dir)
    if not backup.is_file():
        raise EqHostError(
            f"No backup at {backup}. Nothing to revert to — set the "
            f"[{SECTION}] {KEY}= line back by hand."
        )

    path = eqhost_path(eq_dir)
    original = backup.read_bytes()
    if path.is_file() and path.read_bytes() == original:
        return False

    # copy2, not a re-render: the bytes that were there before are the answer,
    # down to the newline style and any trailing whitespace the client cares
    # about. Rewriting through read_lines/write_lines would normalise them.
    shutil.copy2(backup, path)
    return True
