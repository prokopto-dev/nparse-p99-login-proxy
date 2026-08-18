"""Shared fixtures, and the one piece of scaffolding this suite genuinely needs.

``nparseplus_sdk.eqfiles`` defines none of the helpers it exports. It is a lazy
``__getattr__`` forwarder to the host application's ``nparseplus.core.eqini``,
and the host is not on PyPI — only the SDK is. So "the tests pass with only the
SDK installed" and "the tests exercise the real install-file helpers" cannot
both be literally true in one environment.

Rather than skip the ``eqhost.py`` tests when the app is absent — which would
mean the file with the most destructive potential in this repo is the one CI
never checks — this installs a faithful stub of ``nparseplus.core.eqini`` when,
and only when, the real module cannot be imported. The test bodies are identical
either way:

- **SDK only** (the default, and what most contributors will run): the stub
  backs the helpers, so the tests still prove *our* orchestration — preflight
  gating, backup-before-first-write, revert-from-backup, idempotence, and that
  no other section or the newline style is disturbed.
- **With the host installed** (``pip install -e '.[host]'``, and one CI job):
  the real helpers back them, proving the same assertions against the code that
  will actually run inside nParse+.

The stub mirrors the documented semantics of the real module exactly, including
the sharp edges: ``read_lines`` answers ``[]`` for any ``OSError`` so a missing
file is indistinguishable from an empty one, ``backup_once`` keeps only the
first copy, and ``preflight`` demands both ``eqgame.exe`` and ``uifiles/``.
"""

from __future__ import annotations

import shutil
import sys
import types
from pathlib import Path

import pytest


def _real_host_available() -> bool:
    try:
        from nparseplus.core import eqini  # noqa: F401
    except Exception:
        return False
    return True


# --------------------------------------------------------------------------
# The stub, used only when the host app is not installed
# --------------------------------------------------------------------------

NULL_SENTINEL = "*NULL*"


def preflight(eq_dir):
    if eq_dir is None:
        return "Set the EQ install directory first."
    path = Path(eq_dir)
    if not path.is_dir():
        return f"Not a directory: {eq_dir}"
    if not (path / "eqgame.exe").is_file():
        return "No eqgame.exe here — not an EQ install directory."
    if not (path / "uifiles").is_dir():
        return "No uifiles/ here — not an EQ install directory."
    return None


def backup_once(path, dir_name):
    path = Path(path)
    target_dir = path.parent / dir_name
    target = target_dir / path.name
    if target.exists():
        return  # keep the FIRST copy, always
    target_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, target)


def read_lines(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="surrogateescape").splitlines()
    except OSError:
        return []


def write_lines(path, lines, *, newline="\n"):
    Path(path).write_text(
        newline.join(lines) + newline,
        encoding="utf-8",
        errors="surrogateescape",
        newline="",
    )


def detect_newline(path):
    try:
        return "\r\n" if b"\r\n" in Path(path).read_bytes() else "\n"
    except OSError:
        return "\n"


def section_bounds(lines, name):
    header = f"[{name}]".lower()
    start = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if start is None:
            if stripped.lower() == header:
                start = index
            continue
        if stripped.startswith("["):
            return start, index
    if start is None:
        return None
    return start, len(lines)


def section_body(lines, name):
    bounds = section_bounds(lines, name)
    if bounds is None:
        return []
    start, end = bounds
    return lines[start + 1 : end]


def replace_section(lines, name, body):
    result = list(lines)
    bounds = section_bounds(result, name)
    if bounds is None:
        if result and result[-1].strip():
            result.append("")
        result.append(f"[{name}]")
        result.extend(body)
        return result
    start, end = bounds
    result[start + 1 : end] = list(body)
    return result


def split_key_value(line):
    stripped = line.strip()
    if not stripped or stripped[0] in ";#[":
        return None
    key, sep, value = stripped.partition("=")
    if not sep or not key.strip():
        return None
    return key.strip(), value.strip()


_STUB_NAMES = {
    "NULL_SENTINEL": NULL_SENTINEL,
    "backup_once": backup_once,
    "detect_newline": detect_newline,
    "preflight": preflight,
    "read_lines": read_lines,
    "replace_section": replace_section,
    "section_body": section_body,
    "section_bounds": section_bounds,
    "split_key_value": split_key_value,
    "write_lines": write_lines,
}


def _install_stub() -> None:
    """Register ``nparseplus.core.eqini`` so the SDK's lazy forwarder resolves."""
    eqini = types.ModuleType("nparseplus.core.eqini")
    for name, value in _STUB_NAMES.items():
        setattr(eqini, name, value)

    nparseplus = sys.modules.get("nparseplus") or types.ModuleType("nparseplus")
    nparseplus.__path__ = []  # namespace-ish; nothing should resolve through it
    core = types.ModuleType("nparseplus.core")
    core.__path__ = []
    core.eqini = eqini
    nparseplus.core = core

    sys.modules.setdefault("nparseplus", nparseplus)
    sys.modules["nparseplus.core"] = core
    sys.modules["nparseplus.core.eqini"] = eqini


HOST_APP_INSTALLED = _real_host_available()
if not HOST_APP_INSTALLED:
    _install_stub()


def pytest_report_header(config):
    backend = "real nparseplus.core.eqini" if HOST_APP_INSTALLED else "stubbed eqfiles"
    return f"eqfiles backend: {backend}"


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

DEFAULT_EQHOST = b"[LoginServer]\nHost=login.eqemulator.net:5998\n"


@pytest.fixture
def eq_dir(tmp_path: Path) -> Path:
    """A directory that passes ``preflight``, with a stock ``eqhost.txt``.

    ``preflight`` demands both markers, so a fixture with only one of them
    silently tests the refusal path instead of the happy path.
    """
    install = tmp_path / "EverQuest"
    install.mkdir()
    (install / "eqgame.exe").write_text("stub")
    (install / "uifiles").mkdir()
    # write_bytes, not write_text: on Windows the default newline translation
    # turns a literal \n into \r\n, which would make the newline-preservation
    # assertions test the fixture rather than the code.
    (install / "eqhost.txt").write_bytes(DEFAULT_EQHOST)
    return install
