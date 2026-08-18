"""No packet-content logging path exists, at any level, in any build.

This stream carries login credentials, and the nParse+ host mirrors its logger
tree to ``nparseplus.log`` on disk. A hex dump that is harmless in a C debugger
would write a player's login traffic to a file on their machine. Both reference
implementations carry one (``protocol.c:12-49`` behind ``#if _DEBUG``, and the
C# port's equivalent writing to ``Debug``); this port carries none.

That is an easy thing to promise in a code review and an easy thing to
regress six months later, so it is asserted two ways: by actually running
traffic through the codec with logging turned all the way up and inspecting
every record emitted, and by scanning the source for the tools you would reach
for to build a dump in the first place.
"""

from __future__ import annotations

import ast
import base64
import logging
import struct
from pathlib import Path

import pytest

from p99_login_proxy.proxy import LoginCodec

from .test_codec import HEADER16, ack, combined, fragments, packet, payload, record

PACKAGE = Path(__file__).resolve().parent.parent / "p99_login_proxy"

#: Distinctive byte runs standing in for the credentials this stream carries.
#: Nothing resembling these may appear in any log record, in any encoding.
SECRETS = (
    b"hunter2-the-account-password",
    b"account-name-do-not-log-me",
    bytes(range(0xE0, 0xF0)),
)


class Capture(logging.Handler):
    """Catches every record at every level, formatted and raw."""

    def __init__(self) -> None:
        super().__init__(level=0)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def texts(self) -> list[str]:
        out: list[str] = []
        for entry in self.records:
            out.append(entry.getMessage())
            out.append(repr(entry.args))
            out.append(repr(getattr(entry, "msg", "")))
            if entry.exc_info:
                out.append(repr(entry.exc_info))
        return out


@pytest.fixture
def capture():
    handler = Capture()
    root = logging.getLogger()
    previous_level = root.level
    previous_disable = logging.root.manager.disable

    # Turn everything all the way up: a dump guarded behind DEBUG is exactly
    # the case this test exists to catch.
    logging.disable(logging.NOTSET)
    root.setLevel(0)
    root.addHandler(handler)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)
        logging.disable(previous_disable)


def secret_payload() -> bytes:
    """A server list whose every string field carries a marker."""
    records = [
        record(
            "Project 1999 " + SECRETS[0].decode(),
            ip=SECRETS[1].decode(),
            region="R" * 80,
        ),
        record("Some Other Server", region="R" * 80),
    ]
    return payload(records, header=HEADER16)


def drive_a_whole_session(codec: LoginCodec) -> None:
    """Everything the codec can be asked to do, with markers throughout."""
    body = secret_payload()

    codec.from_remote(b"\x00\x02" + SECRETS[0])
    codec.from_local(b"\x00\x01" + SECRETS[0])
    codec.from_remote(packet(0, SECRETS[0]))
    codec.from_remote(combined(packet(1, SECRETS[1]), b"\x00\xaa" + SECRETS[2]))
    codec.from_local(combined(ack(3), b"\x00\xaa" + SECRETS[1]))

    for frag in fragments(body, start_seq=3):
        codec.from_remote(frag)

    codec.from_local(ack(9))
    codec.from_local(b"\x00\x05" + SECRETS[2])

    # And the error paths, which are the likeliest place a dump gets added.
    codec.from_remote(b"\x00\x0d\x00\x63" + SECRETS[0])
    codec.from_remote(b"\x00\x03\xff" + SECRETS[1])
    codec.from_remote(
        b"\x00\x0d" + struct.pack(">H", 0) + struct.pack(">I", 9) + b"\x18\x00" + SECRETS[0]
    )
    codec.from_remote(
        b"\x00\x0d" + struct.pack(">H", 0) + struct.pack(">I", 1 << 30) + b"\x18\x00" + SECRETS[0]
    )
    for seq in range(600):  # trip the reassembly window cap
        codec.from_remote(b"\x00\x0d" + struct.pack(">H", (seq + 900) & 0xFFFF) + SECRETS[2] * 8)


def test_no_log_record_contains_packet_content(capture: Capture):
    codec = LoginCodec(logging.getLogger("p99_login_proxy.test"))
    drive_a_whole_session(codec)

    assert capture.records, "the codec must actually have logged something"

    blob = "\n".join(capture.texts())
    lowered = blob.lower()
    for secret in SECRETS:
        assert secret.decode("latin-1") not in blob, "raw bytes leaked into a log record"
        assert secret.hex() not in lowered, "hex-encoded bytes leaked into a log record"
        assert base64.b64encode(secret).decode() not in blob, "base64 bytes leaked"


def test_no_log_record_contains_any_long_run_from_the_stream(capture: Capture):
    """Catches a partial dump that no marker happens to fall inside."""
    codec = LoginCodec(logging.getLogger("p99_login_proxy.test"))
    body = secret_payload()
    drive_a_whole_session(codec)

    blob = "\n".join(capture.texts())
    latin = body.decode("latin-1")
    window = 8
    leaks = [
        latin[i : i + window] for i in range(len(latin) - window) if latin[i : i + window] in blob
    ]
    assert not leaks, f"an 8-byte run of the payload appeared in a log record: {leaks[:3]!r}"


def test_logging_happens_at_all_so_the_assertions_above_mean_something(capture: Capture):
    codec = LoginCodec(logging.getLogger("p99_login_proxy.test"))
    drive_a_whole_session(codec)
    messages = [r.getMessage() for r in capture.records]
    assert any("server list" in m for m in messages), (
        "if the codec logged nothing, the leak assertions would pass vacuously"
    )


# --------------------------------------------------------------------------
# Static: the tools you would build a dump with are absent
# --------------------------------------------------------------------------

_BANNED_IMPORTS = {"binascii", "base64", "codecs", "pprint"}
_BANNED_SUBSTRINGS = ("hexdump", "hexlify", "b64encode", ".hex()")


def source_files() -> list[Path]:
    return sorted(PACKAGE.rglob("*.py"))


def test_the_package_has_no_encoding_helpers_a_dump_would_need():
    assert source_files(), "the package should have source files to scan"
    for path in source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in _BANNED_IMPORTS, (
                        f"{path.name}:{node.lineno} imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in _BANNED_IMPORTS, (
                    f"{path.name}:{node.lineno} imports from {node.module}"
                )


def test_no_source_line_mentions_a_dump_helper():
    for path in source_files():
        text = path.read_text(encoding="utf-8")
        for needle in _BANNED_SUBSTRINGS:
            assert needle not in text, f"{path.name} mentions {needle!r}"


SUSPICIOUS_NAMES = {
    "data",
    "payload",
    "buf",
    "buffer",
    "chunk",
    "body",
    "frag",
    "reply",
    "records",
    "secret",
    "name",
}


def _packet_names_in(node: ast.AST) -> list[str]:
    """Packet-ish names reachable from ``node``, ignoring those inside ``len()``.

    ``len(data)`` is a number and is exactly what the rule permits — opcodes,
    sequence numbers and lengths. ``data`` on its own is the thing that must
    never reach a formatter.
    """
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "len":
        return []
    found: list[str] = []
    if isinstance(node, ast.Name) and node.id in SUSPICIOUS_NAMES:
        found.append(node.id)
    for child in ast.iter_child_nodes(node):
        found.extend(_packet_names_in(child))
    return found


def test_no_log_call_passes_a_packet_variable():
    """A log call may pass a length or an opcode, never the bytes themselves."""
    offenders: list[str] = []

    for path in source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {
                "debug",
                "info",
                "warning",
                "error",
                "critical",
                "exception",
                "log",
            }:
                continue
            for arg in node.args[1:] + [kw.value for kw in node.keywords]:
                offenders.extend(
                    f"{path.name}:{node.lineno} logs {found!r}" for found in _packet_names_in(arg)
                )

    assert not offenders, offenders
