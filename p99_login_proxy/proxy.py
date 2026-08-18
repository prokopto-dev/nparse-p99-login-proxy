"""The P99 login-server middleman: EQEmu protocol codec and the UDP relay thread.

Ported from Zaela's `p99-login-middlemand`_ (C, `Unlicense`_ — a public-domain
dedication imposing no obligation), read at commit
``9b74f470cb15f3518cd66e89c8c4732f337b0ed3``. The protocol knowledge here is
Zaela's; the bugs are ours. Credit where it is due: without that ~800 lines of
C, and the P99 wiki pages that point players at it, this add-on would not exist.

.. _p99-login-middlemand: https://github.com/Zaela/p99-login-middlemand
.. _Unlicense: https://unlicense.org

**Why any of this exists.** The EQEmu login server's server list is roughly 6 KB
and is sent as ~10 fragmented UDP datagrams. That protocol has no retransmit and
no out-of-order handling, so a single dropped fragment leaves the player staring
at a permanently blank server-select screen with no error at all. It is common
on Linux/WINE and macOS/CrossOver. This proxy reassembles the fragments itself,
discards every server that is not P99, and hands the client **one small packet**
instead of ten — nothing is left to drop.

**This module is deliberately pure standard library.** No Qt, no SDK, no
third-party imports. The codec is separated from the sockets so that every byte
of the wire format is verifiable in a unit test, which matters more than usual
here: there are no tests for the middleman in any existing implementation, so
these are the first, and a codec bug shows up as a blank screen rather than a
stack trace.

**Never log packet contents.** This stream carries login credentials, and the
nParse+ host mirrors its logger tree to ``nparseplus.log`` on disk. The C
reference carries a debug hex dump (``protocol.c:12-49``); it has no descendant
here, at any level, in any build. Opcodes, sequence numbers and lengths only.
``tests/test_no_logging.py`` asserts this rather than trusting convention.

Endianness is mixed, and it is the easiest thing in the format to get wrong:
protocol headers are big-endian, application fields are little-endian. See
``_APP_OPCODE_*`` and ``_pack_server_count`` below.
"""

from __future__ import annotations

import contextlib
import enum
import logging
import select
import socket
import struct
import threading
import time

__all__ = [
    "ACCEPTED_SERVER_PREFIXES",
    "DEFAULT_LOGIN_HOST",
    "DEFAULT_LOGIN_PORT",
    "LISTEN_HOST",
    "LoginCodec",
    "LoginProxy",
    "ProxyError",
    "ProxyStatus",
    "ResolveError",
]

_log = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Protocol constants
# --------------------------------------------------------------------------

#: Server names we keep. A record survives the filter when its **server name**
#: starts with one of these, compared case-insensitively.
#:
#: One named constant rather than literals buried in the codec, so the accepted
#: set can change without anyone touching parsing code. Zaela's C hard-codes a
#: single case-*sensitive* 12-byte compare against ``"Project 1999"``
#: (``sequence.h:9``, ``sequence.c:240``); EQTool's C# port also accepts
#: ``"An Interesting"`` and compares with ``OrdinalIgnoreCase``. We take the
#: broader, case-insensitive reading: a player who cannot see their server is
#: exactly the failure this add-on removes, so err toward showing one.
#:
#: Entries must be lowercase — the comparison lowercases the candidate only.
ACCEPTED_SERVER_PREFIXES: tuple[str, ...] = ("project 1999", "an interesting")

#: Where the game client is told to connect. See ``LoginProxy`` for why this is
#: loopback and never ``0.0.0.0``.
LISTEN_HOST = "127.0.0.1"

DEFAULT_LOGIN_HOST = "login.eqemulator.net"
DEFAULT_LOGIN_PORT = 5998

# Protocol opcodes, big-endian at offset 0 of every datagram.
OP_SESSION_RESPONSE = 0x02
OP_COMBINED = 0x03
OP_SESSION_DISCONNECT = 0x05
OP_PACKET = 0x09
OP_FRAGMENT = 0x0D
OP_ACK = 0x15

#: Application opcode for ServerListResponse. Unlike the protocol opcode this is
#: **little-endian** on the wire: the C compares ``frag->appOpcode != 0x18``
#: through a packed struct with no byte swap (``sequence.c:202``), so the bytes
#: at fragment offset 8..9 are ``18 00``, not ``00 18``.
APP_OP_SERVER_LIST_RESPONSE = 0x18

# Header sizes, from the packed structs at ``sequence.h:29-43``.
# Note FIRST_FRAG_HEADER includes the 2-byte app opcode: every use of
# ``sizeof(FirstFrag)`` in the C strips it along with the header.
FIRST_FRAG_HEADER = 10  # protocolOpcode[2] sequence[2] totalLen[4] appOpcode[2]
FRAG_HEADER = 4  # protocolOpcode[2] sequence[2]

# The reassembled server-list payload: 16 opaque header bytes, the server's own
# 4-byte count (which we discard and replace), then variable-length records.
SERVER_LIST_HEADER_LEN = 16
SERVER_LIST_RECORDS_OFFSET = 20

#: Smallest believable ``totalLen``: the preamble above plus the app opcode that
#: ``totalLen`` also counts. A list of zero servers is legal; a shorter one is not.
MIN_SERVER_LIST_LEN = SERVER_LIST_RECORDS_OFFSET + 2

# Datagram sizing the login server actually uses. Only used as a sanity bound on
# the fragment count now — see ``_begin_fragment_run`` for why completion is
# driven by accumulated bytes instead.
ASSUMED_DATAGRAM_SIZE = 512
FIRST_FRAG_PAYLOAD = ASSUMED_DATAGRAM_SIZE - 8  # 504; totalLen counts the app opcode
LATER_FRAG_PAYLOAD = ASSUMED_DATAGRAM_SIZE - FRAG_HEADER  # 508

# --------------------------------------------------------------------------
# Resource bounds
# --------------------------------------------------------------------------
# None of these exist in either reference implementation. The C indexes a heap
# array by raw wire sequence and grows it toward 65536 slots, never clearing it
# after a successful reassembly; it reassembles into a ``malloc(totalLen)`` sized
# by a number the peer chose; and it builds its reply in a fixed 512-byte *stack*
# array with no bounds check at all. A broken or hostile peer must not be able to
# make us allocate arbitrarily, so every one of those is capped here and every
# cap is tested.

#: Largest datagram we will accept. Matches the C's ``BUFFER_SIZE``.
MAX_DATAGRAM = 2048

#: Most out-of-order packets we will hold before giving up on a run.
MAX_BUFFERED_PACKETS = 512

#: Largest server list we will reassemble. The real one is ~6 KB, so this is
#: already absurdly generous; it exists to bound a peer that lies about it.
MAX_REASSEMBLY_BYTES = 128 * 1024

#: Sanity bound on a fragment run. Kept equal to the packet window, since a run
#: longer than the window could never be held whole anyway.
MAX_FRAGMENTS = MAX_BUFFERED_PACKETS

#: How deep nested ``0x03`` combined packets may nest. The C recurses through
#: ``recv_from_remote`` with no depth limit (``sequence.c:189``).
MAX_COMBINED_DEPTH = 4

#: Largest reply we will synthesize, guarding the record-copy loop.
MAX_REPLY_BYTES = 16 * 1024

#: How long a quiet client keeps its session before a new source address is
#: treated as a fresh client. Matches the C's SESSION_TIMEOUT_SECONDS.
SESSION_TIMEOUT_SECONDS = 60

_SEQ_MASK = 0xFFFF

_u16_be = struct.Struct(">H")
_u32_be = struct.Struct(">I")
_u32_le = struct.Struct("<I")


def _ceil_div(numerator: int, denominator: int) -> int:
    return -(-numerator // denominator)


def _pack_server_count(count: int) -> bytes:
    """Pack the kept-server count for offset 22 of the synthesized reply.

    **Little-endian, deliberately.** The C writes it as a native ``int``:
    ``*(int*)(&outBuffer[22]) = outCount;`` (``sequence.c:325``) with no
    ``htonl``, unlike the sequence two fields earlier which does go through
    ``ToNetworkShort``. Application-layer fields in this protocol are
    little-endian; only the protocol header is big-endian. Writing this
    big-endian instead produces a packet the client reads as ~285 million
    servers, which is not a subtle failure but is a silent one.
    """
    return _u32_le.pack(count & 0xFFFFFFFF)


class ProxyStatus(enum.Enum):
    """What the proxy is doing, for the settings page to render.

    Every one of these is a distinct thing the player may need to act on, so
    none of them may be collapsed into a generic failure — silence here means a
    blank server list and no clue why.
    """

    STOPPED = "stopped"
    LISTENING = "listening"
    NO_EQ_DIR = "no_eq_dir"
    NOT_CONFIGURED = "not_configured"
    PORT_IN_USE = "port_in_use"
    ERROR = "error"


class ProxyError(Exception):
    """The proxy could not start."""


class PortInUseError(ProxyError):
    """The listen port is already taken — commonly by Zaela's own binary."""


class BindError(ProxyError):
    """The listen socket could not be bound for some other reason."""


class ResolveError(ProxyError):
    """The upstream login server hostname could not be resolved."""


class _Buffered:
    """One datagram held while we wait for the rest of its run.

    ``payload`` is only populated for fragments; ordinary packets need their
    length recorded for the in-order scan but their bytes are forwarded
    immediately and never retained. That mirrors the C, where ``p->data`` stays
    ``NULL`` for ``OP_Packet`` (``sequence.c:88``), and it means we hold no more
    credential-bearing bytes than the job strictly requires.
    """

    __slots__ = ("length", "payload")

    def __init__(self, length: int, payload: bytes | None = None) -> None:
        self.length = length
        self.payload = payload


class LoginCodec:
    """The protocol half of the middleman: bytes in, bytes out, no sockets.

    Direction is implied by the method, matching the reference implementation
    where everything arriving from the login server is destined for the client
    and everything from the client is destined for the login server:

    - :meth:`from_remote` returns the datagrams to send to the **client**.
    - :meth:`from_local` returns the datagrams to send to the **login server**.

    Both are total: any input at all produces a (possibly empty) list and never
    raises. When something is malformed or exceeds a bound, the codec forwards
    what it can and abandons the filter rather than emitting a packet it is not
    sure about — a forwarded packet the client ignores is recoverable, an
    invented one is not.
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._log = logger or _log
        self.in_session = False
        self.reset()

    # -- state -------------------------------------------------------------

    def reset(self) -> None:
        """Drop all sequence state. Called on session start, end and rebase."""
        #: What the client believes comes next. Every datagram we hand the
        #: client is stamped with this, then it increments.
        self.seq_to_local = 0
        #: The next real sequence we expect from the login server.
        self.seq_from_remote = 0
        self._packets: dict[int, _Buffered] = {}
        self._clear_fragment_run()

    def _clear_fragment_run(self) -> None:
        self._frag_start = 0
        self._frag_count = 0
        self._frag_bytes = 0
        self._frag_total = 0

    @property
    def buffered_bytes(self) -> int:
        """Bytes currently retained for reassembly. Asserted against the cap."""
        return sum(len(p.payload) for p in self._packets.values() if p.payload)

    # -- login server -> client -------------------------------------------

    def from_remote(self, data: bytes, _depth: int = 0) -> list[bytes]:
        """Handle a datagram from the login server; return what the client gets."""
        if len(data) < 2 or len(data) > MAX_DATAGRAM:
            # Too short to carry an opcode, or larger than we will look at.
            # The C drops sub-2-byte reads (``connection.c:67``); we forward
            # instead, because an opcode we cannot read is by definition one we
            # do not handle, and unhandled traffic belongs to the client.
            return [data] if data else []

        opcode = _u16_be.unpack_from(data, 0)[0]

        if opcode == OP_SESSION_RESPONSE:
            self.in_session = True
            self.reset()
            return [data]

        if opcode == OP_COMBINED:
            # The wrapper is never forwarded; its pieces are, individually.
            return self._recv_combined(data, _depth)

        if opcode == OP_PACKET:
            return self._recv_packet(data)

        if opcode == OP_FRAGMENT:
            # Never forwarded. Filtering these is the entire point of the proxy.
            return self._recv_fragment(data)

        return [data]

    def _recv_combined(self, data: bytes, depth: int) -> list[bytes]:
        """Unwrap an ``0x03`` combined packet and dispatch each sub-packet.

        Layout after the 2-byte opcode: a run of ``[1-byte length][payload]``.
        A zero length or one that would overrun the buffer ends the run — this
        input is attacker-influenced and must be dropped, never trusted.
        """
        if depth >= MAX_COMBINED_DEPTH:
            # Deliberate: the C recurses through ``recv_from_remote`` with no
            # depth limit (``sequence.c:189``). Bounded in practice by the
            # 255-byte sub-length shrinking each level, but "bounded in
            # practice" is not a property worth relying on.
            self._log.warning("combined packet nested past depth %d; dropped", depth)
            return []

        out: list[bytes] = []
        for sub in _iter_combined(data):
            out.extend(self.from_remote(sub, depth + 1))
        return out

    def _recv_packet(self, data: bytes) -> list[bytes]:
        """Buffer an ``0x09`` packet, restamp its sequence, forward it."""
        if len(data) < 4:
            return [data]

        seq = _u16_be.unpack_from(data, 2)[0]
        self._remember(seq, _Buffered(len(data)))

        # Restamp for the client. This happens unconditionally and before the
        # in-order scan below, matching ``sequence.c:113``.
        stamped = data[:2] + _u16_be.pack(self.seq_to_local) + data[4:]
        self.seq_to_local = (self.seq_to_local + 1) & _SEQ_MASK

        out = [stamped]
        if seq == self.seq_from_remote:
            out.extend(self._advance_in_order(seq))
        return out

    def _advance_in_order(self, start: int) -> list[bytes]:
        """Walk contiguous received sequences, consuming any server-list run.

        **Deliberate divergence: we stop at the first gap.** The C's scan is
        ``for (i = val; i < seq->count; i++)`` guarded by ``if (len > 0)``
        (``sequence.c:118-130``) — a missing slot does *not* break the loop, so
        it keeps scanning and advances ``seqFromRemote`` past the hole for any
        later-arrived slot. Since every client ACK is rewritten to
        ``seq_from_remote - 1``, that makes us acknowledge datagrams the login
        server never actually delivered, defeating the only recovery the client
        had. Stopping at the gap keeps the acknowledgement honest.
        """
        out: list[bytes] = []
        seq = start
        for _ in range(MAX_BUFFERED_PACKETS):
            held = self._packets.get(seq)
            if held is None:
                break
            self.seq_from_remote = (self.seq_from_remote + 1) & _SEQ_MASK
            if held.payload is not None and self._begin_fragment_run(held.payload):
                out.extend(self._try_complete_run())
                break
            # Consumed and forwarded already; nothing will ask for it again.
            # The C leaves every slot populated for the life of the session,
            # which is what makes its buffer grow without bound.
            del self._packets[seq]
            seq = (seq + 1) & _SEQ_MASK
        return out

    def _recv_fragment(self, data: bytes) -> list[bytes]:
        """Buffer an ``0x0d`` fragment. Never forwarded; may emit the filtered list."""
        if len(data) < FRAG_HEADER:
            return []

        seq = _u16_be.unpack_from(data, 2)[0]
        if not self._remember(seq, _Buffered(len(data), bytes(data))):
            return []

        if seq == self.seq_from_remote:
            self._begin_fragment_run(data)
            # The C does not check for completion here (``sequence.c:142-145``),
            # which is harmless only because a server list is never one
            # fragment. Checking costs nothing and closes the case.
            return self._try_complete_run()
        if self._frag_count > 0:
            return self._try_complete_run()
        return []

    def _remember(self, seq: int, held: _Buffered) -> bool:
        """Store a datagram against its sequence, refusing to grow without bound."""
        if seq not in self._packets and len(self._packets) >= MAX_BUFFERED_PACKETS:
            self._log.warning(
                "reassembly window full at %d packets; dropping run", len(self._packets)
            )
            self._packets.clear()
            self._clear_fragment_run()
            return False
        if held.payload is not None and (
            self.buffered_bytes + len(held.payload) > MAX_REASSEMBLY_BYTES
        ):
            self._log.warning("reassembly byte cap reached; dropping run")
            self._packets.clear()
            self._clear_fragment_run()
            return False
        self._packets[seq] = held
        return True

    def _begin_fragment_run(self, data: bytes) -> bool:
        """If ``data`` is the first fragment of a ServerListResponse, start a run.

        Returns True when a run was started, so the caller knows this sequence
        opens something we intend to swallow.
        """
        if len(data) < FIRST_FRAG_HEADER:
            return False

        # Little-endian: see APP_OP_SERVER_LIST_RESPONSE.
        app_opcode = int.from_bytes(data[8:10], "little")
        if app_opcode != APP_OP_SERVER_LIST_RESPONSE:
            # Not ours. Leave the normal path alone.
            return False

        total_len = _u32_be.unpack_from(data, 4)[0]

        # A list smaller than its own fixed preamble cannot be one. Note the
        # bound is the preamble, NOT the 504-byte first-fragment capacity: the C
        # effectively assumes the latter and computes the difference in unsigned
        # arithmetic (``sequence.c:206``), so any totalLen below 504 wraps to a
        # gigantic fragment count. Since completion here is byte-driven rather
        # than count-driven, nothing about this needs a 512-byte datagram.
        if total_len < MIN_SERVER_LIST_LEN or total_len > MAX_REASSEMBLY_BYTES:
            self._log.warning("server list declares implausible length %d; ignored", total_len)
            return False

        estimated = 1 + _ceil_div(max(0, total_len - FIRST_FRAG_PAYLOAD), LATER_FRAG_PAYLOAD)
        if estimated > MAX_FRAGMENTS:
            self._log.warning("server list would need %d fragments; ignored", estimated)
            return False

        self._frag_start = _u16_be.unpack_from(data, 2)[0]
        # Only ever a sanity bound and an "a run is open" flag; the authority on
        # completion is ``total_len`` against the bytes that actually arrive.
        self._frag_count = max(1, estimated)
        self._frag_total = total_len
        self._frag_bytes = 0
        self._log.debug(
            "server list run opened at seq %d: %d bytes, ~%d fragments",
            self._frag_start,
            total_len,
            estimated,
        )
        return True

    def _try_complete_run(self) -> list[bytes]:
        """Emit the filtered list if every fragment of the current run has arrived.

        **Deliberate divergence: completion is decided by accumulated bytes,
        not by the fragment count.** The C waits for exactly ``fragCount``
        contiguous slots, where ``fragCount = (totalLen - 504) / 508 + 2``
        (``sequence.c:206``, ``sequence.c:222-234``). That formula over-counts
        by one whenever ``totalLen - 504`` is an exact positive multiple of 508
        — ``totalLen = 1012`` yields 3 when the list really arrives in 2
        fragments — and ``check_fragment_finished`` then waits forever for a
        fragment that will never be sent. The result is a permanently blank
        server-select screen: precisely the bug this add-on exists to fix,
        reintroduced roughly one list in 508. It also breaks outright if the
        login server ever uses a datagram size other than 512, since both magic
        numbers are derived from it.

        Summing what actually arrived has neither problem, and the wire's own
        ``totalLen`` is the authority on when we have it all.
        """
        if self._frag_count == 0:
            return []

        first = self._packets.get(self._frag_start)
        if first is None or first.payload is None:
            return []

        # totalLen counts the app opcode, so the first fragment contributes its
        # length less the 8 header bytes that precede that opcode.
        got = first.length - (FIRST_FRAG_HEADER - 2)
        index = self._frag_start
        ordered = [first]

        while got < self._frag_total:
            if len(ordered) >= MAX_FRAGMENTS:
                return []
            index = (index + 1) & _SEQ_MASK
            held = self._packets.get(index)
            if held is None or held.payload is None:
                return []  # still waiting
            got += held.length - FRAG_HEADER
            ordered.append(held)

        if got != self._frag_total:
            # Overshot: a fragment was longer than the declared total allows.
            self._log.warning(
                "server list reassembled to %d bytes, expected %d; abandoned",
                got,
                self._frag_total,
            )
            self._clear_fragment_run()
            return []

        return self._filter_server_list(ordered, index)

    def _filter_server_list(self, ordered: list[_Buffered], last_index: int) -> list[bytes]:
        """Reassemble, drop non-P99 records, and synthesize the single reply."""
        payload = bytearray()
        payload += ordered[0].payload[FIRST_FRAG_HEADER:]  # type: ignore[operator]
        for held in ordered[1:]:
            payload += held.payload[FRAG_HEADER:]  # type: ignore[index]

        # The payload excludes the app opcode, so it is totalLen - 2 long.
        expected = self._frag_total - 2
        if len(payload) < SERVER_LIST_RECORDS_OFFSET or len(payload) < expected:
            self._log.warning("server list payload truncated at %d bytes; abandoned", len(payload))
            self._rebase(last_index)
            return []
        del payload[expected:]

        kept = self._select_records(payload)
        if kept is None:
            # Malformed records. Abandon the filter rather than emit a list we
            # are not sure about; the run is consumed either way, so rebasing
            # keeps the sequence arithmetic coherent.
            self._rebase(last_index)
            return []

        records, count = kept
        reply = bytearray()
        reply += b"\x00\x09"  # OP_Packet
        reply += _u16_be.pack(self.seq_to_local)
        reply += b"\x18\x00"  # OP_ServerListResponse, little-endian
        reply += payload[:SERVER_LIST_HEADER_LEN]  # 16 opaque header bytes, verbatim
        reply += _pack_server_count(count)
        reply += records
        self.seq_to_local = (self.seq_to_local + 1) & _SEQ_MASK

        self._log.info(
            "filtered server list: kept %d of the listed servers, %d bytes in one packet",
            count,
            len(reply),
        )
        self._rebase(last_index)
        return [bytes(reply)]

    def _select_records(self, payload: bytearray) -> tuple[bytes, int] | None:
        """Return the kept records verbatim and their count, or None if malformed.

        Each record is variable-length, in order: IP address (NUL-terminated),
        ListId (int32), RuntimeId (int32), server name (NUL-terminated),
        language (NUL-terminated), region (NUL-terminated), status (int32),
        player count (int32).

        Every field advance is bounds-checked. The C checks none of them and
        walks off the end of its buffer on a truncated final record
        (``sequence.c:303-322``); EQTool additionally advances one byte too far
        past the server name, a drift that is latent only because the following
        non-empty language string absorbs it. Neither is reproduced.
        """
        end = len(payload)
        pos = SERVER_LIST_RECORDS_OFFSET
        out = bytearray()
        count = 0

        while pos < end:
            start = pos
            pos = _skip_cstring(payload, pos, end)  # IP address
            if pos < 0:
                return None
            pos += 8  # ListId, RuntimeId
            if pos > end:
                return None

            name_start = pos
            pos = _skip_cstring(payload, pos, end)  # server name
            if pos < 0:
                return None
            name = bytes(payload[name_start : pos - 1])

            pos = _skip_cstring(payload, pos, end)  # language
            if pos < 0:
                return None
            pos = _skip_cstring(payload, pos, end)  # region
            if pos < 0:
                return None

            pos += 8  # Status, player count
            if pos > end:
                return None

            if _is_accepted(name):
                if len(out) + (pos - start) > MAX_REPLY_BYTES:
                    self._log.warning("kept records exceed the reply cap; abandoned")
                    return None
                out += payload[start:pos]
                count += 1

        return bytes(out), count

    def _rebase(self, last_index: int) -> None:
        """Consume the fragment run and drop everything buffered for it.

        The sequence the login server will send next is one past the last
        fragment we consumed; the client, meanwhile, has seen only the single
        packet we synthesized. That intentional divergence is what the ACK
        rewrite in :meth:`_adjust_ack` exists to paper over.

        Clearing the buffer is EQTool's addition, and it is the right call:
        Zaela's C indexes its packet array by raw wire sequence and never resets
        it, so a second server-list request inside one session grows it without
        bound and leaves stale entries the in-order scan then trips over.
        """
        self.seq_from_remote = (last_index + 1) & _SEQ_MASK
        self._packets.clear()
        self._clear_fragment_run()

    # -- client -> login server -------------------------------------------

    def from_local(self, data: bytes) -> list[bytes]:
        """Handle a datagram from the game client; return what the server gets.

        Nothing from the client is ever swallowed — every branch forwards.
        """
        if len(data) < 2 or len(data) > MAX_DATAGRAM:
            return [data] if data else []

        opcode = _u16_be.unpack_from(data, 0)[0]

        if opcode == OP_COMBINED:
            return [self._adjust_combined(data)]

        if opcode == OP_SESSION_DISCONNECT:
            self.in_session = False
            self.reset()
            return [data]

        if opcode == OP_ACK:
            return [self._adjust_ack(data)]

        return [data]

    def _adjust_ack(self, data: bytes) -> bytes:
        """Rewrite a client ACK to the last sequence the server really sent.

        Collapsing ~10 fragments into 1 packet desynchronises the client's view
        of the sequence numbers, so an ACK carrying the client's idea of the
        stream would acknowledge packets the login server never sent. Rewriting
        to ``seq_from_remote - 1`` keeps the server's side of the conversation
        truthful. The mask matters: at ``seq_from_remote == 0`` this must wrap
        to ``0xFFFF``, and EQTool's signed ``short`` is exactly where that goes
        wrong.
        """
        if len(data) < 4:
            return data
        acked = (self.seq_from_remote - 1) & _SEQ_MASK
        return data[:2] + _u16_be.pack(acked) + data[4:]

    def _adjust_combined(self, data: bytes) -> bytes:
        """Rewrite any ACK nested inside a combined packet, forwarding the rest.

        Unlike the remote direction this does not recurse — it patches in place
        and the whole original datagram is forwarded, matching
        ``sequence.c:148-172``.
        """
        out = bytearray(data)
        for start, length in _iter_combined_spans(data):
            if length >= 4 and _u16_be.unpack_from(data, start)[0] == OP_ACK:
                patched = self._adjust_ack(bytes(data[start : start + length]))
                out[start : start + length] = patched
        return bytes(out)


def _iter_combined_spans(data: bytes):
    """Yield ``(offset, length)`` for each sub-packet of an ``0x03`` datagram.

    Stops on a zero length or a length that would overrun the buffer. Malformed
    input must be dropped quietly, never crash: this is the one place a remote
    peer directly controls a length field we index with.
    """
    end = len(data)
    if end < 4:
        return
    pos = 2
    while pos < end:
        sublen = data[pos]
        pos += 1
        if sublen == 0 or pos + sublen > end:
            return
        yield pos, sublen
        pos += sublen


def _iter_combined(data: bytes):
    for start, length in _iter_combined_spans(data):
        yield bytes(data[start : start + length])


def _skip_cstring(buf: bytearray, pos: int, end: int) -> int:
    """Return the offset just past the NUL of the string at ``pos``, or -1."""
    if pos >= end:
        return -1
    nul = buf.find(0, pos, end)
    if nul < 0:
        return -1
    return nul + 1


def _is_accepted(name: bytes) -> bool:
    """Whether a server record's name matches one of the accepted prefixes."""
    try:
        decoded = name.decode("latin-1").lower()
    except (UnicodeDecodeError, AttributeError):  # pragma: no cover - latin-1 is total
        return False
    return decoded.startswith(ACCEPTED_SERVER_PREFIXES)


class LoginProxy:
    """The UDP relay: two sockets, one thread, one :class:`LoginCodec`.

    **Binds loopback only, never ``INADDR_ANY``.** Both reference
    implementations bind all interfaces (``connection.c:34``,
    ``LoginMiddlemand.cs:100``). Loopback keeps an unauthenticated UDP relay off
    the LAN, and it is the reason macOS never raises a firewall prompt — Apple's
    firewall does not prompt for loopback binds. The client connects to
    ``localhost``, so nothing is lost.

    **That choice is why this uses two sockets where the C uses one.** A socket
    bound to ``127.0.0.1`` cannot send to a public address, so the upstream leg
    needs its own socket on an ephemeral any-interface port. The C multiplexes a
    single ``INADDR_ANY`` socket and tells client from server by comparing
    source addresses; here the socket a datagram arrives on *is* the direction,
    which is both simpler and harder to spoof.
    """

    def __init__(
        self,
        listen_port: int,
        remote_host: str = DEFAULT_LOGIN_HOST,
        remote_port: int = DEFAULT_LOGIN_PORT,
        *,
        logger: logging.Logger | None = None,
    ) -> None:
        self.listen_port = listen_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self._log = logger or _log
        self._codec = LoginCodec(self._log)
        self._client_sock: socket.socket | None = None
        self._remote_sock: socket.socket | None = None
        self._remote_addr: tuple[str, int] | None = None
        self._client_addr: tuple[str, int] | None = None
        self._thread: threading.Thread | None = None
        self._last_recv = 0.0
        self._stop = threading.Event()
        self._status = ProxyStatus.STOPPED
        self._error: str | None = None

    # -- lifecycle ---------------------------------------------------------

    @property
    def status(self) -> ProxyStatus:
        return self._status

    @property
    def error(self) -> str | None:
        """Human-readable detail for :attr:`status`, when there is any."""
        return self._error

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def bound_address(self) -> tuple[str, int] | None:
        """The address the client socket is actually bound to, once started.

        Mostly here so tests can assert the loopback bind and use an ephemeral
        port; also what the settings page reports when the listen port came from
        ``eqhost.txt`` rather than a default.
        """
        if self._client_sock is None:
            return None
        try:
            host, port = self._client_sock.getsockname()[:2]
        except OSError:  # pragma: no cover - socket closed under us
            return None
        return host, port

    def start(self) -> None:
        """Bind both sockets and start the relay thread.

        Raises rather than degrading silently: a proxy that thinks it is running
        and is not leaves the player at the blank screen with no explanation.
        """
        if self.running:
            return

        try:
            info = socket.getaddrinfo(
                self.remote_host, self.remote_port, socket.AF_INET, socket.SOCK_DGRAM
            )
        except OSError as exc:
            self._status = ProxyStatus.ERROR
            self._error = f"could not resolve {self.remote_host}: {exc}"
            raise ResolveError(self._error) from exc
        self._remote_addr = info[0][4][:2]

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # LISTEN_HOST, never "" or "0.0.0.0". See the class docstring.
            client.bind((LISTEN_HOST, self.listen_port))
        except OSError as exc:
            client.close()
            self._status = ProxyStatus.ERROR
            if exc.errno in (48, 98, 10048):  # EADDRINUSE across platforms
                self._status = ProxyStatus.PORT_IN_USE
                self._error = (
                    f"port {self.listen_port} is already in use — another copy of the "
                    f"login middleman may already be running"
                )
                raise PortInUseError(self._error) from exc
            self._error = f"could not bind {LISTEN_HOST}:{self.listen_port}: {exc}"
            raise BindError(self._error) from exc

        remote = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Any interface, ephemeral port: this leg has to reach the internet.
            remote.bind(("", 0))
        except OSError as exc:
            client.close()
            remote.close()
            self._status = ProxyStatus.ERROR
            self._error = f"could not open the upstream socket: {exc}"
            raise BindError(self._error) from exc

        self._client_sock = client
        self._remote_sock = remote
        self._client_addr = None
        self._last_recv = 0.0
        self._codec.reset()
        self._stop.clear()
        self._status = ProxyStatus.LISTENING
        self._error = None

        self._thread = threading.Thread(target=self._serve, name="p99-login-proxy", daemon=True)
        self._thread.start()
        self._log.info(
            "listening on %s:%d, forwarding to %s:%d",
            LISTEN_HOST,
            self.listen_port,
            self.remote_host,
            self.remote_port,
        )

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the relay and join the thread.

        The blocking read is unblocked deliberately — the stop flag ends the
        select loop and closing both sockets wakes it immediately. Nothing here
        relies on daemon-thread death at interpreter exit, because the host
        calls this at app quit and expects the port released.
        """
        self._stop.set()
        for sock in (self._client_sock, self._remote_sock):
            if sock is not None:
                with contextlib.suppress(OSError):  # close is best-effort
                    sock.close()
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout)
            if thread.is_alive():  # pragma: no cover - needs a wedged syscall
                self._log.warning("relay thread did not exit within %.1fs", timeout)
        self._client_sock = None
        self._remote_sock = None
        if self._status is ProxyStatus.LISTENING:
            self._status = ProxyStatus.STOPPED
        self._log.info("stopped")

    # -- the loop ----------------------------------------------------------

    def _serve(self) -> None:
        client = self._client_sock
        remote = self._remote_sock
        assert client is not None and remote is not None

        while not self._stop.is_set():
            try:
                readable, _, _ = select.select([client, remote], [], [], 0.5)
            except (OSError, ValueError):
                # Sockets closed under us by stop(). That is the shutdown path.
                break

            for sock in readable:
                try:
                    data, addr = sock.recvfrom(MAX_DATAGRAM)
                except OSError:
                    if not self._stop.is_set():  # pragma: no cover - transient
                        self._log.debug("recvfrom failed; continuing")
                    continue

                try:
                    if sock is remote:
                        self._handle_remote(data, addr)
                    else:
                        self._handle_client(data, addr)
                    # Stamped for either direction, as the C does
                    # (``connection.c:97``): a client that is merely quiet while
                    # the server talks has not gone away.
                    self._last_recv = time.monotonic()
                except Exception:  # pragma: no cover - defence in depth
                    # A codec bug must not take the thread down and strand the
                    # player at a blank screen. Note the absence of the packet.
                    self._log.exception("relay error on a %d-byte datagram", len(data))

    def _handle_client(self, data: bytes, addr: tuple[str, int]) -> None:
        now = time.monotonic()
        if addr != self._client_addr:
            # A new source address only counts as a new client when we are not
            # mid-session or the old one has gone quiet, matching the C
            # (``connection.c:91``). Resetting on every address change would let
            # a single stray datagram wipe a live session's sequence state.
            idle = now - self._last_recv
            if not self._codec.in_session or idle > SESSION_TIMEOUT_SECONDS:
                self._log.info("client connected from port %d", addr[1])
                self._client_addr = addr
                self._codec.reset()
            else:
                self._log.debug("ignoring a datagram from a second local sender")
                return
        for out in self._codec.from_local(data):
            self._send(self._remote_sock, out, self._remote_addr)

    def _handle_remote(self, data: bytes, addr: tuple[str, int]) -> None:
        if self._remote_addr is not None and addr[0] != self._remote_addr[0]:
            self._log.debug("ignoring a datagram from an unexpected upstream address")
            return
        for out in self._codec.from_remote(data):
            self._send(self._client_sock, out, self._client_addr)

    def _send(
        self,
        sock: socket.socket | None,
        data: bytes,
        addr: tuple[str, int] | None,
    ) -> None:
        if sock is None or addr is None:
            return
        try:
            sock.sendto(data, addr)
        except OSError as exc:  # pragma: no cover - transient network failure
            self._log.warning("send of %d bytes failed: %s", len(data), exc)
