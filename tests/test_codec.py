"""Byte-level tests for the protocol codec.

There are no tests for the middleman in Zaela's C or in EQTool's C# port, so
there is no corpus to port and these are the first. Everything here is
synthesized bytes checked against exact expected bytes — the failure mode this
guards against is a blank server-select screen, which produces no traceback and
no log line, so "it ran without raising" proves nothing at all.
"""

from __future__ import annotations

import struct

import pytest

from p99_login_proxy.proxy import (
    APP_OP_SERVER_LIST_RESPONSE,
    ASSUMED_DATAGRAM_SIZE,
    MAX_BUFFERED_PACKETS,
    MAX_REASSEMBLY_BYTES,
    LoginCodec,
)

# --------------------------------------------------------------------------
# Builders — synthesize the wire format the login server would send
# --------------------------------------------------------------------------

#: 16 opaque bytes the proxy must copy through verbatim without interpreting.
HEADER16 = bytes(range(0x40, 0x50))


def record(
    name: str,
    *,
    ip: str = "63.235.51.100",
    language: str = "US",
    region: str = "United States",
    list_id: int = 1,
    runtime_id: int = 2,
    status: int = 1,
    players: int = 42,
) -> bytes:
    """One variable-length server record, in the documented field order."""
    return (
        ip.encode() + b"\0"
        + struct.pack("<i", list_id)
        + struct.pack("<i", runtime_id)
        + name.encode() + b"\0"
        + language.encode() + b"\0"
        + region.encode() + b"\0"
        + struct.pack("<i", status)
        + struct.pack("<i", players)
    )  # fmt: skip


def payload(records: list[bytes], header: bytes = HEADER16) -> bytes:
    """The reassembled ServerListResponse body, excluding the app opcode."""
    assert len(header) == 16
    return header + struct.pack("<I", len(records)) + b"".join(records)


def fragments(
    body: bytes, start_seq: int = 0, datagram: int = ASSUMED_DATAGRAM_SIZE
) -> list[bytes]:
    """Split a payload into 0x0d fragment datagrams the way the server does.

    ``totalLen`` counts the app opcode, the first fragment carries an 8-byte
    header before it and later fragments a 4-byte one.
    """
    full = struct.pack("<H", APP_OP_SERVER_LIST_RESPONSE) + body
    total_len = len(full)
    first_cap = datagram - 8
    later_cap = datagram - 4

    out = [
        b"\x00\x0d"
        + struct.pack(">H", start_seq & 0xFFFF)
        + struct.pack(">I", total_len)
        + full[:first_cap]
    ]
    pos = first_cap
    seq = start_seq + 1
    while pos < len(full):
        chunk = full[pos : pos + later_cap]
        out.append(b"\x00\x0d" + struct.pack(">H", seq & 0xFFFF) + chunk)
        pos += len(chunk)
        seq += 1
    return out


def packet(seq: int, body: bytes = b"\xff\xff") -> bytes:
    """An ordinary 0x09 OP_Packet."""
    return b"\x00\x09" + struct.pack(">H", seq & 0xFFFF) + body


def combined(*subs: bytes) -> bytes:
    """An 0x03 combined wrapper around the given sub-packets."""
    out = bytearray(b"\x00\x03")
    for sub in subs:
        out.append(len(sub))
        out += sub
    return bytes(out)


def ack(seq: int) -> bytes:
    return b"\x00\x15" + struct.pack(">H", seq & 0xFFFF)


def filler_record(size: int) -> bytes:
    """A well-formed, non-P99 record of exactly ``size`` bytes.

    Padding a fixture with zero bytes instead would be padding it with *records*
    — twenty zero bytes parse as one record of empty strings — and any leftover
    that does not divide evenly reads as a truncated record, which the codec
    correctly refuses. Sizing a real record is the honest way to hit an exact
    payload length.
    """
    fixed = len(record("", ip="", language="", region=""))
    assert size >= fixed, f"a record cannot be shorter than {fixed} bytes"
    return record("", ip="", language="", region="R" * (size - fixed))


def big_list(n_p99: int = 2, n_other: int = 12, pad: int = 60) -> tuple[bytes, list[bytes]]:
    """A realistic list: a couple of P99 servers among many others.

    ``pad`` inflates the region string so the list spans several fragments,
    which is the whole reason this proxy exists.
    """
    kept = [record(f"Project 1999 {i}", region="R" * pad) for i in range(n_p99)]
    dropped = [record(f"Some Other Server {i}", region="R" * pad) for i in range(n_other)]
    # Interleave so the filter cannot pass by accident on ordering.
    records: list[bytes] = []
    for index in range(max(len(kept), len(dropped))):
        if index < len(dropped):
            records.append(dropped[index])
        if index < len(kept):
            records.append(kept[index])
    return payload(records), kept


def drive(codec: LoginCodec, datagrams: list[bytes]) -> list[bytes]:
    out: list[bytes] = []
    for data in datagrams:
        out.extend(codec.from_remote(data))
    return out


def parse_reply(reply: bytes) -> tuple[int, bytes, bytes]:
    """Return ``(count, header16, records)`` from a synthesized reply."""
    assert reply[0:2] == b"\x00\x09"
    assert reply[4:6] == b"\x18\x00"
    count = struct.unpack_from("<I", reply, 22)[0]
    return count, reply[6:22], reply[26:]


# --------------------------------------------------------------------------
# The happy path
# --------------------------------------------------------------------------


def test_multi_fragment_list_reassembles_and_filters():
    body, kept = big_list()
    frags = fragments(body)
    assert len(frags) >= 3, "fixture should span several fragments"

    codec = LoginCodec()
    out = drive(codec, frags)

    assert len(out) == 1, "ten fragments in, exactly one packet out"
    count, header, records = parse_reply(out[0])
    assert count == len(kept)
    assert header == HEADER16, "the 16 header bytes are copied verbatim"
    assert records == b"".join(kept), "kept records are copied verbatim, in order"


def test_non_p99_records_are_dropped():
    body = payload([record("Some Other Server"), record("Project 1999"), record("EZ Server")])
    codec = LoginCodec()
    out = drive(codec, fragments(body, datagram=64))

    count, _, records = parse_reply(out[0])
    assert count == 1
    assert b"Project 1999" in records
    assert b"Some Other Server" not in records
    assert b"EZ Server" not in records


def test_server_count_is_little_endian_at_offset_22():
    """The single easiest byte-order mistake in the format to make.

    The C writes this as a native int with no htonl, unlike the sequence two
    fields earlier. Big-endian here yields a packet the client reads as ~285
    million servers.
    """
    body = payload([record(f"Project 1999 {i}") for i in range(3)])
    codec = LoginCodec()
    out = drive(codec, fragments(body, datagram=64))

    assert out[0][22:26] == b"\x03\x00\x00\x00"
    assert struct.unpack_from("<I", out[0], 22)[0] == 3
    assert struct.unpack_from(">I", out[0], 22)[0] != 3


def test_accepted_prefixes_are_case_insensitive_and_include_an_interesting():
    body = payload(
        [
            record("PROJECT 1999 Green"),
            record("an interesting server"),
            record("Project Zero"),
        ]
    )
    codec = LoginCodec()
    count, _, records = parse_reply(drive(codec, fragments(body, datagram=64))[0])
    assert count == 2
    assert b"Project Zero" not in records


def test_reply_layout_is_exact():
    body = payload([record("Project 1999")])
    codec = LoginCodec()
    codec.seq_to_local = 7
    reply = drive(codec, fragments(body, datagram=64))[0]

    assert reply[0] == 0x00
    assert reply[1] == 0x09  # OP_Packet
    assert reply[2:4] == struct.pack(">H", 7)  # sequence, big-endian
    assert reply[4] == 0x18  # OP_ServerListResponse
    assert reply[5] == 0x00
    assert reply[6:22] == HEADER16
    assert len(reply) == 26 + len(record("Project 1999"))


# --------------------------------------------------------------------------
# Sequence handling
# --------------------------------------------------------------------------


def test_packets_are_restamped_with_a_gapless_client_sequence():
    codec = LoginCodec()
    out = [codec.from_remote(packet(seq))[0] for seq in range(5)]
    assert [struct.unpack_from(">H", p, 2)[0] for p in out] == [0, 1, 2, 3, 4]


def test_the_synthesized_packet_continues_the_client_sequence():
    """Ten fragments collapse to one packet, so the client's count stays dense."""
    codec = LoginCodec()
    codec.from_remote(packet(0))  # client sees 0

    body, _ = big_list()
    frags = fragments(body, start_seq=1)
    out = drive(codec, frags)

    assert struct.unpack_from(">H", out[0], 2)[0] == 1, "next in the client's stream"
    # The server, meanwhile, has moved on by the whole run.
    assert codec.seq_from_remote == 1 + len(frags)

    nxt = codec.from_remote(packet(1 + len(frags)))[0]
    assert struct.unpack_from(">H", nxt, 2)[0] == 2, "client stream stays gapless"


def test_client_acks_are_rewritten_to_the_real_remote_sequence():
    codec = LoginCodec()
    for seq in range(4):
        codec.from_remote(packet(seq))
    assert codec.seq_from_remote == 4

    out = codec.from_local(ack(999))[0]
    assert struct.unpack_from(">H", out, 2)[0] == 3  # seq_from_remote - 1
    assert out[0:2] == b"\x00\x15"


def test_ack_rewrite_wraps_below_zero():
    """EQTool's signed short is exactly where this goes wrong."""
    codec = LoginCodec()
    assert codec.seq_from_remote == 0
    out = codec.from_local(ack(0))[0]
    assert struct.unpack_from(">H", out, 2)[0] == 0xFFFF


def test_sequences_wrap_past_0xffff():
    body = payload([record("Project 1999")])
    codec = LoginCodec()
    codec.seq_from_remote = 0xFFFE
    codec.seq_to_local = 0xFFFE

    out = drive(codec, fragments(body, start_seq=0xFFFE, datagram=64))
    assert len(out) == 1
    assert codec.seq_from_remote <= 0xFFFF
    assert codec.seq_to_local <= 0xFFFF


def test_short_ack_is_forwarded_untouched():
    codec = LoginCodec()
    assert codec.from_local(b"\x00\x15") == [b"\x00\x15"]


# --------------------------------------------------------------------------
# Combined packets
# --------------------------------------------------------------------------


def test_combined_from_remote_unwraps_and_forwards_each_piece():
    codec = LoginCodec()
    out = codec.from_remote(combined(packet(0), b"\x00\xaa\x01\x02", packet(1)))

    assert len(out) == 3, "the wrapper itself is never forwarded"
    assert out[0][0:2] == b"\x00\x09"
    assert out[1] == b"\x00\xaa\x01\x02", "unhandled opcodes pass through untouched"
    assert out[2][0:2] == b"\x00\x09"
    assert [struct.unpack_from(">H", out[i], 2)[0] for i in (0, 2)] == [0, 1]


def test_combined_from_remote_recurses():
    codec = LoginCodec()
    out = codec.from_remote(combined(combined(packet(0)), b"\x00\xaa"))
    assert len(out) == 2
    assert out[0][0:2] == b"\x00\x09"
    assert out[1] == b"\x00\xaa"


def test_combined_nesting_is_depth_limited():
    """The C recurses through recv_from_remote with no depth limit."""
    codec = LoginCodec()
    data = packet(0)
    for _ in range(12):
        data = combined(data) if len(data) < 250 else data
    # Deeply nested input must produce no output rather than recursing forever.
    assert codec.from_remote(data) == []


def test_combined_from_local_patches_acks_in_place_and_forwards_intact():
    codec = LoginCodec()
    for seq in range(3):
        codec.from_remote(packet(seq))

    original = combined(ack(500), b"\x00\xaa\x01")
    out = codec.from_local(original)

    assert len(out) == 1, "the client's wrapper is forwarded whole, not unwrapped"
    assert len(out[0]) == len(original)
    # The embedded ack has been rewritten; everything else is byte-identical.
    assert out[0][3:5] == b"\x00\x15"
    assert struct.unpack_from(">H", out[0], 5)[0] == 2
    assert out[0][7:] == original[7:]


# --------------------------------------------------------------------------
# Everything else must pass through untouched
# --------------------------------------------------------------------------

_REMOTE_REWRITES = {0x03, 0x09, 0x0D}
_LOCAL_REWRITES = {0x03, 0x15}


@pytest.mark.parametrize("low", range(256))
def test_every_unhandled_opcode_from_remote_is_forwarded_byte_identical(low):
    data = bytes([0x00, low]) + b"payload-bytes-here"
    codec = LoginCodec()
    out = codec.from_remote(data)
    if low in _REMOTE_REWRITES:
        return
    assert out == [data], f"opcode 0x{low:02x} was altered"


@pytest.mark.parametrize("low", range(256))
def test_every_unhandled_opcode_from_local_is_forwarded_byte_identical(low):
    data = bytes([0x00, low]) + b"payload-bytes-here"
    codec = LoginCodec()
    out = codec.from_local(data)
    if low in _LOCAL_REWRITES:
        return
    assert out == [data], f"opcode 0x{low:02x} was altered"


def test_session_response_and_disconnect_are_forwarded_and_reset_state():
    codec = LoginCodec()
    for seq in range(3):
        codec.from_remote(packet(seq))
    assert codec.seq_to_local == 3

    assert codec.from_remote(b"\x00\x02rest") == [b"\x00\x02rest"]
    assert codec.seq_to_local == 0
    assert codec.in_session is True

    codec.from_remote(packet(0))
    assert codec.from_local(b"\x00\x05rest") == [b"\x00\x05rest"]
    assert codec.seq_to_local == 0
    assert codec.in_session is False


def test_fragments_are_never_forwarded():
    body, _ = big_list()
    frags = fragments(body)
    codec = LoginCodec()
    emitted = drive(codec, frags[:-1])  # withhold the last one
    assert emitted == [], "a partial run emits nothing at all"


# --------------------------------------------------------------------------
# The deliberate divergences
# --------------------------------------------------------------------------


def test_exact_fragment_boundary_completes_instead_of_hanging():
    """Divergence: the C's fragment-count formula over-counts by one here.

    ``(totalLen - 504) / 508 + 2`` yields 3 for a 1012-byte list that really
    arrives in 2 fragments, so ``check_fragment_finished`` waits forever for a
    fragment the server will never send — a permanently blank server-select
    screen, which is the exact bug this add-on exists to remove.
    """
    total_len = 504 + 508  # 1012, an exact boundary
    body_len = total_len - 2
    kept = record("Project 1999", region="R" * 40)
    pad = filler_record(body_len - 20 - len(kept))
    body = HEADER16 + struct.pack("<I", 2) + kept + pad
    assert len(body) == body_len

    frags = fragments(body)
    assert len(frags) == 2, "the fixture really is an exact two-fragment boundary"
    assert (total_len - 504) % 508 == 0
    assert (total_len - 504) // 508 + 2 == 3, "the C would wait for a third fragment"

    codec = LoginCodec()
    out = drive(codec, frags)
    assert len(out) == 1, "byte-driven completion fires on the second fragment"
    assert parse_reply(out[0])[0] == 1


@pytest.mark.parametrize("datagram", [64, 128, 256, 512, 1024])
def test_completion_does_not_depend_on_a_512_byte_datagram(datagram):
    """Both magic numbers in the C's formula derive from an assumed 512."""
    body, kept = big_list()
    codec = LoginCodec()
    out = drive(codec, fragments(body, datagram=datagram))
    assert len(out) == 1
    assert parse_reply(out[0])[0] == len(kept)


def test_a_gap_does_not_advance_the_remote_sequence_past_it():
    """Divergence: the C's in-order scan skips holes and over-acknowledges.

    Its loop is guarded by ``if (len > 0)`` but does not break on a miss, so a
    later-arrived packet advances seqFromRemote past a datagram that never
    came. Every client ACK is rewritten to seqFromRemote - 1, so that
    acknowledges data the login server never delivered.
    """
    codec = LoginCodec()
    codec.from_remote(packet(0))
    assert codec.seq_from_remote == 1

    codec.from_remote(packet(2))  # 1 is missing
    assert codec.seq_from_remote == 1, "must not skip the hole"

    acked = struct.unpack_from(">H", codec.from_local(ack(9))[0], 2)[0]
    assert acked == 0, "acknowledge only what actually arrived"

    codec.from_remote(packet(1))  # the gap fills
    assert codec.seq_from_remote == 3, "now both 1 and the buffered 2 are consumed"


# --------------------------------------------------------------------------
# Malformed input: refused, never fatal
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00",
        b"\x00\x0d",
        b"\x00\x0d\x00",
        b"\x00\x0d\x00\x00\xff",
        b"\x00\x0d\x00\x00\xff\xff\xff\xff\x18",
        b"\x00\x09",
        b"\x00\x03",
        b"\x00\x03\x00",
        b"\x00\x03\xff\x01\x02",  # sublen overruns the buffer
        b"\x00\x03\x00\x01\x02",  # zero sublen
        b"\x00\x03\x04" + b"\x00\x09\x00\x00" + b"\xff",  # trailing junk
    ],
)
def test_malformed_datagrams_never_raise(data):
    codec = LoginCodec()
    assert isinstance(codec.from_remote(data), list)
    assert isinstance(codec.from_local(data), list)


def test_a_declared_length_below_the_first_fragment_payload_is_refused():
    """The C computes this unsigned, so totalLen < 504 wraps to a huge count."""
    frag = b"\x00\x0d" + struct.pack(">H", 0) + struct.pack(">I", 10) + b"\x18\x00" + b"x" * 8
    codec = LoginCodec()
    assert codec.from_remote(frag) == []
    assert codec._frag_count == 0, "no run was opened"


def test_an_implausibly_large_declared_length_is_refused():
    frag = (
        b"\x00\x0d"
        + struct.pack(">H", 0)
        + struct.pack(">I", MAX_REASSEMBLY_BYTES + 1)
        + b"\x18\x00"
        + b"x" * 502
    )
    codec = LoginCodec()
    assert codec.from_remote(frag) == []
    assert codec._frag_count == 0


def test_a_fragmented_message_that_is_not_a_server_list_opens_no_run():
    frag = (
        b"\x00\x0d"
        + struct.pack(">H", 0)
        + struct.pack(">I", 2000)
        + struct.pack("<H", 0x19)  # not ServerListResponse
        + b"x" * 502
    )
    codec = LoginCodec()
    assert codec.from_remote(frag) == []
    assert codec._frag_count == 0


def test_unterminated_record_strings_abandon_the_filter_without_raising():
    # A record whose region string runs to the end with no NUL.
    broken = b"1.2.3.4\0" + struct.pack("<i", 1) + struct.pack("<i", 2)
    broken += b"Project 1999\0" + b"US\0" + b"no-terminator-here"
    body = HEADER16 + struct.pack("<I", 1) + broken

    codec = LoginCodec()
    out = drive(codec, fragments(body, datagram=64))
    assert out == [], "no packet is invented from a payload we could not parse"


def test_a_run_that_never_completes_emits_nothing_and_stays_bounded():
    body, _ = big_list()
    frags = fragments(body)
    codec = LoginCodec()
    assert drive(codec, frags[:1] + frags[2:]) == [], "fragment 1 never arrives"
    assert codec.buffered_bytes <= MAX_REASSEMBLY_BYTES


# --------------------------------------------------------------------------
# Bounded memory
# --------------------------------------------------------------------------


def test_the_reassembly_window_is_bounded():
    """A peer that never completes a run must not grow our footprint forever."""
    codec = LoginCodec()
    for seq in range(MAX_BUFFERED_PACKETS * 3):
        frag = b"\x00\x0d" + struct.pack(">H", (seq + 1) & 0xFFFF) + b"x" * 508
        codec.from_remote(frag)
        assert len(codec._packets) <= MAX_BUFFERED_PACKETS
        assert codec.buffered_bytes <= MAX_REASSEMBLY_BYTES


def test_oversized_datagrams_are_not_buffered():
    codec = LoginCodec()
    huge = b"\x00\x0d" + struct.pack(">H", 0) + b"x" * 65000
    assert codec.from_remote(huge) == [huge]  # forwarded, not retained
    assert codec.buffered_bytes == 0


def test_ordinary_packets_are_not_retained_after_they_are_consumed():
    codec = LoginCodec()
    for seq in range(200):
        codec.from_remote(packet(seq))
    assert len(codec._packets) <= 1, "consumed packets are released"
    assert codec.buffered_bytes == 0
