"""End-to-end tests over real loopback sockets.

The real login server cannot be reached from CI, and pointing tests at it would
be rude besides, so the remote end is faked: a UDP socket on loopback that
replies with whatever byte sequence the test wants. Everything between the game
client's socket and that fake is the code that ships.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

from p99_login_proxy.proxy import (
    LISTEN_HOST,
    LoginProxy,
    PortInUseError,
    ProxyStatus,
    ResolveError,
)

from .test_codec import HEADER16, big_list, fragments, packet, parse_reply

RECV_TIMEOUT = 5.0


class FakeLoginServer:
    """A UDP socket standing in for ``login.eqemulator.net``."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LISTEN_HOST, 0))
        self.sock.settimeout(RECV_TIMEOUT)
        self.received: list[bytes] = []
        self.peer: tuple[str, int] | None = None

    @property
    def address(self) -> tuple[str, int]:
        return self.sock.getsockname()[:2]

    def recv(self) -> bytes:
        data, self.peer = self.sock.recvfrom(4096)
        self.received.append(data)
        return data

    def send(self, data: bytes) -> None:
        assert self.peer is not None, "the proxy must talk to us before we talk back"
        self.sock.sendto(data, self.peer)

    def close(self) -> None:
        self.sock.close()


@pytest.fixture
def login_server():
    server = FakeLoginServer()
    yield server
    server.close()


@pytest.fixture
def proxy(login_server: FakeLoginServer):
    host, port = login_server.address
    # Port 0: let the OS pick, so concurrent CI jobs cannot collide.
    instance = LoginProxy(0, host, port)
    instance.start()
    yield instance
    instance.stop()


@pytest.fixture
def client(proxy: LoginProxy):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(RECV_TIMEOUT)
    yield sock
    sock.close()


def proxy_address(proxy: LoginProxy) -> tuple[str, int]:
    address = proxy.bound_address
    assert address is not None
    return address


# --------------------------------------------------------------------------
# The bind
# --------------------------------------------------------------------------


def test_the_proxy_binds_loopback_only(proxy: LoginProxy):
    """Both reference implementations bind INADDR_ANY; this one must not.

    Loopback keeps an unauthenticated UDP relay off the LAN, and it is why
    macOS never raises a firewall prompt.
    """
    host, _ = proxy_address(proxy)
    assert host == "127.0.0.1"
    assert host not in ("0.0.0.0", "")


def test_a_port_already_in_use_is_reported_as_such(login_server: FakeLoginServer):
    """Someone running Zaela's binary on 5998 is a realistic collision."""
    squatter = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    squatter.bind((LISTEN_HOST, 0))
    taken = squatter.getsockname()[1]
    try:
        host, port = login_server.address
        clashing = LoginProxy(taken, host, port)
        with pytest.raises(PortInUseError):
            clashing.start()
        assert clashing.status is ProxyStatus.PORT_IN_USE
        assert "already in use" in (clashing.error or "")
        assert not clashing.running
    finally:
        squatter.close()


def test_an_unresolvable_upstream_is_reported_not_raised_as_a_crash():
    unreachable = LoginProxy(0, "no-such-host.invalid", 5998)
    with pytest.raises(ResolveError):
        unreachable.start()
    assert unreachable.status is ProxyStatus.ERROR
    assert not unreachable.running


# --------------------------------------------------------------------------
# Relaying
# --------------------------------------------------------------------------


def test_client_traffic_reaches_the_login_server_untouched(
    proxy: LoginProxy, login_server: FakeLoginServer, client: socket.socket
):
    payload = b"\x00\x01session-request-bytes"
    client.sendto(payload, proxy_address(proxy))
    assert login_server.recv() == payload


def test_a_fragmented_server_list_arrives_as_one_filtered_packet(
    proxy: LoginProxy, login_server: FakeLoginServer, client: socket.socket
):
    """The whole point, end to end: ~10 datagrams in, exactly 1 out."""
    body, kept = big_list()
    frags = fragments(body)
    assert len(frags) >= 3

    client.sendto(b"\x00\x01hello", proxy_address(proxy))
    login_server.recv()

    for frag in frags:
        login_server.send(frag)

    reply, _ = client.recvfrom(4096)
    count, header, records = parse_reply(reply)
    assert count == len(kept)
    assert header == HEADER16
    assert records == b"".join(kept)

    # And nothing else follows: the fragments themselves were swallowed.
    client.settimeout(0.4)
    with pytest.raises(socket.timeout):
        client.recvfrom(4096)


def test_unhandled_opcodes_reach_the_client_byte_identical(
    proxy: LoginProxy, login_server: FakeLoginServer, client: socket.socket
):
    client.sendto(b"\x00\x01hello", proxy_address(proxy))
    login_server.recv()

    original = b"\x00\xaa" + bytes(range(64))
    login_server.send(original)

    reply, _ = client.recvfrom(4096)
    assert reply == original


def test_packet_sequences_are_restamped_on_the_wire(
    proxy: LoginProxy, login_server: FakeLoginServer, client: socket.socket
):
    client.sendto(b"\x00\x01hello", proxy_address(proxy))
    login_server.recv()

    for seq in (500, 501, 502):
        login_server.send(packet(seq))

    seen = [struct.unpack_from(">H", client.recvfrom(4096)[0], 2)[0] for _ in range(3)]
    assert seen == [0, 1, 2], "the client sees a gapless stream from zero"


def test_client_acks_are_rewritten_before_they_reach_the_server(
    proxy: LoginProxy, login_server: FakeLoginServer, client: socket.socket
):
    address = proxy_address(proxy)
    client.sendto(b"\x00\x01hello", address)
    login_server.recv()

    for seq in range(3):
        login_server.send(packet(seq))
    for _ in range(3):
        client.recvfrom(4096)

    client.sendto(b"\x00\x15" + struct.pack(">H", 999), address)
    forwarded = login_server.recv()
    assert struct.unpack_from(">H", forwarded, 2)[0] == 2


def test_a_datagram_from_an_unexpected_address_is_ignored(
    proxy: LoginProxy, login_server: FakeLoginServer, client: socket.socket
):
    """A stray local sender must not hijack an established session."""
    client.sendto(b"\x00\x01hello", proxy_address(proxy))
    login_server.recv()

    # Establish the session first. Until the login server sends its
    # SessionResponse there is no session to protect, and the first local sender
    # to speak legitimately claims the client slot — that is how the real client
    # gets latched in the first place.
    login_server.send(b"\x00\x02session-response")
    client.recvfrom(4096)

    for seq in range(2):
        login_server.send(packet(seq))
    for _ in range(2):
        client.recvfrom(4096)

    # A second local sender is not the login server and is not the client.
    intruder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        intruder.sendto(b"\x00\x05disconnect", proxy_address(proxy))
        time.sleep(0.2)
    finally:
        intruder.close()

    login_server.send(packet(2))
    reply, _ = client.recvfrom(4096)
    assert struct.unpack_from(">H", reply, 2)[0] == 2, "session state survived"


# --------------------------------------------------------------------------
# Shutdown
# --------------------------------------------------------------------------


def test_stop_joins_the_thread_and_releases_the_port(login_server: FakeLoginServer):
    """The blocking read is unblocked deliberately, not left to daemon death."""
    host, port = login_server.address
    instance = LoginProxy(0, host, port)
    instance.start()
    listen_port = proxy_address(instance)[1]

    names_before = {t.name for t in threading.enumerate()}
    assert "p99-login-proxy" in names_before
    assert instance.running

    started = time.monotonic()
    instance.stop()
    elapsed = time.monotonic() - started

    assert not instance.running
    assert elapsed < 2.0, "shutdown must not wait out the select timeout"
    assert "p99-login-proxy" not in {t.name for t in threading.enumerate()}
    assert instance.status is ProxyStatus.STOPPED

    # The port is genuinely free again.
    rebind = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        rebind.bind((LISTEN_HOST, listen_port))
    finally:
        rebind.close()


def test_stop_is_idempotent(proxy: LoginProxy):
    proxy.stop()
    proxy.stop()
    assert not proxy.running


def test_start_after_stop_works(login_server: FakeLoginServer):
    host, port = login_server.address
    instance = LoginProxy(0, host, port)
    try:
        instance.start()
        instance.stop()
        instance.start()
        assert instance.running
        assert proxy_address(instance)[0] == "127.0.0.1"
    finally:
        instance.stop()
