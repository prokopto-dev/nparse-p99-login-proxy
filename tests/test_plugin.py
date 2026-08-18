"""Plugin lifecycle against the SDK's FakePluginContext — no app, no Qt, no network.

The host activates a plugin on the GUI thread before the log driver starts, and
``nparseplus-plugin validate`` does the same against a fake context whose
``eq_dir`` is ``None``. Both must survive that, so most of what is asserted here
is that nothing raises where the host cannot tolerate a raise.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from nparseplus_sdk import PluginMeta
from nparseplus_sdk.testing import FakePluginContext
from nparseplus_sdk.validate import validate_plugin

from p99_login_proxy import LoginProxyPlugin, create_plugin, eqhost
from p99_login_proxy.eqhost import EqHostError
from p99_login_proxy.proxy import ProxyError, ProxyStatus

PACKAGE_DIR = Path(__file__).resolve().parent.parent / "p99_login_proxy"


@pytest.fixture
def plugin():
    instance = create_plugin()
    yield instance
    instance.deactivate()


def context(eq_dir: Path | None = None, **kwargs) -> FakePluginContext:
    return FakePluginContext(LoginProxyPlugin.meta, eq_dir=eq_dir, **kwargs)


def relay_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "p99-login-proxy"]


# --------------------------------------------------------------------------
# Metadata and the validate CLI
# --------------------------------------------------------------------------


def test_metadata_is_valid_and_declares_the_sdk_it_needs():
    meta = LoginProxyPlugin.meta
    PluginMeta.model_validate(meta, from_attributes=True)
    assert meta.id == "p99-login-proxy"
    # 1.2 is the release that added eq_dir, eq_is_running() and eqfiles.
    assert meta.requires_sdk == ">=1.2,<2"
    assert meta.min_app_version == "2.14.0"


def test_the_validate_cli_passes():
    report = validate_plugin(PACKAGE_DIR)
    assert report.ok, report.errors
    assert report.page_count == 1
    assert report.window_count == 0
    assert report.tick_count == 0, "this plugin touches no host state at all"
    assert report.parser_count == 0
    assert report.subscription_count == 0


def test_the_only_advisory_warnings_are_the_expected_socket_ones():
    """A UDP proxy importing `socket` is flagged by the advisory scan.

    Warnings never fail validation; this pins which ones we expect so a new,
    unexpected one is visible rather than lost in the noise.
    """
    report = validate_plugin(PACKAGE_DIR)
    unexpected = [w for w in report.warnings if "socket" not in w]
    assert not unexpected, unexpected


def test_create_plugin_is_a_module_level_factory():
    assert callable(create_plugin)
    assert isinstance(create_plugin(), LoginProxyPlugin)
    assert create_plugin() is not create_plugin()


def test_the_package_imports_without_qt():
    import sys

    assert "PySide6" not in sys.modules, (
        "importing the plugin must not pull Qt — the validate CLI and this suite "
        "both run in Qt-free environments"
    )


def test_the_settings_page_module_itself_imports_without_qt():
    """The module the package never imports is the one that would regress.

    ``settings_page`` is only reached through the builder, so a stray top-level
    ``from PySide6 import ...`` would pass every other test here and only fail
    inside ``nparseplus-plugin validate`` on a machine without Qt.
    """
    import sys

    from p99_login_proxy import settings_page

    assert "PySide6" not in sys.modules
    assert callable(settings_page.build_page)


def test_the_builder_the_host_receives_is_the_settings_page_one(plugin: LoginProxyPlugin):
    """The host calls this on the GUI thread; check the wiring, not the widgets."""
    ctx = context()
    plugin.activate(ctx)
    builder = ctx.settings_pages[0].builder

    called: list[object] = []
    import p99_login_proxy.settings_page as page_module

    original = page_module.build_page
    page_module.build_page = lambda owner, parent: called.append((owner, parent)) or "widget"
    try:
        assert builder(sentinel := object()) == "widget"
    finally:
        page_module.build_page = original

    assert called == [(plugin, sentinel)], "the page is built with the plugin as its owner"


# --------------------------------------------------------------------------
# Activation
# --------------------------------------------------------------------------


def test_activate_with_no_eq_directory_does_not_raise(plugin: LoginProxyPlugin):
    """The normal first-run state, and exactly what the validate CLI does."""
    ctx = context(eq_dir=None)
    plugin.activate(ctx)

    assert len(ctx.settings_pages) == 1
    assert ctx.settings_pages[0].title == "P99 Login Proxy"
    assert ctx.settings_pages[0].apply is None
    assert callable(ctx.settings_pages[0].builder)

    state, detail = plugin.status()
    assert state is ProxyStatus.NO_EQ_DIR
    assert detail
    assert not plugin.running


def test_activate_registers_no_host_callbacks(plugin: LoginProxyPlugin):
    """The proxy touches no host state, so none of these should be used."""
    ctx = context()
    plugin.activate(ctx)
    assert ctx.ticks == []
    assert ctx.subscriptions == []
    assert ctx.parsers == []
    assert ctx.submitted == [], "a blocking loop must never be parked on ctx.submit"
    assert ctx.windows == []


def test_activate_does_not_start_when_not_configured(plugin: LoginProxyPlugin, eq_dir: Path):
    ctx = context(eq_dir=eq_dir)
    ctx.storage.data["enabled"] = True
    plugin.activate(ctx)

    state, detail = plugin.status()
    assert state is ProxyStatus.NOT_CONFIGURED
    assert "login.eqemulator.net" in detail
    assert not plugin.running, "refuses to listen when eqhost.txt is not pointed at us"


def test_activate_starts_the_relay_when_enabled_and_configured(
    plugin: LoginProxyPlugin, eq_dir: Path
):
    # A free port, so the test does not depend on 5998 being available.
    import socket

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    (eq_dir / "eqhost.txt").write_bytes(f"[LoginServer]\nHost=127.0.0.1:{port}\n".encode())
    (eq_dir / eqhost.BACKUP_DIR_NAME).mkdir()
    (eq_dir / eqhost.BACKUP_DIR_NAME / "eqhost.txt").write_bytes(
        f"[LoginServer]\nHost=127.0.0.1:{port}\n".encode()
    )

    ctx = context(eq_dir=eq_dir)
    ctx.storage.data["enabled"] = True
    plugin.activate(ctx)

    assert plugin.running
    state, detail = plugin.status()
    assert state is ProxyStatus.LISTENING
    assert f"127.0.0.1:{port}" in detail


def test_activation_survives_a_relay_that_cannot_start(plugin: LoginProxyPlugin, eq_dir: Path):
    """A failure here must reach the settings page, not abort activation."""
    (eq_dir / "eqhost.txt").write_bytes(b"[LoginServer]\nHost=127.0.0.1:5998\n")
    (eq_dir / eqhost.BACKUP_DIR_NAME).mkdir()
    (eq_dir / eqhost.BACKUP_DIR_NAME / "eqhost.txt").write_bytes(
        b"[LoginServer]\nHost=no-such-host.invalid:5998\n"
    )

    ctx = context(eq_dir=eq_dir)
    ctx.storage.data["enabled"] = True
    plugin.activate(ctx)  # must not raise

    assert len(ctx.settings_pages) == 1
    assert not plugin.running


# --------------------------------------------------------------------------
# The thread
# --------------------------------------------------------------------------


def test_deactivate_joins_the_relay_thread(eq_dir: Path):
    import socket

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    (eq_dir / "eqhost.txt").write_bytes(f"[LoginServer]\nHost=127.0.0.1:{port}\n".encode())
    (eq_dir / eqhost.BACKUP_DIR_NAME).mkdir()
    (eq_dir / eqhost.BACKUP_DIR_NAME / "eqhost.txt").write_bytes(
        b"[LoginServer]\nHost=login.eqemulator.net:5998\n"
    )

    before = relay_threads()
    plugin = create_plugin()
    ctx = context(eq_dir=eq_dir)
    ctx.storage.data["enabled"] = True
    plugin.activate(ctx)

    assert plugin.running
    assert len(relay_threads()) == len(before) + 1

    plugin.deactivate()

    assert not plugin.running
    assert relay_threads() == before, "the thread is gone, not merely detached"


def test_deactivate_is_safe_without_activate():
    create_plugin().deactivate()


def test_deactivate_is_idempotent(plugin: LoginProxyPlugin):
    plugin.activate(context())
    plugin.deactivate()
    plugin.deactivate()
    assert not plugin.running


# --------------------------------------------------------------------------
# Enable / disable and persistence
# --------------------------------------------------------------------------


def test_enable_applies_the_edit_persists_the_flag_and_starts(
    plugin: LoginProxyPlugin, eq_dir: Path
):
    ctx = context(eq_dir=eq_dir)
    plugin.activate(ctx)
    assert plugin.enabled is False

    plugin.enable()

    assert plugin.enabled is True
    assert ctx.storage.data["enabled"] is True
    assert "Host=127.0.0.1:5998" in (eq_dir / "eqhost.txt").read_text()
    assert "login.eqemulator.net" in (eq_dir / eqhost.BACKUP_DIR_NAME / "eqhost.txt").read_text()


def test_disable_stops_first_then_reverts(plugin: LoginProxyPlugin, eq_dir: Path):
    original = (eq_dir / "eqhost.txt").read_bytes()
    ctx = context(eq_dir=eq_dir)
    plugin.activate(ctx)
    plugin.enable()

    plugin.disable()

    assert not plugin.running
    assert plugin.enabled is False
    assert ctx.storage.data["enabled"] is False
    assert (eq_dir / "eqhost.txt").read_bytes() == original


def test_the_enabled_flag_is_restored_on_a_later_activate(eq_dir: Path):
    from nparseplus_sdk.testing import FakeStorage

    storage = FakeStorage()
    first = create_plugin()
    first.activate(FakePluginContext(LoginProxyPlugin.meta, eq_dir=eq_dir, storage=storage))
    try:
        first.enable()
    finally:
        first.deactivate()

    assert storage.data["enabled"] is True

    second = create_plugin()
    second.activate(FakePluginContext(LoginProxyPlugin.meta, eq_dir=eq_dir, storage=storage))
    try:
        assert second.enabled is True
    finally:
        second.deactivate()
        second.disable()


def test_enable_without_an_eq_directory_reports_rather_than_starting(plugin: LoginProxyPlugin):
    plugin.activate(context(eq_dir=None))
    with pytest.raises(EqHostError):
        plugin.enable()
    assert not plugin.running
    assert plugin.enabled is False


def test_start_refuses_when_eqhost_does_not_point_at_localhost(
    plugin: LoginProxyPlugin, eq_dir: Path
):
    plugin.activate(context(eq_dir=eq_dir))
    with pytest.raises(ProxyError, match="localhost"):
        plugin.start()
    assert not plugin.running


# --------------------------------------------------------------------------
# The EQ-running probe
# --------------------------------------------------------------------------


def test_eq_is_running_reflects_the_host_probe(plugin: LoginProxyPlugin, eq_dir: Path):
    ctx = context(eq_dir=eq_dir, eq_running=True)
    plugin.activate(ctx)
    assert plugin.eq_is_running() is True

    ctx.eq_running = False
    assert plugin.eq_is_running() is False


def test_eq_dir_is_read_live_and_never_cached(plugin: LoginProxyPlugin, eq_dir: Path, tmp_path):
    ctx = context(eq_dir=None)
    plugin.activate(ctx)
    assert plugin.eq_dir is None

    # A player repointing nParse+ mid-session must move this too.
    ctx._eq_dir = eq_dir
    assert plugin.eq_dir == eq_dir
    assert plugin.status()[0] is ProxyStatus.NOT_CONFIGURED
