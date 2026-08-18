"""P99 Login Proxy — an nParse+ add-on that fixes the blank server-select screen.

Project 1999 players on Linux/WINE, Proton and macOS/CrossOver commonly reach
server select and see nothing at all. The EQEmu login server sends its server
list as roughly 6 KB across ~10 fragmented UDP datagrams and the loginserver
protocol has no retransmit, so one dropped fragment means an empty list and no
error message. The P99 wiki's Tech Support, Linux and Steam Deck pages all point
at the same fix: a local UDP proxy that reassembles the fragments, keeps only
the P99 servers, and hands the client one small packet.

That fix is Zaela's `p99-login-middlemand`_, released under the `Unlicense`_ — a
public-domain dedication that imposes no obligation whatsoever. The protocol
work in :mod:`p99_login_proxy.proxy` is a port of it, read at commit
``9b74f470cb15f3518cd66e89c8c4732f337b0ed3``. Credit is given because it is
deserved, not because it is required. No C or C# source is vendored here.

.. _p99-login-middlemand: https://github.com/Zaela/p99-login-middlemand
.. _Unlicense: https://unlicense.org

What this add-on adds over running the C tool: no compiler, a checkbox, a status
line that distinguishes the four ways this can fail to work, and an
``eqhost.txt`` edit that backs the original up before touching it and reverts to
*that* rather than to a hardcoded default.

**Two sharp edges, stated here, in the settings page, and in the README**, since
either one turns a working setup into a worse version of the original bug:

1. Once ``eqhost.txt`` points at localhost, **nParse+ must be running before you
   log in**, or the server list is blank.
2. **Revert before uninstalling**, or you are locked out with no obvious cause.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from nparseplus_sdk import NParsePlugin, PluginMeta, PluginSettingsPageSpec

from . import eqhost
from .eqhost import EqHostError, EqHostState, EqHostStatus
from .proxy import LoginProxy, ProxyError, ProxyStatus

__all__ = ["LoginProxyPlugin", "create_plugin"]

#: Key under which the enabled flag lives in ``ctx.storage``.
_ENABLED_KEY = "enabled"

_SETTINGS_TITLE = "P99 Login Proxy"


class LoginProxyPlugin(NParsePlugin):
    """Owns the relay thread, the ``eqhost.txt`` edit and the settings page."""

    meta = PluginMeta(
        id="p99-login-proxy",
        name="P99 Login Proxy",
        version="1.0.0",
        # 1.2 is the SDK release that added ctx.eq_dir, ctx.eq_is_running() and
        # nparseplus_sdk.eqfiles. There is no graceful degradation below it —
        # on an older host those attributes are simply absent — so this is a
        # hard floor rather than a preference. v2.14.0 is the first app release
        # that bundles it.
        requires_sdk=">=1.2,<2",
        min_app_version="2.14.0",
        description=(
            "Fixes the blank server-select screen on Linux/WINE and macOS/CrossOver "
            "by reassembling the EQEmu login server list locally and filtering it to "
            "P99 servers. Ports Zaela's p99-login-middlemand."
        ),
        author="prokopto-dev",
        homepage="https://github.com/prokopto-dev/nparse-p99-login-proxy",
    )

    def __init__(self) -> None:
        self._ctx: Any = None
        self._log: logging.Logger = logging.getLogger(f"nparseplus.plugins.{self.meta.id}")
        self._proxy: LoginProxy | None = None
        self._last_error: str | None = None

    # -- lifecycle ---------------------------------------------------------

    def activate(self, ctx: Any) -> None:
        """Register the settings page and, if enabled, start the relay.

        Runs on the GUI thread before the app's log driver starts — early
        enough that the proxy is listening well before the player reaches
        server select.

        Nothing in here may raise. ``eq_dir`` is ``None`` on first run, and the
        ``nparseplus-plugin validate`` CLI activates every plugin against a fake
        context in exactly that state.
        """
        self._ctx = ctx
        self._log = ctx.logger

        ctx.add_settings_page(
            PluginSettingsPageSpec(title=_SETTINGS_TITLE, builder=self._build_page, apply=None)
        )

        if not self.enabled:
            return
        try:
            self.start()
        except (ProxyError, OSError) as exc:
            # A failure here must not abort activation: the settings page is the
            # place the player finds out and retries.
            self._last_error = str(exc)
            self._log.warning("could not start the proxy at activation: %s", exc)

    def deactivate(self) -> None:
        """Stop the relay and join its thread. Called by the host at app quit."""
        self.stop()

    # -- the thread --------------------------------------------------------
    #
    # We own this thread rather than using ctx.submit(). The host's own plugin
    # docs discourage self-started threads, and the concern behind that is real
    # — a thread nobody joins outlives the app. But ctx.submit is a shared queue
    # for short fire-and-forget calls, and parking a blocking recvfrom loop on
    # it would starve every other plugin and app feature for the entire session.
    # So: one daemon thread, started here, joined in deactivate(), and guarded
    # so a failed start cannot leave one running.

    def start(self) -> None:
        """Start the relay, reading the listen port out of ``eqhost.txt``.

        Refuses when the file does not point at localhost. There is no default
        to fall back on: a listener on a port the client is not talking to is
        indistinguishable from a working one right up until the player cannot
        log in.
        """
        state = self.eqhost_state
        if not state.is_proxied:
            raise ProxyError(
                state.reason or "eqhost.txt does not point at localhost — apply the change first."
            )
        assert state.port is not None

        self.stop()
        proxy = LoginProxy(
            state.port,
            state.upstream_host,
            state.upstream_port,
            logger=self._log,
        )
        try:
            proxy.start()
        except ProxyError:
            self._last_error = proxy.error
            self._proxy = proxy  # keep it so the UI can read the failure status
            raise
        self._proxy = proxy
        self._last_error = None

    def stop(self) -> None:
        """Stop the relay if it is running. Safe to call any number of times."""
        if self._proxy is not None:
            self._proxy.stop()
            self._proxy = None

    @property
    def running(self) -> bool:
        return self._proxy is not None and self._proxy.running

    # -- state the settings page reads ------------------------------------

    @property
    def eq_dir(self) -> Path | None:
        """The EQ install directory, read live.

        Never cached: a player who repoints nParse+ at a different install
        mid-session moves this, and a stale copy would edit the wrong game.
        """
        if self._ctx is None:
            return None
        return self._ctx.eq_dir

    @property
    def eqhost_state(self) -> EqHostState:
        return eqhost.read_state(self.eq_dir)

    @property
    def enabled(self) -> bool:
        """Whether the player has turned the proxy on. Persisted per-plugin."""
        if self._ctx is None:
            return False
        return bool(self._ctx.storage.load().get(_ENABLED_KEY, False))

    def _set_enabled(self, value: bool) -> None:
        if self._ctx is None:
            return
        data = self._ctx.storage.load()
        data[_ENABLED_KEY] = bool(value)
        self._ctx.storage.save(data)

    def status(self) -> tuple[ProxyStatus, str]:
        """The current status and a sentence explaining it, for the UI."""
        state = self.eqhost_state

        if state.status is EqHostStatus.NO_EQ_DIR:
            return ProxyStatus.NO_EQ_DIR, state.reason or "No EverQuest directory set."

        if state.status in (
            EqHostStatus.NOT_AN_INSTALL,
            EqHostStatus.MISSING,
            EqHostStatus.UNREADABLE,
        ):
            return ProxyStatus.ERROR, state.reason or "eqhost.txt could not be read."

        if not state.is_proxied:
            return (
                ProxyStatus.NOT_CONFIGURED,
                f"eqhost.txt points at {state.host}:{state.port}. "
                f"Enable the proxy to route it through this machine.",
            )

        if self._proxy is not None and self._proxy.status is ProxyStatus.PORT_IN_USE:
            return ProxyStatus.PORT_IN_USE, self._proxy.error or "Port already in use."

        if self.running:
            upstream = f"{state.upstream_host}:{state.upstream_port}"
            suffix = " (assumed — no backup found)" if state.upstream_is_default else ""
            return (
                ProxyStatus.LISTENING,
                f"Listening on 127.0.0.1:{state.port}, forwarding to {upstream}{suffix}.",
            )

        detail = self._last_error or (
            "eqhost.txt points at this machine but the proxy is not running — "
            "the server list will be blank until it is."
        )
        return ProxyStatus.STOPPED, detail

    # -- actions the settings page invokes --------------------------------

    def enable(self) -> None:
        """Apply the ``eqhost.txt`` edit and start the relay."""
        eqhost.apply(self.eq_dir)
        self._set_enabled(True)
        self.start()

    def disable(self) -> None:
        """Stop the relay and put ``eqhost.txt`` back the way it was.

        Order matters: revert first would leave a window where the file is
        correct but a stale listener still holds the port.
        """
        self.stop()
        self._set_enabled(False)
        try:
            eqhost.revert(self.eq_dir)
        except EqHostError:
            # Nothing to revert to, or the directory moved. The relay is stopped
            # either way, which is the part that matters for correctness; the
            # page surfaces the reason.
            self._log.warning("could not revert eqhost.txt", exc_info=True)
            raise

    def eq_is_running(self) -> bool:
        """Best-effort check for a live EQ client.

        Spawns a process, so this is only ever called from a settings-page
        button press — never from a timer or a tick.
        """
        if self._ctx is None:
            return False
        try:
            return bool(self._ctx.eq_is_running())
        except Exception:  # pragma: no cover - host probe is best-effort
            return False

    # -- settings page -----------------------------------------------------

    def _build_page(self, parent: Any) -> Any:
        # Imported here, not at module scope: settings_page pulls PySide6, and
        # this package must stay importable in Qt-free environments (the
        # validate CLI and the whole unit-test suite depend on that).
        from .settings_page import build_page

        return build_page(self, parent)


def create_plugin() -> LoginProxyPlugin:
    """Module-level factory the host imports and calls. Required."""
    return LoginProxyPlugin()
