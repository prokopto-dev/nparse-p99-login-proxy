"""The Settings page. PySide6 is imported inside the builder, never at import time.

The host calls :func:`build_page` on the GUI thread with the page's parent
widget. Every Qt import lives inside that call so this module stays importable
without Qt at all — ``nparseplus-plugin validate`` and the entire unit-test
suite rely on that, and a top-level ``import PySide6`` would break both.

The page's job is not just the checkbox. It is the only place a player finds out
*which* of the several ways this can be misconfigured is the one they are in, so
the status line names it specifically rather than saying "not working".
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .eqhost import EqHostError
from .proxy import ProxyError, ProxyStatus

if TYPE_CHECKING:  # pragma: no cover - typing only
    from . import LoginProxyPlugin

#: How often the status line refreshes. Cheap: it reads a small file and an
#: in-memory flag. Deliberately does *not* call ctx.eq_is_running(), which
#: spawns a process — that is bound to a button press instead.
_POLL_MS = 1000

_WARNING = (
    "<b>Before you enable this, two things worth knowing:</b>"
    "<ul>"
    "<li><b>nParse+ must be running before you log in.</b> Once eqhost.txt points at "
    "this machine, starting EverQuest without nParse+ running gives you a blank server "
    "list — worse than the problem this fixes.</li>"
    "<li><b>Revert before uninstalling.</b> Removing this add-on does not undo the "
    "eqhost.txt change on its own, and a leftover setting locks you out with no "
    "obvious cause.</li>"
    "</ul>"
)

_ABOUT = (
    "The EQEmu login server sends its server list as ~6 KB of fragmented UDP with no "
    "retransmit, so a single dropped fragment leaves you at an empty server-select "
    "screen. This runs a local proxy that reassembles the list, keeps only the P99 "
    "servers, and hands the client one small packet instead of ten.<br><br>"
    'Ports <a href="https://github.com/Zaela/p99-login-middlemand">Zaela\'s '
    "p99-login-middlemand</a> (Unlicense)."
)

_STATUS_COLOURS = {
    ProxyStatus.LISTENING: "#2e7d32",
    ProxyStatus.NOT_CONFIGURED: "#777777",
    ProxyStatus.NO_EQ_DIR: "#777777",
    ProxyStatus.STOPPED: "#c62828",
    ProxyStatus.PORT_IN_USE: "#c62828",
    ProxyStatus.ERROR: "#c62828",
}

_STATUS_LABELS = {
    ProxyStatus.LISTENING: "Listening",
    ProxyStatus.NOT_CONFIGURED: "Not configured",
    ProxyStatus.NO_EQ_DIR: "No EverQuest directory set",
    ProxyStatus.STOPPED: "Not running",
    ProxyStatus.PORT_IN_USE: "Port already in use",
    ProxyStatus.ERROR: "Problem",
}


def build_page(plugin: LoginProxyPlugin, parent: Any) -> Any:
    """Build and return the settings page widget. GUI thread only."""
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtWidgets import (
        QCheckBox,
        QFrame,
        QLabel,
        QMessageBox,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )

    page = QWidget(parent)
    layout = QVBoxLayout(page)
    layout.setSpacing(10)

    about = QLabel(_ABOUT, page)
    about.setWordWrap(True)
    about.setOpenExternalLinks(True)
    layout.addWidget(about)

    rule = QFrame(page)
    rule.setFrameShape(QFrame.Shape.HLine)
    rule.setFrameShadow(QFrame.Shadow.Sunken)
    layout.addWidget(rule)

    warning = QLabel(_WARNING, page)
    warning.setWordWrap(True)
    warning.setTextFormat(Qt.TextFormat.RichText)
    layout.addWidget(warning)

    enable = QCheckBox("Route EverQuest's login through the local proxy", page)
    enable.setChecked(plugin.enabled)
    layout.addWidget(enable)

    status = QLabel(page)
    status.setWordWrap(True)
    status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    layout.addWidget(status)

    eq_warning = QLabel(page)
    eq_warning.setWordWrap(True)
    eq_warning.setStyleSheet("color: #ef6c00;")
    eq_warning.setVisible(False)
    layout.addWidget(eq_warning)

    check_eq = QPushButton("Check whether EverQuest is running", page)
    layout.addWidget(check_eq)

    layout.addStretch(1)

    def refresh() -> None:
        state, detail = plugin.status()
        colour = _STATUS_COLOURS.get(state, "#777777")
        label = _STATUS_LABELS.get(state, state.value)
        status.setText(f'<b style="color:{colour}">{label}.</b> {detail}')
        # Keep the box honest if activation failed or something stopped it.
        if enable.isChecked() != plugin.enabled:
            enable.blockSignals(True)
            enable.setChecked(plugin.enabled)
            enable.blockSignals(False)

    def report(title: str, message: str) -> None:
        QMessageBox.warning(page, title, message)

    def on_toggled(checked: bool) -> None:
        try:
            if checked:
                plugin.enable()
            else:
                plugin.disable()
        except (EqHostError, ProxyError, OSError) as exc:
            report("P99 Login Proxy", str(exc))
            enable.blockSignals(True)
            enable.setChecked(plugin.enabled)
            enable.blockSignals(False)
        refresh()
        if checked and plugin.running:
            on_check_eq(quiet=True)

    def on_check_eq(quiet: bool = False) -> None:
        # Only ever from a button press or straight after a successful enable:
        # the host implementation spawns a process (~18 ms).
        if plugin.eq_is_running():
            eq_warning.setText(
                "EverQuest appears to be running. It reads eqhost.txt at startup, so "
                "restart the client for this change to take effect."
            )
            eq_warning.setVisible(True)
        elif quiet:
            eq_warning.setVisible(False)
        else:
            eq_warning.setText("EverQuest does not appear to be running.")
            eq_warning.setStyleSheet("color: #777777;")
            eq_warning.setVisible(True)

    enable.toggled.connect(on_toggled)
    check_eq.clicked.connect(lambda: on_check_eq(quiet=False))

    timer = QTimer(page)
    timer.setInterval(_POLL_MS)
    timer.timeout.connect(refresh)
    timer.start()
    # Parented to the page, so the host destroying the page stops the timer.

    refresh()
    return page
