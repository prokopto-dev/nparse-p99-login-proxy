# P99 Login Proxy

An [nParse+](https://github.com/prokopto-dev/nparse-plus) add-on that fixes the blank
server-select screen Project 1999 players hit on Linux/WINE, Proton and macOS/CrossOver.

---

## What it fixes

You log in with your P99 account, the client accepts it, and then the server-select screen
is completely empty. No servers, no error, no explanation.

The EQEmu login server sends its server list as roughly 6 KB split across about ten UDP
datagrams. The loginserver protocol has **no retransmit and no out-of-order handling**, so
if a single fragment is dropped or reordered the client never reassembles the list and
draws nothing at all. It is strongly correlated with Wi-Fi, it is router-dependent, and it
is common enough that the P99 wiki documents it on its
[Tech Support](https://wiki.project1999.com/Tech_Support),
[Linux](https://wiki.project1999.com/EverQuest_in_Linux_Guide) and
[Steam Deck](https://wiki.project1999.com/Project_1999_on_Steam_Deck_and_Linux_via_Proton)
pages. Plenty of players find it works on Ethernet, or on a phone hotspot, and never at
home.

The fix those pages recommend is a small local proxy: it sits between the game client and
the login server, forwards everything untouched except the server list, and for that one
message reassembles the fragments itself, discards every server that is not P99, and hands
the client **one small packet instead of ten**. Nothing is left to drop.

This add-on is that proxy, as a checkbox inside an app you are already running. Previously
it meant installing a C toolchain and running `make` — a real barrier on Steam Deck's
read-only filesystem.

## Credits

The protocol work is a port of **[Zaela's
p99-login-middlemand](https://github.com/Zaela/p99-login-middlemand)**, read at commit
`9b74f470cb15f3518cd66e89c8c4732f337b0ed3`. It is released under the
[Unlicense](https://unlicense.org), a public-domain dedication that imposes no obligation
of any kind — the credit here is given because it is deserved, not because it is required.
Without those ~800 lines of C this add-on would not exist.

No C or C# source is vendored into this repository. It was read, ported, and cited.

## Requirements

- nParse+ **v2.14.0** or newer (the first release bundling SDK 1.2, which is what exposes
  the EQ install directory this plugin needs)
- Python 3.12+, which nParse+ already provides
- No additional dependencies — the proxy is pure standard library

## Install

**End users do not `pip install` nParse+ add-ons.** Use one of:

1. **From the release zip** — download `p99_login_proxy.zip` from
   [Releases](https://github.com/prokopto-dev/nparse-p99-login-proxy/releases), then in
   nParse+ go to *Settings → Plugins → Install from file…*
2. **From URL** — *Settings → Plugins → Install from URL…* with the zip's download link.
3. **By hand** — drop the `p99_login_proxy/` directory into your plugins folder and
   restart nParse+:
   - macOS: `~/Library/Application Support/nparseplus/plugins/`
   - Linux: `~/.config/nparseplus/plugins/`
   - Windows: `%LOCALAPPDATA%\nparseplus\nparseplus\plugins\`

Add-ons are opt-in: enable them under *Settings → Advanced → Enable plugins*, then consent
to this one by name.

## Use

1. Set your EverQuest install directory in nParse+ settings, if you have not already.
2. Open *Settings → P99 Login Proxy*.
3. Tick **Route EverQuest's login through the local proxy**.
4. Restart EverQuest if it is already running — the client reads `eqhost.txt` at startup.

Ticking the box backs up your `eqhost.txt`, then rewrites it from

```ini
[LoginServer]
Host=login.eqemulator.net:5998
```

to

```ini
[LoginServer]
Host=127.0.0.1:5998
```

Your original port is carried over, so a custom one keeps working. Unticking the box stops
the proxy and restores the backup byte for byte.

---

## ⚠️ Two things to know before you enable this

**1. nParse+ must be running before you log in.**

Once `eqhost.txt` points at this machine, the game client talks to the proxy instead of the
login server. If nParse+ is not running when you start EverQuest, there is nothing
listening and your server list will be blank — which is worse than the problem this fixes,
because now it happens every single time.

**2. Revert before uninstalling.**

Removing this add-on does **not** undo the `eqhost.txt` change on its own. If you delete
the plugin while it is still enabled, `eqhost.txt` keeps pointing at a proxy that will
never run again, and you are locked out with no obvious cause. Untick the box first, then
uninstall.

If you have already hit either of these: open `eqhost.txt` in your EverQuest directory and
set `Host=` back to `login.eqemulator.net:5998`. A pristine copy is also kept in
`<EverQuest>/p99_login_proxy_backup/eqhost.txt`.

---

## What it does and does not touch

- The **only** file it ever writes in your EverQuest install is `eqhost.txt`, and only the
  `[LoginServer]` section of it. Other sections, comments and the file's newline style are
  preserved.
- It listens on **`127.0.0.1` only**, never on all interfaces. An unauthenticated UDP relay
  has no business being reachable from your LAN, and a loopback bind is also why macOS
  never raises a firewall prompt for it.
- It **never logs packet contents**, at any level, in any build. This stream carries your
  login credentials and nParse+ writes its log to disk. Opcodes, sequence numbers and
  lengths only — and there is a test that asserts it rather than a comment that promises
  it.
- It only sits in front of the **login** server. It does nothing to the game server
  connection, and it does not touch your account, password or characters.

## Note for reviewers

`nparseplus-plugin validate` emits one advisory warning:

```
warning: p99_login_proxy/proxy.py:44: imports socket — opens raw network sockets
```

That is expected. This plugin *is* a UDP proxy; `socket` is the entire point. The advisory
scan flags the import for a human to look at, and warnings never fail validation. The
sockets it opens are one loopback listener and one outbound socket to the login server.

## Development

```sh
uv venv --python 3.12
uv pip install -e '.[dev]'

ruff check . && ruff format --check .
python -m pytest -q
nparseplus-plugin validate p99_login_proxy
```

The suite runs with only the SDK installed. One caveat worth knowing:
`nparseplus_sdk.eqfiles` defines none of the helpers it exports — it is a lazy forwarder to
the host app's `nparseplus.core.eqini`, and the app is not on PyPI. So `tests/conftest.py`
uses the real helpers when the app is importable and a faithful stub otherwise; the test
bodies are identical either way. To run against the real ones:

```sh
uv pip install -e '.[host]'
python -m pytest -q tests/test_eqhost.py
```

CI runs both legs, across Ubuntu, macOS and Windows.

## Licence

MIT — see [LICENSE](LICENSE). The ported protocol logic originates in Zaela's
`p99-login-middlemand`, which is public domain under the Unlicense.
