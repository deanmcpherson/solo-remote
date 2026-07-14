# Solo Remote

> ⚠️ **Not official. Highly experimental. Likely broken.**
> This is a personal hack project for remote-controlling [Solo](https://soloterm.com) from a phone.
> It is not affiliated with or endorsed by the Solo team, it pokes at Solo's internals in
> unsupported ways (including editing its SQLite database), and any Solo update may break it.
> Use at your own risk.

A mobile-first PWA remote control for [Solo](https://soloterm.com). Run it on the Mac
where Solo lives, open it on your phone, and drive your agents from the couch.

## What it does

- **Live screen** — every agent across all projects, ordered by last response, with
  AI session titles and responding / working / waiting status
- **Full interactive terminals** — real colored rendering (xterm.js), keystroke or
  compose-and-send input, quick keys (^C, esc, tab, ⇧tab, arrows), scroll gestures
  forwarded to the TUI with momentum
- **Per-screen pty sizing** — sessions reflow to phone width when opened on the phone,
  and hand the pty back to desktop dimensions when you leave
- **Projects** — todos, scratchpads, commands (start/stop/restart), terminals, agent
  spawning (defaults to Claude) and session resume (specific session or picker)
- **Transcript view** — lazy-loaded conversation history read from Claude's session files
- **Notifications** — Web Push when an agent finishes and is waiting for input
  (debounced, deduped, suppressed while you're looking at it), with an in-app inbox
- **Auth** — 6-digit PIN + WebAuthn passkeys, sessions expire after 5 minutes without
  interaction, in-place lock screen
- **Installable PWA** — standalone app on Android/iOS, e-ink-friendly black & white
  theme with light/dark modes

## Requirements

- macOS with [Solo](https://soloterm.com) installed at `/Applications/Solo.app` and running
- Node.js 20+
- Solo's HTTP API discovery file at `~/.config/soloterm/http-api.json` (Solo writes
  this automatically)
- Optional but recommended: [Tailscale](https://tailscale.com) for HTTPS (required for
  passkeys, push notifications, and Android PWA install)

## Setup

```sh
git clone https://github.com/deanmcpherson/solo-remote
cd solo-remote
npm install
node server.mjs
```

The server prints your LAN URL and a generated 6-digit PIN (persisted in `auth.json`;
delete that file to rotate everything). Open the URL on your phone and enter the PIN.

> If you launch the server from a terminal *inside* Solo, that's fine — it strips
> Solo's environment so its MCP helper stays anonymous. See "How it works" for why.

### Colored terminals (optional, invasive)

Solo strips ANSI colors from all output it serves, so out of the box you get plain-text
terminals. Solo Remote can render full color by wrapping Claude sessions in `script(1)`,
which tees the raw pty byte stream to `/tmp`. That requires rewriting the Claude agent
tool command **in Solo's own database** (this is the "likely broken" part — schema may
change any time; back up `~/.config/soloterm/solo.db` first):

```sh
sqlite3 ~/.config/soloterm/solo.db <<'SQL'
UPDATE agent_tool_installations
SET command='wrap() { L=/tmp/solo-tee-$$.log; if [ $# -eq 0 ]; then exec script -qF $L claude --session-id $(uuidgen | tr A-Z a-z); else exec script -qF $L claude "$@"; fi }; wrap'
WHERE agent_tool_id = (SELECT id FROM agent_tools WHERE tool_type='claude');
SQL
```

New Claude sessions (spawned from Solo or the remote) then record raw ANSI and get the
full colored terminal. The `--session-id` part also gives each session a known UUID so
titles/transcripts/resume are exact when several agents share a project. Existing
sessions keep the plain-text view until restarted.

To undo: set the command back to `claude`.

### HTTPS via Tailscale (optional)

Passkeys, push notifications, and Android's "Install app" all require a secure context,
which a LAN IP over HTTP is not. With Tailscale on the Mac and your phone:

```sh
tailscale serve --bg 8123
```

You'll get `https://<machine>.<tailnet>.ts.net` with a valid certificate. Everything
works over plain HTTP on the LAN except those three features.

### Install as an app

Open the HTTPS URL on your phone → browser menu → **Install app** (Android) or
**Add to Home Screen** (iOS). Then, in the app's settings (⚙): add a passkey and
enable push notifications.

## Configuration

| Env var | Default | |
|---|---|---|
| `PORT` | `8123` | Listen port |
| `SOLO_DISCOVERY` | `~/.config/soloterm/http-api.json` | Solo API discovery file |
| `SOLO_MCP_BIN` | `/Applications/Solo.app/Contents/MacOS/mcp` | Solo MCP helper binary |
| `PUSH_CONTACT` | `mailto:solo-remote@example.com` | VAPID contact sent to push services (set to your email) |

## How it works (and why it's fragile)

Solo's HTTP API binds to loopback only, so `server.mjs` is a LAN/tailnet proxy that
injects Solo's bearer token server-side. Several things the UI needs aren't exposed by
Solo's API at all, so the proxy reaches around it:

- **Typing** goes through Solo's MCP stdio helper (`send_input`), spawned with a
  scrubbed environment and no controlling tty — Solo identifies MCP clients by their
  process context, and a helper that inherits a Solo-managed identity breaks whenever
  Solo restarts and renumbers processes. The bridge also self-heals by respawning on
  stale-identity errors.
- **Color** comes from the `script(1)` tee described above; the inner pty is resized
  per viewing screen with `stty`, and scroll gestures are forwarded as SGR mouse-wheel
  escape sequences (Claude has mouse reporting on, so it scrolls its own content).
- **Session titles, transcripts, resume targets, and "responding" detection** are read
  from Claude Code's session files in `~/.claude/projects/…` — matched to processes via
  `lsof`/`ps` (cwd + `--session-id`/`--resume` in argv). Pty output can't be used for
  activity detection because Claude's idle screen animates constantly.
- **Notifications** come from a server-side watcher polling Solo every 6s.

Every one of those is an implementation detail of Solo and/or Claude Code that can
change without notice. Hence: experimental, likely broken.

## Security notes

- The PIN gates everything; a correct PIN sets a session that dies after 5 minutes
  without user interaction. Passkeys (WebAuthn, verified server-side, no dependencies)
  make re-auth a biometric tap.
- `auth.json` holds the PIN, session secret, VAPID keys, passkey public keys, and push
  subscriptions — it's gitignored and created with mode 600. Don't commit it.
- The proxy has full control over Solo (and therefore your shell). Only expose it on
  networks you trust; Tailscale is the sane way to reach it from outside.

## License

No license granted yet — all rights reserved. Open an issue if you want to do something
with it.
