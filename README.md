# ai-bridge — Termux ↔ ChatGPT

A **secure, local bridge** that lets ChatGPT operate your Android Termux environment:
run shell commands, read/write/search files, run git & Gradle, inspect the system and
trigger custom workflows — exactly like this Dev Environment tool, but from ChatGPT.

```
User → ChatGPT (Custom GPT) → OpenAPI Action → https tunnel → Termux bridge → shell/files/git/build
```

---

## Quick start

```bash
# 1. install (python + openssh already present on most Termux setups)
cd ~/ai-bridge && bash install.sh

# 2. start server + public tunnel
ai-bridge start

# 3. Copy the printed "OpenAPI" URL into ChatGPT:
#    Custom GPT ➜ Configure ➜ Actions ➜ Import from URL  (Authentication: No authentication)
```

That's it. No API key to copy. The secret is already inside the URL path.

---

## No-API-key design (read this)

ChatGPT Actions normally want an API key header. For the simplest phone workflow this
bridge uses **capability-URL authentication instead**:

* Every request must hit an unguessable path, e.g. `https://<host>/<32-char-token>/execute`.
* The token is generated with `secrets.token_urlsafe(20)` and stored in
  `config/config.json`. Whoever holds the URL holds the capability.
* The bridge only listens on `127.0.0.1`; it is exposed only through the SSH reverse tunnel
  you started with `ai-bridge start` (no random ports forwarded from the phone).
* You can *also* require a header key by setting `api_key` in `config/config.json`.

**Treat your token like a password.** If your ChatGPT conversation has the URL, anyone
who can use that Custom GPT can reach your phone.

---

## Project structure

```
~/ai-bridge/
├── ai-bridge          # control script (start/stop/mode/log/...)
├── install.sh         # package + symlink installer
├── bridge.py          # the zero-dependency server (Python stdlib only)
├── start.sh / stop.sh / status.sh   # convenience wrappers
├── test_local.sh      # manual API test run
├── test_git.sh        # manual git-ops test run
├── config/
│   └── config.json    # token, mode, workspaces, timeouts ...
├── workflows/         # drop bash scripts here to expose them to ChatGPT
├── logs/              # server.log + structured bridge.log (JSONL)
└── run/               # pid files + temp command output
```

---

## Control commands

| Command | What it does |
|---|---|
| `ai-bridge start` | starts server + public tunnel, prints ChatGPT import URL |
| `ai-bridge stop` | kills tunnel + server (emergency stop) |
| `ai-bridge restart` | stop + start |
| `ai-bridge status` | show server/tunnel/mode |
| `ai-bridge mode safe\|development\|full` | switch safety mode (no restart needed) |
| `ai-bridge token show\|rotate` | view / regenerate the secret token |
| `ai-bridge add-project <path>` | allow another project directory |
| `ai-bridge enable\|disable` | emergency enable / hard stop |
| `ai-bridge log [n]` | show recent structured logs |
| `ai-bridge openapi` | print the ChatGPT import URL |
| `ai-bridge workflows` | list available workflows |
| `ai-bridge boot on\|off` | optional autostart at phone boot (Termux:Boot) |

---

## Config

`config/config.json` (all re-read per request — no restarts needed):

```jsonc
{
  "enabled": true,
  "port": 8765,
  "token": "<secret, keep private>",
  "api_key": "",               // optional extra header auth
  "mode": "DEVELOPMENT",       // SAFE | DEVELOPMENT | FULL
  "workspaces": ["/data/data/com.termux/files/home"],  // allowed roots
  "allow_full_filesystem": false,
  "default_timeout": 600,
  "max_timeout": 3600,
  "max_capture": 4194304,      // bytes of stdout/stderr kept per command
  "rate_limit": 180,           // requests/min per client
  "max_open_commands": 20
}
```

---

## Modes

* **SAFE** — read-only. `files/write|delete|move`, `git push|pull|commit`, installs and
  builds are blocked for `/execute`.
* **DEVELOPMENT** (default) — modify project files, run builds/tests, use git, install
  dev deps inside workspaces. Destructive/system-level commands (use in `FULL`).
* **FULL** — nearly anything explicitly allowed. Force push etc. requires this mode.

Emergency: `ai-bridge stop` or `ai-bridge disable` immediately stops accepting requests.

---

## API tools (what ChatGPT sees)

| Tool | Endpoint | Notes |
|---|---|---|
| `termux_run_command` | `POST /execute` | async or sync, timeout, captured output |
| `termux_process_status/output/cancel/list` | `/process/*` | long-running command control |
| `termux_list_directory` | `POST /files/list` | names, types, sizes, mtimes |
| `termux_read_file` / `write` / `delete` / `move` | `/files/*` | sandboxed to workspaces |
| `termux_search_files` | `POST /files/search` | glob search, shielded from `.git/build` |
| `termux_file_exists` | `POST /files/exists` | |
| `termux_git` | `POST /git` | status, diff, log, add, commit, push, pull |
| `termux_dev` | `POST /dev` | build, clean, test, gradle, script |
| `termux_system_info` | `POST /system/info` | OS + installed toolchain |
| `termux_disk_usage` | `POST /system/disk` | `df -h` |
| `termux_processes` | `POST /system/processes` | process table |
| `termux_check_command` | `POST /system/check` | is a binary installed? |
| `termux_list_workflows` | `GET /workflows` | |
| `termux_run_workflow` | `POST /workflows` | runs `workflows/<name>.sh` |

The live schema (with your token embedded) is served at:
`https://<tunnel-host>/<token>/openapi.json`

---

## Workflows

Drop a bash script into `workflows/`. The first non-shebang `# comment` line becomes its
description shown to ChatGPT. Then just say: *"run the deploy workflow on AyuGram"*.

```bash
#!/data/data/com.termux/files/usr/bin/bash
# Deploy: pull latest and rebuild. Usage: deploy.sh <project-dir>
set -e
cd "$1"
git pull --ff-only
./gradlew build
```

---

## Security summary

* Secret capability token in URL path (plus optional `X-API-Key` header).
* Server bound to `127.0.0.1` only; tunnel is SSH-based (localhost.run/serveo.net), no
  phone ports exposed.
* Path sandbox: `realpath` containment inside `workspaces`; `../` escapes rejected.
* Command policy: permanently-blocked patterns (writes to `/`, `mkfs`, pipe-to-shell …)
  and destructive patterns (`rm -rf`, force push, `kill -9`, `pkill` …) gated by mode.
* SAFE mode blocks installing/building/writing at the shell level.
* Rate limiting per client IP.
* Structured JSONL logs (never log tokens, keys, passwords).
* Right-sized timeouts, large-output capture, async long-running commands with cancel.

---

## Troubleshooting

* `ai-bridge start` prints no public URL → no internet, or SSH tunnels are blocked.
  Fallbacks: `pkg install cloudflared` then
  `cloudflared tunnel --url http://localhost:8765`, or tunnel to another device.
* ChatGPT says "action failed" → check `ai-bridge log 20` and `ai-bridge status`.
* After `ai-bridge token rotate`, re-import the *new* OpenAPI URL in ChatGPT.
* Slow setup from phone → the bridge reads config per request; toggling modes never
  requires a restart.

---

## For developers / fresh clone

```bash
git clone <repo-url> && cd ai-bridge
bash install.sh        # installs python + openssh, generates config/config.json (real token)
ai-bridge start        # shows the ChatGPT import URL
```

* `config/config.example.json` — sanitized reference config. The real
  `config/config.json` (with your generated token) is **gitignored**; `install.sh`
  creates it automatically. Do not hand-edit the example into place.
* `config/config.json` will be generated automatically on first run. Never commit it.
* `openapi/example.json` — auditable snapshot of the OpenAPI schema used by the
  bridge. The live schema is served dynamically at `/<token>/openapi.json` with your
  token embedded. Regenerate the snapshot with
  `python3 scripts/export_openapi.py openapi/example.json`.
* `.env.example` — documents the optional environment variables. No real
  credentials go in `.env`; secrets belong in the gitignored `config/config.json`.
* The SSH tunnel implementation is in `ai-bridge` (`start_tunnel`), using
  zero-setup providers `localhost.run` → `serveo.net` fallback, no tunnel secrets
  required.

## Testing

```bash
bash test_local.sh   # health, execute, async/cancel, files, path-escape, modes, workflows
bash test_git.sh     # git status/log/diff/commit against a scratch repo
```

Or manually: `ai-bridge start`, then hit `http://127.0.0.1:8765/<token>/health`.