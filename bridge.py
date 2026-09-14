#!/usr/bin/env python3
"""
ai-bridge - secure Termux bridge server for AI assistants (ChatGPT).

Zero third-party dependencies. Standard library only.

Security model (per plugin.txt):
  * The access token is embedded in the URL path (e.g. /<token>/execute).
    Whoever holds the secret URL holds the capability -> effectively
    "works without an API key" while still being an unguessable secret.
  * Workspaces are enforced with realpath containment.
  * Operation modes (SAFE / DEVELOPMENT / FULL) gate destructive actions.
  * Rate limiting, structured logs, optional header API key.

Run:  python bridge.py   (or `ai-bridge start`)
"""

import datetime
import fnmatch
import json
import logging
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TERMUX_PREFIX = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
BRIDGE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BRIDGE_DIR, "config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
WORKFLOWS_DIR = os.path.join(BRIDGE_DIR, "workflows")
LOG_FILE = os.path.join(BRIDGE_DIR, "logs", "bridge.log")
RUN_DIR = os.path.join(BRIDGE_DIR, "run")
PID_FILE = os.path.join(RUN_DIR, "bridge.pid")

for _d in (CONFIG_DIR, WORKFLOWS_DIR, os.path.join(BRIDGE_DIR, "logs"), RUN_DIR):
    os.makedirs(_d, exist_ok=True)

# ---------------------------------------------------------------- config

DEFAULT_CONFIG = {
    "version": 1,
    "enabled": True,
    "host": "127.0.0.1",
    "port": 8765,
    "token": None,  # generated below
    "api_key": "",  # optional extra header auth; empty = disabled
    "mode": "DEVELOPMENT",       # SAFE | DEVELOPMENT | FULL
    "workspaces": [],            # empty -> default to home
    "allow_full_filesystem": False,
    "default_timeout": 600,      # seconds for sync commands
    "max_timeout": 3600,
    "max_capture": 4194304,      # max bytes of stdout/stderr kept per command
    "rate_limit": 180,           # requests per minute per client
    "max_open_commands": 20,
    "git_allow_rebase": False,
}

NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def load_config():
    if not os.path.exists(CONFIG_FILE):
        cfg = dict(DEFAULT_CONFIG)
        cfg["token"] = secrets.token_urlsafe(20)
        cfg["api_key"] = ""
        home = os.path.expanduser("~")
        if not cfg["workspaces"]:
            cfg["workspaces"] = [home]
        if not cfg["api_key"] and not cfg.get("token"):
            cfg["token"] = secrets.token_urlsafe(20)
        save_config(cfg)
        logging.getLogger("config").info("wrote new config at %s", CONFIG_FILE)
        return cfg
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("config").error("corrupt config: %s", exc)
        return dict(DEFAULT_CONFIG)
    changed = False
    for k, v in DEFAULT_CONFIG.items():
        if k not in cfg:
            cfg[k] = v
            changed = True
    if cfg["mode"] not in ("SAFE", "DEVELOPMENT", "FULL"):
        cfg["mode"] = "DEVELOPMENT"
        changed = True
    if changed:
        save_config(cfg)
    return cfg


def save_config(cfg):
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    os.replace(tmp, CONFIG_FILE)


_config = load_config()


def get_config():
    reload_opt = os.environ.get("AI_BRIDGE_CFG_CHECK", "1") == "1"
    if reload_opt:
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:  # noqa: BLE001
            return _config
    return _config


# ---------------------------------------------------------------- logging

_json_log = logging.getLogger("ai-bridge-json")
_json_log.setLevel(logging.INFO)
_fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
_fmt = logging.Formatter("%(message)s")
_fh.setFormatter(_fmt)
_json_log.addHandler(_fh)

_console = logging.getLogger("ai-bridge")
_console.setLevel(logging.INFO)
_ch = logging.StreamHandler(sys.stdout)
_ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
_console.addHandler(_ch)


def log_operation(record):
    record.setdefault("ts", datetime.datetime.now().isoformat(timespec="seconds"))
    try:
        _json_log.info(json.dumps(record, ensure_ascii=False))
    except Exception:  # noqa: BLE001
        pass
    _console.info("%s %s cwd=%s success=%s", record.get("operation"),
                  (record.get("command") or record.get("tool") or "")[:120],
                  record.get("working_directory"),
                  record.get("success"))


def sanitize(text, limit=2000):
    return (text or "")[:limit]


# ---------------------------------------------------------------- path safety

def resolve_path(path, base=None):
    if base:
        path = path if os.path.isabs(path) else os.path.join(base, path)
    return os.path.realpath(path)


def workspace_roots(cfg):
    roots = []
    if cfg.get("allow_full_filesystem"):
        return ["/"]
    for w in cfg.get("workspaces") or []:
        r = os.path.realpath(os.path.expanduser(str(w)))
        if os.path.isdir(r) or r == "/":
            roots.append(r)
    # fallback to home if none valid
    if not roots:
        roots = [os.path.realpath(os.path.expanduser("~"))]
    return roots


def is_allowed_path(cfg, path):
    roots = workspace_roots(cfg)
    if "/" in roots:
        return True
    return any(path == r or path.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


def require_path(cfg, raw, base=None):
    """Validate a client-supplied path against workspaces. Returns realpath or raises ValueError."""
    if not raw or not isinstance(raw, str):
        raise ValueError("path is required and must be a string")
    path = resolve_path(raw, base)
    if not is_allowed_path(cfg, path):
        raise ValueError("path is outside the configured workspace: " + path)
    return path


# ---------------------------------------------------------------- command policy

BLOCKED_RE = [
    re.compile(r"(^|[;&|]\s*)(rm\s+-rf\s+/\b|rm\s+-rf\s+~)",
               re.IGNORECASE),
    re.compile(r"\bmkfs\b|\bfdisk\b|\bparted\b|\bdd\s+if=.*of=/\S*\b", re.IGNORECASE),
    re.compile(r"\bwipe\b|\bjffs2reset\b|\bformat\b", re.IGNORECASE),
    re.compile(r"(^|[;&|]\s*)shutdown\b|(^|[;&|]\s*)reboot\b", re.IGNORECASE),
    re.compile(r"\bcurl\s+.*\|\s*(sh|bash)\b|\bwget\s+.*\|\s*(sh|bash)\b", re.IGNORECASE),
    re.compile(r"/dev/tcp/|/dev/udp/", re.IGNORECASE),
]

CONFIRM_RE = [
    re.compile(r"\brm\s+(-[a-z]*r[a-z]*f?[a-z]*\s+|\s*-f)", re.IGNORECASE),
    re.compile(r"\bgit\s+push\b[^|;&]*--force\b|\bgit\s+push\b[^|;&]*\s-f\s", re.IGNORECASE),
    re.compile(r"\bpkill\b|\bkill\s+-9\b|\bkilled\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+-R\b|\bchown\s+-R\b", re.IGNORECASE),
    re.compile(r"\bsudo\b|\bsu\s+-", re.IGNORECASE),
    re.compile(r"\btermux-reload-settings\b|\binit\b", re.IGNORECASE),
]


SAFE_WRITE_RE = [
    re.compile(r"\bnpm\s+(install|update|remove|add)\b", re.IGNORECASE),
    re.compile(r"\bpip\s+(install|uninstall|download)\b", re.IGNORECASE),
    re.compile(r"\b(pkg|apt|dpkg)\s+\S*install|pkg\s+upgrade", re.IGNORECASE),
    re.compile(r"\bgit\s+(commit|push|pull|merge|rebase|add|reset)\b", re.IGNORECASE),
    re.compile(r"(^|[;&|]$|\s)(mv|cp|rm|rmdir|touch|mkdir|chmod|chown)\b", re.IGNORECASE),
    re.compile(r"\./gradlew|gradle(?![a-z])", re.IGNORECASE),
    re.compile(r"\bmake\b|\bcmake\b", re.IGNORECASE),
    re.compile(r"^\s*(\w[^>]*)?>\s*\S+|>>\s*\S+"),
    re.compile(r"\bnpx\b"),  # downloads packages
]


def classify_command(command):
    command = (command or "").strip()
    for rx in BLOCKED_RE:
        if rx.search(command):
            return "BLOCKED"
    if any(rx.search(command) for rx in CONFIRM_RE):
        return "DESTRUCTIVE"
    return "NORMAL"


def mode_allows(cfg, op, path=None):
    mode = (cfg.get("mode") or "DEVELOPMENT").upper()
    if mode == "FULL":
        return True, None
    if mode == "SAFE":
        # read-only
        if op in ("read", "list", "search", "exists", "system", "status",
                  "log", "diff", "info"):
            return True, None
        return False, "SAFE mode only allows read-only operations"
    # DEVELOPMENT: writes within workspace ok, destructive/system needs confirm and workspace path
    if op in ("destroy", "kill", "system_modify", "force_push"):
        if path and is_allowed_path(cfg, path):
            return True, None
        return False, "operation blocked in DEVELOPMENT mode (use FULL mode or confirm)"
    return True, None


# ---------------------------------------------------------------- process registry

class ProcEntry:
    __slots__ = ("pid", "proc", "cmd", "cwd", "out_path", "err_path", "start",
                 "timeout", "finished", "exit_code", "note")

    def __init__(self, pid, proc, cmd, cwd, out_path, err_path, timeout):
        self.pid = pid
        self.proc = proc
        self.cmd = cmd
        self.cwd = cwd
        self.out_path = out_path
        self.err_path = err_path
        self.start = time.time()
        self.timeout = timeout
        self.finished = None
        self.exit_code = None
        self.note = None


class ProcRegistry:
    def __init__(self):
        self.lock = threading.Lock()
        self.procs = {}

    def register(self, entry):
        with self.lock:
            if len(self.procs) >= int(get_config().get("max_open_commands", 20)):
                raise RuntimeError("too many concurrent commands, cancel some first")
            self.procs[str(entry.pid)] = entry

    def get(self, pid):
        with self.lock:
            return self.procs.get(str(pid))

    def unregister(self, pid):
        with self.lock:
            self.procs.pop(str(pid), None)

    def refresh(self, pid):
        entry = self.get(pid)
        if entry is None or entry.finished is not None:
            return entry
        if entry.proc.poll() is not None:
            entry.finished = time.time()
            entry.exit_code = entry.proc.poll()
        return entry

    def cancel(self, pid):
        entry = self.refresh(pid)
        if entry is None:
            return False
        if entry.finished is None:
            try:
                entry.proc.terminate()
            except Exception:  # noqa: BLE001
                pass
            for _ in range(50):
                if entry.proc.poll() is not None:
                    break
                time.sleep(0.1)
            try:
                if entry.proc.poll() is None:
                    entry.proc.kill()
            except Exception:  # noqa: BLE001
                pass
            entry.finished = time.time()
            entry.exit_code = entry.proc.poll() or -9
            entry.note = "cancelled"
        return True

    def list(self):
        out = []
        with self.lock:
            ids = list(self.procs.keys())
        for pid in ids:
            e = self.refresh(pid)
            if e is None:
                continue
            running = e.finished is None
            if not running:
                self.unregister(pid)
            out.append({
                "process_id": e.pid,
                "command": e.cmd,
                "working_directory": e.cwd,
                "started_at": int(e.start),
                "duration": round(time.time() - e.start, 2) if running else round(e.finished - e.start, 2),
                "running": running,
                "exit_code": e.exit_code,
                "note": e.note,
            })
        return out


REGISTRY = ProcRegistry()

CAPTURE_TAIL = int(get_config().get("max_capture", 4194304))


def _read_stream(path, max_bytes=None):
    max_bytes = max_bytes or CAPTURE_TAIL
    if not path or not os.path.exists(path):
        return "", False
    size = os.path.getsize(path)
    truncated = size > max_bytes
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        if truncated:
            fh.seek(size - max_bytes)
        data = fh.read()
    return data, truncated


def _cmd_env():
    env = dict(os.environ)
    env.setdefault("TERM", "xterm-256color")
    env.setdefault("HOME", os.path.expanduser("~"))
    return env


def _prune_tmp_files():
    now = time.time()
    try:
        for name in os.listdir(RUN_DIR):
            if name.startswith("aib_"):
                p = os.path.join(RUN_DIR, name)
                try:
                    if now - os.path.getmtime(p) > 3600:
                        os.unlink(p)
                except OSError:
                    pass
    except OSError:
        pass


def run_command(command, cwd, timeout=None, async_mode=False,
                max_capture=None, env_extra=None):
    cfg = get_config()
    max_capture = max_capture or int(cfg.get("max_capture", CAPTURE_TAIL))
    timeout = timeout or int(cfg.get("default_timeout", 600))
    timeout = max(1, min(int(timeout), int(cfg.get("max_timeout", 3600))))

    _prune_tmp_files()
    fd_out, out_path = tempfile.mkstemp(prefix="aib_out_", dir=RUN_DIR)
    fd_err, err_path = tempfile.mkstemp(prefix="aib_err_", dir=RUN_DIR)
    os.close(fd_out)
    os.close(fd_err)

    env = _cmd_env()
    if env_extra:
        env.update({str(k): str(v) for k, v in env_extra.items()})

    try:
        proc = subprocess.Popen(
            ["bash", "-c", command],
            stdout=open(out_path, "wb"),
            stderr=open(err_path, "wb"),
            cwd=cwd,
            env=env,
            start_new_session=True,
        )
    except FileNotFoundError:
        return {"error": "command_not_found", "message": "bash not found"}
    except Exception as exc:  # noqa: BLE001
        return {"error": "spawn_failed", "message": str(exc)}

    start = time.time()

    if async_mode:
        entry = ProcEntry(proc.pid, proc, command, cwd, out_path, err_path, timeout)
        REGISTRY.register(entry)
        return {
            "async": True,
            "process_id": proc.pid,
            "command": command,
            "working_directory": cwd,
            "running": True,
        }

    try:
        # self-terminating watchdog so timeouts clean up the whole process group
        def _killer():
            time.sleep(timeout)
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:  # noqa: BLE001
                pass

        killer = threading.Thread(target=_killer, daemon=True)
        killer.start()
        proc.wait()
        exit_code = proc.poll() or 0
        timed_out = False
    except Exception as exc:  # noqa: BLE001
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:  # noqa: BLE001
            pass
        proc.wait()
        exit_code = proc.poll() or -1
        timed_out = True

    duration = round(time.time() - start, 2)
    stdout, out_trunc = _read_stream(out_path, max_capture)
    stderr, err_trunc = _read_stream(err_path, max_capture)
    try:
        os.unlink(out_path)
    except Exception:  # noqa: BLE001
        pass
    try:
        os.unlink(err_path)
    except Exception:  # noqa: BLE001
        pass

    return {
        "success": True,
        "command": command,
        "working_directory": cwd,
        "exit_code": exit_code,
        "timeout": timed_out,
        "duration": duration,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": out_trunc,
        "stderr_truncated": err_trunc,
    }


# ---------------------------------------------------------------- tool implementations

def tool_execute(body):
    cmd = body.get("command")
    if not cmd or not isinstance(cmd, str):
        raise ValueError("'command' (string) is required")
    cfg = get_config()
    cwd = require_path(cfg, body.get("working_directory") or os.path.expanduser("~"))

    level = classify_command(cmd)
    if level == "BLOCKED":
        return {"error": "blocked_command",
                "message": "command matches a permanently blocked pattern"}
    if level == "DESTRUCTIVE":
        ok, reason = mode_allows(cfg, "destroy", cwd)
        if not ok:
            return {"error": "blocked_destructive_command",
                    "message": reason + ". Destructive command denied before execution"}
    mode = (cfg.get("mode") or "DEVELOPMENT").upper()
    if mode == "SAFE" and level == "NORMAL" and any(rx.search(cmd) for rx in SAFE_WRITE_RE):
        return {"error": "safe_mode_write_blocked",
                "message": "SAFE mode only allows read-only commands"}

    res = run_command(cmd, cwd,
                      timeout=body.get("timeout"),
                      async_mode=bool(body.get("async")),
                      max_capture=body.get("max_output"))
    if isinstance(res, dict) and res.get("error"):
        raise RuntimeError(res["message"])
    return res


def _file_op(cfg, raw_path, must_exist=True, base=None):
    return require_path(cfg, raw_path, base)


def tool_list_directory(body):
    cfg = get_config()
    path = _file_op(cfg, body.get("path") or os.path.expanduser("~"), must_exist=False)
    if not os.path.isdir(path):
        raise ValueError("not_a_directory: " + path)
    entries = []
    try:
        names = sorted(os.listdir(path))
    except PermissionError:
        raise ValueError("permission_denied reading directory")
    for name in names:
        p = os.path.join(path, name)
        try:
            st = os.lstat(p)
            kind = "dir" if os.path.isdir(p) else ("link" if os.path.islink(p) else "file")
            entries.append({
                "name": name,
                "path": p,
                "type": kind,
                "size": st.st_size,
                "mtime": int(st.st_mtime),
            })
        except Exception:  # noqa: BLE001
            entries.append({"name": name, "path": p, "type": "?", "size": -1, "mtime": -1})
    return {"path": path, "entries": entries}


def tool_read_file(body):
    cfg = get_config()
    path = _file_op(cfg, body.get("path"))
    if not os.path.isfile(path):
        raise ValueError("file_not_found: " + path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except PermissionError:
        raise ValueError("permission_denied reading file")
    except OSError as exc:
        raise ValueError("read_failed: %s" % exc)
    return {"path": path, "content": content, "size": len(content)}


def tool_write_file(body):
    cfg = get_config()
    path = require_path(cfg, body.get("path"))
    content = body.get("content")
    if not isinstance(content, str):
        raise ValueError("'content' (string) is required")
    ok, reason = mode_allows(cfg, "write", path)
    if not ok:
        return {"error": "permission", "message": reason}
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        if not is_allowed_path(cfg, parent):
            raise ValueError("parent directory outside workspace")
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            raise ValueError("mkdir_failed: %s" % exc)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    except OSError as exc:
        raise ValueError("write_failed: %s" % exc)
    return {"success": True, "path": path, "bytes": len(content)}


def tool_delete_file(body):
    cfg = get_config()
    path = _file_op(cfg, body.get("path"))
    ok, reason = mode_allows(cfg, "destroy", path)
    if not ok:
        return {"error": "permission", "message": reason}
    recursive = bool(body.get("recursive"))
    if os.path.isdir(path) and not recursive:
        raise ValueError("is_directory: pass recursive=true to delete a directory")
    try:
        if os.path.isdir(path) and recursive:
            shutil.rmtree(path)
        else:
            os.remove(path)
    except FileNotFoundError:
        raise ValueError("file_not_found: " + path)
    except OSError as exc:
        raise ValueError("delete_failed: %s" % exc)
    return {"success": True, "path": path}


def tool_move_file(body):
    cfg = get_config()
    src = _file_op(cfg, body.get("source"))
    dst = require_path(cfg, body.get("destination"))
    ok, reason = mode_allows(cfg, "write", dst)
    if not ok:
        return {"error": "permission", "message": reason}
    if not os.path.exists(src):
        raise ValueError("file_not_found: " + src)
    parent = os.path.dirname(dst)
    if not is_allowed_path(cfg, parent):
        raise ValueError("destination outside workspace")
    try:
        os.makedirs(parent, exist_ok=True)
        os.replace(src, dst)
    except OSError as exc:
        raise ValueError("move_failed: %s" % exc)
    return {"success": True, "source": src, "destination": dst}


def tool_search_files(body):
    cfg = get_config()
    root = _file_op(cfg, body.get("path") or os.path.expanduser("~"), must_exist=False)
    pattern = body.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("'pattern' is required (e.g. '*.java')")
    if not os.path.isdir(root):
        raise ValueError("not_a_directory: " + root)
    max_depth = int(body.get("depth") or 8)
    limit = int(body.get("limit") or 500)
    results = []
    root_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath.rstrip(os.sep).count(os.sep) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if not d.startswith(".git") and not d.startswith("build")]
        for name in filenames:
            if fnmatch.fnmatch(name, pattern):
                p = os.path.join(dirpath, name)
                results.append(p)
                if len(results) >= limit:
                    return {"path": root, "pattern": pattern, "results": results, "truncated": True}
    return {"path": root, "pattern": pattern, "results": results, "truncated": False}


def tool_file_exists(body):
    cfg = get_config()
    try:
        path = require_path(cfg, body.get("path"))
    except ValueError:
        return {"path": body.get("path"), "exists": False}
    return {"path": path, "exists": os.path.exists(path),
            "is_file": os.path.isfile(path), "is_dir": os.path.isdir(path)}


# ---------------------------------------------------------------- git / dev / system

def _git(cfg, project, args, capture=True, timeout=300):
    cwd = _file_op(cfg, project)
    if not os.path.isdir(os.path.join(cwd, ".git")) and args[0] not in ("init",):
        if not os.path.isdir(cwd):
            raise ValueError("project directory does not exist")
    argline = "git " + " ".join(shlex_quote(a) for a in args)
    return run_command(argline, cwd, timeout=timeout)


def git_handle(body):
    cfg = get_config()
    project = body.get("path")
    if not project:
        raise ValueError("'path' (project directory) is required")
    op = body.get("op")
    ok, reason = mode_allows(cfg, "status", None)
    if not ok:
        return {"error": "permission", "message": reason}

    if op == "status":
        return _git(cfg, project, ["status"])
    if op == "diff":
        return _git(cfg, project, ["diff"], timeout=600)
    if op == "log":
        return _git(cfg, project, ["log", "--oneline", "-30", "--decorate"])
    if op == "add":
        ok, reason = mode_allows(cfg, "write")
        if not ok:
            return {"error": "permission", "message": reason}
        files = body.get("files") or ["."]
        return _git(cfg, project, ["add"] + files)
    if op == "commit":
        ok, reason = mode_allows(cfg, "write")
        if not ok:
            return {"error": "permission", "message": reason}
        msg = body.get("message")
        if not msg:
            raise ValueError("'message' is required for commit")
        staged = _git(cfg, project, ["diff", "--cached", "--quiet"], timeout=60)
        # git diff --cached --quiet exits 1 when something is staged, 0 when nothing is
        if staged.get("exit_code") == 0 and not staged.get("stderr"):
            _git(cfg, project, ["add", "-A"])
        return _git(cfg, project, ["commit", "-m", msg])
    if op == "push":
        ok, reason = mode_allows(cfg, "force_push", project)
        if not ok:
            return {"error": "permission", "message": reason}
        if body.get("force"):
            if (cfg.get("mode") or "DEVELOPMENT").upper() != "FULL":
                return {"error": "permission",
                        "message": "git force push requires FULL mode"}
        remote = body.get("remote") or "origin"
        branch = body.get("branch") or ""
        cmd = ["push", remote] + ([branch] if branch else [])
        return _git(cfg, project, cmd, timeout=600)
    if op == "pull":
        ok, reason = mode_allows(cfg, "write")
        if not ok:
            return {"error": "permission", "message": reason}
        remote = body.get("remote") or "origin"
        branch = body.get("branch") or ""
        cmd = ["pull", remote] + ([branch] if branch else [])
        return _git(cfg, project, cmd, timeout=600)
    raise ValueError("unknown git op: %s" % op)


def _gradlew(cfg, project, argstr, timeout=1800):
    cwd = _file_op(cfg, project)
    if not os.path.isdir(cwd):
        raise ValueError("project directory does not exist")
    if os.path.exists(os.path.join(cwd, "gradlew")):
        return run_command("./gradlew " + argstr, cwd, timeout=timeout)
    return run_command("gradle " + argstr, cwd, timeout=timeout)


def dev_handle(body):
    cfg = get_config()
    project = body.get("path")
    if not project:
        raise ValueError("'path' (project directory) is required")
    ok, reason = mode_allows(cfg, "write", None)
    if not ok:
        return {"error": "permission", "message": reason}
    task = body.get("task") or "build"
    kind = body.get("kind") or "build"

    if kind == "gradle":
        return _gradlew(cfg, project, task)
    if kind == "test":
        return _gradlew(cfg, project, "test")
    if kind == "build":
        return _gradlew(cfg, project, task or "build")
    if kind == "clean":
        return _gradlew(cfg, project, "clean")
    if kind == "script":
        script = body.get("script")
        if not isinstance(script, str) or not script:
            raise ValueError("'script' is required for kind=script")
        additional = body.get("args") or ""
        return run_command("%s %s" % (script, additional), _file_op(cfg, project))
    raise ValueError("unknown dev kind: %s" % kind)


def tool_system_info(body=None):
    uname = platform.uname()
    info = {
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": uname.machine,
        "node": uname.node,
        "python": sys.version.split()[0],
        "home": os.path.expanduser("~"),
        "device": platform.platform(),
    }
    for cmd in ("git", "node", "npm", "gradle", "java", "cmake", "make", "python3", "bash", "clang", "kotlinc"):
        r = run_command("command -v %s && %s --version 2>&1 | head -1" % (cmd, cmd),
                        os.path.expanduser("~"), timeout=20)
        path = None
        for line in r.get("stdout", "").splitlines():
            if line.startswith("/"):
                path = line
                break
        info[cmd] = os.path.basename(path) if path else None
    return {"info": info}


def tool_disk_usage(body=None):
    r = run_command("df -h", os.path.expanduser("~"), timeout=30)
    return {"stdout": r["stdout"], "stderr": r["stderr"]}


def tool_process_list(body=None):
    r = run_command("ps -eo pid,ppid,user,%cpu,%mem,etime,args",
                    os.path.expanduser("~"), timeout=30)
    lines = []
    for l in r.get("stdout", "").splitlines():
        parts = l.split(None, 6)
        if parts and parts[0].isdigit():
            lines.append(parts)
    return {"processes": lines, "count": len(lines)}


def tool_check_command(body):
    name = body.get("command") if isinstance(body, dict) else None
    if not name or not isinstance(name, str) or not re.match(r"^[A-Za-z0-9._-]+$", name):
        raise ValueError("valid 'command' name required")
    r = run_command("command -v %s || echo MISSING" % name, os.path.expanduser("~"), timeout=20)
    found = "MISSING" not in r.get("stdout", "") and bool(r.get("stdout", "").strip())
    version = run_command("%s --version 2>&1 | head -3" % name, os.path.expanduser("~"), timeout=20).get("stdout")
    return {"command": name, "found": found, "version": version.strip() or None}


# ---------------------------------------------------------------- workflows

def _workflow_list():
    if not os.path.isdir(WORKFLOWS_DIR):
        return []
    items = []
    for name in sorted(os.listdir(WORKFLOWS_DIR)):
        if not re.match(r"^[A-Za-z0-9._-]+$", name) or not name.endswith(".sh"):
            continue
        path = os.path.join(WORKFLOWS_DIR, name)
        desc = ""
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    raw = fh.readlines()
                for line in raw:
                    line = line.strip()
                    if line.startswith("#!"):
                        continue
                    first = line
                    break
                else:
                    first = ""
                if first.startswith("#"):
                    desc = first.lstrip("# ").strip()
            except Exception:  # noqa: BLE001
                pass
        items.append({"name": name[:-3], "description": desc, "path": path})
    return items


def workflow_run(body):
    cfg = get_config()
    name = body.get("name")
    if not isinstance(name, str) or not re.match(r"^[A-Za-z0-9._-]+$", name):
        raise ValueError("invalid workflow name")
    path = os.path.join(WORKFLOWS_DIR, name + ".sh")
    if not os.path.isfile(path):
        raise ValueError("workflow not found: " + name)
    ok, reason = mode_allows(cfg, "write", None)
    if not ok:
        return {"error": "permission", "message": reason}
    args = body.get("args") or []
    if not isinstance(args, list):
        args = [str(args)]
    env_extra = body.get("env")
    cmd = "bash %s %s" % (path, " ".join(shlex_quote(a) for a in args))
    return run_command(cmd, os.path.dirname(path) or os.path.expanduser("~"),
                       timeout=body.get("timeout"), env_extra=env_extra,
                       async_mode=bool(body.get("async")))


def shlex_quote(s):
    if not s:
        return "''"
    if re.match(r"^[A-Za-z0-9_./:=@%+-]+$", s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


# ---------------------------------------------------------------- openapi

def _openapi(cfg, host):
    local = host.split(":")[0] in ("127.0.0.1", "localhost", "0.0.0.0", "")
    scheme = "http" if local else "https"
    base = "%s://%s" % (scheme, host)
    server_url = "%s/%s" % (base.rstrip("/"), cfg.get("token", "TOKEN"))

    def body(name, required, props):
        p = {}
        for key, typ, desc, req2 in props:
            p[key] = {"type": typ, "description": desc}
            if req2:
                required.append(key)
        return {
            "name": name,
            "required": required,
            "content": {"application/json": {"schema": {
                "type": "object",
                "properties": p,
                "required": required,
            }}},
        }

    def op(operation_id, summary, desc, req=None):
        spec = {
            "operationId": operation_id,
            "summary": summary,
            "description": desc,
            "responses": {"200": {"description": "OK"}},
        }
        if req:
            spec["requestBody"] = req
        return spec

    f = lambda a, b, c, l: (a, b, c, l)  # noqa: E731 helper
    paths = {
        "/health": {
            "get": op("bridge_health", "Check the bridge is alive",
                      "Returns bridge status, mode and token id (never the token itself).")
        },
        "/version": {
            "get": op("bridge_version", "Get bridge version info", "Returns tool version details.")
        },
        "/execute": {
            "post": op("termux_run_command", "Run an arbitrary Termux shell command",
                       "Runs a bash command in the requested working directory. Returns stdout, stderr, exit_code and duration.",
                       body("ExecuteRequest", ["command"], [
                           f("command", "string",
                             "The shell command to execute, e.g. 'ls -la' or './gradlew assembleDebug'", True),
                           f("working_directory", "string",
                             "Absolute path to run in (must be inside a workspace)", False),
                           f("timeout", "integer", "Timeout in seconds (max 3600)", False),
                           f("async", "boolean", "If true returns a process_id instead of waiting", False),
                           f("max_output", "integer", "Max bytes of stdout/stderr to capture", False),
                       ]))
        },
        "/process/status": {
            "post": op("termux_process_status", "Check long-running command status",
                       "Polls a process started with async=true", body("ProcRequest", ["process_id"],
                       [f("process_id", "integer", "The pid returned by execute", True)]))
        },
        "/process/output": {
            "post": op("termux_process_output", "Read output of a long-running command",
                       "Returns stdout/stderr captured so far", body("ProcRequest", ["process_id"],
                       [f("process_id", "integer", "The pid returned by execute", True)]))
        },
        "/process/cancel": {
            "post": op("termux_process_cancel", "Cancel a long-running command",
                       "Terminates the process group", body("ProcRequest", ["process_id"],
                       [f("process_id", "integer", "The pid to kill", True)]))
        },
        "/process/list": {
            "get": op("termux_process_list", "List running commands", "List active long-running commands")
        },
        "/files/list": {
            "post": op("termux_list_directory", "List a directory",
                       "Returns files with type, size and mtime.", body("FilesListRequest", ["path"],
                       [f("path", "string", "Absolute directory path", True)]))
        },
        "/files/read": {
            "post": op("termux_read_file", "Read a file",
                       "Returns the full contents of a text file.", body("PathRequest", ["path"],
                       [f("path", "string", "Absolute file path", True)]))
        },
        "/files/write": {
            "post": op("termux_write_file", "Create or overwrite a file",
                       "Writes content to a path inside a workspace.",
                       body("FilesWriteRequest", ["path", "content"],
                       [f("path", "string", "Absolute file path", True),
                        f("content", "string", "Full file content", True)]))
        },
        "/files/delete": {
            "post": op("termux_delete_file", "Delete a file or directory",
                       "Deletes a file, or directory with recursive=true.",
                       body("FilesDeleteRequest", ["path"],
                       [f("path", "string", "Absolute path", True),
                        f("recursive", "boolean", "Delete directories recursively", False)]))
        },
        "/files/move": {
            "post": op("termux_move_file", "Move or rename a file",
                       "Moves/renames within allowed workspaces.",
                       body("FilesMoveRequest", ["source", "destination"],
                       [f("source", "string", "Source absolute path", True),
                        f("destination", "string", "Destination absolute path", True)]))
        },
        "/files/search": {
            "post": op("termux_search_files", "Search files by name pattern",
                       "Finds files matching a glob (e.g. *.java).",
                       body("FilesSearchRequest", ["path", "pattern"],
                       [f("path", "string", "Root directory", True),
                        f("pattern", "string", "Glob pattern e.g. '*.java' or '*Test*'", True),
                        f("depth", "integer", "Max subdirectory depth", False),
                        f("limit", "integer", "Max results", False)]))
        },
        "/files/exists": {
            "post": op("termux_file_exists", "Check whether a path exists",
                       "Returns exists/is_file/is_dir.", body("PathRequest", ["path"],
                       [f("path", "string", "Absolute path", True)]))
        },
        "/git": {
            "post": op("termux_git", "Run a safe git operation",
                       "ops: status, diff, log, add, commit, push, pull. commit needs 'message'. push can take 'remote' and 'branch'.",
                       body("GitRequest", ["path", "op"],
                       [f("path", "string", "Project directory", True),
                        f("op", "string", "status|diff|log|add|commit|push|pull", True),
                        f("message", "string", "Commit message (for commit)", False),
                        f("remote", "string", "Remote name (default origin)", False),
                        f("branch", "string", "Branch name (push/pull)", False),
                        f("force", "boolean", "Force push (FULL mode only)", False),
                        f("files", "array", "Files to add (default .)", False)]))
        },
        "/dev": {
            "post": op("termux_dev", "Run a development build task",
                       "kinds: build, clean, test, gradle, script.",
                       body("DevRequest", ["path", "kind"],
                       [f("path", "string", "Project directory", True),
                        f("kind", "string", "build|clean|test|gradle|script", True),
                        f("task", "string", "Gradle task, e.g. assembleDebug", False),
                        f("script", "string", "Custom script path (for kind=script)", False),
                        f("args", "string", "Extra args", False)]))
        },
        "/system/info": {
            "post": op("termux_system_info", "Inspect system environment",
                       "Returns OS, device, installed toolchain versions.")
        },
        "/system/disk": {
            "post": op("termux_disk_usage", "Check disk usage", "Returns df -h output.")
        },
        "/system/processes": {
            "post": op("termux_processes", "List system processes", "Returns process table.")
        },
        "/system/check": {
            "post": op("termux_check_command", "Check if a command is installed",
                       "Returns found + version.",
                       body("CheckCommandRequest", ["command"],
                       [f("command", "string", "Binary name, e.g. gradle", True)]))
        },
        "/workflows": {
            "get": op("termux_list_workflows", "List available workflows",
                      "Returns names and descriptions of scripts in workflows/."),
            "post": op("termux_run_workflow", "Run a named workflow",
                       "Executes workflows/<name>.sh with args.",
                       body("WorkflowRequest", ["name"],
                       [f("name", "string", "Workflow name without .sh", True),
                        f("args", "array", "Arguments passed to the script", False),
                        f("env", "object", "Extra environment variables", False),
                        f("timeout", "integer", "Timeout seconds", False),
                        f("async", "boolean", "Run in background", False)]))
        },
    }

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Termux AI Bridge",
            "description": (
                "Lets ChatGPT operate your Android Termux environment: run shell commands, "
                "read/write/search files, run git and gradle, inspect the system and trigger "
                "workflows. Workspaces, operation modes and path sandboxing keep it safe. "
                "Setup: choose 'No authentication' in ChatGPT Actions - the secret URL path "
                "already authenticates you.")
            ,
            "version": "1.0.0",
        },
        "servers": [{"url": server_url}],
        "security": [],
        "paths": paths,
    }


# ---------------------------------------------------------------- HTTP handler

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ai-bridge/1.0"

    def log_message(self, fmt, *args):
        return  # structured logging happens per-request

    # -- helpers -------------------------------------------------------

    def _json(self, code, payload):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(min(length, 10 * 1024 * 1024))
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            raise ValueError("malformed JSON body")
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def _auth_ok(self, cfg, token):
        if cfg.get("enabled") is False:
            return False, "bridge is disabled (run `ai-bridge enable`)"
        if token != cfg.get("token"):
            return False, "invalid access token"
        api_key = cfg.get("api_key")
        if api_key:
            supplied = self.headers.get("X-API-Key") or ""
            if supplied != api_key:
                return False, "invalid API key"
        return True, None

    def _rate_ok(self):
        cfg = get_config()
        limit = int(cfg.get("rate_limit", 180))
        if limit <= 0:
            return True
        now = time.time()
        key = self.client_address[0]
        with getattr(self.server, "rl_lock", threading.Lock()):
            bucket = self.server.rl.setdefault(key, [])
            bucket[:] = [t for t in bucket if now - t < 60]
            if len(bucket) >= limit:
                return False
            bucket.append(now)
        return True

    # -- routing -------------------------------------------------------

    def do_OPTIONS(self):
        self._json(204, {})

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        started = time.time()
        cfg = get_config()
        token = cfg.get("token", "")
        path = urllib.parse.urlparse(self.path).path

        try:
            if not self._rate_ok():
                return self._json(429, {"success": False, "error": {"type": "rate_limited",
                                                                     "message": "too many requests"}})
            parts = [p for p in path.split("/") if p]
            if not parts or parts[0] != token:
                return self._json(404, {"success": False,
                                        "error": {"type": "not_found", "message": "endpoint not found"}})
            ok, err = self._auth_ok(cfg, token)
            if not ok:
                log_operation({"operation": "auth", "success": False, "note": err})
                return self._json(401, {"success": False, "error": {"type": "authentication_failed",
                                                                    "message": err}})
            route = "/" + "/".join(parts[1:])

            if method == "GET" and route == "/":
                return self._json(200, self._status_payload(cfg))
            if method == "GET" and route == "/health":
                return self._json(200, {"success": True, "status": "ok",
                                        "mode": cfg.get("mode"), "bridge": "online"})
            if method == "GET" and route == "/version":
                return self._json(200, {"success": True, "version": "1.0.0", "server": "ai-bridge"})
            if method == "GET" and route == "/openapi.json":
                host = self.headers.get("Host") or ("127.0.0.1:%s" % cfg.get("port"))
                return self._json(200, _openapi(cfg, host))
            if method == "GET" and route == "/process/list":
                return self._json(200, {"success": True, "processes": REGISTRY.list()})
            if method == "GET" and route == "/workflows":
                return self._json(200, {"success": True, "workflows": _workflow_list()})

            if method != "POST":
                return self._json(405, {"success": False,
                                        "error": {"type": "method_not_allowed", "message": "use POST"}})

            body = self._body()
            handlers = {
                "/execute": lambda b: tool_execute(b),
                "/process/status": self._proc_status,
                "/process/output": self._proc_output,
                "/process/cancel": self._proc_cancel,
                "/files/list": lambda b: tool_list_directory(b),
                "/files/read": lambda b: tool_read_file(b),
                "/files/write": lambda b: tool_write_file(b),
                "/files/delete": lambda b: tool_delete_file(b),
                "/files/move": lambda b: tool_move_file(b),
                "/files/search": lambda b: tool_search_files(b),
                "/files/exists": lambda b: tool_file_exists(b),
                "/git": lambda b: git_handle(b),
                "/dev": lambda b: dev_handle(b),
                "/system/info": lambda b: tool_system_info(b),
                "/system/disk": lambda b: tool_disk_usage(b),
                "/system/processes": lambda b: tool_process_list(b),
                "/system/check": lambda b: tool_check_command(b),
                "/workflows": lambda b: workflow_run(b),
            }
            fn = handlers.get(route)
            if fn is None:
                return self._json(404, {"success": False,
                                        "error": {"type": "not_found", "message": route + " unknown"}})
            result = fn(body)
            if isinstance(result, dict) and result.get("error"):
                raise RuntimeError(result["message"])
            dur = round(time.time() - started, 3)
            log_operation({
                "operation": route.lstrip("/"),
                "client": self.client_address[0],
                "success": True,
                "command": body.get("command"),
                "tool": route,
                "working_directory": body.get("working_directory"),
                "exit_code": result.get("exit_code") if isinstance(result, dict) else None,
                "duration_s": dur,
            })
            self._json(200, {"success": True, "result": result})
        except ValueError as exc:
            dur = round(time.time() - started, 3)
            log_operation({"operation": path, "client": self.client_address[0], "success": False,
                           "note": sanitize(str(exc)), "duration_s": dur})
            self._json(400, {"success": False, "error": {"type": "invalid_request", "message": str(exc)}})
        except RuntimeError as exc:
            dur = round(time.time() - started, 3)
            log_operation({"operation": path, "client": self.client_address[0], "success": False,
                           "note": sanitize(str(exc)), "duration_s": dur})
            self._json(422, {"success": False, "error": {"type": "operation_denied", "message": str(exc)}})
        except Exception as exc:  # noqa: BLE001
            dur = round(time.time() - started, 3)
            log_operation({"operation": path, "client": self.client_address[0], "success": False,
                           "note": sanitize(str(exc)), "duration_s": dur})
            traceback.print_exc()
            self._json(500, {"success": False, "error": {"type": "internal_error", "message": str(exc)}})

    def _status_payload(self, cfg):
        return {
            "success": True,
            "bridge": "ai-bridge",
            "status": "online",
            "mode": cfg.get("mode"),
            "workspaces": workspace_roots(cfg),
            "allow_full_filesystem": bool(cfg.get("allow_full_filesystem")),
            "processes_running": len(REGISTRY.list()),
            "workflows": len(_workflow_list()),
            "token_id": (cfg.get("token") or "none")[:8] + "...",
        }

    def _proc_status(self, body):
        pid = body.get("process_id")
        if not pid:
            raise ValueError("process_id required")
        e = REGISTRY.refresh(pid)
        if e is None:
            raise ValueError("unknown process_id: %s" % pid)
        running = e.finished is None
        return {
            "process_id": e.pid,
            "running": running,
            "exit_code": e.exit_code,
            "command": e.cmd,
            "duration": round((time.time() if running else e.finished) - e.start, 2),
            "note": e.note,
        }

    def _proc_output(self, body):
        pid = body.get("process_id")
        if not pid:
            raise ValueError("process_id required")
        e = REGISTRY.get(pid)
        if e is None:
            raise ValueError("unknown process_id: %s" % pid)
        stdout, t1 = _read_stream(e.out_path)
        stderr, t2 = _read_stream(e.err_path)
        running = e.finished is None
        return {
            "process_id": e.pid,
            "running": running,
            "exit_code": e.exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": t1,
            "stderr_truncated": t2,
        }

    def _proc_cancel(self, body):
        pid = body.get("process_id")
        if not pid:
            raise ValueError("process_id required")
        ok = REGISTRY.cancel(pid)
        if not ok:
            raise ValueError("unknown process_id: %s" % pid)
        return {"success": True, "process_id": pid, "cancelled": True}


class BridgeServer(ThreadingHTTPServer):
    daemon_threads = True
    rl = {}
    rl_lock = threading.Lock()


def main():
    if "--init" in sys.argv:
        cfg = get_config()
        print("config ready: %s" % CONFIG_FILE)
        print("token id: %s..." % cfg.get("token", "")[:8])
        sys.exit(0)

    cfg = get_config()
    host = cfg.get("host", "127.0.0.1")
    port = int(cfg.get("port", 8765))
    try:
        server = BridgeServer((host, port), Handler)
    except OSError as exc:
        print("Failed to bind %s:%s - %s" % (host, port, exc), file=sys.stderr)
        sys.exit(1)
    with open(PID_FILE, "w", encoding="utf-8") as fh:
        fh.write(str(os.getpid()))
    print("ai-bridge listening on http://%s:%s" % (host, port), flush=True)
    print("access token id: %s... (in %s)" % (cfg.get("token", "")[:8], CONFIG_FILE), flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nshutting down", flush=True)
        server.server_close()


if __name__ == "__main__":
    main()