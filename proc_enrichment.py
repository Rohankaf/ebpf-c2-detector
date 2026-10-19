"""Snoop enrichment layer — investigation data for a PID, sourced from an
external process-inspection tool via its --json output.

This is the ONLY file in the project aware of which external tool is used.
Nothing above this module (app.py, the GUI) ever sees a tool name or raw
CLI output — enrich() always returns a plain, structured dict, or a
graceful "unavailable" dict on any failure. Never raises.

Read-only by design: only ever invoked with --json, never with any
control/action flag (kill, signals, etc.) — this module intentionally
does not expose those capabilities.
"""
import json
import shutil
import subprocess

TOOL_BIN = "peek"          # the only place this name appears in the project
TIMEOUT_SECONDS = 5

_tool_path_cache = None


def _tool_path():
    global _tool_path_cache
    if _tool_path_cache is None:
        _tool_path_cache = shutil.which(TOOL_BIN) or ""
    return _tool_path_cache


def _unavailable(reason):
    return {"available": False, "reason": reason}


def enrich(pid, timeout=TIMEOUT_SECONDS):
    """Returns structured investigation data for `pid`, or an
    {"available": False, "reason": ...} dict if it can't be obtained."""
    path = _tool_path()
    if not path:
        return _unavailable("enrichment tool not installed")

    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return _unavailable("invalid PID")

    try:
        result = subprocess.run(
            [path, str(pid_int), "--all", "--json"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return _unavailable("enrichment timed out")
    except PermissionError:
        return _unavailable("permission denied")
    except Exception:
        return _unavailable("enrichment failed to run")

    if result.returncode != 0:
        stderr_lower = (result.stderr or "").lower()
        if "no such process" in stderr_lower or "not found" in stderr_lower:
            return _unavailable("process no longer exists")
        if "permission" in stderr_lower:
            return _unavailable("permission denied")
        return _unavailable("enrichment tool reported an error")

    try:
        raw = json.loads(result.stdout)
    except (ValueError, TypeError):
        return _unavailable("enrichment data was malformed")

    try:
        return _shape(raw)
    except Exception:
        return _unavailable("enrichment data had an unexpected shape")

def _unwrap_capabilities(cap_string):
    """peek returns capabilities as one big comma-separated string;
    split into a list for cleaner rendering, without changing meaning."""
    if not cap_string:
        return []
    return [c.strip() for c in cap_string.split(",") if c.strip()]


def _flatten_tree(node, out, is_root=True):
    """process_tree from peek is a recursive {pid,name,...,children:[...]}
    structure rooted at the inspected PID itself. We split it into a
    flat 'children' list for display (the inspected process has no
    ancestors in this payload — peek's tree here only goes downward)."""
    if node is None:
        return
    if not is_root:
        out.append({"pid": node.get("pid"), "name": node.get("name")})
    for child in node.get("children") or []:
        _flatten_tree(child, out, is_root=False)


def _shape(raw):
    """Maps peek's actual --all --json shape onto Snoop's sections.
    raw is the top-level object itself (not wrapped under "process")."""

    children = []
    _flatten_tree(raw.get("process_tree"), children, is_root=True)

    env_list = raw.get("env_vars") or []
    environment = {e.get("key"): e.get("value") for e in env_list if e.get("key")}

    files = [
        {"fd": f.get("fd"), "type": f.get("fd_type"), "path": f.get("description")}
        for f in (raw.get("open_files") or [])
    ]

    net = raw.get("network") or {}
    listening = [
        {"protocol": "tcp", "local_address": addr} for addr in (net.get("listening_tcp") or [])
    ] + [
        {"protocol": "udp", "local_address": addr} for addr in (net.get("listening_udp") or [])
    ]
    connections = [
        {
            "protocol": c.get("protocol", "tcp"),
            "local_address": c.get("local_address") or c.get("local"),
            "remote_address": c.get("remote_address") or c.get("remote"),
            "state": c.get("state"),
        }
        for c in (net.get("connections") or [])
    ]

    kernel = raw.get("kernel") or {}

    return {
        "available": True,

        "process": {
            "pid": raw.get("pid"),
            "name": raw.get("name"),
            "cmdline": raw.get("cmdline"),
            "exe": raw.get("exe"),
            "state": raw.get("state"),
            "ppid": raw.get("ppid"),
            "uid": raw.get("uid"),
            "gid": raw.get("gid"),
            "started": raw.get("started_at"),
            "threads": raw.get("threads"),
        },

        "resources": {
            "cpu_percent": raw.get("cpu_percent"),
            "memory_rss_kb": raw.get("rss_kb"),
            "memory_vsz_kb": raw.get("vm_size_kb"),
            "fd_count": raw.get("fd_count"),
        },

        "network": {
            "listening": listening,
            "connections": connections,
        },

        "kernel": {
            "scheduler": kernel.get("sched_policy"),
            "oom_score": kernel.get("oom_score"),
            "cgroup": kernel.get("cgroup"),
            "namespaces": [n.get("ns_type") for n in (kernel.get("namespaces") or [])],
            "seccomp": kernel.get("seccomp"),
            "capabilities": _unwrap_capabilities(kernel.get("cap_effective")),
        },

        "files": files,

        "tree": {
            "ancestors": [],   # peek's tree here is rooted at the inspected PID itself
            "children": children,
        },

        "environment": environment,
    }
