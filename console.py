"""Investigation Console — generic command/code execution inside this VM.

Deliberately NOT allowlisted: the analyst needs to type arbitrary
investigation commands (including pipes/redirects), run against their own
VM for investigation purposes — the same trust model as a local shell or
an EDR live-response console. This module is the single place that owns
execution; it's reachable only via /api/console/run in app.py, which is
itself bound to 127.0.0.1 only.

Each command:
  - runs via subprocess with shell=True (required for pipes/redirects),
    scoped to this project's working directory
  - has a hard timeout so a hung command can't hang the backend
  - captures stdout, stderr, return code, and wall-clock duration
  - is recorded in an in-memory, process-local history (not written to
    disk), capped in length

If a pid is supplied, it's exposed to the command two ways:
  - as the shell environment variable $PID
  - via literal substitution of the token {pid} in the command text
No sanitization is applied to the command text itself — it runs as typed,
by design. This module does not judge what's "safe"; that's the analyst's
call, same as a real shell would be.
"""
import collections
import os
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HISTORY_MAX = 200
DEFAULT_TIMEOUT = 20

history = collections.deque(maxlen=HISTORY_MAX)
_next_id = 1


def run_command(command, pid=None, timeout=DEFAULT_TIMEOUT):
    global _next_id

    if not command or not command.strip():
        raise ValueError("empty command")

    cmd_text = command.strip()
    if pid is not None:
        cmd_text = cmd_text.replace("{pid}", str(pid))

    env = os.environ.copy()
    if pid is not None:
        env["PID"] = str(pid)

    entry = {
        "id": _next_id,
        "command": cmd_text,
        "pid": pid,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _next_id += 1

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd_text,
            shell=True,
            cwd=HERE,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        entry.update(
            status="ok",
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
    except subprocess.TimeoutExpired as e:
        entry.update(
            status="timeout",
            returncode=None,
            stdout=(e.stdout or ""),
            stderr=(e.stderr or "") + "\n[console] timed out after %ss" % timeout,
        )
    except Exception as ex:
        entry.update(
            status="error",
            returncode=None,
            stdout="",
            stderr="[console] failed to execute: %r" % (ex,),
        )

    entry["duration_ms"] = round((time.monotonic() - start) * 1000, 1)
    history.append(entry)
    return entry


def get_history(limit=100):
    return list(history)[-limit:]
