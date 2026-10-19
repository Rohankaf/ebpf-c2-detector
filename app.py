"""Dashboard backend — Flask REST API over the existing collector.

Binds to 127.0.0.1 only. Owns the tcp_connect_trace.py subprocess and
runs collector.ingest() in a background thread. No detection logic
lives here — every endpoint just reads collector state and formats it.

Run (needs root for the eBPF tracer):
    sudo python3 app.py
"""
import os
import subprocess
import sys
import threading
import time

from flask import Flask, abort, jsonify, request, send_from_directory

from collector import Collector, read_stream
import console as console_mod
import proc_enrichment


HERE = os.path.dirname(os.path.abspath(__file__))
START_TIME = time.monotonic()

app = Flask(__name__)
collector = None       # set in main()
tracer_proc = None     # the tcp_connect_trace.py subprocess, for status reporting


# ---------------------------------------------------------------------
# /proc best-effort lookup for the Investigation endpoint.
# This is NOT eBPF telemetry — it's a live /proc read done at query
# time, so it only works while the process is still running, and must
# degrade gracefully once it has exited.
# ---------------------------------------------------------------------
def read_proc_info(pid):
    info = {"pid": pid, "proc_available": False}
    base = "/proc/%s" % pid
    if not os.path.isdir(base):
        return info
    try:
        info["exe"] = os.readlink(base + "/exe")
    except OSError:
        info["exe"] = None
    try:
        with open(base + "/cmdline", "rb") as f:
            raw = f.read()
        info["cmdline"] = " ".join(p for p in raw.decode(errors="replace").split("\x00") if p)
    except OSError:
        info["cmdline"] = None
    try:
        with open(base + "/stat") as f:
            fields = f.read().rsplit(")", 1)[-1].split()
        # /proc/<pid>/stat fields after the process name: state is [0], ppid is [1]
        info["ppid"] = int(fields[1])
    except (OSError, IndexError, ValueError):
        info["ppid"] = None
    info["proc_available"] = True
    return info


# ---------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------
@app.get("/")
def index():
    return send_from_directory(HERE, "dashboard.html")


@app.get("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(os.path.join(HERE, "static"), filename)

@app.get("/api/events")
def api_events():
    since = request.args.get("since", 0, type=int)
    limit = request.args.get("limit", 500, type=int)
    raw = collector.events_since(since, limit=limit)
    clean = [{k: v for k, v in e.items() if k != "_ts"} for e in raw]
    return jsonify(events=clean)

@app.get("/api/tree")
def api_tree():
    return jsonify(processes=collector.tree())


@app.get("/api/alerts")
def api_alerts():
    """Any process whose current verdict is not NORMAL, newest-verdict-first."""
    procs = collector.tree()
    alerts = []
    for p in procs:
        if p["verdict"] == "NORMAL":
            continue
        last = p["history"][-1] if p["history"] else {}
        alerts.append({
            "pid": p["pid"],
            "process": p["process"],
            "verdict": p["verdict"],
            "reason": last.get("reason", ""),
            "observations": last.get("observations", []),
            "ts": last.get("ts", ""),
            "destinations": p["destinations"][:10],
        })
    alerts.sort(key=lambda a: a["ts"], reverse=True)
    return jsonify(alerts=alerts)


@app.get("/api/investigation/<int:pid>")
def api_investigation(pid):
    procs = collector.tree()
    matches = [p for p in procs if p["pid"] == pid]
    if not matches:
        abort(404, description="No telemetry recorded for this PID.")
    # if the same PID somehow maps to more than one process name
    # (shouldn't normally happen), return the most recently active one
    p = sorted(matches, key=lambda x: x["last_id"], reverse=True)[0]

    proc_info = read_proc_info(pid)

    snoop = proc_enrichment.enrich(pid)

    return jsonify(
        pid=p["pid"],
        process=p["process"],
        current_verdict=p["verdict"],
        destinations=p["destinations"],
        history=p["history"],
        proc_info=proc_info,
	snoop=snoop,
    )


@app.get("/api/system-status")
def api_system_status():
    tracer_alive = tracer_proc is not None and tracer_proc.poll() is None
    with collector.lock:
        n_events = len(collector.events)
        n_procs = len(collector.procs)
        error_count = collector.error_count
    return jsonify(
        tracer_running=tracer_alive,
        uptime_seconds=round(time.monotonic() - START_TIME, 1),
        events_buffered=n_events,
        processes_tracked=n_procs,
        detector_errors=error_count,
        window_seconds=30,  # placeholder, see note below
    )
@app.post("/api/console/run")
def api_console_run():
    data = request.get_json(silent=True) or {}
    command = data.get("command", "")
    pid = data.get("pid")
    timeout = data.get("timeout", console_mod.DEFAULT_TIMEOUT)
    try:
        entry = console_mod.run_command(command, pid=pid, timeout=timeout)
    except ValueError as e:
        abort(400, description=str(e))
    return jsonify(entry)


@app.get("/api/console/history")
def api_console_history():
    limit = request.args.get("limit", 100, type=int)
    return jsonify(history=console_mod.get_history(limit=limit))

# ---------------------------------------------------------------------
def main():
    global collector, tracer_proc

    if os.geteuid() != 0:
        sys.exit("Run with sudo: the eBPF tracer needs root.")

    collector = Collector()

    tracer_proc = subprocess.Popen(
        ["python3", "-u", "tcp_connect_trace.py"],
        cwd=HERE, stdout=subprocess.PIPE, text=True, bufsize=1,
    )
    threading.Thread(target=read_stream, args=(collector, tracer_proc.stdout),
                      daemon=True).start()

    app.run(host="127.0.0.1", port=5000, threaded=True)


if __name__ == "__main__":
    main()
