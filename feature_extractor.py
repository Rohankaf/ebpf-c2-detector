import json, sys, statistics
from datetime import datetime, timedelta
from collections import defaultdict

def load_events(path):
    events = []
    for line in open(path):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        e["_ts"] = datetime.fromisoformat(e["timestamp"])
        events.append(e)
    events.sort(key=lambda e: e["_ts"])
    return events

def compute_window_features(window_events):
    """window_events: chronologically sorted events for ONE process,
    already filtered to the trailing time window. May contain a mix
    of "connect" and "state_change" events."""

    connect_events = [e for e in window_events if e.get("event") == "connect"]
    state_events = [e for e in window_events if e.get("event") == "state_change"]

    n = len(connect_events)
    dest_ips = {e["destination_ip"] for e in connect_events}
    dest_ports = {e["destination_port"] for e in connect_events}
    times = [e["_ts"] for e in connect_events]
    span = (times[-1] - times[0]).total_seconds() if n > 1 else 0.0

    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    if len(gaps) >= 2:
        mean_gap = statistics.mean(gaps)
        std_gap = statistics.stdev(gaps)
        cv_gap = std_gap / mean_gap if mean_gap > 0 else 0.0
    elif len(gaps) == 1:
        mean_gap = gaps[0]
        cv_gap = 0.0
    else:
        mean_gap = 0.0
        cv_gap = 0.0

    raw_span = (times[-1] - times[0]).total_seconds() if n > 1 else 0.0
    rate = n / raw_span if raw_span > 0.001 else float(n) * 1000
    rate = min(rate, 9999.0)
    # ---- NEW: destination churn — how often the destination changes
    #      from one connection to the very next one, as a fraction.
    #      0.0 = destination never changes consecutively (sticky).
    #      1.0 = destination changes on every single connection.
    #      This is distinct from unique_dest_ips/ports, which only
    #      count total diversity, not the pattern of switching. ----
    if n >= 2:
        ip_transitions = sum(
            1 for a, b in zip(connect_events, connect_events[1:])
            if a["destination_ip"] != b["destination_ip"]
        )
        port_transitions = sum(
            1 for a, b in zip(connect_events, connect_events[1:])
            if a["destination_port"] != b["destination_port"]
        )
        dest_ip_churn_rate = ip_transitions / (n - 1)
        dest_port_churn_rate = port_transitions / (n - 1)
    else:
        dest_ip_churn_rate = 0.0
        dest_port_churn_rate = 0.0

    # ---- NEW: failure-aware features, derived from state_change events ----
    n_state_total = len(state_events)
    n_failed = sum(1 for e in state_events if not e.get("success", True))
    failure_rate = n_failed / n_state_total if n_state_total > 0 else 0.0
    failed_ports = {e["destination_port"] for e in state_events
                     if not e.get("success", True)}

    return {
        "n_connections": n,
        "unique_dest_ips": len(dest_ips),
        "unique_dest_ports": len(dest_ports),
        "window_span_sec": round(span, 2),
        "mean_gap_sec": round(mean_gap, 3),
        "cv_gap": round(cv_gap, 3),
        "rate_per_sec": round(rate, 3),
        "n_failed": n_failed,
        "failure_rate": round(failure_rate, 3),
        "unique_failed_ports": len(failed_ports),
        "dest_ip_churn_rate": round(dest_ip_churn_rate, 3),
        "dest_port_churn_rate": round(dest_port_churn_rate, 3),
    }

def extract_features(events, window_seconds=15, min_events=3):
    """
    For each process, slides a trailing time window across its events.
    Yields one feature snapshot per event once min_events reached,
    each snapshot describing the trailing `window_seconds` of activity
    ending at that event.
    """
    by_proc = defaultdict(list)
    for e in events:
        by_proc[(e["pid"], e["process"])].append(e)

    results = []
    for (pid, proc), evs in by_proc.items():
        evs.sort(key=lambda e: e["_ts"])
        left = 0
        for right in range(len(evs)):
            cutoff = evs[right]["_ts"] - timedelta(seconds=window_seconds)
            while evs[left]["_ts"] < cutoff:
                left += 1
            window = evs[left:right + 1]
            if len(window) < min_events:
                continue
            feats = compute_window_features(window)
            feats["pid"] = pid
            feats["process"] = proc
            feats["last_dest_ip"] = window[-1]["destination_ip"]
            feats["last_dest_port"] = window[-1]["destination_port"]
            feats["timestamp"] = window[-1]["timestamp"]
            results.append(feats)
    return results


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "telemetry_log.jsonl"
    events = load_events(path)
    feats = extract_features(events)
    print(f"{'PID':<7}{'PROCESS':<14}{'N':>3}{'IPs':>4}{'PORTs':>6}"
          f"{'SPAN(s)':>9}{'GAP(s)':>9}{'CV':>8}{'RATE/s':>10}")
    print("-" * 74)
    for f in feats[-20:]:  # last 20 snapshots, avoid flooding output
        print(f"{f['pid']:<7}{f['process']:<14}{f['n_connections']:>3}"
              f"{f['unique_dest_ips']:>4}{f['unique_dest_ports']:>6}"
              f"{f['window_span_sec']:>9}{f['mean_gap_sec']:>9}"
              f"{f['cv_gap']:>8}{f['rate_per_sec']:>10}")
