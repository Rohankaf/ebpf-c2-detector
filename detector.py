import json, sys, statistics
from datetime import datetime
from collections import defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else "telemetry_log.jsonl"

# ---- Tunable thresholds (Day 3 first cut, can refine later) ----
CV_THRESHOLD = 0.15       # below this = suspiciously regular
MIN_EVENTS = 5            # need at least this many connects to trust stats
MIN_MEAN_GAP = 0.5        # ignore super-fast bursts (not beacon-like, different pattern)

groups = defaultdict(list)

for line in open(path):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue
    key = (e["pid"], e["process"], e["destination_ip"], e["destination_port"])
    groups[key].append(datetime.fromisoformat(e["timestamp"]))

print(f"{'PID':<7}{'PROCESS':<14}{'DEST':<16}{'N':>3}{'MEAN(s)':>9}{'CV':>8}  VERDICT")
print("-" * 70)

for (pid, proc, ip, port), times in groups.items():
    if len(times) < MIN_EVENTS:
        continue
    times.sort()
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    mean = statistics.mean(gaps)
    std = statistics.stdev(gaps)
    cv = std / mean if mean > 0 else 0

    if mean < MIN_MEAN_GAP:
        verdict = "SKIP (too fast/bursty)"
    elif cv < CV_THRESHOLD:
        verdict = "BEACON-LIKE"
    else:
        verdict = "benign"

    dest = f"{ip}:{port}"
    print(f"{pid:<7}{proc:<14}{dest:<16}{len(times):>3}{mean:>9.2f}{cv:>8.3f}  {verdict}")
