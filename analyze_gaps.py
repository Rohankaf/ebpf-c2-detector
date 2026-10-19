import json, sys, statistics
from datetime import datetime
from collections import defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else "telemetry_log.jsonl"
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

print(f"{'PID':<7}{'PROCESS':<14}{'DEST':<16}{'N':>3}{'MEAN(s)':>9}{'STD(s)':>9}{'CV':>8}")
for (pid, proc, ip, port), times in groups.items():
    if len(times) < 5:
        continue
    times.sort()
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    mean = statistics.mean(gaps)
    std = statistics.stdev(gaps)
    print(f"{pid:<7}{proc:<14}{ip + ':' + str(port):<16}{len(times):>3}"
          f"{mean:>9.2f}{std:>9.3f}{std / mean:>8.3f}")
