import sys, json
from datetime import datetime, timedelta
from collections import defaultdict, deque

from feature_extractor import compute_window_features
from multi_detector import classify, print_result

WINDOW_SECONDS = 30
MIN_EVENTS = 3

# per-(pid, process) rolling history of recent events
history = defaultdict(deque)

# avoid re-printing the same verdict every single event
last_label = {}


def process_event(e):
    e["_ts"] = datetime.fromisoformat(e["timestamp"])
    key = (e["pid"], e["process"])
    dq = history[key]
    dq.append(e)

    # drop events outside the trailing window
    cutoff = e["_ts"] - timedelta(seconds=WINDOW_SECONDS)
    while dq and dq[0]["_ts"] < cutoff:
        dq.popleft()

    if len(dq) < MIN_EVENTS:
        return

    feats = compute_window_features(list(dq))
    feats["pid"] = e["pid"]
    feats["process"] = e["process"]
    feats["last_dest_ip"] = e["destination_ip"]
    feats["last_dest_port"] = e["destination_port"]

    label, obs, reason = classify(feats)
    if label is None:
        return

    # only print when the verdict for this process CHANGES,
    # so the demo doesn't spam the same line every event
    if last_label.get(key) != label:
        print_result(feats, label, obs, reason)
        last_label[key] = label


def main():
    print("Live detector running... waiting for connection events.\n",
          file=sys.stderr)
    for line in sys.stdin:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        process_event(e)


if __name__ == "__main__":
    main()
