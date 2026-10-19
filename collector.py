"""Collector: turns the eBPF JSON event stream into in-memory dashboard state.

Reuses the existing detection code UNCHANGED — this file only adapts data
shapes between tcp_connect_trace.py's raw JSON and what feature_extractor.py /
multi_detector.py already expect:

  feature_extractor.compute_window_features(window_events)
  multi_detector.classify(feature_snapshot)

Two contract requirements these functions have, which this collector must
satisfy itself (normally handled by feature_extractor.load_events()/
extract_features(), which a live rolling-window collector bypasses by design):

  1. compute_window_features() reads event["_ts"] (a parsed datetime) on
     every event — we must add this ourselves from the JSON "timestamp".
  2. classify() reads f['last_dest_ip'] / f['last_dest_port'] directly for
     its observation text — compute_window_features() does NOT add these
     (extract_features() does, elsewhere), so we must add them ourselves
     before calling classify().

Detector-call failures are logged loudly (not silently swallowed) so a
broken contract is visible immediately during the smoke test, rather than
manifesting later as "verdicts never change."
"""
import collections
import copy
import json
import sys
import threading
import time
import traceback
from datetime import datetime

from feature_extractor import compute_window_features
from multi_detector import classify

WINDOW_SECONDS = 30      # keep equal to live_detector.py
MAX_EVENTS = 2000
MAX_PROCS = 200
SHOW = ["n_connections", "unique_dest_ips", "unique_dest_ports", "cv_gap",
        "rate_per_sec", "failure_rate", "dest_ip_churn_rate"]


def _unpack(result):
    """classify() returns (label, observations_list, reason_string).
    Keep all three — earlier code dropped the real reason by only
    reading the first two elements. Still defensive about shape in
    case classify() output ever changes."""
    if isinstance(result, str):
        return result, [], ""
    if isinstance(result, dict):
        label = result.get("label") or result.get("verdict") or "UNKNOWN"
        obs = result.get("observations") or []
        reason = result.get("reason") or result.get("explanation") or ""
        return str(label), list(obs), str(reason)
    if isinstance(result, (tuple, list)):
        label = result[0] if len(result) > 0 else "UNKNOWN"
        obs = result[1] if len(result) > 1 else []
        reason = result[2] if len(result) > 2 else ""
        return str(label), (list(obs) if obs else []), str(reason)
    return str(result), [], ""


class Collector:
    def __init__(self, ignore_port=None, verbose=False):
        self.lock = threading.Lock()
        self.events = collections.deque(maxlen=MAX_EVENTS)
        self.next_id = 1
        self.windows = {}    # (pid, process) -> deque[(arrival_monotonic, event)]
        self.procs = {}      # (pid, process) -> dashboard record
        self.ignore_port = ignore_port
        self.verbose = verbose       # smoke test runs with this on
        self.error_count = 0

    def ingest(self, line):
        line = line.strip()
        if not line.startswith("{"):
            return
        try:
            e = json.loads(line)
        except ValueError:
            return
        if not isinstance(e, dict) or "pid" not in e:
            return

        # REQUIREMENT 1: compute_window_features() needs a parsed datetime
        # on every event, under the key "_ts".
        try:
            e["_ts"] = datetime.fromisoformat(e["timestamp"])
        except (KeyError, ValueError):
            return  # malformed/missing timestamp — skip rather than poison the window

        if (self.ignore_port is not None
                and e.get("destination_port") == self.ignore_port
                and str(e.get("destination_ip", "")).startswith("127.")):
            return

        now = time.monotonic()
        with self.lock:
            e["id"] = self.next_id
            self.next_id += 1
            self.events.append(e)
            key = (e["pid"], e.get("process", "?"))
            w = self.windows.setdefault(key, collections.deque())
            w.append((now, e))
            while w and now - w[0][0] > WINDOW_SECONDS:
                w.popleft()
            self._update(key, [x for _, x in w], e)

    def _update(self, key, evs, latest):
        ts = latest.get("timestamp", "")
        p = self.procs.get(key)
        if p is None:
            if len(self.procs) >= MAX_PROCS:
                oldest = next(iter(self.procs))
                self.procs.pop(oldest)
                self.windows.pop(oldest, None)
            p = {"pid": key[0], "process": key[1], "verdict": "NORMAL", "last_id": 0,
                 "destinations": [],
                 "history": [{"ts": ts, "verdict": "NORMAL", "reason": "first seen",
                              "observations": []}]}
            self.procs[key] = p
        p["last_id"] = latest["id"]

        if latest.get("event") == "connect":
            d = "%s:%s" % (latest.get("destination_ip"), latest.get("destination_port"))
            if d not in p["destinations"] and len(p["destinations"]) < 50:
                p["destinations"].append(d)

        try:
            feats = compute_window_features(evs)
            if not feats:
                return

            # REQUIREMENT 2: classify() reads these two keys directly off
            # the feature dict; compute_window_features() does not set them.
            feats["last_dest_ip"] = latest.get("destination_ip", "")
            feats["last_dest_port"] = latest.get("destination_port", "")

            label, observations, reason = _unpack(classify(feats))
        except Exception as ex:
            self.error_count += 1
            # Loud on purpose — a swallowed exception here means verdicts
            # silently freeze forever, which is exactly the bug class we're
            # testing against in Phase 1.
            print("collector: detector call failed for %r: %r" % (key, ex),
                  file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return

        if self.verbose:
            print("[%s] pid=%s proc=%s n=%s verdict=%s reason=%s" % (
                ts, key[0], key[1], feats.get("n_connections"), label, reason),
                file=sys.stderr)

        if label != p["verdict"]:
            p["verdict"] = label
            p["history"].append({
                "ts": ts, "verdict": label, "reason": reason,
                "observations": observations,
                "features": {k: feats[k] for k in SHOW if k in feats}})
            del p["history"][:-50]

    def events_since(self, since, limit=500):
        with self.lock:
            return [e for e in self.events if e["id"] > since][:limit]

    def tree(self):
        with self.lock:
            procs = sorted(self.procs.values(), key=lambda p: p["last_id"], reverse=True)
            return copy.deepcopy(procs)


def read_stream(collector, stream):
    for line in stream:
        collector.ingest(line)
