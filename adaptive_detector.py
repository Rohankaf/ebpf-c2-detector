import sys, json, statistics
import math
from feature_extractor import load_events, extract_features

# The features we'll baseline — same ones feature_extractor already produces.
# No new telemetry needed.
FEATURES = [
    "n_connections",
    "unique_dest_ips",
    "unique_dest_ports",
    "mean_gap_sec",
    "cv_gap",
    "rate_per_sec",
]


def learn_baseline(telemetry_paths, window_seconds=15, min_events=3):
    """
    telemetry_paths: list of JSONL files containing ONLY normal traffic.
    Returns a profile dict: {feature: {"mean": x, "std": y, "n_samples": k}}
    """
    all_snapshots = []
    for path in telemetry_paths:
        events = load_events(path)
        feats = extract_features(events, window_seconds=window_seconds,
                                  min_events=min_events)
        all_snapshots.extend(feats)

    if len(all_snapshots) < 5:
        raise ValueError(
            f"Only {len(all_snapshots)} feature snapshots collected — "
            "need more normal traffic to learn a meaningful baseline."
        )

    profile = {}
    for feature in FEATURES:
        values = [s[feature] for s in all_snapshots]
        mean = statistics.mean(values)
        # stdev needs at least 2 points; guard against a degenerate case
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        # floor std so we never divide by zero later when scoring deviations
        std = max(std, 0.05)
        profile[feature] = {
            "mean": round(mean, 4),
            "std": round(std, 4),
        }

    profile["_meta"] = {
        "n_samples": len(all_snapshots),
        "window_seconds": window_seconds,
        "source_files": telemetry_paths,
    }
    return profile


def save_profile(profile, path="baseline_profile.json"):
    with open(path, "w") as f:
        json.dump(profile, f, indent=2)


def load_profile(path="baseline_profile.json"):
    with open(path) as f:
        return json.load(f)

def _deviation_label(z):
    az = abs(z)
    if az < 1.5:
        return "Low"
    elif az < 3.0:
        return "Medium"
    else:
        return "High"


def score_observation(feature_vector, profile):
    """
    feature_vector: dict with the same FEATURES keys as the baseline
                     (a single snapshot from feature_extractor)
    profile: the loaded baseline profile

    Returns: (anomaly_score 0-1, verdict, explanation_rows, reasons)
    """
    rows = []
    z_scores = []

    for feature in FEATURES:
        baseline = profile[feature]
        mean, std = baseline["mean"], baseline["std"]
        current = feature_vector.get(feature, 0.0)

        std = max(std, 1e-9)  # extra safety net at scoring time too
        z = (current - mean) / std
        z_scores.append(z)

        rows.append({
            "feature": feature,
            "baseline": mean,
            "current": current,
            "z_score": round(z, 2),
            "deviation": _deviation_label(z),
        })

    # combine per-feature z-scores into one 0-1 anomaly score.
    # we use the average absolute z-score, then squash it into [0,1]
    # with a simple saturating function — no need for anything fancier
    # at this stage.
    avg_abs_z = sum(abs(z) for z in z_scores) / len(z_scores)
    anomaly_score = 1 - math.exp(-avg_abs_z / 3.0)  # 0 = identical to baseline, →1 = very different
    anomaly_score = round(min(anomaly_score, 1.0), 3)

    ANOMALY_THRESHOLD = 0.5
    verdict = "ANOMALOUS" if anomaly_score >= ANOMALY_THRESHOLD else "NORMAL"

    # build plain-language reasons for the High/Medium deviations, worst first
    reasons = []
    for row in sorted(rows, key=lambda r: -abs(r["z_score"])):
        if row["deviation"] == "Low":
            continue
        direction = "above" if row["z_score"] > 0 else "below"
        reasons.append(
            f"{row['feature']} is significantly {direction} the learned baseline "
            f"(z={row['z_score']})"
        )

    return anomaly_score, verdict, rows, reasons


def print_adaptive_verdict(pid, process, anomaly_score, verdict, rows, reasons):
    print(f"Process: {process}")
    print(f"PID: {pid}\n")
    print(f"Adaptive verdict: {verdict}   (anomaly score: {anomaly_score})\n")
    print(f"{'Feature':<20}{'Baseline':>10}{'Current':>10}{'Z-score':>10}{'Deviation':>12}")
    print("-" * 62)
    for r in rows:
        print(f"{r['feature']:<20}{r['baseline']:>10}{r['current']:>10}"
              f"{r['z_score']:>10}{r['deviation']:>12}")
    if reasons:
        print("\nReasons:")
        for r in reasons:
            print(f"- {r}")
    else:
        print("\nReasons: none — observation is within the learned baseline range.")
    print("-" * 62)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 adaptive_detector.py learn <file1.jsonl> [file2.jsonl ...]")
        print("  python3 adaptive_detector.py score <telemetry_file.jsonl>")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "learn":
        paths = sys.argv[2:] if len(sys.argv) > 2 else ["telemetry_log.jsonl"]
        profile = learn_baseline(paths)
        save_profile(profile)
        print(f"Baseline learned from {profile['_meta']['n_samples']} snapshots "
              f"across {len(paths)} file(s).\n")
        print(f"{'FEATURE':<20}{'MEAN':>10}{'STD':>10}")
        print("-" * 40)
        for feature in FEATURES:
            p = profile[feature]
            print(f"{feature:<20}{p['mean']:>10}{p['std']:>10}")
        print(f"\nSaved to baseline_profile.json")

    elif mode == "score":
        path = sys.argv[2] if len(sys.argv) > 2 else "telemetry_log.jsonl"
        profile = load_profile()
        events = load_events(path)
        feats = extract_features(events)

        # only score the LATEST snapshot per (pid, process), same approach
        # multi_detector.py already uses
        latest = {}
        for f in feats:
            latest[(f["pid"], f["process"])] = f

        for f in latest.values():
            score, verdict, rows, reasons = score_observation(f, profile)
            print_adaptive_verdict(f["pid"], f["process"], score, verdict, rows, reasons)
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)
