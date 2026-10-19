import sys
from feature_extractor import load_events, extract_features


# ============================================================
# Detection thresholds
# ============================================================

# Connection burst
BURST_MIN_N = 5
BURST_MAX_GAP = 0.2
BURST_MAX_PORTS = 2 
# Port scanning
SCAN_MIN_PORTS = 5
SCAN_MAX_IPS = 1

# Multi-destination
MULTIDEST_MIN_IPS = 4

# Destination churn
CHURN_MIN_N = 5
CHURN_RATE_THRESHOLD = 0.6     # 60%+ of consecutive connections change destination
CHURN_MIN_UNIQUE_IPS = 2  

# Beaconing
BEACON_MIN_N = 4
BEACON_MAX_CV = 0.20

# Failed connections
FAILURE_MIN_ATTEMPTS = 4
FAILURE_RATE_THRESHOLD = 0.70


# ============================================================
# CLASSIFIER
# ============================================================

def classify(f):
    """
    Classify one feature snapshot.

    Returns:
        (label, observations, reason)
    """

    n = f["n_connections"]
    ips = f["unique_dest_ips"]
    ports = f["unique_dest_ports"]
    mean_gap = f["mean_gap_sec"]
    cv = f["cv_gap"]

    # Failure-related features
    failure_rate = f.get("failure_rate", 0.0)
    n_failed = f.get("n_failed", 0)
    failed_ports = f.get("unique_failed_ports", 0)

    # ========================================================
    # 1. CONNECTION BURST
    # ========================================================
    if n >= BURST_MIN_N and mean_gap < BURST_MAX_GAP and ports <= BURST_MAX_PORTS:

        obs = [
            f"{n} connections observed in "
            f"{f['window_span_sec']}s window",

            f"average gap between connections: "
            f"{mean_gap}s",

            f"destination: "
            f"{f['last_dest_ip']}",
        ]

        reason = (
            "Rapid sequence of connections with "
            "near-zero spacing."
        )

        return "CONNECTION BURST", obs, reason


    # ========================================================
    # 2. SCANNING-LIKE ACTIVITY
    # ========================================================
    #
    # Count BOTH successful and failed destination ports.
    #
    # Example:
    #
    # IP: 10.0.0.5
    # ports: 22, 23, 80, 443, 8080
    #
    # Even if some ports refuse the connection, they
    # still represent ports that were contacted.
    # ========================================================

    total_ports_touched = ports + failed_ports

    if (
        total_ports_touched >= SCAN_MIN_PORTS
        and ips <= SCAN_MAX_IPS
    ):

        obs = [
            f"{total_ports_touched} distinct destination "
            f"ports contacted "
            f"({ports} successful, {failed_ports} failed)",

            f"all directed at a single IP: "
            f"{f['last_dest_ip']}",

            f"within a "
            f"{f['window_span_sec']}s window",
        ]

        reason = (
            "Single destination probed across many "
            "ports — port-scanning pattern."
        )

        return "SCANNING-LIKE ACTIVITY", obs, reason


    # ========================================================
    # 3. FAILED-CONNECTION ANOMALY
    # ========================================================
    #
    # This rule comes AFTER scanning.
    #
    # Therefore:
    #
    # many failed ports -> SCANNING
    #
    # repeated failures to limited ports -> FAILED CONNECTION
    # ========================================================

    if (
        failure_rate >= FAILURE_RATE_THRESHOLD
        and n_failed >= FAILURE_MIN_ATTEMPTS
    ):

        obs = [
            f"{n_failed} failed connection "
            f"attempt(s) observed",

            f"failure rate: "
            f"{round(failure_rate * 100)}% of attempts",

            f"{failed_ports} distinct port(s) affected",
        ]

        reason = (
            "High proportion of connection attempts are "
            "failing — consistent with probing unreachable/"
            "closed services or a target that has gone offline."
        )

        return "FAILED-CONNECTION ANOMALY", obs, reason


    # ========================================================
    # 4. MULTI-DESTINATION ACTIVITY
    # ========================================================

    if ips >= MULTIDEST_MIN_IPS:

        obs = [
            f"{ips} distinct destination IPs contacted",

            f"{n} total connections in "
            f"{f['window_span_sec']}s window",
        ]

        reason = (
            "Process is communicating with an unusually "
            "large number of distinct hosts."
        )

        return "MULTI-DESTINATION ACTIVITY", obs, reason
    
    # ========================================================
    # 5. DESTINATION CHURN
    # ========================================================
    # High rate of destination switching between consecutive
    # connections — distinct from MULTI-DESTINATION (which only
    # counts total diversity). Catches rapid round-robin-style
    # rotation even across a small number of IPs.
    #
    # Only triggers when timing is NOT already regular (cv > BEACON
    # threshold) — if timing IS regular, the rotating-destination
    # beacon rule above already explains it more specifically.
    # ========================================================

    ip_churn = f.get("dest_ip_churn_rate", 0.0)

    if (
        n >= CHURN_MIN_N
        and ips >= CHURN_MIN_UNIQUE_IPS
        and ip_churn >= CHURN_RATE_THRESHOLD
        and cv > BEACON_MAX_CV
    ):

        obs = [
            f"destination IP changed on "
            f"{round(ip_churn * 100)}% of consecutive connections",

            f"{ips} distinct destination IP(s) involved",

            f"{n} connections observed in "
            f"{f['window_span_sec']}s window",
        ]

        reason = (
            "Destination is switching rapidly between connections — "
            "a round-robin-like rotation pattern, independent of "
            "overall destination count."
        )

        return "DESTINATION CHURN", obs, reason

    # ========================================================
    # 6. C2-LIKE BEACONING
    # ========================================================

    if n >= BEACON_MIN_N and cv <= BEACON_MAX_CV:

        if ips <= 1:
            dest_desc = (
                f"same destination throughout: "
                f"{f['last_dest_ip']}:{f['last_dest_port']}"
            )
        else:
            dest_desc = (
                f"destination rotated across {ips} distinct IPs "
                f"during this window"
            )

        obs = [
            "repeated TCP connections",
            dest_desc,
            "consistent timing interval",
            f"CV: {cv}",
        ]

        reason = (
            "Periodic communication pattern detected based on timing "
            "regularity" + (
                " (destination fixed)." if ips <= 1 else
                ", independent of destination IP — the interval "
                "between connections stayed consistent even though "
                "the destination changed."
            )
        )

        return "C2-LIKE BEACONING", obs, reason

    # ========================================================
    # 7. NORMAL
    # ========================================================

    obs = [
        f"{n} connection(s) observed",

        f"{ips} distinct destination IP(s)",

        f"{ports} distinct destination port(s)",
    ]

    reason = (
        "No configured suspicious network behavior "
        "pattern was detected."
    )

    return "NORMAL", obs, reason


# ============================================================
# OUTPUT
# ============================================================

def print_result(f):
    """
    Print a human-readable classification.
    """

    label, observations, reason = classify(f)

    print()
    print("=" * 60)

    print(f"Process: {f['process']}")
    print(f"PID: {f['pid']}")
    print(f"Behavior: {label}")

    print("\nObservations:")

    for item in observations:
        print(f"- {item}")

    print("\nReason:")
    print(reason)

    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) != 2:
        print(
            "Usage: python3 multi_detector.py <telemetry.jsonl>"
        )
        sys.exit(1)

    telemetry_file = sys.argv[1]

    events = load_events(telemetry_file)

    if not events:
        print("No telemetry events found.")
        sys.exit(0)

    features = extract_features(
        events,
        min_events=3
    )

    if not features:
        print("No feature snapshots generated.")
        sys.exit(0)

    for f in features:
        print_result(f)


if __name__ == "__main__":
    main()
