# eBPF-Based Detection of C2 Communication Using Network Behavioral Analysis

A Linux-based network behavior detection system that uses **eBPF telemetry and behavioral analysis** to identify suspicious connection patterns associated with command-and-control (C2) activity.

The project focuses on detecting network behaviors such as periodic beaconing, connection bursts, port-scanning-like activity, and communication across multiple destinations. It combines kernel-level TCP connection monitoring with Python-based feature extraction and detection logic.

## Overview

Command-and-control communication often exhibits recognizable network patterns, including repeated connections at regular intervals, unusually frequent connection attempts, and connections to multiple destinations or ports.

This project explores how **eBPF-based network telemetry** can be used to collect TCP connection events and analyze them for potentially suspicious behavior.

The system is designed as a defensive research prototype and is tested using controlled, benign traffic simulations.

## Key Features

- **eBPF-based telemetry:** Observe TCP connection activity on Linux using eBPF instrumentation.
- **Behavioral analysis:** Extract network features and analyze connection patterns.
- **Beaconing detection:** Identify repeated connections with potentially periodic timing.
- **Connection burst detection:** Examine unusually concentrated connection activity.
- **Scanning-like behavior detection:** Analyze connection attempts involving multiple ports or destinations.
- **Multi-destination analysis:** Examine connections across multiple destination addresses.
- **Adaptive detection:** Experiment with baseline-based anomaly detection.
- **Process enrichment:** Associate network events with available process information.
- **Visualization:** Provide a web-based dashboard for presenting detection results.

Detection results indicate suspicious behavior for further investigation; they do not independently establish that a host is compromised.

## Architecture

```text
        Controlled Test Traffic
                  |
                  v
       eBPF TCP Connection Monitor
                  |
                  v
          Telemetry Collection
                  |
                  v
          Feature Extraction
                  |
                  v
       Behavioral Detection Engine
                  |
          +-------+-------+
          |               |
          v               v
   Detection Results   Baseline Analysis
          |               |
          +-------+-------+
                  |
                  v
          Web Dashboard
```

## Technology Stack

- **Operating System:** Linux (Ubuntu)
- **Kernel telemetry:** eBPF
- **Instrumentation:** BCC and Python
- **Programming language:** Python
- **Frontend:** HTML, CSS, JavaScript
- **Analysis:** Statistical features and behavioral heuristics
- **Version control:** Git and GitHub

## Project Structure

```text
ebpf-c2-detector/
├── tcp_connect_trace.py
├── collector.py
├── feature_extractor.py
├── detector.py
├── live_detector.py
├── multi_detector.py
├── adaptive_detector.py
├── analyze_gaps.py
├── proc_enrichment.py
├── app.py
├── console.py
├── combined_server.py
├── beacon_client.py
├── rotating_beacon_client.py
├── burst_client.py
├── portscan_client.py
├── multidest_client.py
├── multidest_server.py
├── multiport_server.py
├── echo_server.py
├── dashboard.html
├── static/
│   ├── app.js
│   └── styles.css
└── README.md
```

## Detection Behaviors

| Behavior | Description |
|---|---|
| Periodic beaconing | Repeated connections with similar time intervals |
| Connection bursts | A high concentration of connections in a short period |
| Scanning-like activity | Connections across multiple ports or destinations |
| Multi-destination activity | Connections involving multiple destination addresses |
| Repeated connection attempts | Frequent attempts to establish connections |
| Adaptive anomaly detection | Deviations from an observed baseline |

The exact coverage and accuracy of each detector depend on its implementation, configuration, and test conditions.

## Getting Started

### Prerequisites

- A Linux system with a compatible kernel and BCC/eBPF support.
- Python 3.
- Required BCC packages and development dependencies.
- Appropriate permissions for kernel tracing.
- A web browser for viewing the dashboard.

> **Note:** eBPF setup varies by Linux distribution and kernel version. The collector may require elevated privileges and compatible kernel instrumentation support.

### 1. Clone the Repository

```bash
git clone https://github.com/rohankaf/ebpf-c2-detector.git
cd ebpf-c2-detector
```

### 2. Set Up Python

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install additional Python dependencies if required by the application. The project dependency list will be documented in `requirements.txt` as it is finalized.

### 3. Run the Telemetry Collector

Review `tcp_connect_trace.py` before running it to understand its kernel probes, event format, and output behavior.

For a compatible environment, the collector may require elevated privileges:

```bash
sudo python3 tcp_connect_trace.py
```

Use the actual Python environment and BCC installation supported by your system.

### 4. Run the Detection Engine

Review the detector's expected input format and the collector's output configuration before connecting them.

Available detection modules include:

- `detector.py`
- `live_detector.py`
- `multi_detector.py`
- `adaptive_detector.py`

### 5. Launch the Dashboard

Inspect `app.py` to confirm the configured framework, entry point, and dependencies. Start the application using its documented run command and open the configured local address in your browser.

**Important:** The precise startup commands and dependencies should be verified against the current implementation before use.

## Testing and Evaluation

The project includes benign traffic generators for experimenting with different network behaviors, including periodic connections, bursts, multi-destination activity, and scanning-like patterns.

Recommended evaluation metrics:

- True positives (TP)
- True negatives (TN)
- False positives (FP)
- False negatives (FN)
- Precision
- Recall
- F1-score
- Detection latency

Tests should distinguish between normal traffic, simulated suspicious behavior, and edge cases. Thresholds should be evaluated against representative data to understand false-positive and false-negative rates.

## Safety and Scope

This project is intended for **defensive cybersecurity research, education, and controlled testing**.

- Use only systems and networks you own or are authorized to test.
- Generate test traffic in a controlled lab environment.
- Do not deploy malware or operate real malicious C2 infrastructure.
- Do not interpret a behavioral alert as definitive proof of malicious activity.

## Limitations

- Behavioral patterns can overlap with legitimate network activity.
- Periodic connections alone do not prove C2 communication.
- Detection quality depends on event coverage, feature selection, and threshold configuration.
- Kernel compatibility and available telemetry may vary across Linux environments.
- Further testing is required to establish detection performance and generalizability.

## Future Work

- Improve detection thresholds and reduce false positives.
- Expand evaluation across normal and simulated suspicious traffic.
- Add structured alert reporting and severity scoring.
- Improve process-level enrichment and event correlation.
- Integrate MITRE ATT&CK technique mapping where supported by the detection logic.
- Improve dashboard usability and exportable evaluation reports.
- Add reproducible setup instructions and automated tests.

## Research Focus

This project explores the intersection of:

- eBPF and Linux observability
- Network behavior analysis
- Defensive security engineering
- Anomaly detection
- Security telemetry and visualization

## Disclaimer

This repository is a research prototype, not a production-grade intrusion detection or endpoint detection and response system. Findings require validation and investigation before operational use.

## Author

**Rohan Kafle**

GitHub: [@rohankaf](https://github.com/rohankaf)

Interested in security engineering, OSINT systems, systems programming, automation, and intelligent security research.

Contributions, suggestions, and constructive feedback are welcome.
