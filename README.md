# Network-Security-Analyzer

A real-time, **rule-based DDoS detection and traffic monitoring tool** for HTTPS networks.

The system captures live network traffic, analyzes observable packet metadata against configurable detection rules, and raises immediate alerts when traffic matches a known DDoS attack pattern. It is designed to detect attacks within encrypted HTTPS traffic **without decrypting payloads**, relying entirely on metadata and traffic behavior.

> Graduation project, Middle East University, Faculty of Information Technology, Cybersecurity Department.

----

## Key Idea

HTTPS traffic is encrypted with TLS, so deep packet inspection cannot read the payload. This creates a visibility gap that application-layer (Layer 7) DDoS attacks exploit. Instead of decrypting traffic, this tool analyzes observable metadata that remains visible even under encryption: source and destination IP addresses, packet length, timestamps, TCP flags, and TLS handshake indicators.

Detection is **deterministic and explainable**: every alert maps directly to a specific rule that was triggered, rather than to a model prediction.

## Features

- **Live packet capture** from a local network interface using Tshark
- **Metadata-only analysis** of HTTPS traffic (no payload decryption)
- **Rule-based detection** across three DDoS categories:
  - Volume-based attacks (bits-per-second thresholds)
  - Protocol-level attacks such as SYN floods (packets-per-second analysis)
  - Application-layer attacks (requests-per-second tracking)
- **JSON-defined signatures** that can be edited or extended without changing the code
- **Real-time alerts** to the terminal, with structured **JSON logging** for historical investigation
- **Interactive Streamlit dashboard** showing live Bps/Pps/Rps trends, top source IPs, and triggered alerts, with filtering and search

## Architecture Overview

```mermaid
flowchart TD
    A["Network Interface<br/>(Live HTTPS Traffic)"]

    subgraph CAPTURE["Packet Capture Layer"]
        B["Tshark<br/>Captures TCP:443 packets<br/>Extracts metadata only"]
    end

    subgraph PROC["Processing & Analysis Layer"]
        C["Python Processing Engine<br/>Traffic Parsing + Metric Aggregation<br/>(Bps / Pps / Rps)"]
        D["Signature Matching Engine<br/>Classifies traffic as<br/>Normal / Suspicious"]
        E[("JSON Signature Store<br/>Detection Rules")]
    end

    subgraph OUTPUT["Output Layer"]
        F["Alert Generator<br/>Real-time terminal alerts"]
        G[("JSON Log Store<br/>Persistent structured logs")]
    end

    subgraph PRESENT["Presentation Layer"]
        H["Streamlit Dashboard<br/>Trends, top IPs, alert feed,<br/>log search & filtering"]
    end

    A --> B
    B --> C
    C --> D
    D <--> E
    D --> F
    D --> G
    C --> H
    F --> H
    G --> H
```

See [docs/architecture.md](docs/architecture.md) for the full description.

## Technology Stack

| Component | Tool | Role |
|-----------|------|------|
| Packet capture | **Tshark** | Real-time sniffing of TCP:443 traffic with flexible filtering |
| Processing | **Python** | Core engine: parsing, metric aggregation, rule evaluation |
| Data storage | **JSON** | Human-readable signature rules and structured logs |
| Data processing | **Pandas + NumPy** | Traffic metrics and analysis |
| Dashboard | **Streamlit** | Live charts and alert visualization |
| Environment | **Local machine** | Controlled local deployment |

## Documentation

| Document | Contents |
|----------|----------|
| [docs/architecture.md](docs/architecture.md) | System architecture and component layers |
| [docs/data-formats.md](docs/data-formats.md) | JSON signature and log file schemas with examples |
| [docs/design.md](docs/design.md) | UML design diagrams (use case, class, sequence, activity, deployment, state) |
| [docs/implementation-notes.md](docs/implementation-notes.md) | Decisions made while building, and known limits |

## Setup

Requires Python 3.11+ and Wireshark (which includes Tshark and Npcap on Windows).

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows (on Linux: source .venv/bin/activate)
pip install -r requirements.txt
```

Check the detection rules and run the tests:

```bash
python -m analyzer.signatures
python -m pytest -q
```

Watch the packets the analyzer sees (live, or from the included sample file):

```bash
python -m analyzer.capture --list-interfaces
python -m analyzer.capture -i Wi-Fi -c 20
python -m analyzer.capture -r tests/data/sample_https.pcapng
```

Live capture may need an administrator terminal, depending on how Npcap was installed.

## Project Status

Implementation in progress.

| Step | Part | Status |
|------|------|--------|
| 1 | Signature store and loader (`signatures/`, `analyzer/signatures.py`) | Done |
| 2 | Packet capture and parsing (`analyzer/capture.py`) | Done |
| 3 | Metric aggregation (Bps / Pps / Rps) | Next |
| 4 | Detection engine, alerts and JSON logs | Planned |
| 5 | Monitoring session (main program) | Planned |
| 6 | Streamlit dashboard | Planned |
| 7 | Attack simulation and testing | Planned |

## Team

Hamzeh Amireh · Basil Awadallah · Khalid Daghlass · Malik Alqudah
Supervised by Dr. Basem Al-Absi.
