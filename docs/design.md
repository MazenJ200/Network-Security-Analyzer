# Design Diagrams

UML design for the Network-Security-Analyzer. All diagrams render natively on GitHub.

---

## Use Case Diagram

Two actors interact with the system: the **Security Analyst** (human operator who monitors alerts, manages rules, and reviews logs) and the **Network Interface** (system actor representing the automated flow of live traffic).

```mermaid
graph TB
    subgraph System["DDoS Detection System"]
        UC1(Monitor Live Traffic)
        UC2(Capture Packets)
        UC3(Extract Metadata)
        UC4(Evaluate Detection Rules)
        UC5(Generate Alert)
        UC6(Log Alert Event)
        UC7(Display Terminal Alert)
        UC8(View Real-Time Dashboard)
        UC9(Filter and Search Logs)
        UC10(Manage Signatures)
    end

    Analyst["Security Analyst"]
    NIC["Network Interface<br/>(System Actor)"]

    NIC --> UC1
    UC1 --> UC2
    UC1 --> UC3
    UC2 --> UC4
    UC3 --> UC4
    UC4 --> UC5
    UC5 --> UC6
    UC5 --> UC7
    Analyst --> UC8
    Analyst --> UC9
    Analyst --> UC10
    UC8 --> UC6
    UC9 --> UC6
```

---

## Class Diagram

`DetectionEngine` is central: it depends on `SignatureLoader` for rules and `MetricAggregator` for rolling statistics. On a match it delegates to `AlertGenerator`, which writes through `Logger` and produces `Alert` objects. `MonitoringSession` is the lifecycle controller that owns a `PacketCapture` instance.

```mermaid
classDiagram
    class MonitoringSession {
        +String session_id
        +String interface_name
        +DateTime start_time
        +String status
        +start()
        +stop()
    }

    class PacketCapture {
        +String interface_name
        +String bpf_filter
        +start()
        +stop()
        +get_stream() Stream
    }

    class TrafficParser {
        +parse(raw_packet) PacketRecord
    }

    class PacketRecord {
        +float time
        +String src_ip
        +String dst_ip
        +int src_port
        +int dst_port
        +int packet_length
        +String timestamp
        +String protocol
        +String tcp_flags
        +bool is_syn
        +bool tls_handshake
        +bool is_request
        +String sni
    }

    class SignatureLoader {
        +String signatures_path
        +load()
        +reload()
        +get_signatures() List~Signature~
    }

    class Signature {
        +String signature_id
        +String name
        +String attack_category
        +String monitored_attribute
        +float threshold
        +int time_window_sec
        +String severity
        +String description
    }

    class MetricAggregator {
        +int window_sec
        +update(packet PacketRecord)
        +get_bps() float
        +get_pps() float
        +get_rps() float
        +get_snapshot() MetricSnapshot
    }

    class DetectionEngine {
        +List~Signature~ signatures
        +evaluate(packet PacketRecord) Alert
    }

    class AlertGenerator {
        +generate(packet PacketRecord, sig Signature) Alert
        +display(alert Alert)
        +save(alert Alert)
    }

    class Alert {
        +String log_id
        +String session_id
        +String alert_timestamp
        +String src_ip
        +String triggered_signature_id
        +String severity
        +String scope
        +float observed_value
        +float threshold
        +float metric_bps
        +float metric_pps
        +float metric_rps
        +String status
    }

    class Logger {
        +String log_path
        +append(alert Alert)
        +query(filters dict) List~Alert~
    }

    class Dashboard {
        +run()
        +render_metrics()
        +render_alerts()
        +render_filters()
    }

    MonitoringSession "1" --> "1" PacketCapture : owns
    PacketCapture --> TrafficParser : feeds
    TrafficParser --> PacketRecord : produces
    PacketRecord --> DetectionEngine : input to
    SignatureLoader --> DetectionEngine : supplies
    SignatureLoader "1" --> "many" Signature : loads
    MetricAggregator --> DetectionEngine : used by
    DetectionEngine --> AlertGenerator : delegates to
    AlertGenerator --> Alert : creates
    AlertGenerator --> Logger : writes through
    Logger --> Dashboard : read by
    MetricAggregator --> Dashboard : read by
```

---

## Component Diagram

Components and the interfaces through which they communicate.

```mermaid
graph LR
    NIC["Network Interface"]

    subgraph host["Host Machine"]
        TSH["Tshark<br/>(Packet Capture)"]
        PYE["Python<br/>Processing Engine"]
        JSS[("JSON<br/>Signature Files")]
        JSL[("JSON<br/>Log Files")]
        STR["Streamlit<br/>Dashboard"]
    end

    Terminal["Terminal"]

    NIC -->|raw packets| TSH
    TSH -->|metadata stream / stdout pipe| PYE
    JSS -->|file read on startup + reload| PYE
    PYE -->|append on alert| JSL
    PYE -->|real-time alert| Terminal
    JSL -->|file read / query| STR
    PYE -->|in-memory metrics| STR
```

---

## Deployment Diagram

All components run on a single host machine connected to the local network via a NIC. The host runs three concurrent processes; a browser accesses the dashboard over HTTP. The monitored server is a separate node on the same network whose traffic is observed.

```mermaid
graph TD
    subgraph LAN["Local Network"]
        subgraph Host["Host Machine (Monitoring Node)"]
            NIC_H["Network Interface Card"]
            subgraph Processes["Running Processes"]
                P1["Tshark Process<br/>(packet capture)"]
                P2["Python Engine Process<br/>(detection pipeline)"]
                P3["Streamlit Server Process<br/>(localhost:8501)"]
            end
            subgraph Storage["Local Storage"]
                F1[("signatures/*.json")]
                F2[("logs/session_*.json")]
            end
        end

        subgraph Target["Monitored Server (Target Node)"]
            WEB["Web Service<br/>(HTTPS, port 443)"]
        end

        Browser["Browser (Dashboard Client)"]
    end

    NIC_H -->|captures traffic| P1
    P1 -->|stdout pipe| P2
    F1 -->|read| P2
    P2 -->|append| F2
    F2 -->|read| P3
    P3 -->|HTTP localhost:8501| Browser
    Target -->|HTTPS traffic observed by NIC| NIC_H
```

---

## Activity Diagram

End-to-end operational flow from startup to shutdown.

```mermaid
flowchart TD
    START([Start]) --> INIT1[Load JSON Signature Files]
    INIT1 --> INIT2[Initialise Tshark on Network Interface]
    INIT2 --> INIT3[Create Monitoring Session]
    INIT3 --> LOOP{Monitoring Loop Active?}

    LOOP -->|Yes| CAP[Capture Next Packet]
    CAP --> PARSE[Parse Metadata]
    PARSE --> METRICS[Update Metric Aggregator<br/>Bps / Pps / Rps]
    METRICS --> EVAL[Evaluate Against All Signatures]

    EVAL --> MATCH{Signature Matched?}

    MATCH -->|No| LOOP
    MATCH -->|Yes| ALERT[Generate Alert Object]
    ALERT --> LOG[Append to JSON Log File]
    ALERT --> TERM[Display Alert in Terminal]
    LOG --> LOOP
    TERM --> LOOP

    LOOP -->|No - Stop Signal| CLOSE[Close Monitoring Session]
    CLOSE --> FINAL[Finalise Log Files]
    FINAL --> END([End])
```

---

## Sequence Diagram

Interactions during a single packet capture and detection cycle that results in an alert.

```mermaid
sequenceDiagram
    participant NIC as Network Interface
    participant TSH as Tshark
    participant PC as PacketCapture
    participant TP as TrafficParser
    participant MA as MetricAggregator
    participant SL as SignatureLoader
    participant DE as DetectionEngine
    participant AG as AlertGenerator
    participant LG as Logger
    participant DB as Dashboard

    NIC->>TSH: raw HTTPS packet (TCP:443)
    TSH->>PC: stdout pipe (structured fields)
    PC->>TP: parse(raw_packet)
    TP-->>PC: PacketRecord
    PC->>MA: update(PacketRecord)
    MA-->>PC: updated metrics (Bps/Pps/Rps)
    PC->>DE: evaluate(PacketRecord)
    DE->>MA: get_snapshot()
    MA-->>DE: MetricSnapshot
    DE->>SL: get_signatures()
    SL-->>DE: List[Signature]
    DE->>DE: compare metrics against thresholds

    alt Signature matched
        DE->>AG: generate(PacketRecord, Signature)
        AG-->>DE: Alert
        AG->>LG: append(Alert)
        LG-->>AG: ok
        AG->>AG: display(Alert) [terminal]
    else No match
        DE-->>PC: None
    end

    Note over DB,LG: Dashboard refresh cycle (independent)
    DB->>LG: query(filters)
    LG-->>DB: List[Alert]
    DB->>MA: get_bps(), get_pps(), get_rps()
    MA-->>DB: current metrics
```

---

## State Transition Diagrams

### System Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Idle

    Idle --> Initialising : operator starts system
    Initialising --> Capturing : signatures loaded, Tshark attached
    Initialising --> Idle : initialisation failed

    Capturing --> Alerting : signature match detected
    Alerting --> Capturing : alert generated and dispatched

    Capturing --> Stopping : stop signal received
    Alerting --> Stopping : stop signal received

    Stopping --> Idle : logs finalised, session closed
```

### Alert Lifecycle

```mermaid
stateDiagram-v2
    [*] --> New : alert created by DetectionEngine

    New --> Reviewed : analyst opens alert in dashboard
    Reviewed --> Escalated : confirmed attack, action required
    Reviewed --> Dismissed : false positive, no action needed

    Escalated --> [*]
    Dismissed --> [*]
```
