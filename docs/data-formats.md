# Data Formats

The system persists data in **structured JSON files** rather than a relational database. JSON was chosen because it is natively supported by Python, human-readable, and well-suited to semi-structured event records where fields may vary between packet and alert types. It also keeps the deployment lightweight with no database dependency.

There are two categories of data file: **signature files** and **log files**.

---

## Signature Files

Signature files store the detection rules the analysis engine evaluates against live traffic. They are read-only at runtime and modified only by an analyst. Each file represents one attack category and contains an array of rule objects.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `signature_id` | string | Yes | Unique identifier (e.g., `"VOL-001"`) |
| `name` | string | Yes | Human-readable name of the signature |
| `attack_category` | string | Yes | One of: `volume`, `protocol`, `application` |
| `monitored_attribute` | string | Yes | Attribute evaluated (e.g., `rps`, `pps`, `bps`, `tls_handshake_rate`) |
| `threshold` | number | Yes | Value that triggers detection when exceeded |
| `time_window_sec` | integer | Yes | Rolling time window in seconds over which the attribute is measured |
| `severity` | string | Yes | One of: `low`, `medium`, `high`, `critical` |
| `description` | string | No | Plain-language explanation of the pattern |

### Example

```json
{
  "signature_id": "APP-002",
  "name": "HTTPS Request Rate Flood",
  "attack_category": "application",
  "monitored_attribute": "rps",
  "threshold": 200,
  "time_window_sec": 5,
  "severity": "high",
  "description": "Triggers when a single source IP exceeds 200 HTTPS requests within a 5-second window, indicating an HTTP flood attack."
}
```

---

## Log Files

Log files are written during live operation. Each generated alert appends an entry to the active session's log file. Log files are append-only at runtime and are queried by the dashboard for historical review.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `log_id` | string | Yes | Unique identifier for the entry (UUID) |
| `session_id` | string | Yes | Identifier of the monitoring session |
| `alert_timestamp` | string | Yes | ISO 8601 timestamp of when the alert was generated |
| `src_ip` | string | Yes | Source IP of the suspicious traffic |
| `dst_ip` | string | Yes | Destination IP |
| `src_port` | integer | Yes | Source port |
| `dst_port` | integer | Yes | Destination port (typically 443) |
| `packet_length` | integer | Yes | Packet length in bytes |
| `protocol` | string | Yes | Protocol (e.g., `TCP`, `TLS`) |
| `tcp_flags` | string | Yes | TCP flag string (e.g., `SYN`, `ACK`) |
| `tls_handshake` | boolean | Yes | Whether a TLS handshake was detected |
| `sni` | string | No | Server Name Indication from the TLS handshake |
| `triggered_signature_id` | string | Yes | `signature_id` of the matched rule |
| `triggered_signature_name` | string | Yes | Human-readable name of the matched signature |
| `severity` | string | Yes | Severity inherited from the matched signature |
| `metric_bps` | number | Yes | Bits per second at the time of the alert |
| `metric_pps` | number | Yes | Packets per second at the time of the alert |
| `metric_rps` | number | Yes | Requests per second at the time of the alert |
| `status` | string | Yes | One of: `new`, `reviewed`, `dismissed` |

### Example

```json
{
  "log_id": "a3f2c1d4-8b0e-4f5a-9c2d-1e7b6f3a0d88",
  "session_id": "session-2026-05-23-001",
  "alert_timestamp": "2026-05-23T14:32:07.441Z",
  "src_ip": "192.168.1.45",
  "dst_ip": "192.168.1.100",
  "src_port": 52341,
  "dst_port": 443,
  "packet_length": 1420,
  "protocol": "TLS",
  "tcp_flags": "ACK",
  "tls_handshake": false,
  "sni": "targetsite.local",
  "triggered_signature_id": "APP-002",
  "triggered_signature_name": "HTTPS Request Rate Flood",
  "severity": "high",
  "metric_bps": 18540000,
  "metric_pps": 1620,
  "metric_rps": 214,
  "status": "new"
}
```

---

## Relationship

```mermaid
erDiagram
    SIGNATURE_FILE {
        string signature_id PK
        string name
        string attack_category
        string monitored_attribute
        number threshold
        int time_window_sec
        string severity
        string description
    }

    LOG_FILE {
        string log_id PK
        string session_id
        string alert_timestamp
        string src_ip
        string triggered_signature_id FK
        string severity
        number metric_bps
        number metric_pps
        number metric_rps
        string status
    }

    SIGNATURE_FILE ||--o{ LOG_FILE : "triggers (matched by signature_id)"
```

## File Naming and Storage

| File Type | Naming Convention | Location | Access Mode |
|-----------|-------------------|----------|-------------|
| Signature file | `<category>_signatures.json` (e.g., `volume_signatures.json`) | `/signatures/` | Read-only at runtime |
| Log file | `session_<date>_<id>.json` (e.g., `session_2026-05-23_001.json`) | `/logs/` | Append-only at runtime |
