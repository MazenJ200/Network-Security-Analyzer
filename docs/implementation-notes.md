# Implementation Notes

Decisions made while building the system, with the reason for each. These feed Chapter 6 (Implementation) of the report.

## Step 1: Signature store

- **Thresholds are per-second rates** averaged over the rule's `time_window_sec`. One meaning for every rule keeps the detection engine simple.
- **New `scope` field** (`per_source` or `global`). Measuring each source IP on its own misses a distributed attack, where many IPs each send a little. `global` rules measure all traffic together.
- **New attribute `syn_rate`** for SYN flood rules: SYN packets without ACK, which are new connection attempts.
- **Bad rule files are rejected as a whole.** If an analyst breaks a file, the loader reports which file and rule, and a running system keeps its old rules.

## Step 2: Packet capture

- **Tshark runs as a child process** and prints one tab-separated line per packet with only the fields we need (`analyzer/capture.py`, list `FIELDS`). Python reads the lines as they arrive.
- **Live capture uses a capture filter** (`tcp port 443`), so Tshark drops other traffic before Python sees it. Saved files use the matching display filter, because capture filters only work live.
- **TLS 1.3 hides record types.** After the handshake, TLS 1.3 sends every record as "application data" (Wireshark field `tls.record.opaque_type`), so both `tls.record.content_type` and `tls.record.opaque_type` are read.
- **Counting requests without decryption.** HTTPS requests cannot be seen directly. A request is estimated as a client-to-server packet that carries encrypted application data. Two kinds of packet look the same but are skipped:
  - the packet that finishes the TLS handshake (it also carries ChangeCipherSpec)
  - encrypted alerts of 24 bytes or less, such as the one sent when a connection closes

  Checked against a test capture of 5 known requests: the parser counts exactly 5 requests, 5 SYNs and 5 TLS handshakes (`tests/test_capture.py`).
- **Known limit:** a large request split over several TCP packets, or HTTP/2 control frames (settings, pings), can be counted as more than one request. During a flood the count still rises and falls with the real request rate, which is what the rules need.
- **Direction** is decided by port: a packet to port 443 is client-to-server.
