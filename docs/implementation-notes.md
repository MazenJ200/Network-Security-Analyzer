# Implementation Notes

Decisions made while building the system, with the reason for each. These feed Chapter 6 (Implementation) of the report.

## 6.1 Signature store

- **Thresholds are per-second rates** averaged over the rule's `time_window_sec`. One meaning for every rule keeps the detection engine simple.
- **New `scope` field** (`per_source` or `global`). Measuring each source IP on its own misses a distributed attack, where many IPs each send a little. `global` rules measure all traffic together.
- **New attribute `syn_rate`** for SYN flood rules: SYN packets without ACK, which are new connection attempts.
- **Bad rule files are rejected as a whole.** If an analyst breaks a file, the loader reports which file and rule, and a running system keeps its old rules.

## 6.2 Packet capture

- **Tshark runs as a child process** and prints one tab-separated line per packet with only the fields we need (`analyzer/capture.py`, list `FIELDS`). Python reads the lines as they arrive.
- **Live capture uses a capture filter** (`tcp port 443`), so Tshark drops other traffic before Python sees it. Saved files use the matching display filter, because capture filters only work live.
- **TLS 1.3 hides record types.** After the handshake, TLS 1.3 sends every record as "application data" (Wireshark field `tls.record.opaque_type`), so both `tls.record.content_type` and `tls.record.opaque_type` are read.
- **Counting requests without decryption.** HTTPS requests cannot be seen directly. A request is estimated as a client-to-server packet that carries encrypted application data. Two kinds of packet look the same but are skipped:
  - the packet that finishes the TLS handshake (it also carries ChangeCipherSpec)
  - encrypted alerts of 24 bytes or less, such as the one sent when a connection closes

  Checked against a test capture of 5 known requests: the parser counts exactly 5 requests, 5 SYNs and 5 TLS handshakes (`tests/test_capture.py`).
- **Known limit:** a large request split over several TCP packets, or HTTP/2 control frames (settings, pings), can be counted as more than one request. During a flood the count still rises and falls with the real request rate, which is what the rules need.
- **Direction** is decided by port: a packet to port 443 is client-to-server.

## 6.3 Traffic metrics

- **One-second buckets.** Each second gets one counter per attribute (bits, packets, requests, SYNs, TLS handshakes). A rate is the total of the last N buckets divided by N. Under a flood this adds up a few numbers instead of thousands of packets, so the cost per packet stays the same.
- **Per source IP and overall.** Every packet is added twice: to its source IP and to an overall counter. This serves both `per_source` and `global` rules.
- **Packet time, not the wall clock.** Rates use the time stamped on each packet, so replaying a saved capture gives the same numbers as watching it live, and tests can use exact times.
- **Only traffic sent to the server counts.** Packets to the server port are measured; the server's replies are not. Otherwise a large download to a normal user would look like a bandwidth flood.
- **Memory stays bounded.** Buckets older than the window are dropped once per second, and a source IP with nothing left in the window is forgotten. This matters during attacks from many spoofed IPs.
- **The current second is still filling**, so a rate reads slightly low for part of each second. This errs on the side of fewer false alarms.
- **Clean stop.** Tshark runs in its own process group, so Ctrl+C reaches only Python, which then stops Tshark. Without this, Tshark could exit first and look like a crash. A `-d SECONDS` option uses Tshark's own auto-stop for timed demos.

## 6.4 Detection engine, alerts and logs

- **How a rule is checked.** After each packet updates the metrics, every signature reads one rate: for the packet's source IP (`per_source`) or for all traffic (`global`), over the signature's own window. If the rate is above the threshold, the rule matches.
- **No alert storms.** During an attack every packet breaks the rule. A rule alerts once when it starts matching, then at most once every 30 seconds (packet time) while it keeps matching. For `per_source` rules this is tracked per source IP, so two attackers give two alerts.
- **Global alerts name the busiest source** in `src_ip`, so the analyst has a starting point even when the attack is spread out.
- **Alerts explain themselves.** Each alert stores the measured rate, the threshold, the attribute and the scope, so it can be checked by hand against the rule that fired.
- **One place for output.** `AlertGenerator.generate()` builds the alert, appends it to the log and prints it, matching the sequence diagram.
- **JSON Lines log.** One JSON object per line, opened, appended and closed for each alert. Alerts are rare (cooldown), so this costs nothing and nothing is lost if the program stops. `Logger.query()` filters by any field for the dashboard and skips a half-written last line.
- **Signature windows are checked at start.** A rule whose window is longer than the metrics keep is rejected with its ID, instead of silently reading too few seconds.
- **Measured on a simulated attack** (synthetic packets through the real rules): a 300 SYN/s flood from one IP raised PRO-001 after about 1.7 s (when the 5-second average passed 100/s); a 2000 SYN/s flood from 400 IPs raised only PRO-002 (global). 13,800 packets raised exactly 2 alerts. Metrics plus detection ran at about 100,000 packets per second on the development laptop, so Tshark, not Python, sets the speed limit.
