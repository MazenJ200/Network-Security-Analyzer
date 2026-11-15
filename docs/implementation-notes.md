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

## 6.5 Monitoring session

- **One command runs everything:** `python -m analyzer -i <interface>`. `MonitoringSession` follows the activity diagram: load signatures, create the session and its files, start Tshark, then for each packet update metrics and evaluate rules, until Ctrl+C or the `-d` time ends.
- **Rules are loaded before anything is created.** A broken signature file stops the program with a clear message and leaves no empty log files behind.
- **The metrics window follows the rules.** It is set to the longest `time_window_sec` among the loaded signatures.
- **Session files.** Each session gets an ID (`session-<date>-<number>`) and two files in `logs/`: the alert log and a metrics file with one line of rates per second of traffic. The dashboard is a separate process, so it reads these files instead of the engine's memory.
- **Signature reload while running.** Every 2 seconds the session checks whether any signature file changed. A valid change is loaded at once; a broken one prints a warning and the old rules stay active, so editing rules never stops monitoring.
- **Clean stop.** Ctrl+C or the end of `-d` stops Tshark, writes the last metrics line and prints a summary: run time, packets seen, and alerts per rule.
- **End-to-end check on real packets** (local HTTPS test server, loopback adapter, unchanged repository rules): one client opening 169 TLS connections per second, each with one GET, raised APP-001 (TLS handshake flood), PRO-003 (packet rate) and PRO-001 (SYN flood), each exactly once. The request estimate read 171.2 requests/s against 171.2 handshakes/s, which matches one request per connection. 23,264 packets, clean stop, no Tshark process left behind.

## 6.6 Dashboard

- **Separate process, reads files.** `streamlit run dashboard.py` reads the session files in `logs/`; it never talks to the running analyzer. The analyzer keeps working if the dashboard is closed, and old sessions can be reviewed after they end.
- **Data helpers are plain functions** (`analyzer/dashboard_data.py`): list sessions, load metrics, load alerts, filter alerts, live or not. They are tested on their own; the page (`dashboard.py`) only lays them out.
- **Auto-refresh** redraws the main area every 2 seconds (`st.fragment(run_every=2)`); the sidebar filters keep their values.
- **Live or ended.** A session counts as live if its metrics file changed in the last 10 seconds. A live session that has been quiet for a whole window shows zero; an ended session shows its last values.
- **Quiet seconds show as zero on the charts.** The analyzer only writes a metrics line for seconds that had traffic, so gaps are filled with zero.
- **Bug found while testing live (fixed in the session code):** metrics lines first stored the last packet time rounded to milliseconds, so a packet at x.9996 s was stored as the next second, two lines collided and a second went missing, which drew false drops to zero in the middle of a flood. Each line now stores the whole second it covers.
- **Charts are drawn with Altair, not `st.line_chart`.** Streamlit's built-in charts zoom when the mouse wheel is over them, which stopped the page from scrolling during testing.
- **Metric cards are two rows of three** with the unit in the label, so values are not cut off on small screens.
- **The rule filter lists every rule from the signature files**, not just rules that already fired, so an analyst can filter before an attack happens.
- **Checked in a browser during a live loopback flood** (two floods 17 s apart): rates and charts updated every 2 s, the three alerts appeared as they were raised, the second flood raised no new alerts because it fell inside the 30 s cooldown, and the severity, rule and search filters narrowed the alert table as expected.
