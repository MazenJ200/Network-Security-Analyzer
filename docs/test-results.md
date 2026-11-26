# Test Results

System tests run with `python tools/run_lab.py` on 2026-11-15 (results file `tools/lab_results.json`, run at 13:53). Every scenario starts its own analyzer session on the Windows loopback adapter, sends traffic to the local lab server (127.0.0.1:8443, self-signed certificate), then compares the alerts that fired with the expected ones. Nothing is sent to any other machine.

Environment: Windows 11 (build 26300), Intel Core i7-12700H, 32 GB RAM, Python 3.11.9, Tshark 4.2.4, Npcap. Repository rules unchanged (`signatures/`).

| ID | Scenario | Traffic generated | Must fire | Must not fire | Fired | First alert (s) | Packets | Capture / session (s) | Result |
|----|----------|-------------------|-----------|---------------|-------|-----------------|---------|-----------------------|--------|
| S1 | Normal browsing (no attack) | requests 44 in 40.1 s | none | VOL-001, VOL-002, PRO-001, PRO-002, PRO-003, APP-001, APP-002 | none | none | 583 | 47 / 48 | PASS |
| S2 | TLS handshake flood | connections 711 in 10.0 s | APP-001 | APP-002, PRO-002, VOL-001, VOL-002 | APP-001 | APP-001 3.92 | 16,245 | 17 / 18 | PASS |
| S3 | HTTPS request flood on one connection | requests 26105 in 10.0 s | APP-002 | APP-001, PRO-001, PRO-002 | APP-002, PRO-003 | APP-002 0.46, PRO-003 0.73 | 156,651 | 17 / 18 | PASS |
| S4 | TCP connection (SYN) flood, one source | connections 19516, sources 1 in 10.0 s | PRO-001 | APP-001, APP-002 | PRO-001, PRO-002, PRO-003 | PRO-001 0.24, PRO-002 0.74, PRO-003 0.82 | 78,066 | 17 / 18 | PASS |
| S5 | Distributed connection flood, 100 sources | connections 18787, sources 100 in 10.0 s | PRO-002 | PRO-001, APP-001, APP-002 | PRO-002 | PRO-002 0.75 | 75,150 | 17 / 18 | PASS |
| S6 | Upload (bandwidth) flood | megabytes_sent 1898.0 in 10.0 s | VOL-001, VOL-002 | APP-001, PRO-001, PRO-002 | APP-002, PRO-003, VOL-001, VOL-002 | VOL-002 0.08, APP-002 0.1, VOL-001 0.19, PRO-003 0.44 | 239,236 | 17 / 18 | PASS |

## Other checks

| ID | Check | Expected | Actual | Result |
|----|-------|----------|--------|--------|
| S7 | Normal use on the real Wi-Fi interface for 121 s while fetching 25 public websites | No alerts | 10,505 packets, 0 alerts; peaks 21.2 requests/s, 87.6 packets/s, 1.2 handshakes/s, 0.17 Mbps | PASS |
| S8 | Lab normal traffic (S1) peak rates | Far below every threshold | Peaks 1.4 requests/s, 9.8 packets/s, 0.8 handshakes/s | PASS |
| S9 | `-p 8443` and a Tshark run on port 9443 | TLS handshakes still recognised on non-443 ports | 8443: APP-001 raised, handshakes counted; 9443: 70 Client Hellos decoded without any decode-as option | PASS |

## Engine throughput

`python tools/bench.py` feeds 300,000 synthetic packets through the metrics and detection code (no Tshark):

| Traffic pattern | Packets per second processed | Alerts |
|-----------------|------------------------------|--------|
| One source, normal (1,000 packets/s) | 112,243 | 0 |
| One source, SYN flood (10,000 packets/s) | 86,483 | 3 (PRO-001, PRO-002, PRO-003) |
| New spoofed source on every packet (10,000/s) | 64,365 | 1 (PRO-002) |

## Observations

- **S6:** a 1.9 GB upload also raised APP-002 (request flood). Large uploads are split into many encrypted data packets and each one is counted as a request; see the known limit in `implementation-notes.md` (6.2).
- **S4:** one source at about 2,000 connections/s is also above the global SYN limit, so PRO-002 fired with PRO-001. That is expected.
- **S5:** 100 sources at about 19 connections/s each stay below the per-source limit, so only the global rule PRO-002 fired, which is the purpose of the `global` scope.
- First-alert times match the window maths: a rule with threshold T over a W-second window fires once T x W events have arrived. S2 ran at about 71 handshakes/s, so the earliest possible alert was 50 x 5 / 71 = 3.5 s; it fired at 3.92 s.
- **Capture / session:** Tshark stops at the planned time (warm-up + attack + tail). Every session ended within 1 s of it, so the analyzer kept up with the capture even at about 24,000 packets/s (S6).
