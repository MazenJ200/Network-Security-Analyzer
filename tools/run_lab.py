"""Run every lab scenario against the real analyzer and record expected vs actual results.

    python tools/run_lab.py                  (Windows loopback, port 8443)
    python tools/run_lab.py -i lo            (Linux loopback)
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import traffic  # noqa: E402

ALL_RULES = ["VOL-001", "VOL-002", "PRO-001", "PRO-002", "PRO-003", "APP-001", "APP-002"]
WARMUP_SEC, TAIL_SEC = 4, 3

# id, name, generator, seconds, rules that must fire, rules that must not fire
SCENARIOS = [
    ("S1", "Normal browsing (no attack)", traffic.normal, 40, [], ALL_RULES),
    ("S2", "TLS handshake flood", traffic.handshake_flood, 10, ["APP-001"], ["APP-002", "PRO-002", "VOL-001", "VOL-002"]),
    ("S3", "HTTPS request flood on one connection", traffic.request_flood, 10, ["APP-002"], ["APP-001", "PRO-001", "PRO-002"]),
    ("S4", "TCP connection (SYN) flood, one source", traffic.connection_flood, 10, ["PRO-001"], ["APP-001", "APP-002"]),
    ("S5", "Distributed connection flood, 100 sources", traffic.distributed_flood, 10, ["PRO-002"], ["PRO-001", "APP-001", "APP-002"]),
    ("S6", "Upload (bandwidth) flood", traffic.upload_flood, 10, ["VOL-001", "VOL-002"], ["APP-001", "PRO-001", "PRO-002"]),
]


def stop(process):
    # On Windows a venv python.exe is a launcher with a child process; terminate() would leave the child running.
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True)
    else:
        process.terminate()


def run_scenario(sid, name, generator, seconds, must, must_not, interface, logs, port):
    analyzer = subprocess.Popen(
        [sys.executable, "-m", "analyzer", "-i", interface, "-p", str(port), "-d", str(WARMUP_SEC + seconds + TAIL_SEC),
         "--logs", str(logs), "--stats", "0"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    output = []
    for line in analyzer.stdout:
        output.append(line.rstrip())
        if line.startswith("Press Ctrl+C"):
            break
    alert_log = next(Path(l.split(":", 1)[1].strip()) for l in output if l.startswith("Alerts:"))
    time.sleep(WARMUP_SEC)

    start = time.time()
    stats = generator(seconds)
    end = time.time()
    output += [line.rstrip() for line in analyzer.stdout]
    analyzer.wait()

    alerts = [json.loads(line) for line in alert_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    first = {}
    for a in alerts:
        t = datetime.fromisoformat(a["alert_timestamp"].replace("Z", "+00:00")).timestamp()
        first.setdefault(a["triggered_signature_id"], round(t - start, 2))
    fired = sorted(first)
    summary = next((l for l in output if "packets," in l), "")
    packets = int(summary.split(":")[1].split("packets")[0].strip().split()[-1]) if summary else 0
    passed = set(must) <= set(fired) and not set(fired) & set(must_not)
    return {
        "id": sid, "name": name, "seconds": round(end - start, 1), "traffic": stats,
        "expected": must, "forbidden": must_not, "fired": fired, "first_alert_sec": first,
        "alerts": len(alerts), "packets": packets, "session": alert_log.stem, "result": "PASS" if passed else "FAIL",
        # Raw output names local folders, so it is kept only to explain a failure.
        "analyzer_output": [] if passed else output,
    }


def main():
    ap = argparse.ArgumentParser(description="Run the lab scenarios against the analyzer.")
    ap.add_argument("-i", "--interface", default=r"\Device\NPF_Loopback")
    ap.add_argument("-p", "--port", type=int, default=8443, help="lab server port (default 8443)")
    ap.add_argument("--logs", default=str(ROOT / "tools" / "lab_logs"))
    ap.add_argument("--only", nargs="*", help="scenario ids to run, e.g. S2 S3")
    args = ap.parse_args()

    traffic.PORT = args.port
    server = subprocess.Popen([sys.executable, str(ROOT / "tools" / "lab_server.py"), "-p", str(args.port)],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    first = server.stdout.readline()
    if not first.startswith("Test server"):
        stop(server)
        sys.exit(f"Lab server did not start on port {args.port} (port in use?): {first.strip()}")
    results = []
    try:
        for scenario in SCENARIOS:
            if args.only and scenario[0] not in args.only:
                continue
            print(f"{scenario[0]} {scenario[1]} ...", flush=True)
            r = run_scenario(*scenario, args.interface, Path(args.logs), args.port)
            results.append(r)
            print(f"   {r['result']}  fired={r['fired'] or 'none'}  first={r['first_alert_sec']}  "
                  f"packets={r['packets']}  traffic={r['traffic']}", flush=True)
    finally:
        stop(server)

    out = ROOT / "tools" / "lab_results.json"
    out.write_text(json.dumps({"run_at": datetime.now().isoformat(timespec="seconds"), "results": results}, indent=1))
    print(f"\n{sum(r['result'] == 'PASS' for r in results)}/{len(results)} passed, details in {out}")


if __name__ == "__main__":
    main()
