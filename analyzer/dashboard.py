"""Dashboard web server, Python standard library only: python -m analyzer.dashboard"""

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from analyzer.dashboard_data import (
    RATES, current_rates, filter_alerts, is_live, list_sessions, load_alerts, load_metrics,
)
from analyzer.signatures import SignatureError, SignatureLoader

PAGE = Path(__file__).resolve().parent / "static" / "index.html"
ALERT_COLUMNS = ["severity", "triggered_signature_id", "triggered_signature_name", "src_ip", "dst_ip",
                 "dst_port", "scope", "monitored_attribute", "observed_value", "threshold", "sni", "status"]


def _split(values):
    return [v for v in ",".join(values or []).split(",") if v]


def session_data(logs_dir, session, minutes=10, severities=None, rules=None, search=""):
    metrics = load_metrics(logs_dir, session)
    alerts = load_alerts(logs_dir, session)
    live = is_live(logs_dir, session)
    recent = metrics.tail(minutes * 60)
    shown = filter_alerts(alerts, severities, rules, search)

    series = {"time": [int(t.timestamp()) for t in recent.index],
              **{key: [round(float(v), 3) for v in recent[key]] for key in RATES + ["mbps"]}}
    if live and series["time"]:
        # No packets means no metrics lines; draw the quiet seconds up to now as zero, like the live numbers.
        for second in range(series["time"][-1] + 1, int(time.time())):
            series["time"].append(second)
            for key in RATES + ["mbps"]:
                series[key].append(0.0)
        for key in series:
            series[key] = series[key][-minutes * 60:]

    rows = []
    for _, a in shown.iterrows():
        row = {key: a.get(key) for key in ALERT_COLUMNS}
        row["time"] = a["time"].strftime("%Y-%m-%d %H:%M:%S")
        rows.append(row)

    return {
        "session": session,
        "live": live,
        "seconds": len(metrics),
        "rates": current_rates(metrics, live),
        "series": series,
        "top_sources": metrics["top_sources"].iloc[-1] if not metrics.empty else [],
        "alerts_total": len(alerts),
        "alerts_critical": int((alerts["severity"] == "critical").sum()),
        "alerts": rows,
    }


def rule_ids(signatures_path):
    try:
        return sorted(s.signature_id for s in SignatureLoader(signatures_path).load())
    except SignatureError:
        return []


def make_handler(logs_dir, signatures_path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlparse(self.path)
            query = parse_qs(url.query)
            if url.path in ("/", "/index.html"):
                self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/api/sessions":
                self._json({"sessions": list_sessions(logs_dir)})
            elif url.path == "/api/rules":
                self._json({"rules": rule_ids(signatures_path)})
            elif url.path == "/api/session":
                name = query.get("name", [""])[0]
                # Only names from the logs folder are accepted, so a request cannot read other files.
                if name not in list_sessions(logs_dir):
                    return self._json({"error": "unknown session"}, 404)
                try:
                    minutes = min(max(int(query.get("minutes", ["10"])[0]), 1), 60)
                except ValueError:
                    minutes = 10
                self._json(session_data(logs_dir, name, minutes, _split(query.get("severity")),
                                        _split(query.get("rule")), query.get("q", [""])[0]))
            else:
                self._json({"error": "not found"}, 404)

        def _json(self, data, status=200):
            body = json.dumps(data, default=lambda v: v.item() if hasattr(v, "item") else str(v))
            self._send(status, body.encode("utf-8"), "application/json")

        def _send(self, status, body, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass  # the page polls every 2 seconds; logging each request would flood the terminal

    return Handler


def make_server(logs_dir="logs", signatures_path="signatures", host="127.0.0.1", port=8501):
    return ThreadingHTTPServer((host, port), make_handler(logs_dir, signatures_path))


def main():
    ap = argparse.ArgumentParser(prog="python -m analyzer.dashboard", description="Web dashboard for the analyzer.")
    ap.add_argument("--logs", default="logs", help="folder with session logs (default logs)")
    ap.add_argument("--signatures", default="signatures", help="folder with *_signatures.json (default signatures)")
    ap.add_argument("--port", type=int, default=8501, help="port (default 8501)")
    ap.add_argument("--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1, this computer only)")
    args = ap.parse_args()

    server = make_server(args.logs, args.signatures, args.host, args.port)
    print(f"Dashboard on http://{args.host}:{args.port}  (reading {args.logs}/, Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
