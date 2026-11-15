"""Monitoring session: wires capture, metrics, detection and logging together from start to stop."""

import json
import re
import time
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from analyzer.alerts import AlertGenerator, Logger
from analyzer.capture import PacketCapture
from analyzer.detection import DetectionEngine
from analyzer.metrics import MetricAggregator
from analyzer.signatures import SignatureError, SignatureLoader

RELOAD_CHECK_SEC = 2


def next_session_number(logs_dir, date):
    numbers = [int(m.group(1)) for p in Path(logs_dir).glob(f"session_{date}_*.jsonl")
               if (m := re.fullmatch(rf"session_{date}_(\d+)\.jsonl", p.name))]
    return max(numbers, default=0) + 1


class MonitoringSession:
    def __init__(self, interface_name=None, pcap_file=None, server_port=443, signatures_path="signatures",
                 logs_dir="logs", duration=None, cooldown_sec=30, stats_every=5, output=print):
        self.capture = PacketCapture(interface_name, pcap_file, server_port, duration)
        self.interface_name = interface_name or str(pcap_file)
        self.server_port = server_port
        self.loader = SignatureLoader(signatures_path)
        self.logs_dir = Path(logs_dir)
        self.cooldown_sec = cooldown_sec
        self.stats_every = stats_every
        self.output = output
        self.status = "idle"
        self.session_id = None
        self.packets = 0
        self.alerts = []

    def start(self):
        """Run until the capture ends or Ctrl+C, then stop cleanly."""
        self.status = "initialising"
        try:
            signatures = self.loader.load()
        except SignatureError:
            self.status = "idle"
            raise
        self._signature_mtimes = self._mtimes()
        self._next_reload_check = time.monotonic() + RELOAD_CHECK_SEC

        self.start_time = datetime.now()
        date = self.start_time.strftime("%Y-%m-%d")
        number = next_session_number(self.logs_dir, date)
        self.session_id = f"session-{date}-{number:03d}"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.alert_log = self.logs_dir / f"session_{date}_{number:03d}.jsonl"
        self.metrics_log = self.logs_dir / f"session_{date}_{number:03d}_metrics.jsonl"
        self.alert_log.touch()
        self.metrics_log.touch()

        window = max(s.time_window_sec for s in signatures)
        self.metrics = MetricAggregator(window_sec=window, server_port=self.server_port)
        generator = AlertGenerator(self.session_id, Logger(self.alert_log), output=self.output)
        self.engine = DetectionEngine(signatures, self.metrics, generator, self.cooldown_sec)

        self.output(f"Session {self.session_id} on {self.interface_name}, port {self.server_port}")
        self.output(f"Loaded {len(signatures)} signatures from {self.loader.signatures_path}/")
        self.output(f"Alerts:  {self.alert_log}\nMetrics: {self.metrics_log}\nPress Ctrl+C to stop.\n")

        self.status = "capturing"
        try:
            self._run()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def _run(self):
        last_second = None
        for packet in self.capture.get_stream():
            second = int(packet.time)
            if last_second is not None and second > last_second:
                self._write_metrics(last_second)
                if self.stats_every and second // self.stats_every > last_second // self.stats_every:
                    self._print_stats()
            last_second = max(second, last_second or second)

            self.packets += 1
            self.metrics.update(packet)
            self.alerts += self.engine.evaluate(packet)

            if time.monotonic() >= self._next_reload_check:
                self.reload_signatures_if_changed()
        if last_second is not None:
            self._write_metrics(last_second)

    def _mtimes(self):
        return {p.name: p.stat().st_mtime for p in self.loader.signatures_path.glob("*_signatures.json")}

    def reload_signatures_if_changed(self):
        self._next_reload_check = time.monotonic() + RELOAD_CHECK_SEC
        mtimes = self._mtimes()
        if mtimes == self._signature_mtimes:
            return False
        self._signature_mtimes = mtimes
        try:
            signatures = self.loader.load()
            self.engine.set_signatures(signatures)
        except (SignatureError, ValueError) as err:
            self.output(f"[WARN] Signature files changed but were not loaded, keeping the old rules: {err}")
            return False
        self.output(f"[INFO] Reloaded {len(signatures)} signatures")
        return True

    def _write_metrics(self, second):
        # Store the whole second the line covers; a rounded packet time could land on the next second.
        line = {key: round(value, 3) for key, value in asdict(self.metrics.get_snapshot()).items()}
        line["time"] = second
        line["top_sources"] = [[ip, round(pps, 2)] for ip, pps in self.metrics.top_sources(5)]
        with self.metrics_log.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")

    def _print_stats(self):
        s = self.metrics.get_snapshot()
        self.output(f"[stats] {s.bps / 1e6:.3f} Mbps  {s.pps:.1f} pps  {s.rps:.1f} rps  "
                    f"{s.syn_rate:.1f} syn/s  {s.tls_handshake_rate:.1f} handshakes/s")

    def stop(self):
        if self.status != "capturing":
            return
        self.status = "stopping"
        self.capture.stop()
        seconds = (datetime.now() - self.start_time).total_seconds()
        by_rule = Counter(a.triggered_signature_id for a in self.alerts)
        self.output(f"\nSession {self.session_id} stopped after {seconds:.0f}s: "
                    f"{self.packets} packets, {len(self.alerts)} alerts"
                    + (f" ({', '.join(f'{k} x{v}' for k, v in sorted(by_rule.items()))})" if by_rule else ""))
        self.status = "stopped"
