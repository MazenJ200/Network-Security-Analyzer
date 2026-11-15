"""Measure how many packets per second the metrics and detection code can handle (no Tshark involved)."""

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from analyzer.alerts import AlertGenerator  # noqa: E402
from analyzer.capture import PacketRecord  # noqa: E402
from analyzer.detection import DetectionEngine  # noqa: E402
from analyzer.metrics import MetricAggregator  # noqa: E402
from analyzer.signatures import SignatureLoader  # noqa: E402

T0 = 1_800_000_000


def packet(time_, src, syn):
    return PacketRecord(time_, "", src, "10.0.0.1", 50000, 443, 60, "TCP", "SYN" if syn else "ACK",
                        syn, False, False, "")


def run(name, packets):
    metrics = MetricAggregator(5)
    engine = DetectionEngine(SignatureLoader(ROOT / "signatures").load(), metrics,
                             AlertGenerator("bench", output=lambda _: None))
    start = time.perf_counter()
    alerts = 0
    for p in packets:
        metrics.update(p)
        alerts += len(engine.evaluate(p))
    seconds = time.perf_counter() - start
    print(f"{name:42} {len(packets):>9,} packets  {seconds:6.2f} s  {len(packets) / seconds:>9,.0f} packets/s  {alerts} alerts")


if __name__ == "__main__":
    n = 300_000
    run("one source, normal (1,000 packets/s)", [packet(T0 + i / 1000, "10.0.0.5", i % 50 == 0) for i in range(n)])
    run("one source, SYN flood (10,000 packets/s)", [packet(T0 + i / 10000, "10.0.0.66", True) for i in range(n)])
    run("new spoofed source every packet (10,000/s)",
        [packet(T0 + i / 10000, f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}", True) for i in range(n)])
