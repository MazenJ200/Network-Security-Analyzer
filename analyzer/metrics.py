"""Rolling traffic rates (Bps, Pps, Rps, SYN and TLS handshake rates), per source IP and overall."""

import argparse
from dataclasses import dataclass

ATTRIBUTES = ("bps", "pps", "rps", "syn_rate", "tls_handshake_rate")
GLOBAL = "*"


@dataclass(frozen=True)
class MetricSnapshot:
    time: float
    bps: float
    pps: float
    rps: float
    syn_rate: float
    tls_handshake_rate: float


class MetricAggregator:
    def __init__(self, window_sec=5, server_port=443):
        self.window_sec = window_sec
        self.server_port = server_port
        self.now = 0.0
        self._now_sec = 0
        self._buckets = {}  # source IP (or GLOBAL) -> {second: one counter per ATTRIBUTES entry}

    def update(self, packet):
        # Only traffic sent to the protected service counts; the server's own replies would look like a flood.
        if packet.dst_port != self.server_port:
            return
        second = int(packet.time)
        if second > self._now_sec:
            self._now_sec = second
            self._drop_old()
        self.now = max(self.now, packet.time)
        if second <= self._now_sec - self.window_sec:
            return

        values = (packet.packet_length * 8, 1, packet.is_request, packet.is_syn, packet.tls_handshake)  # same order as ATTRIBUTES
        for key in (packet.src_ip, GLOBAL):
            bucket = self._buckets.setdefault(key, {}).setdefault(second, [0, 0, 0, 0, 0])
            for i, value in enumerate(values):
                bucket[i] += value

    def _drop_old(self):
        oldest = self._now_sec - self.window_sec + 1
        for key in list(self._buckets):
            seconds = self._buckets[key]
            for second in [s for s in seconds if s < oldest]:
                del seconds[second]
            if not seconds:
                del self._buckets[key]

    def rate(self, attribute, window_sec=None, src_ip=None):
        """Per-second average of an attribute over the last window_sec seconds."""
        window = window_sec or self.window_sec
        if attribute not in ATTRIBUTES:
            raise ValueError(f"unknown attribute {attribute!r}")
        if window > self.window_sec:
            raise ValueError(f"window {window}s is longer than the {self.window_sec}s being kept")

        index = ATTRIBUTES.index(attribute)
        seconds = self._buckets.get(src_ip or GLOBAL, {})
        total = sum(seconds.get(s, (0,) * 5)[index] for s in range(self._now_sec - window + 1, self._now_sec + 1))
        return total / window

    def get_bps(self, src_ip=None):
        return self.rate("bps", src_ip=src_ip)

    def get_pps(self, src_ip=None):
        return self.rate("pps", src_ip=src_ip)

    def get_rps(self, src_ip=None):
        return self.rate("rps", src_ip=src_ip)

    def get_snapshot(self, src_ip=None):
        return MetricSnapshot(self.now, *(self.rate(a, src_ip=src_ip) for a in ATTRIBUTES))

    def sources(self):
        return [key for key in self._buckets if key != GLOBAL]

    def top_sources(self, n=5, attribute="pps"):
        ranked = sorted(((ip, self.rate(attribute, src_ip=ip)) for ip in self.sources()), key=lambda x: -x[1])
        return ranked[:n]


def main():
    from analyzer.capture import PacketCapture

    ap = argparse.ArgumentParser(description="Print traffic rates once per second.")
    ap.add_argument("-i", "--interface", help="interface name or number")
    ap.add_argument("-r", "--read", help="read a saved .pcap/.pcapng file")
    ap.add_argument("-w", "--window", type=int, default=5, help="averaging window in seconds (default 5)")
    ap.add_argument("-p", "--port", type=int, default=443, help="server port to watch (default 443)")
    ap.add_argument("-d", "--duration", type=int, help="stop a live capture after this many seconds")
    args = ap.parse_args()
    if not args.interface and not args.read:
        ap.error("give -i INTERFACE or -r FILE")

    capture = PacketCapture(args.interface, args.read, args.port, args.duration)
    metrics = MetricAggregator(window_sec=args.window, server_port=args.port)
    last_printed = None

    def show():
        s = metrics.get_snapshot()
        top = ", ".join(f"{ip} {pps:.1f}" for ip, pps in metrics.top_sources(3))
        print(
            f"{s.bps / 1e6:8.3f} Mbps  {s.pps:8.1f} pps  {s.rps:6.1f} rps  "
            f"{s.syn_rate:6.1f} syn/s  {s.tls_handshake_rate:6.1f} hs/s  top pps: {top}"
        )

    try:
        for packet in capture.get_stream():
            metrics.update(packet)
            if last_printed is not None and int(metrics.now) > last_printed:
                show()
            last_printed = int(metrics.now)
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop()
    show()


if __name__ == "__main__":
    main()
