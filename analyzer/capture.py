"""Run Tshark and turn each HTTPS packet into a PacketRecord (metadata only, no decryption)."""

import argparse
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "frame.len",
    "tcp.len",
    "tcp.flags",
    "tls.record.content_type",
    "tls.record.opaque_type",  # TLS 1.3 reports encrypted records here, not in content_type
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
]

TLS_CHANGE_CIPHER_SPEC = 20
TLS_APPLICATION_DATA = 23
TLS_CLIENT_HELLO = 1
MAX_ALERT_SIZE = 24  # an encrypted TLS alert is 24 bytes; real requests are bigger

TCP_FLAG_NAMES = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]

WINDOWS_TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")


class CaptureError(Exception):
    """Tshark is missing or stopped with an error."""


@dataclass(frozen=True)
class PacketRecord:
    time: float
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packet_length: int
    protocol: str
    tcp_flags: str
    is_syn: bool
    tls_handshake: bool
    is_request: bool
    sni: str


def _numbers(text):
    return {int(part) for part in text.split(",") if part.strip()}


def flags_to_text(flags):
    names = [name for bit, name in TCP_FLAG_NAMES if flags & bit]
    return ",".join(names) if names else "NONE"


class TrafficParser:
    def __init__(self, server_port=443):
        self.server_port = server_port

    def parse(self, line):
        """Return a PacketRecord, or None if the line is not a usable packet."""
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) != len(FIELDS):
            return None
        row = dict(zip(FIELDS, parts))

        try:
            time = float(row["frame.time_epoch"])
            src_port = int(row["tcp.srcport"])
            dst_port = int(row["tcp.dstport"])
            length = int(row["frame.len"])
            payload = int(row["tcp.len"] or 0)
            flags = int(row["tcp.flags"], 16)
            record_types = _numbers(row["tls.record.content_type"]) | _numbers(row["tls.record.opaque_type"])
            handshake_types = _numbers(row["tls.handshake.type"])
        except ValueError:
            return None

        src_ip = row["ip.src"] or row["ipv6.src"]
        dst_ip = row["ip.dst"] or row["ipv6.dst"]
        if not src_ip or not dst_ip:
            return None

        # Requests are encrypted, so estimate them: encrypted data sent to the server,
        # minus the handshake-finish packet and small alerts, which look the same.
        is_request = (
            dst_port == self.server_port
            and TLS_APPLICATION_DATA in record_types
            and TLS_CHANGE_CIPHER_SPEC not in record_types
            and payload > MAX_ALERT_SIZE
        )

        return PacketRecord(
            time=time,
            timestamp=datetime.fromtimestamp(time, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            packet_length=length,
            protocol="TLS" if record_types else "TCP",
            tcp_flags=flags_to_text(flags),
            is_syn=bool(flags & 0x02) and not flags & 0x10,
            tls_handshake=TLS_CLIENT_HELLO in handshake_types,
            is_request=is_request,
            sni=row["tls.handshake.extensions_server_name"].split(",")[0],
        )


def find_tshark():
    path = shutil.which("tshark")
    if path:
        return path
    if WINDOWS_TSHARK.exists():
        return str(WINDOWS_TSHARK)
    raise CaptureError("Tshark not found. Install Wireshark (it includes Tshark) and try again.")


def list_interfaces():
    result = subprocess.run([find_tshark(), "-D"], capture_output=True, text=True)
    return result.stdout.strip()


class PacketCapture:
    def __init__(self, interface_name=None, pcap_file=None, server_port=443, duration=None):
        if (interface_name is None) == (pcap_file is None):
            raise ValueError("give exactly one of interface_name or pcap_file")
        self.interface_name = interface_name
        self.pcap_file = pcap_file
        self.server_port = server_port
        self.duration = duration
        self.bpf_filter = f"tcp port {server_port}"
        self.parser = TrafficParser(server_port)
        self._process = None

    def _command(self):
        cmd = [find_tshark(), "-n", "-l", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
        if self.pcap_file:
            # Capture filters only work live, so files use the matching display filter.
            cmd += ["-r", str(self.pcap_file), "-Y", f"tcp.port == {self.server_port}"]
        else:
            cmd += ["-i", self.interface_name, "-f", self.bpf_filter]
            if self.duration:
                cmd += ["-a", f"duration:{self.duration}"]
        for field in FIELDS:
            cmd += ["-e", field]
        return cmd

    def start(self):
        # Own process group, so Ctrl+C reaches only Python, which then stops Tshark itself.
        if os.name == "nt":
            group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        else:
            group = {"start_new_session": True}
        self._process = subprocess.Popen(
            self._command(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            **group,
        )

    def get_stream(self):
        if self._process is None:
            self.start()
        for line in self._process.stdout:
            record = self.parser.parse(line)
            if record is not None:
                yield record
        if self._process.wait() != 0:
            raise CaptureError(f"Tshark stopped with an error: {self._process.stderr.read().strip()}")

    def stop(self):
        if self._process and self._process.poll() is None:
            self._process.terminate()
            self._process.wait(timeout=5)


def _print_record(r):
    marks = [name for name, on in (("SYN", r.is_syn), ("HELLO", r.tls_handshake), ("REQ", r.is_request)) if on]
    print(
        f"{r.timestamp}  {r.src_ip}:{r.src_port} -> {r.dst_ip}:{r.dst_port}  "
        f"{r.packet_length:>5}B  {r.protocol:3}  {r.tcp_flags:9}  {' '.join(marks):14} {r.sni}"
    )


def main():
    ap = argparse.ArgumentParser(description="Show the packets the analyzer sees.")
    ap.add_argument("-i", "--interface", help="interface name or number from --list-interfaces")
    ap.add_argument("-r", "--read", help="read a saved .pcap/.pcapng file instead of capturing live")
    ap.add_argument("-c", "--count", type=int, default=0, help="stop after this many packets")
    ap.add_argument("-p", "--port", type=int, default=443, help="server port to watch (default 443)")
    ap.add_argument("-d", "--duration", type=int, help="stop a live capture after this many seconds")
    ap.add_argument("--list-interfaces", action="store_true")
    args = ap.parse_args()

    if args.list_interfaces:
        print(list_interfaces())
        return
    if not args.interface and not args.read:
        ap.error("give -i INTERFACE or -r FILE")

    capture = PacketCapture(args.interface, args.read, args.port, args.duration)
    seen = 0
    try:
        for record in capture.get_stream():
            _print_record(record)
            seen += 1
            if args.count and seen >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop()
    print(f"{seen} packets")


if __name__ == "__main__":
    main()
