"""Run the analyzer: python -m analyzer -i Wi-Fi"""

import argparse
import sys

from analyzer.capture import CaptureError, list_interfaces
from analyzer.session import MonitoringSession
from analyzer.signatures import SignatureError


def main():
    ap = argparse.ArgumentParser(prog="python -m analyzer", description="Rule-based DDoS detection for HTTPS traffic.")
    ap.add_argument("-i", "--interface", help="interface name or number from --list-interfaces")
    ap.add_argument("-r", "--read", help="analyze a saved .pcap/.pcapng file instead of live traffic")
    ap.add_argument("-p", "--port", type=int, default=443, help="server port to protect (default 443)")
    ap.add_argument("-d", "--duration", type=int, help="stop a live capture after this many seconds")
    ap.add_argument("--signatures", default="signatures", help="folder with *_signatures.json (default signatures)")
    ap.add_argument("--logs", default="logs", help="folder for session logs (default logs)")
    ap.add_argument("--cooldown", type=int, default=30, help="seconds between repeat alerts for one rule (default 30)")
    ap.add_argument("--stats", type=int, default=5, help="print traffic rates every N seconds, 0 to turn off (default 5)")
    ap.add_argument("--list-interfaces", action="store_true")
    args = ap.parse_args()

    if args.list_interfaces:
        print(list_interfaces())
        return 0
    if not args.interface and not args.read:
        ap.error("give -i INTERFACE or -r FILE")

    session = MonitoringSession(args.interface, args.read, args.port, args.signatures, args.logs,
                                args.duration, args.cooldown, args.stats)
    try:
        session.start()
    except (SignatureError, CaptureError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
