from pathlib import Path

import pytest

from analyzer.capture import FIELDS, CaptureError, PacketCapture, TrafficParser, find_tshark

SAMPLE = Path(__file__).resolve().parent / "data" / "sample_https.pcapng"


def tshark_line(**values):
    defaults = {
        "frame.time_epoch": "1794762103.828352000",
        "ip.src": "10.0.0.5",
        "ip.dst": "10.0.0.1",
        "tcp.srcport": "50000",
        "tcp.dstport": "443",
        "frame.len": "60",
        "tcp.len": "0",
        "tcp.flags": "0x0010",
    }
    defaults.update(values)
    return "\t".join(defaults.get(field, "") for field in FIELDS) + "\r\n"


parser = TrafficParser(server_port=443)


def test_syn_packet():
    r = parser.parse(tshark_line(**{"tcp.flags": "0x0002"}))
    assert r.is_syn and r.tcp_flags == "SYN" and r.protocol == "TCP"
    assert not r.tls_handshake and not r.is_request


def test_syn_ack_is_not_a_new_connection():
    r = parser.parse(tshark_line(**{"tcp.flags": "0x0012"}))
    assert r.tcp_flags == "SYN,ACK" and not r.is_syn


def test_client_hello_with_sni():
    r = parser.parse(
        tshark_line(**{
            "tcp.len": "452",
            "tcp.flags": "0x0018",
            "tls.record.content_type": "22",
            "tls.handshake.type": "1",
            "tls.handshake.extensions_server_name": "testsite.local",
        })
    )
    assert r.tls_handshake and r.sni == "testsite.local" and r.protocol == "TLS"
    assert not r.is_request


def test_encrypted_request_counts():
    r = parser.parse(tshark_line(**{"tcp.len": "100", "tls.record.opaque_type": "23"}))
    assert r.is_request


def test_handshake_finish_is_not_a_request():
    r = parser.parse(
        tshark_line(**{"tcp.len": "80", "tls.record.content_type": "20", "tls.record.opaque_type": "23"})
    )
    assert not r.is_request


def test_small_encrypted_alert_is_not_a_request():
    r = parser.parse(tshark_line(**{"tcp.len": "24", "tls.record.opaque_type": "23"}))
    assert not r.is_request


def test_server_reply_is_not_a_request():
    r = parser.parse(
        tshark_line(**{"tcp.srcport": "443", "tcp.dstport": "50000", "tcp.len": "500", "tls.record.opaque_type": "23"})
    )
    assert not r.is_request


def test_ipv6_addresses():
    r = parser.parse(tshark_line(**{"ip.src": "", "ip.dst": "", "ipv6.src": "fe80::1", "ipv6.dst": "fe80::2"}))
    assert (r.src_ip, r.dst_ip) == ("fe80::1", "fe80::2")


def test_timestamp_is_iso_utc():
    r = parser.parse(tshark_line())
    assert r.timestamp == "2026-11-15T17:01:43.828Z"


@pytest.mark.parametrize("line", ["", "garbage", tshark_line(**{"tcp.srcport": "abc"}), tshark_line(**{"ip.src": ""})])
def test_bad_lines_are_skipped(line):
    assert parser.parse(line) is None


def test_needs_exactly_one_source():
    with pytest.raises(ValueError):
        PacketCapture()
    with pytest.raises(ValueError):
        PacketCapture(interface_name="Wi-Fi", pcap_file="x.pcapng")


def test_live_command_uses_capture_filter_and_duration(monkeypatch):
    monkeypatch.setattr("analyzer.capture.find_tshark", lambda: "tshark")
    cmd = PacketCapture(interface_name="Wi-Fi", duration=10)._command()
    assert cmd[cmd.index("-f") + 1] == "tcp port 443"
    assert cmd[cmd.index("-a") + 1] == "duration:10"
    assert "-a" not in PacketCapture(interface_name="Wi-Fi")._command()


def tshark_installed():
    try:
        find_tshark()
        return True
    except CaptureError:
        return False


@pytest.mark.skipif(not tshark_installed(), reason="Tshark is not installed")
def test_sample_capture_file():
    records = list(PacketCapture(pcap_file=SAMPLE).get_stream())
    assert len(records) == 113
    assert sum(r.is_syn for r in records) == 5
    assert sum(r.tls_handshake for r in records) == 5
    assert sum(r.is_request for r in records) == 5
    assert {r.sni for r in records if r.tls_handshake} == {"testsite.local"}
