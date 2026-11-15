from pathlib import Path

import pytest

from analyzer.capture import PacketCapture, PacketRecord
from analyzer.metrics import MetricAggregator
from tests.test_capture import tshark_installed

SAMPLE = Path(__file__).resolve().parent / "data" / "sample_https.pcapng"
T0 = 1_800_000_000


def packet(time, src="10.0.0.5", length=100, syn=False, hello=False, request=False, dst_port=443):
    return PacketRecord(
        time=time, timestamp="", src_ip=src, dst_ip="10.0.0.1", src_port=50000, dst_port=dst_port,
        packet_length=length, protocol="TCP", tcp_flags="", is_syn=syn, tls_handshake=hello,
        is_request=request, sni="",
    )


def test_rates_are_averaged_over_the_window():
    m = MetricAggregator(window_sec=5)
    for i in range(10):
        m.update(packet(T0 + 0.1 * i, length=125, request=True))
    assert m.get_pps() == 2.0  # 10 packets / 5 s
    assert m.get_bps() == 2000.0  # 10 * 125 bytes * 8 bits / 5 s
    assert m.get_rps() == 2.0


def test_shorter_window():
    m = MetricAggregator(window_sec=5)
    m.update(packet(T0))
    m.update(packet(T0 + 4))
    assert m.rate("pps", window_sec=1) == 1.0
    assert m.rate("pps", window_sec=5) == 0.4


def test_old_traffic_leaves_the_window():
    m = MetricAggregator(window_sec=5)
    for i in range(50):
        m.update(packet(T0 + i * 0.01, syn=True))
    assert m.rate("syn_rate") == 10.0
    m.update(packet(T0 + 5))
    assert m.rate("syn_rate") == 0.0
    assert m.get_pps() == 0.2


def test_per_source_and_global():
    m = MetricAggregator(window_sec=5)
    for i in range(20):
        m.update(packet(T0 + i * 0.01, src="10.0.0.5", hello=True))
    for i in range(5):
        m.update(packet(T0 + i * 0.01, src="10.0.0.6", hello=True))
    assert m.rate("tls_handshake_rate", src_ip="10.0.0.5") == 4.0
    assert m.rate("tls_handshake_rate", src_ip="10.0.0.6") == 1.0
    assert m.rate("tls_handshake_rate") == 5.0
    assert m.top_sources(1) == [("10.0.0.5", 4.0)]


def test_quiet_sources_are_forgotten():
    m = MetricAggregator(window_sec=5)
    m.update(packet(T0, src="10.0.0.9"))
    m.update(packet(T0 + 10, src="10.0.0.5"))
    assert m.sources() == ["10.0.0.5"]
    assert m.get_pps(src_ip="10.0.0.9") == 0.0


def test_server_replies_are_not_counted():
    m = MetricAggregator(window_sec=5)
    m.update(packet(T0, length=1500, dst_port=50000))
    assert m.get_bps() == 0.0
    assert m.sources() == []


def test_late_packet_outside_the_window_is_ignored():
    m = MetricAggregator(window_sec=5)
    m.update(packet(T0 + 10))
    m.update(packet(T0))
    assert m.get_pps() == 0.2


def test_snapshot():
    m = MetricAggregator(window_sec=5)
    m.update(packet(T0 + 1.5, syn=True))
    s = m.get_snapshot()
    assert (s.time, s.pps, s.syn_rate, s.rps) == (T0 + 1.5, 0.2, 0.2, 0.0)


def test_bad_arguments():
    m = MetricAggregator(window_sec=5)
    with pytest.raises(ValueError):
        m.rate("cpu")
    with pytest.raises(ValueError):
        m.rate("pps", window_sec=10)


@pytest.mark.skipif(not tshark_installed(), reason="Tshark is not installed")
def test_sample_capture_rates():
    m = MetricAggregator(window_sec=5)
    for record in PacketCapture(pcap_file=SAMPLE).get_stream():
        m.update(record)
    # 5 requests, 5 SYNs and 5 handshakes, all inside one 5-second window
    assert m.get_rps() == 1.0
    assert m.rate("syn_rate") == 1.0
    assert m.rate("tls_handshake_rate") == 1.0
    assert m.sources() == ["127.0.0.1"]
