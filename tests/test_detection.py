from pathlib import Path

import pytest

from analyzer.alerts import AlertGenerator, Logger
from analyzer.detection import DetectionEngine
from analyzer.metrics import MetricAggregator
from analyzer.signatures import Signature, SignatureLoader
from tests.test_metrics import T0, packet

REPO_SIGNATURES = Path(__file__).resolve().parent.parent / "signatures"


def rule(sig_id="TST-001", attribute="syn_rate", threshold=10, scope="per_source", window=5):
    return Signature(sig_id, "Test rule", "protocol", attribute, threshold, window, "high", scope)


def setup(signatures, tmp_path=None, cooldown=30):
    metrics = MetricAggregator(window_sec=5)
    printed = []
    logger = Logger(tmp_path / "alerts.jsonl") if tmp_path else None
    generator = AlertGenerator("session-test", logger, output=printed.append)
    return metrics, DetectionEngine(signatures, metrics, generator, cooldown), printed


def feed(metrics, engine, packets):
    alerts = []
    for p in packets:
        metrics.update(p)
        alerts += engine.evaluate(p)
    return alerts


def syn_flood(src, per_second, seconds, start=T0):
    return [packet(start + i / per_second, src=src, syn=True) for i in range(per_second * seconds)]


def test_normal_traffic_raises_nothing():
    metrics, engine, printed = setup([rule(threshold=10)])
    assert feed(metrics, engine, syn_flood("10.0.0.5", per_second=5, seconds=5)) == []
    assert printed == []


def test_flood_raises_one_alert_then_waits_for_the_cooldown():
    metrics, engine, printed = setup([rule(threshold=10)], cooldown=30)
    alerts = feed(metrics, engine, syn_flood("10.0.0.5", per_second=100, seconds=10))
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.src_ip, a.triggered_signature_id, a.severity, a.scope) == ("10.0.0.5", "TST-001", "high", "per_source")
    assert a.observed_value > 10
    assert "TST-001" in printed[0] and "10.0.0.5" in printed[0]

    alerts = feed(metrics, engine, syn_flood("10.0.0.5", per_second=100, seconds=25, start=T0 + 10))
    assert len(alerts) == 1  # still attacking 30 s after the first alert


def test_each_source_gets_its_own_alert():
    metrics, engine, _ = setup([rule(threshold=10)])
    flood = syn_flood("10.0.0.5", 50, 3) + syn_flood("10.0.0.6", 50, 3)
    alerts = feed(metrics, engine, sorted(flood, key=lambda p: p.time))
    assert sorted(a.src_ip for a in alerts) == ["10.0.0.5", "10.0.0.6"]


def test_global_rule_catches_a_distributed_attack():
    rules = [rule("PER-1", threshold=10), rule("ALL-1", threshold=50, scope="global")]
    metrics, engine, printed = setup(rules)
    flood = []
    for n in range(20):
        flood += syn_flood(f"10.0.1.{n}", per_second=5 + (n == 7), seconds=5)
    alerts = feed(metrics, engine, sorted(flood, key=lambda p: p.time))
    assert [a.triggered_signature_id for a in alerts] == ["ALL-1"]
    assert alerts[0].src_ip == "10.0.1.7"  # the busiest source is named
    assert "all sources" in printed[0]


def test_server_replies_raise_nothing():
    metrics, engine, _ = setup([rule("BW-1", attribute="bps", threshold=1000)])
    replies = [packet(T0 + i / 100, length=1500, dst_port=50000) for i in range(500)]
    assert feed(metrics, engine, replies) == []


def test_alerts_are_logged_as_json_lines(tmp_path):
    metrics, engine, _ = setup([rule(threshold=10)], tmp_path)
    feed(metrics, engine, syn_flood("10.0.0.5", 100, 2) + syn_flood("10.0.0.6", 100, 2, start=T0 + 2))
    logger = Logger(tmp_path / "alerts.jsonl")
    lines = (tmp_path / "alerts.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    entry = logger.query(src_ip="10.0.0.6")[0]
    assert entry["session_id"] == "session-test"
    assert entry["triggered_signature_id"] == "TST-001"
    assert entry["status"] == "new"
    assert len(logger.query(severity="high")) == 2
    assert logger.query(severity="critical") == []


def test_query_skips_a_half_written_line(tmp_path):
    log = tmp_path / "alerts.jsonl"
    log.write_text('{"severity": "high"}\n{"severity": "hi', encoding="utf-8")
    assert Logger(log).query() == [{"severity": "high"}]
    assert Logger(tmp_path / "missing.jsonl").query() == []


def test_rule_window_must_fit_in_the_metrics_window():
    with pytest.raises(ValueError, match="TST-001"):
        setup([rule(window=10)])


def test_repo_rules_catch_a_syn_flood():
    metrics, engine, _ = setup(SignatureLoader(REPO_SIGNATURES).load())
    alerts = feed(metrics, engine, syn_flood("10.0.0.66", per_second=200, seconds=5))
    assert [(a.triggered_signature_id, a.severity) for a in alerts] == [("PRO-001", "critical")]
