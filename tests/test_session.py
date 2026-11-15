import json
import os
import shutil
from pathlib import Path

import pytest

from analyzer.session import MonitoringSession, next_session_number
from analyzer.signatures import SignatureError
from tests.test_capture import tshark_installed

DATA = Path(__file__).resolve().parent / "data"
REPO_SIGNATURES = Path(__file__).resolve().parent.parent / "signatures"
needs_tshark = pytest.mark.skipif(not tshark_installed(), reason="Tshark is not installed")

LOW_RULE = [{
    "signature_id": "TST-001", "name": "Any handshakes", "attack_category": "application",
    "monitored_attribute": "tls_handshake_rate", "threshold": 0.5, "time_window_sec": 5, "severity": "low",
}]


def write_rules(folder, rules):
    folder.mkdir(exist_ok=True)
    (folder / "application_signatures.json").write_text(json.dumps(rules), encoding="utf-8")


def run_on_sample(tmp_path, signatures):
    printed = []
    session = MonitoringSession(pcap_file=DATA / "sample_https.pcapng", signatures_path=signatures,
                                logs_dir=tmp_path / "logs", output=printed.append)
    session.start()
    return session, printed


def test_session_numbers_count_up(tmp_path):
    assert next_session_number(tmp_path, "2026-11-15") == 1
    (tmp_path / "session_2026-11-15_001.jsonl").touch()
    (tmp_path / "session_2026-11-15_001_metrics.jsonl").touch()
    (tmp_path / "session_2026-11-15_007.jsonl").touch()
    (tmp_path / "session_2026-11-14_009.jsonl").touch()
    assert next_session_number(tmp_path, "2026-11-15") == 8


@needs_tshark
def test_quiet_sample_raises_no_alerts(tmp_path):
    session, printed = run_on_sample(tmp_path, REPO_SIGNATURES)
    assert session.status == "stopped"
    assert session.packets == 113 and session.alerts == []
    assert session.alert_log.exists() and session.alert_log.read_text() == ""
    assert session.session_id.endswith("-001")
    assert "113 packets, 0 alerts" in printed[-1]

    metrics = [json.loads(line) for line in session.metrics_log.read_text().splitlines()]
    assert metrics and set(metrics[-1]) >= {"time", "bps", "pps", "rps", "syn_rate", "top_sources"}
    assert metrics[-1]["top_sources"][0][0] == "127.0.0.1"


@needs_tshark
def test_sample_with_a_low_rule_logs_an_alert(tmp_path):
    write_rules(tmp_path / "rules", LOW_RULE)
    session, printed = run_on_sample(tmp_path, tmp_path / "rules")
    assert [a.triggered_signature_id for a in session.alerts] == ["TST-001"]
    logged = json.loads(session.alert_log.read_text().splitlines()[0])
    assert logged["session_id"] == session.session_id
    assert logged["sni"] == "testsite.local"
    assert any("[ALERT]" in line for line in printed)
    assert "(TST-001 x1)" in printed[-1]

    second, _ = run_on_sample(tmp_path, tmp_path / "rules")
    assert second.session_id.endswith("-002")


def test_bad_signatures_stop_before_any_files(tmp_path):
    write_rules(tmp_path / "rules", [{"signature_id": "BAD"}])
    session = MonitoringSession(pcap_file=DATA / "sample_https.pcapng", signatures_path=tmp_path / "rules",
                                logs_dir=tmp_path / "logs", output=lambda _: None)
    with pytest.raises(SignatureError):
        session.start()
    assert session.status == "idle"
    assert not (tmp_path / "logs").exists()


@needs_tshark
def test_signature_reload(tmp_path):
    rules = tmp_path / "rules"
    shutil.copytree(REPO_SIGNATURES, rules)
    session, printed = run_on_sample(tmp_path, rules)
    session.status = "capturing"  # pretend it is still running

    assert session.reload_signatures_if_changed() is False

    path = rules / "application_signatures.json"
    path.write_text(json.dumps(LOW_RULE), encoding="utf-8")
    os.utime(path, (1, 1))
    assert session.reload_signatures_if_changed() is True
    assert {s.signature_id for s in session.engine.signatures} >= {"TST-001", "PRO-001"}

    path.write_text("not json", encoding="utf-8")
    os.utime(path, (2, 2))
    assert session.reload_signatures_if_changed() is False
    assert "keeping the old rules" in printed[-1]
    assert "TST-001" in {s.signature_id for s in session.engine.signatures}
