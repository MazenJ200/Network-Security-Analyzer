import json
import os
from pathlib import Path

import pytest

from analyzer import dashboard_data as dd

ROOT = Path(__file__).resolve().parent.parent
T0 = 1_800_000_000
SESSION = "session_2026-11-15_002"


def alert(sig="PRO-001", severity="critical", src="10.0.0.5", sni="", seconds=0):
    return {
        "alert_timestamp": f"2027-01-15T08:00:{seconds:02d}.000Z", "severity": severity,
        "triggered_signature_id": sig, "triggered_signature_name": "SYN Flood", "src_ip": src,
        "dst_ip": "10.0.0.1", "dst_port": 443, "sni": sni, "scope": "per_source",
        "monitored_attribute": "syn_rate", "observed_value": 150.0, "threshold": 100.0, "status": "new",
    }


def metric(t, pps):
    return {"time": t, "bps": pps * 800, "pps": pps, "rps": pps / 10, "syn_rate": 1.0,
            "tls_handshake_rate": 1.0, "top_sources": [["10.0.0.5", pps]]}


@pytest.fixture
def logs(tmp_path):
    (tmp_path / "session_2026-11-15_001.jsonl").write_text("", encoding="utf-8")
    (tmp_path / "session_2026-11-15_001_metrics.jsonl").write_text("", encoding="utf-8")
    alerts = [alert(), alert("APP-001", "high", "10.0.0.6", "shop.local", 5), alert("PRO-003", "high", seconds=9)]
    (tmp_path / f"{SESSION}.jsonl").write_text("\n".join(map(json.dumps, alerts)) + "\n", encoding="utf-8")
    lines = [metric(T0 + 0.5, 10), metric(T0 + 1.5, 20), metric(T0 + 4.2, 40)]
    (tmp_path / f"{SESSION}_metrics.jsonl").write_text(
        "\n".join(map(json.dumps, lines)) + '\n{"time": 18', encoding="utf-8")
    return tmp_path


def test_sessions_newest_first(logs):
    assert dd.list_sessions(logs) == [SESSION, "session_2026-11-15_001"]
    assert dd.list_sessions(logs / "missing") == []


def test_metrics_fill_quiet_seconds_with_zero(logs):
    m = dd.load_metrics(logs, SESSION)
    assert list(m["pps"]) == [10, 20, 0, 0, 40]
    assert m["mbps"].iloc[-1] == 40 * 800 / 1e6
    assert m["top_sources"].iloc[2] == []
    assert m.index[0].timestamp() == T0


def test_empty_session(logs):
    m = dd.load_metrics(logs, "session_2026-11-15_001")
    assert m.empty
    assert dd.current_rates(m, live=True)["pps"] == 0.0
    assert dd.load_alerts(logs, "session_2026-11-15_001").empty


def test_alerts_newest_first_and_filters(logs):
    a = dd.load_alerts(logs, SESSION)
    assert list(a["triggered_signature_id"]) == ["PRO-003", "APP-001", "PRO-001"]
    assert len(dd.filter_alerts(a, severities=["critical"])) == 1
    assert len(dd.filter_alerts(a, rules=["APP-001", "PRO-003"])) == 2
    assert list(dd.filter_alerts(a, search="SHOP")["src_ip"]) == ["10.0.0.6"]
    assert list(dd.filter_alerts(a, search="10.0.0.5")["triggered_signature_id"]) == ["PRO-003", "PRO-001"]
    assert dd.filter_alerts(a, severities=["low"]).empty


def test_live_and_current_rates(logs):
    m = dd.load_metrics(logs, SESSION)
    mtime = (logs / f"{SESSION}_metrics.jsonl").stat().st_mtime
    assert dd.is_live(logs, SESSION, now=mtime + 3)
    assert not dd.is_live(logs, SESSION, now=mtime + 60)
    assert dd.current_rates(m, live=True, now=T0 + 5)["pps"] == 40
    assert dd.current_rates(m, live=True, now=T0 + 30)["pps"] == 0.0  # quiet for a whole window
    assert dd.current_rates(m, live=False, now=T0 + 30)["pps"] == 40  # ended session shows its last values


def test_page_renders(logs, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("ANALYZER_LOGS", str(logs))
    monkeypatch.chdir(ROOT)
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=30).run()
    assert not app.exception
    assert app.title[0].value == "Network Security Analyzer"
    assert app.sidebar.selectbox[0].value == SESSION
    assert [m.label for m in app.metric][:3] == ["Bandwidth (Mbps)", "Packets/s", "Requests/s"]
    assert any(s.value == "Alerts (3 of 3)" for s in app.subheader)

    app.sidebar.multiselect[0].select("critical").run()
    assert not app.exception
    assert any(s.value == "Alerts (1 of 3)" for s in app.subheader)


def test_page_without_sessions(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("ANALYZER_LOGS", str(tmp_path))
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=30).run()
    assert not app.exception
    assert "No sessions" in app.info[0].value


def test_page_with_a_session_that_has_no_traffic_yet(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    (tmp_path / "session_2026-11-15_001.jsonl").touch()
    (tmp_path / "session_2026-11-15_001_metrics.jsonl").touch()
    monkeypatch.setenv("ANALYZER_LOGS", str(tmp_path))
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=30).run()
    assert not app.exception
    assert any("No traffic recorded yet" in c.value for c in app.caption)
    assert "PRO-001" in app.sidebar.multiselect[1].options  # rule list comes from the signature files
