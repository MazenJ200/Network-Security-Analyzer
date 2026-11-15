import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from analyzer import dashboard_data as dd
from analyzer.dashboard import make_server

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



@pytest.fixture
def server(logs):
    srv = make_server(logs, ROOT / "signatures", port=0)
    thread = threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def get(url):
    try:
        with urllib.request.urlopen(url) as response:
            return response.status, response.headers["Content-Type"], response.read()
    except urllib.error.HTTPError as err:
        return err.code, err.headers["Content-Type"], err.read()


def get_json(url):
    status, _, body = get(url)
    return status, json.loads(body)


def test_page_is_served(server):
    status, content_type, body = get(server + "/")
    assert status == 200 and content_type.startswith("text/html")
    assert b"<title>Network Security Analyzer</title>" in body


def test_sessions_and_rules(server):
    assert get_json(server + "/api/sessions") == (200, {"sessions": [SESSION, "session_2026-11-15_001"]})
    status, data = get_json(server + "/api/rules")
    assert status == 200 and {"PRO-001", "APP-002", "VOL-001"} <= set(data["rules"])


def test_session_data(server):
    status, d = get_json(server + f"/api/session?name={SESSION}")
    assert status == 200
    assert (d["session"], d["seconds"], d["alerts_total"], d["alerts_critical"]) == (SESSION, 5, 3, 1)
    assert d["series"]["pps"] == [10, 20, 0, 0, 40]
    assert len(d["series"]["time"]) == 5 and d["series"]["time"][0] == T0
    assert d["top_sources"] == [["10.0.0.5", 40]]
    assert [a["triggered_signature_id"] for a in d["alerts"]] == ["PRO-003", "APP-001", "PRO-001"]
    assert set(d["rates"]) >= {"mbps", "pps", "rps", "syn_rate", "tls_handshake_rate"}


@pytest.mark.parametrize("query, expected", [
    ("severity=critical", ["PRO-001"]),
    ("severity=critical,high", ["PRO-003", "APP-001", "PRO-001"]),
    ("rule=APP-001", ["APP-001"]),
    ("q=shop", ["APP-001"]),
    ("severity=high&q=10.0.0.5", ["PRO-003"]),
    ("severity=low", []),
])
def test_alert_filters(server, query, expected):
    _, d = get_json(server + f"/api/session?name={SESSION}&{query}")
    assert [a["triggered_signature_id"] for a in d["alerts"]] == expected
    assert d["alerts_total"] == 3


def test_chart_range(server):
    _, d = get_json(server + f"/api/session?name={SESSION}&minutes=abc")
    assert len(d["series"]["time"]) == 5  # bad value falls back to 10 minutes


def test_empty_session(server):
    _, d = get_json(server + "/api/session?name=session_2026-11-15_001")
    assert (d["seconds"], d["alerts"], d["top_sources"], d["series"]["time"]) == (0, [], [], [])


@pytest.mark.parametrize("path", [
    "/api/session?name=../../signatures/volume_signatures",
    "/api/session?name=",
    "/api/session",
    "/static/index.html",
    "/../analyzer/dashboard.py",
])
def test_unknown_paths_and_sessions_are_refused(server, path):
    status, content_type, _ = get(server + path)
    assert status == 404 and content_type == "application/json"


def test_no_sessions_yet(tmp_path):
    srv = make_server(tmp_path, ROOT / "signatures", port=0)
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    try:
        assert get_json(f"http://127.0.0.1:{srv.server_address[1]}/api/sessions") == (200, {"sessions": []})
    finally:
        srv.shutdown()
        srv.server_close()


def test_live_chart_runs_on_to_now_as_zero(logs, monkeypatch):
    from analyzer import dashboard

    monkeypatch.setattr(dashboard, "is_live", lambda *_: True)
    monkeypatch.setattr(dashboard.time, "time", lambda: T0 + 9.5)
    d = dashboard.session_data(logs, SESSION)
    assert d["series"]["time"] == list(range(T0, T0 + 9))
    assert d["series"]["pps"] == [10, 20, 0, 0, 40, 0, 0, 0, 0]

    monkeypatch.setattr(dashboard.time, "time", lambda: T0 + 500)
    d = dashboard.session_data(logs, SESSION, minutes=1)
    assert len(d["series"]["time"]) == 60 and d["series"]["time"][-1] == T0 + 499
