"""Read session files (alerts and per-second metrics) for the dashboard."""

import json
import time
from datetime import datetime
from pathlib import Path

import pandas as pd

RATES = ["bps", "pps", "rps", "syn_rate", "tls_handshake_rate"]
SEVERITIES = ["critical", "high", "medium", "low"]
LIVE_MAX_AGE_SEC = 10
LOCAL_TZ = datetime.now().astimezone().tzinfo


def list_sessions(logs_dir):
    """Session names (file stems), newest first."""
    files = Path(logs_dir).glob("session_*.jsonl")
    return sorted((p.stem for p in files if not p.stem.endswith("_metrics")), reverse=True)


def read_jsonl(path):
    path = Path(path)
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # the analyzer may be halfway through writing the last line
    return rows


def load_metrics(logs_dir, session):
    """One row per second; seconds the analyzer did not write (no traffic) are filled with zero."""
    rows = read_jsonl(Path(logs_dir) / f"{session}_metrics.jsonl")
    if not rows:
        return pd.DataFrame(columns=RATES + ["mbps", "top_sources"])

    df = pd.DataFrame(rows)
    df["second"] = df["time"].astype(int)
    df = df.drop_duplicates("second", keep="last").set_index("second")
    df = df.reindex(range(df.index.min(), df.index.max() + 1))
    df[RATES] = df[RATES].fillna(0.0)
    df["top_sources"] = df["top_sources"].apply(lambda v: v if isinstance(v, list) else [])
    df["mbps"] = df["bps"] / 1e6
    df.index = pd.to_datetime(df.index, unit="s", utc=True).tz_convert(LOCAL_TZ)
    df.index.name = "time"
    return df


def load_alerts(logs_dir, session):
    """All alerts of a session, newest first."""
    rows = read_jsonl(Path(logs_dir) / f"{session}.jsonl")
    if not rows:
        return pd.DataFrame(columns=["time", "severity", "triggered_signature_id", "src_ip"])
    df = pd.DataFrame(rows)
    df["time"] = pd.to_datetime(df["alert_timestamp"], utc=True).dt.tz_convert(LOCAL_TZ)
    return df.sort_values("time", ascending=False, ignore_index=True)


def filter_alerts(alerts, severities=None, rules=None, search=""):
    if severities:
        alerts = alerts[alerts["severity"].isin(severities)]
    if rules:
        alerts = alerts[alerts["triggered_signature_id"].isin(rules)]
    if search and not alerts.empty:
        text = search.strip().lower()
        columns = ["src_ip", "dst_ip", "sni", "triggered_signature_id", "triggered_signature_name"]
        hit = alerts[columns].astype(str).apply(lambda col: col.str.lower().str.contains(text, regex=False))
        alerts = alerts[hit.any(axis=1)]
    return alerts


def is_live(logs_dir, session, now=None):
    """True if the session's metrics file was written in the last few seconds."""
    path = Path(logs_dir) / f"{session}_metrics.jsonl"
    return path.exists() and (now or time.time()) - path.stat().st_mtime < LIVE_MAX_AGE_SEC


def current_rates(metrics, live, now=None, window_sec=5):
    """Latest rates; a live session that has been quiet for a whole window reads as zero."""
    if metrics.empty:
        return dict.fromkeys(RATES + ["mbps"], 0.0)
    last = metrics.iloc[-1]
    if live and (now or time.time()) - metrics.index[-1].timestamp() > window_sec:
        return dict.fromkeys(RATES + ["mbps"], 0.0)
    return {key: float(last[key]) for key in RATES + ["mbps"]}
