"""Streamlit dashboard. Run: streamlit run dashboard.py   (other logs folder: streamlit run dashboard.py -- --logs PATH)"""

import argparse
import os
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from analyzer.dashboard_data import (
    SEVERITIES, current_rates, filter_alerts, is_live, list_sessions, load_alerts, load_metrics,
)
from analyzer.signatures import SignatureError, SignatureLoader

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument("--logs", default=os.environ.get("ANALYZER_LOGS", HERE / "logs"))
parser.add_argument("--signatures", default=HERE / "signatures")
ARGS = parser.parse_known_args()[0]
LOGS = ARGS.logs


def line_chart(data, columns, names):
    """Plain line chart; Streamlit's own charts zoom on mouse scroll, which hijacks page scrolling."""
    if data.empty:
        st.caption("No traffic recorded yet.")
        return
    long = data[columns].rename(columns=dict(zip(columns, names))).reset_index()
    long = long.melt("time", var_name="Series", value_name="Value")
    chart = alt.Chart(long).mark_line().encode(
        x=alt.X("time:T", title=None, axis=alt.Axis(format="%H:%M:%S")),
        y=alt.Y("Value:Q", title=None, scale=alt.Scale(zero=True)),
        color=alt.Color("Series:N", legend=alt.Legend(orient="bottom", title=None)),
    )
    st.altair_chart(chart.properties(height=220), width="stretch")


def rule_ids(session):
    """Every rule in the signature files, plus any rule seen in this session's alerts."""
    seen = set(load_alerts(LOGS, session)["triggered_signature_id"])
    try:
        seen |= {s.signature_id for s in SignatureLoader(ARGS.signatures).load()}
    except SignatureError:
        pass
    return sorted(seen)

st.set_page_config(page_title="Network Security Analyzer", layout="wide")
st.title("Network Security Analyzer")

sessions = list_sessions(LOGS)
if not sessions:
    st.info(f"No sessions in `{LOGS}` yet. Start one with: `python -m analyzer -i <interface>`")
    st.stop()

with st.sidebar:
    session = st.selectbox("Session", sessions)
    minutes = st.slider("Chart range (minutes)", 1, 60, 10)
    refresh = st.toggle("Auto-refresh every 2 seconds", value=True)
    st.subheader("Alert filters")
    severities = st.multiselect("Severity", SEVERITIES)
    rules = st.multiselect("Rule", rule_ids(session))
    search = st.text_input("Search IP, site or rule")


@st.fragment(run_every=2 if refresh else None)
def live_view():
    metrics = load_metrics(LOGS, session)
    alerts = load_alerts(LOGS, session)
    live = is_live(LOGS, session)
    rates = current_rates(metrics, live)

    st.caption(f"{session}  ·  {'LIVE' if live else 'not running'}  ·  {len(metrics)} seconds of data")

    row1, row2 = st.columns(3), st.columns(3)
    row1[0].metric("Bandwidth (Mbps)", f"{rates['mbps']:.2f}")
    row1[1].metric("Packets/s", f"{rates['pps']:,.0f}")
    row1[2].metric("Requests/s", f"{rates['rps']:,.1f}")
    row2[0].metric("SYN/s", f"{rates['syn_rate']:,.1f}")
    row2[1].metric("Handshakes/s", f"{rates['tls_handshake_rate']:,.1f}")
    critical = int((alerts["severity"] == "critical").sum())
    row2[2].metric("Alerts", len(alerts), f"{critical} critical" if critical else None, delta_color="inverse")

    recent = metrics.tail(minutes * 60)
    left, right = st.columns(2)
    with left:
        st.subheader("Bandwidth (Mbps)")
        line_chart(recent, ["mbps"], ["Mbps"])
        st.subheader("SYN and TLS handshakes per second")
        line_chart(recent, ["syn_rate", "tls_handshake_rate"], ["SYN/s", "Handshakes/s"])
    with right:
        st.subheader("Packets and requests per second")
        line_chart(recent, ["pps", "rps"], ["Packets/s", "Requests/s"])
        st.subheader("Top source IPs (packets/s)")
        top = metrics["top_sources"].iloc[-1] if not metrics.empty else []
        st.dataframe(pd.DataFrame(top, columns=["Source IP", "Packets/s"]), hide_index=True, width="stretch")

    shown = filter_alerts(alerts, severities, rules, search)
    st.subheader(f"Alerts ({len(shown)} of {len(alerts)})")
    if shown.empty:
        st.write("No alerts match." if len(alerts) else "No alerts in this session.")
    else:
        table = pd.DataFrame({
            "Time": shown["time"].dt.strftime("%Y-%m-%d %H:%M:%S"),
            "Severity": shown["severity"].str.upper(),
            "Rule": shown["triggered_signature_id"],
            "Name": shown["triggered_signature_name"],
            "Source": shown["src_ip"],
            "Scope": shown["scope"],
            "Measured": shown["monitored_attribute"] + " " + shown["observed_value"].map("{:,.1f}/s".format),
            "Threshold": shown["threshold"].map("{:,.0f}/s".format),
            "Site (SNI)": shown["sni"],
            "Status": shown["status"],
        })
        st.dataframe(table, hide_index=True, width="stretch")


live_view()
