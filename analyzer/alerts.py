"""Alerts: creation, terminal display and the JSON Lines alert log."""

import json
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Alert:
    log_id: str
    session_id: str
    alert_timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packet_length: int
    protocol: str
    tcp_flags: str
    tls_handshake: bool
    sni: str
    triggered_signature_id: str
    triggered_signature_name: str
    attack_category: str
    severity: str
    scope: str
    monitored_attribute: str
    observed_value: float
    threshold: float
    metric_bps: float
    metric_pps: float
    metric_rps: float
    status: str = "new"


def format_alert(alert):
    who = alert.src_ip if alert.scope == "per_source" else f"all sources (top: {alert.src_ip})"
    return (
        f"[ALERT] {alert.alert_timestamp}  {alert.severity.upper():8} {alert.triggered_signature_id} "
        f"{alert.triggered_signature_name} | {who} -> {alert.dst_ip}:{alert.dst_port} | "
        f"{alert.monitored_attribute} {alert.observed_value:,.1f}/s > {alert.threshold:,.0f}/s"
    )


class Logger:
    """Append-only alert log, one JSON object per line."""

    def __init__(self, log_path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, alert):
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(alert)) + "\n")

    def query(self, **filters):
        """Return logged alerts whose fields equal every given filter, e.g. query(severity="critical")."""
        if not self.log_path.exists():
            return []
        results = []
        with self.log_path.open(encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue  # a half-written last line after a crash
                if all(entry.get(key) == value for key, value in filters.items()):
                    results.append(entry)
        return results


class AlertGenerator:
    def __init__(self, session_id, logger=None, output=print):
        self.session_id = session_id
        self.logger = logger
        self.output = output

    def generate(self, packet, signature, observed, snapshot, src_ip):
        alert = Alert(
            log_id=str(uuid.uuid4()),
            session_id=self.session_id,
            alert_timestamp=packet.timestamp,
            src_ip=src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            packet_length=packet.packet_length,
            protocol=packet.protocol,
            tcp_flags=packet.tcp_flags,
            tls_handshake=packet.tls_handshake,
            sni=packet.sni,
            triggered_signature_id=signature.signature_id,
            triggered_signature_name=signature.name,
            attack_category=signature.attack_category,
            severity=signature.severity,
            scope=signature.scope,
            monitored_attribute=signature.monitored_attribute,
            observed_value=round(observed, 2),
            threshold=signature.threshold,
            metric_bps=round(snapshot.bps, 2),
            metric_pps=round(snapshot.pps, 2),
            metric_rps=round(snapshot.rps, 2),
        )
        self.save(alert)
        self.display(alert)
        return alert

    def display(self, alert):
        self.output(format_alert(alert))

    def save(self, alert):
        if self.logger:
            self.logger.append(alert)
