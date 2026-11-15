"""Detection engine: compares live traffic rates against the signatures and raises alerts."""


class DetectionEngine:
    def __init__(self, signatures, metrics, alert_generator, cooldown_sec=30):
        self.metrics = metrics
        self.alert_generator = alert_generator
        self.cooldown_sec = cooldown_sec
        self._last_alert = {}  # (signature_id, source IP or None) -> packet time of the last alert
        self.set_signatures(signatures)

    def set_signatures(self, signatures):
        too_long = [s.signature_id for s in signatures if s.time_window_sec > self.metrics.window_sec]
        if too_long:
            raise ValueError(f"window longer than the {self.metrics.window_sec}s kept by metrics: {', '.join(too_long)}")
        self.signatures = list(signatures)

    def evaluate(self, packet):
        """Check every rule against current rates (call after metrics.update) and return new alerts."""
        if packet.dst_port != self.metrics.server_port:
            return []

        alerts = []
        for sig in self.signatures:
            src = packet.src_ip if sig.scope == "per_source" else None
            observed = self.metrics.rate(sig.monitored_attribute, sig.time_window_sec, src)
            if observed <= sig.threshold:
                continue

            # One alert when a rule starts matching, then at most one per cooldown while it keeps matching.
            key = (sig.signature_id, src)
            last = self._last_alert.get(key)
            if last is not None and packet.time - last < self.cooldown_sec:
                continue
            self._last_alert[key] = packet.time

            offender = src
            if offender is None:
                top = self.metrics.top_sources(1, sig.monitored_attribute)
                offender = top[0][0] if top else packet.src_ip
            snapshot = self.metrics.get_snapshot(src)
            alerts.append(self.alert_generator.generate(packet, sig, observed, snapshot, offender))
        return alerts
