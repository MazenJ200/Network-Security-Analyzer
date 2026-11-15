"""Load and validate the JSON detection rules in signatures/*_signatures.json."""

import json
from dataclasses import dataclass
from pathlib import Path

CATEGORIES = {"volume", "protocol", "application"}
ATTRIBUTES = {"bps", "pps", "rps", "syn_rate", "tls_handshake_rate"}
SEVERITIES = {"low", "medium", "high", "critical"}
SCOPES = {"per_source", "global"}

REQUIRED_FIELDS = (
    "signature_id",
    "name",
    "attack_category",
    "monitored_attribute",
    "threshold",
    "time_window_sec",
    "severity",
)


class SignatureError(Exception):
    """A signature file is missing, unreadable or holds an invalid rule."""


@dataclass(frozen=True)
class Signature:
    signature_id: str
    name: str
    attack_category: str
    monitored_attribute: str
    threshold: float
    time_window_sec: int
    severity: str
    scope: str = "per_source"
    description: str = ""


def parse_signature(raw, source):
    if not isinstance(raw, dict):
        raise SignatureError(f"{source}: each signature must be a JSON object")

    sig_id = raw.get("signature_id", "?")
    missing = [field for field in REQUIRED_FIELDS if field not in raw]
    if missing:
        raise SignatureError(f"{source}: {sig_id} is missing {', '.join(missing)}")

    def check_choice(field, allowed, default=None):
        value = raw.get(field, default)
        if value not in allowed:
            raise SignatureError(
                f"{source}: {sig_id} has {field}={value!r}, expected one of {sorted(allowed)}"
            )
        return value

    threshold = raw["threshold"]
    # bool is a subclass of int in Python, so rule it out on purpose
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or threshold <= 0:
        raise SignatureError(f"{source}: {sig_id} threshold must be a number above 0")

    window = raw["time_window_sec"]
    if isinstance(window, bool) or not isinstance(window, int) or window < 1:
        raise SignatureError(f"{source}: {sig_id} time_window_sec must be a whole number of 1 or more")

    return Signature(
        signature_id=str(sig_id),
        name=str(raw["name"]),
        attack_category=check_choice("attack_category", CATEGORIES),
        monitored_attribute=check_choice("monitored_attribute", ATTRIBUTES),
        threshold=float(threshold),
        time_window_sec=window,
        severity=check_choice("severity", SEVERITIES),
        scope=check_choice("scope", SCOPES, default="per_source"),
        description=str(raw.get("description", "")),
    )


class SignatureLoader:
    def __init__(self, signatures_path="signatures"):
        self.signatures_path = Path(signatures_path)
        self._signatures = []

    def load(self):
        files = sorted(self.signatures_path.glob("*_signatures.json"))
        if not files:
            raise SignatureError(f"no *_signatures.json files found in {self.signatures_path}")

        signatures = []
        seen_ids = set()
        for path in files:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as err:
                raise SignatureError(f"{path.name}: invalid JSON ({err})") from err
            if not isinstance(data, list):
                raise SignatureError(f"{path.name}: must contain a JSON array of signatures")

            for raw in data:
                sig = parse_signature(raw, path.name)
                if sig.signature_id in seen_ids:
                    raise SignatureError(f"{path.name}: duplicate signature_id {sig.signature_id}")
                seen_ids.add(sig.signature_id)
                signatures.append(sig)

        # Replace the rules only after every file passed, so a bad edit keeps the old rules.
        self._signatures = signatures
        return list(signatures)

    def reload(self):
        return self.load()

    def get_signatures(self):
        return list(self._signatures)


if __name__ == "__main__":
    loader = SignatureLoader()
    rules = loader.load()
    print(f"Loaded {len(rules)} signatures from {loader.signatures_path}/")
    for s in rules:
        print(
            f"  {s.signature_id:8} {s.severity:8} {s.scope:10} "
            f"{s.monitored_attribute} > {s.threshold:,.0f}/s over {s.time_window_sec}s  {s.name}"
        )
