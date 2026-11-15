import json
from pathlib import Path

import pytest

from analyzer.signatures import SignatureError, SignatureLoader

REPO_SIGNATURES = Path(__file__).resolve().parent.parent / "signatures"

GOOD_RULE = {
    "signature_id": "TST-001",
    "name": "Test rule",
    "attack_category": "protocol",
    "monitored_attribute": "pps",
    "threshold": 100,
    "time_window_sec": 5,
    "severity": "high",
}


def write_rules(folder, filename, rules):
    (folder / filename).write_text(json.dumps(rules), encoding="utf-8")


def test_repo_signature_files_are_valid():
    rules = SignatureLoader(REPO_SIGNATURES).load()
    ids = {r.signature_id for r in rules}
    assert {"VOL-001", "PRO-001", "APP-002"} <= ids


def test_scope_defaults_to_per_source(tmp_path):
    write_rules(tmp_path, "protocol_signatures.json", [GOOD_RULE])
    (rule,) = SignatureLoader(tmp_path).load()
    assert rule.scope == "per_source"
    assert rule.threshold == 100.0


def test_missing_field_is_rejected(tmp_path):
    bad = dict(GOOD_RULE)
    del bad["threshold"]
    write_rules(tmp_path, "protocol_signatures.json", [bad])
    with pytest.raises(SignatureError, match="missing threshold"):
        SignatureLoader(tmp_path).load()


@pytest.mark.parametrize(
    "field, value",
    [
        ("severity", "extreme"),
        ("attack_category", "malware"),
        ("monitored_attribute", "cpu"),
        ("scope", "everyone"),
        ("threshold", 0),
        ("threshold", "100"),
        ("time_window_sec", 0),
        ("time_window_sec", 2.5),
    ],
)
def test_bad_values_are_rejected(tmp_path, field, value):
    write_rules(tmp_path, "protocol_signatures.json", [dict(GOOD_RULE, **{field: value})])
    with pytest.raises(SignatureError):
        SignatureLoader(tmp_path).load()


def test_duplicate_ids_across_files_are_rejected(tmp_path):
    write_rules(tmp_path, "protocol_signatures.json", [GOOD_RULE])
    write_rules(tmp_path, "volume_signatures.json", [GOOD_RULE])
    with pytest.raises(SignatureError, match="duplicate"):
        SignatureLoader(tmp_path).load()


def test_invalid_json_is_rejected(tmp_path):
    (tmp_path / "protocol_signatures.json").write_text("[{oops", encoding="utf-8")
    with pytest.raises(SignatureError, match="invalid JSON"):
        SignatureLoader(tmp_path).load()


def test_empty_folder_is_rejected(tmp_path):
    with pytest.raises(SignatureError, match="no \\*_signatures.json"):
        SignatureLoader(tmp_path).load()


def test_bad_reload_keeps_the_old_rules(tmp_path):
    write_rules(tmp_path, "protocol_signatures.json", [GOOD_RULE])
    loader = SignatureLoader(tmp_path)
    loader.load()

    (tmp_path / "protocol_signatures.json").write_text("not json", encoding="utf-8")
    with pytest.raises(SignatureError):
        loader.reload()

    assert [r.signature_id for r in loader.get_signatures()] == ["TST-001"]
