"""Tests for the `quesen` conformance CLI (Quesen Upgrade P2)."""
import json

from quesen_sdk.conformance import main, build_parser, _RECEIPT_VECTORS, _ACTION_VECTORS
from quesen_sdk.receipt import canonical_receipt_bytes
from quesen_sdk.execution import action_hash


def test_conformance_exit_zero(capsys):
    rc = main(["conformance"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CONFORMANT" in out and "NOT CONFORMANT" not in out


def test_embedded_vectors_match_sdk_functions():
    for v in _RECEIPT_VECTORS:
        assert canonical_receipt_bytes(v["receipt"]).decode("utf-8") == v["canonical_bytes_utf8"]
    for v in _ACTION_VECTORS:
        assert action_hash(v["action"]) == v["action_hash"]


def test_version_command(capsys):
    rc = main(["version"])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out)["contract"] == "evidence-contract/v1"


def test_verify_receipt_file(tmp_path, capsys):
    receipt = {"decision": "PASS", "input_snapshot_hash": "a" * 64, "commit_sha": "x", "reasons": []}
    p = tmp_path / "r.json"
    p.write_text(json.dumps(receipt), encoding="utf-8")
    rc = main(["verify", str(p)])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out)["ok"] is True


def test_no_command_prints_help(capsys):
    rc = main([])
    assert rc == 2
