"""Offline unit tests for the reference evaluator + replay + verify_receipt(recompute).

Zero network — everything runs against the vendored public reference evaluator, so this
file is safe to drop straight into CI (the whole point of C-003/C-004: recomputability
without a hosted dependency)."""
from quesen_sdk import replay, verify_receipt
from quesen_sdk.tsc import TscContext


def _receipt_from(ctx):
    """A minimal receipt shaped like the engine's, derived from the local reference."""
    r = replay(ctx)
    return {
        "decision": r["decision"],
        "reasons": r["reasons"],
        "input_snapshot_hash": r["input_snapshot_hash"],
    }


def test_replay_secret_egress_blocks_offline():
    ctx = TscContext.data_egress(data_classes=["secret"], to="https://paste.evil.example",
                                 destination_trust="unverified")
    r = replay(ctx)
    assert r["ok"] is True
    assert r["decision"] == "BLOCK"
    assert r["reason_codes"] == ["EGRESS_SECRET_UNTRUSTED"]
    assert len(r["input_snapshot_hash"]) == 64


def test_replay_is_deterministic():
    ctx = TscContext.tool_call(capability_class="read")
    a, b = replay(ctx), replay(dict(ctx.to_dict()))
    assert a["decision"] == b["decision"] == "PASS"
    assert a["input_snapshot_hash"] == b["input_snapshot_hash"]


def test_replay_payment_unattested_review():
    ctx = TscContext.payment(granted_scopes=["wallet.transfer"], trust_tier="unverified")
    assert replay(ctx)["decision"] == "REVIEW"


def test_replay_malformed_never_raises():
    r = replay({"not": "a valid context"})
    assert r["ok"] is False and "error" in r


def test_verify_receipt_recompute_matches():
    ctx = TscContext.data_egress(data_classes=["secret"], to="https://x", destination_trust="unverified")
    v = verify_receipt(_receipt_from(ctx), recompute_request=ctx)
    assert v.ok is True
    assert v.recomputed is True
    v.require()  # must not raise


def test_verify_receipt_recompute_detects_tampered_hash():
    ctx = TscContext.data_egress(data_classes=["secret"], to="https://x", destination_trust="unverified")
    receipt = _receipt_from(ctx)
    receipt["input_snapshot_hash"] = "0" * 64  # tamper
    v = verify_receipt(receipt, recompute_request=ctx)
    assert v.ok is False
    assert v.recomputed is False


def test_verify_receipt_recompute_detects_tampered_decision():
    ctx = TscContext.tool_call(capability_class="read")
    receipt = _receipt_from(ctx)
    receipt["decision"] = "BLOCK"  # lie about the verdict
    v = verify_receipt(receipt, recompute_request=ctx)
    assert v.ok is False and v.recomputed is False


def test_verify_receipt_without_recompute_leaves_recomputed_none():
    ctx = TscContext.tool_call(capability_class="read")
    v = verify_receipt(_receipt_from(ctx))
    assert v.recomputed is None
