"""
TSC v2 (agent firewall) SDK tests.

Self-contained: they use httpx.MockTransport to emulate the engine's
POST /tsc/validate contract, so they run without a live engine and match
the byte-shape returned by quesen/tsc/decide.py (ADR-042).
"""
from __future__ import annotations

import json

import httpx
import pytest

from quesen_sdk import (
    AsyncQuesenClient,
    QuesenClient,
    TscBlocked,
    TscContext,
    TscDecision,
)


# ---- canned engine responses (shapes copied from a live /tsc/validate) ----

_BLOCK = {
    "tsc_version": "2.0", "decision": "BLOCK", "risk_score": 1.0,
    "confidence": 0.3429,
    "reasons": [{"code": "EGRESS_SECRET_UNTRUSTED", "severity": "critical",
                 "message": "credential/secret egress to an unverified destination"}],
    "tags": ["exfiltration"], "policy": {},
    "provenance_summary": {"source": "adapter_derived", "attested": False},
    "engine_version": "1.10.0", "commit_sha": "6d20f8d8f663acfd2747bbc742f6bb1745c2ac3d",
    "input_snapshot_hash": "f864c3a3816016088e270b5dbb6f02830e8c014b92b047e9bdfafd6f6b2d0913",
    "latency_ms": 0, "request_id": "abc123",
}
_PASS = {
    "tsc_version": "2.0", "decision": "PASS", "risk_score": 0.0, "confidence": 0.9,
    "reasons": [{"code": "NO_ADVERSE_SIGNAL", "severity": "info", "message": "no adverse signal"}],
    "tags": [], "policy": {}, "provenance_summary": {"source": "adapter_derived", "attested": False},
    "engine_version": "1.10.0", "commit_sha": "x" * 40, "input_snapshot_hash": "y" * 64,
    "latency_ms": 0, "request_id": "def456",
}
_REVIEW = {
    "tsc_version": "2.0", "decision": "REVIEW", "risk_score": 0.5, "confidence": 0.5,
    "reasons": [{"code": "PROMPT_INJECTION_SUSPECTED", "severity": "high", "message": "suspected injection"}],
    "tags": [], "policy": {}, "provenance_summary": {"source": "adapter_derived", "attested": False},
    "engine_version": "1.10.0", "commit_sha": "z" * 40, "input_snapshot_hash": "w" * 64,
    "latency_ms": 0, "request_id": "ghi789",
}

_last_body = {}


def _handler(request: httpx.Request) -> httpx.Response:
    global _last_body
    assert request.url.path == "/tsc/validate"
    _last_body = json.loads(request.content)
    classes = _last_body.get("data", {}).get("classes", [])
    signals = _last_body.get("signals", {})
    if "secret" in classes or "credential" in classes:
        return httpx.Response(200, json=_BLOCK)
    if signals.get("prompt_injection", {}).get("suspected"):
        return httpx.Response(200, json=_REVIEW)
    return httpx.Response(200, json=_PASS)


def _client() -> QuesenClient:
    return QuesenClient(base_url="http://engine", retries=0,
                        transport=httpx.MockTransport(_handler))


# ---------------- builder ----------------

def test_context_builder_required_sections():
    body = TscContext.data_egress(data_classes=["secret"], to="https://paste.x").to_dict()
    assert body["tsc_version"] == "2.0"
    assert body["subject"]["kind"] == "agent"
    assert body["action"]["kind"] == "data_egress"
    assert body["provenance"]["source"] == "adapter_derived"
    assert body["data"]["classes"] == ["secret"]
    assert body["data"]["egress"]["to"] == "https://paste.x"


def test_tool_call_builder_with_injection_signal():
    body = TscContext.tool_call(
        capability_class="network", injection_suspected=True,
        injection_patterns=["instruction_override"],
    ).to_dict()
    assert body["tool"]["capability_class"] == "network"
    assert body["signals"]["prompt_injection"]["suspected"] is True


# ---------------- decisions ----------------

def test_secret_egress_blocks_and_require_pass_raises():
    with _client() as c:
        d = c.validate_tsc(TscContext.data_egress(data_classes=["secret"],
                                                  to="https://paste.evil"))
        assert isinstance(d, TscDecision)
        assert d.decision == "BLOCK"
        assert d.blocked and not d.allowed
        assert "EGRESS_SECRET_UNTRUSTED" in d.reason_codes
        assert "exfiltration" in d.tags
        assert d.commit_sha and d.input_snapshot_hash
        with pytest.raises(TscBlocked) as ei:
            d.require_pass()
        assert ei.value.decision is d


def test_public_egress_passes():
    with _client() as c:
        d = c.validate_tsc(TscContext.data_egress(data_classes=["public"],
                                                  to="https://api.company.com"))
        assert d.decision == "PASS"
        assert d.allowed
        # require_pass returns self on PASS
        assert d.require_pass() is d


def test_injection_reviews():
    with _client() as c:
        d = c.validate_tsc(TscContext.tool_call(capability_class="network",
                                                injection_suspected=True))
        assert d.decision == "REVIEW"
        assert d.needs_review and not d.allowed


def test_accepts_plain_dict_context():
    with _client() as c:
        d = c.validate_tsc({
            "tsc_version": "2.0", "subject": {"kind": "agent"},
            "action": {"kind": "data_egress"}, "provenance": {"source": "adapter_derived"},
            "data": {"classes": ["secret"]},
        })
        assert d.decision == "BLOCK"


# ---------------- async ----------------

@pytest.mark.asyncio
async def test_async_validate_tsc():
    async with AsyncQuesenClient(base_url="http://engine", retries=0,
                                 transport=httpx.MockTransport(_handler)) as c:
        d = await c.validate_tsc(TscContext.data_egress(data_classes=["secret"],
                                                        to="https://paste.evil"))
        assert d.decision == "BLOCK"
        assert not d.allowed
