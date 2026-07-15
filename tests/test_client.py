"""
SDK integration tests \u2014 exercise the full stack:
  SDK (sync + async) -> httpx -> real uvicorn -> FastAPI -> engine -> back

Sync tests use a real background uvicorn server (see conftest.py) because
httpx.ASGITransport is async-only. Async tests use ASGITransport for speed.
"""

from __future__ import annotations

import importlib
import json
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from quesen_sdk import (  # noqa: E402
    AsyncQuesenClient,
    QuesenAuthError,
    QuesenClient,
    QuesenRateLimitError,
    QuesenValidationError,
)


def _sync(live_server, env=None, api_key=None) -> QuesenClient:
    srv = live_server(env)
    return QuesenClient(base_url=srv.base_url, api_key=api_key, retries=0, timeout=5.0)


def _reload_app_for_async(env: dict | None = None):
    for k in list(os.environ):
        if k.startswith("QUESEN_"):
            del os.environ[k]
    if env:
        os.environ.update(env)
    from quesen import keys, telegram, reports  # noqa: F401
    from quesen import api as api_module
    importlib.reload(keys)
    importlib.reload(telegram)
    importlib.reload(reports)
    importlib.reload(api_module)
    return api_module.app


def _async(env=None, api_key=None) -> AsyncQuesenClient:
    app = _reload_app_for_async(env)
    return AsyncQuesenClient(
        base_url="http://testserver",
        api_key=api_key,
        retries=0,
        transport=httpx.ASGITransport(app=app),
    )


# ---------------- sync ----------------

def test_sync_health(live_server):
    with _sync(live_server) as c:
        h = c.health()
        assert h["status"] == "ok"
        assert h["engine_version"]


def test_sync_version_advertises_report_schema_version(live_server):
    with _sync(live_server) as c:
        v = c.version()
        assert "weights" in v
        assert v["report_schema_version"]


def test_sync_validate_rug_pattern_returns_SKIP(live_server):
    with _sync(live_server) as c:
        r = c.validate(domain_age_days=1, engagement_ratio=0.95, scam_keyword_count=4)
        assert r.decision == "SKIP"
        assert r.should_skip is True
        assert r.should_proceed is False
        assert r.risk_score >= 0.65
        assert r.conflict_triggers
        assert r.request_id


def test_sync_validate_safe_pattern_returns_PROCEED(live_server):
    with _sync(live_server) as c:
        r = c.validate(domain_age_days=800, engagement_ratio=0.5, scam_keyword_count=0)
        assert r.decision == "PROCEED"


def test_sync_validate_propagates_client_request_id(live_server):
    with _sync(live_server) as c:
        r = c.validate(domain_age_days=100, client_request_id="trace-abc")
        assert r.client_request_id == "trace-abc"


def test_sync_simulate_delta(live_server):
    with _sync(live_server) as c:
        r = c.simulate(
            domain_age_days=120, engagement_ratio=0.1, scam_keyword_count=0,
            thresholds_override={"skip": 0.40, "review": 0.20},
        )
        assert r.baseline.decision in {"REVIEW", "SKIP"}
        assert r.simulated.decision == "SKIP"


def test_sync_report_v1_1_extended_fields(live_server):
    with _sync(live_server) as c:
        r = c.report(
            request_id="trade-1", outcome="WIN",
            realized_pnl=12.5, elapsed_seconds=3600, venue="base:uniswap-v3",
        )
        assert r.accepted is True
        assert r.counters is not None
        assert r.counters.by_outcome["WIN"] == 1


def test_sync_report_returns_counters_deterministic(live_server):
    with _sync(live_server) as c:
        c.report(request_id="a", outcome="WIN", realized_pnl=10.0)
        c.report(request_id="b", outcome="LOSS", realized_pnl=-4.0)
        r = c.report(request_id="c", outcome="OK")
        assert r.counters.total == 3
        assert r.counters.pnl_reported_count == 2
        assert r.counters.pnl_mean == pytest.approx(3.0)


def test_sync_401_when_registry_enabled_without_key(live_server):
    env = {"QUESEN_API_KEYS": json.dumps({"sk_x": {"owner": "o", "price_per_call": 0.0}})}
    with _sync(live_server, env=env) as c:
        with pytest.raises(QuesenAuthError):
            c.validate(domain_age_days=100)


def test_sync_owner_returned_on_valid_key(live_server):
    env = {"QUESEN_API_KEYS": json.dumps({"sk_ok": {"owner": "tester", "price_per_call": 0.0}})}
    with _sync(live_server, env=env, api_key="sk_ok") as c:
        r = c.validate(domain_age_days=100)
        assert r.key_owner == "tester"


def test_sync_422_on_out_of_range(live_server):
    with _sync(live_server) as c:
        with pytest.raises(QuesenValidationError):
            c.validate(engagement_ratio=5.0)


def test_sync_rate_limit_raises(live_server):
    env = {"QUESEN_API_KEYS": json.dumps(
        {"sk_burst": {"owner": "b", "price_per_call": 0.0, "rate_limit_per_min": 2}}
    )}
    with _sync(live_server, env=env, api_key="sk_burst") as c:
        c.validate(domain_age_days=100)
        c.validate(domain_age_days=100)
        with pytest.raises(QuesenRateLimitError):
            c.validate(domain_age_days=100)


# ---------------- async ----------------

@pytest.mark.asyncio
async def test_async_validate_and_report_roundtrip():
    async with _async() as c:
        v = await c.validate(domain_age_days=1, engagement_ratio=0.95, scam_keyword_count=4)
        assert v.decision == "SKIP"
        r = await c.report(request_id=v.request_id, outcome="RUG")
        assert r.accepted is True
        assert r.counters.by_outcome["RUG"] == 1


@pytest.mark.asyncio
async def test_async_simulate():
    async with _async() as c:
        r = await c.simulate(
            domain_age_days=120, engagement_ratio=0.1,
            thresholds_override={"skip": 0.40, "review": 0.20},
        )
        assert r.baseline.decision in {"REVIEW", "SKIP"}
        assert r.simulated.decision == "SKIP"


@pytest.mark.asyncio
async def test_async_health_and_version():
    async with _async() as c:
        h = await c.health()
        assert h["status"] == "ok"
        v = await c.version()
        assert v["report_schema_version"]
