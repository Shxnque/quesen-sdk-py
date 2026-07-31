"""
Quesen SDK HTTP clients (sync + async).

Design anchors:
- Fail-closed on transport error. Callers must decide whether to interpret
  a timeout as SKIP; the SDK will not swallow it silently.
- Deterministic retries. Exponential back-off with jitter is intentionally
  omitted so retry behaviour under a given (attempt, sleep) pair is stable.
- Zero global state. Every method call is independent; no hidden caches.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Any, Dict, Mapping, Optional

import httpx

from .errors import (
    QuesenAuthError,
    QuesenError,
    QuesenRateLimitError,
    QuesenServerError,
    QuesenTimeout,
    QuesenTransportError,
    QuesenValidationError,
)
from .types import ReportResult, SimulateResult, ValidateResult

__all__ = ["QuesenClient", "AsyncQuesenClient", "DEFAULT_USER_AGENT"]

DEFAULT_USER_AGENT = "quesen-sdk-py/0.2.0"
_DEFAULT_TIMEOUT = 5.0
_DEFAULT_RETRIES = 2
_DEFAULT_BACKOFF = 0.2
_RETRYABLE_STATUSES = frozenset({500, 502, 503, 504})


def _headers(api_key: Optional[str], user_agent: str, request_id: str,
             request_id_header: str) -> Dict[str, str]:
    h: Dict[str, str] = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": user_agent,
        request_id_header: request_id,
    }
    if api_key:
        h["X-API-Key"] = api_key
    return h


def _resolve_base_url(base_url: Optional[str]) -> str:
    resolved = base_url or os.environ.get("QUESEN_BASE_URL")
    if not resolved:
        raise QuesenError(
            "QuesenClient requires a base_url. Pass base_url=... or set QUESEN_BASE_URL."
        )
    return resolved.rstrip("/")


def _resolve_api_key(api_key: Optional[str]) -> Optional[str]:
    return api_key if api_key is not None else os.environ.get("QUESEN_API_KEY")


def _raise_for_status(response: httpx.Response) -> None:
    code = response.status_code
    if 200 <= code < 300:
        return
    try:
        payload: Any = response.json()
    except Exception:
        payload = response.text[:400]
    if code == 401:
        raise QuesenAuthError(f"unauthorized: {payload}", status_code=code, payload=payload)
    if code == 422:
        raise QuesenValidationError(f"validation error: {payload}", status_code=code, payload=payload)
    if code == 429:
        retry_after = None
        if response.headers.get("Retry-After"):
            try:
                retry_after = int(response.headers["Retry-After"])
            except ValueError:
                retry_after = None
        raise QuesenRateLimitError(
            f"rate limit exceeded: {payload}",
            retry_after=retry_after, status_code=code, payload=payload,
        )
    if 500 <= code < 600:
        raise QuesenServerError(f"server error {code}: {payload}", status_code=code, payload=payload)
    raise QuesenError(f"unexpected status {code}: {payload}", status_code=code, payload=payload)


# ---------------------------------------------------------------------------
# Synchronous client
# ---------------------------------------------------------------------------

class QuesenClient:
    """Synchronous Quesen client. Thread-safe for concurrent method calls."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        retries: int = _DEFAULT_RETRIES,
        retry_backoff: float = _DEFAULT_BACKOFF,
        request_id_header: str = "X-Request-ID",
        user_agent: str = DEFAULT_USER_AGENT,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.base_url = _resolve_base_url(base_url)
        self.api_key = _resolve_api_key(api_key)
        self.timeout = timeout
        self.retries = max(0, int(retries))
        self.retry_backoff = max(0.0, float(retry_backoff))
        self.request_id_header = request_id_header
        self.user_agent = user_agent
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
        )

    # ---------- lifecycle ----------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "QuesenClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ---------- core request ----------

    def _request(self, method: str, path: str, *, json_body: Optional[Dict[str, Any]] = None,
                 request_id: Optional[str] = None) -> Dict[str, Any]:
        rid = request_id or str(uuid.uuid4())
        headers = _headers(self.api_key, self.user_agent, rid, self.request_id_header)
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                resp = self._client.request(method, path, headers=headers, json=json_body)
            except httpx.TimeoutException as e:
                last_exc = QuesenTimeout(f"timeout after {self.timeout}s: {e}")
            except httpx.TransportError as e:
                last_exc = QuesenTransportError(f"transport error: {e}")
            else:
                if resp.status_code not in _RETRYABLE_STATUSES:
                    _raise_for_status(resp)
                    return resp.json()
                # retryable server error
                last_exc = QuesenServerError(
                    f"server error {resp.status_code} on {method} {path}",
                    status_code=resp.status_code,
                )
            if attempt < self.retries:
                time.sleep(self.retry_backoff * (2 ** attempt))
        assert last_exc is not None
        raise last_exc

    # ---------- endpoints ----------

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/health")

    def version(self) -> Dict[str, Any]:
        return self._request("GET", "/version")

    def validate(
        self,
        domain_age_days: Optional[int] = None,
        engagement_ratio: Optional[float] = None,
        scam_keyword_count: Optional[int] = None,
        *,
        client_request_id: Optional[str] = None,
    ) -> ValidateResult:
        body = _drop_none({
            "domain_age_days": domain_age_days,
            "engagement_ratio": engagement_ratio,
            "scam_keyword_count": scam_keyword_count,
            "client_request_id": client_request_id,
        })
        data = self._request("POST", "/validate", json_body=body, request_id=client_request_id)
        return ValidateResult.from_dict(data)

    def simulate(
        self,
        domain_age_days: Optional[int] = None,
        engagement_ratio: Optional[float] = None,
        scam_keyword_count: Optional[int] = None,
        *,
        weights_override: Optional[Mapping[str, float]] = None,
        thresholds_override: Optional[Mapping[str, float]] = None,
        client_request_id: Optional[str] = None,
    ) -> SimulateResult:
        body = _drop_none({
            "domain_age_days": domain_age_days,
            "engagement_ratio": engagement_ratio,
            "scam_keyword_count": scam_keyword_count,
            "weights_override": dict(weights_override) if weights_override else None,
            "thresholds_override": dict(thresholds_override) if thresholds_override else None,
            "client_request_id": client_request_id,
        })
        data = self._request("POST", "/simulate", json_body=body, request_id=client_request_id)
        return SimulateResult.from_dict(data)

    def report(
        self,
        request_id: str,
        outcome: str,
        *,
        notes: Optional[str] = None,
        realized_pnl: Optional[float] = None,
        elapsed_seconds: Optional[int] = None,
        venue: Optional[str] = None,
        signal_hash: Optional[str] = None,
        client_request_id: Optional[str] = None,
    ) -> ReportResult:
        body = _drop_none({
            "request_id": request_id,
            "outcome": outcome,
            "notes": notes,
            "realized_pnl": realized_pnl,
            "elapsed_seconds": elapsed_seconds,
            "venue": venue,
            "signal_hash": signal_hash,
            "client_request_id": client_request_id,
        })
        data = self._request("POST", "/report", json_body=body, request_id=client_request_id)
        return ReportResult.from_dict(data)


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------

class AsyncQuesenClient:
    """Asyncio-native Quesen client. Use as an async context manager."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        retries: int = _DEFAULT_RETRIES,
        retry_backoff: float = _DEFAULT_BACKOFF,
        request_id_header: str = "X-Request-ID",
        user_agent: str = DEFAULT_USER_AGENT,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.base_url = _resolve_base_url(base_url)
        self.api_key = _resolve_api_key(api_key)
        self.timeout = timeout
        self.retries = max(0, int(retries))
        self.retry_backoff = max(0.0, float(retry_backoff))
        self.request_id_header = request_id_header
        self.user_agent = user_agent
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncQuesenClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def _request(self, method: str, path: str, *, json_body: Optional[Dict[str, Any]] = None,
                       request_id: Optional[str] = None) -> Dict[str, Any]:
        rid = request_id or str(uuid.uuid4())
        headers = _headers(self.api_key, self.user_agent, rid, self.request_id_header)
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                resp = await self._client.request(method, path, headers=headers, json=json_body)
            except httpx.TimeoutException as e:
                last_exc = QuesenTimeout(f"timeout after {self.timeout}s: {e}")
            except httpx.TransportError as e:
                last_exc = QuesenTransportError(f"transport error: {e}")
            else:
                if resp.status_code not in _RETRYABLE_STATUSES:
                    _raise_for_status(resp)
                    return resp.json()
                last_exc = QuesenServerError(
                    f"server error {resp.status_code} on {method} {path}",
                    status_code=resp.status_code,
                )
            if attempt < self.retries:
                await asyncio.sleep(self.retry_backoff * (2 ** attempt))
        assert last_exc is not None
        raise last_exc

    async def health(self) -> Dict[str, Any]:
        return await self._request("GET", "/health")

    async def version(self) -> Dict[str, Any]:
        return await self._request("GET", "/version")

    async def validate(
        self,
        domain_age_days: Optional[int] = None,
        engagement_ratio: Optional[float] = None,
        scam_keyword_count: Optional[int] = None,
        *,
        client_request_id: Optional[str] = None,
    ) -> ValidateResult:
        body = _drop_none({
            "domain_age_days": domain_age_days,
            "engagement_ratio": engagement_ratio,
            "scam_keyword_count": scam_keyword_count,
            "client_request_id": client_request_id,
        })
        data = await self._request("POST", "/validate", json_body=body, request_id=client_request_id)
        return ValidateResult.from_dict(data)

    async def simulate(
        self,
        domain_age_days: Optional[int] = None,
        engagement_ratio: Optional[float] = None,
        scam_keyword_count: Optional[int] = None,
        *,
        weights_override: Optional[Mapping[str, float]] = None,
        thresholds_override: Optional[Mapping[str, float]] = None,
        client_request_id: Optional[str] = None,
    ) -> SimulateResult:
        body = _drop_none({
            "domain_age_days": domain_age_days,
            "engagement_ratio": engagement_ratio,
            "scam_keyword_count": scam_keyword_count,
            "weights_override": dict(weights_override) if weights_override else None,
            "thresholds_override": dict(thresholds_override) if thresholds_override else None,
            "client_request_id": client_request_id,
        })
        data = await self._request("POST", "/simulate", json_body=body, request_id=client_request_id)
        return SimulateResult.from_dict(data)

    async def report(
        self,
        request_id: str,
        outcome: str,
        *,
        notes: Optional[str] = None,
        realized_pnl: Optional[float] = None,
        elapsed_seconds: Optional[int] = None,
        venue: Optional[str] = None,
        signal_hash: Optional[str] = None,
        client_request_id: Optional[str] = None,
    ) -> ReportResult:
        body = _drop_none({
            "request_id": request_id,
            "outcome": outcome,
            "notes": notes,
            "realized_pnl": realized_pnl,
            "elapsed_seconds": elapsed_seconds,
            "venue": venue,
            "signal_hash": signal_hash,
            "client_request_id": client_request_id,
        })
        data = await self._request("POST", "/report", json_body=body, request_id=client_request_id)
        return ReportResult.from_dict(data)


def _drop_none(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}
