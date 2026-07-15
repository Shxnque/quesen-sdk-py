"""Error hierarchy for the Quesen Python SDK."""

from __future__ import annotations

from typing import Any, Optional


class QuesenError(Exception):
    """Base class for every SDK-raised error."""

    def __init__(self, message: str, *, status_code: Optional[int] = None,
                 payload: Optional[Any] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class QuesenAuthError(QuesenError):
    """HTTP 401 — missing or invalid X-API-Key (or admin key on /stats)."""


class QuesenRateLimitError(QuesenError):
    """HTTP 429 — per-key rate limit exceeded."""

    def __init__(self, message: str, *, retry_after: Optional[int] = None,
                 status_code: Optional[int] = 429, payload: Optional[Any] = None) -> None:
        super().__init__(message, status_code=status_code, payload=payload)
        self.retry_after = retry_after


class QuesenValidationError(QuesenError):
    """HTTP 422 — request body failed Pydantic validation server-side."""


class QuesenServerError(QuesenError):
    """HTTP 5xx after retries exhausted."""


class QuesenTimeout(QuesenError):
    """Transport timeout — caller SHOULD treat this as SKIP (fail-closed)."""


class QuesenTransportError(QuesenError):
    """Generic transport failure (DNS, connect, unexpected socket close)."""
