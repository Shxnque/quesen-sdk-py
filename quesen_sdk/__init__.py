"""
Quesen Python SDK — friction-reducing typed client for the Quesen HTTP API.

Public surface:
    QuesenClient        — synchronous httpx client
    AsyncQuesenClient   — asyncio-native client

    ValidateResult, SimulateResult, ReportResult — typed response objects
    QuesenError, QuesenAuthError, QuesenRateLimitError, QuesenValidationError,
    QuesenServerError, QuesenTimeout, QuesenTransportError — error hierarchy

Doctrine anchors (see https://senueren.co.za/quesen for public design principles):
    §1   Priority order: revenue > adoption > determinism > moat > infra.
    §2   Determinism preserved: this SDK does not add ML, prompts, randomness.
    §11  Ecosystem neutrality: single runtime dependency `httpx`.

v0.2.0 — tracks Quesen engine v1.10.0 (ADR-041 receipt provenance). Every
`ValidateResult` now carries `input_snapshot_hash` and `commit_sha` when the
engine is v1.10.0+. Both fields default to "" against older engines so
existing callers keep working unchanged.
"""

from .client import AsyncQuesenClient, QuesenClient
from .errors import (
    QuesenAuthError,
    QuesenError,
    QuesenRateLimitError,
    QuesenServerError,
    QuesenTimeout,
    QuesenTransportError,
    QuesenValidationError,
)
from .types import (
    ReportResult,
    ReportOutcomeCounters,
    SimulateDelta,
    SimulateResult,
    ValidateResult,
    WeightsSnapshot,
    ThresholdsSnapshot,
)
from .tsc import (
    TscContext,
    TscDecision,
    TscReason,
    TscBlocked,
)
from .firewall import QuesenFirewall

__version__ = "0.4.0"

__all__ = [
    "__version__",
    "QuesenClient",
    "AsyncQuesenClient",
    "ValidateResult",
    "SimulateResult",
    "SimulateDelta",
    "ReportResult",
    "ReportOutcomeCounters",
    "WeightsSnapshot",
    "ThresholdsSnapshot",
    "TscContext",
    "TscDecision",
    "TscReason",
    "TscBlocked",
    "QuesenFirewall",
    "QuesenError",
    "QuesenAuthError",
    "QuesenRateLimitError",
    "QuesenValidationError",
    "QuesenServerError",
    "QuesenTimeout",
    "QuesenTransportError",
]
