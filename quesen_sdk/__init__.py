"""
Quesen Python SDK — friction-reducing typed client for the Quesen HTTP API.

Public surface:
    QuesenClient        — synchronous httpx client
    AsyncQuesenClient   — asyncio-native client

    ValidateResult, SimulateResult, ReportResult — typed response objects
    QuesenError, QuesenAuthError, QuesenRateLimitError, QuesenValidationError,
    QuesenServerError, QuesenTimeout, QuesenTransportError — error hierarchy

Doctrine anchors (parent repo Shxnque/Quesen-sib DOCTRINE.md):
    §1   Priority order: revenue > adoption > determinism > moat > infra.
    §2   Determinism preserved: this SDK does not add ML, prompts, randomness.
    §11  Ecosystem neutrality: single runtime dependency `httpx`.
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

__version__ = "0.1.0"

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
    "QuesenError",
    "QuesenAuthError",
    "QuesenRateLimitError",
    "QuesenValidationError",
    "QuesenServerError",
    "QuesenTimeout",
    "QuesenTransportError",
]
