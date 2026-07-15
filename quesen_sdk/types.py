"""
Typed response models for the Quesen SDK.

We use `dataclasses` + `__slots__` rather than Pydantic to keep the SDK
dependency footprint tiny (`httpx` only). If a caller wants Pydantic, they
can `pydantic.TypeAdapter(dict).validate_python(result.raw)` from `.raw`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional


@dataclass(slots=True)
class WeightsSnapshot:
    domain_age: float
    engagement: float
    scam_keywords: float

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "WeightsSnapshot":
        return cls(
            domain_age=float(d["domain_age"]),
            engagement=float(d["engagement"]),
            scam_keywords=float(d["scam_keywords"]),
        )


@dataclass(slots=True)
class ThresholdsSnapshot:
    skip: float
    review: float

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ThresholdsSnapshot":
        return cls(skip=float(d["skip"]), review=float(d["review"]))


@dataclass(slots=True)
class ValidateResult:
    decision: str  # PROCEED | REVIEW | SKIP
    risk_score: float
    confidence: float
    conflict_triggers: List[str]
    latency_ms: int
    request_id: str
    engine_version: str
    weights: WeightsSnapshot
    thresholds: ThresholdsSnapshot
    client_request_id: Optional[str] = None
    key_owner: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def should_proceed(self) -> bool:
        return self.decision == "PROCEED"

    @property
    def should_skip(self) -> bool:
        return self.decision == "SKIP"

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ValidateResult":
        return cls(
            decision=str(d["decision"]),
            risk_score=float(d["risk_score"]),
            confidence=float(d["confidence"]),
            conflict_triggers=list(d.get("conflict_triggers", [])),
            latency_ms=int(d.get("latency_ms", 0)),
            request_id=str(d["request_id"]),
            engine_version=str(d["engine_version"]),
            weights=WeightsSnapshot.from_dict(d["weights"]),
            thresholds=ThresholdsSnapshot.from_dict(d["thresholds"]),
            client_request_id=d.get("client_request_id"),
            key_owner=d.get("key_owner"),
            raw=dict(d),
        )


@dataclass(slots=True)
class SimulateDelta:
    risk_score_delta: float
    decision_changed: bool

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "SimulateDelta":
        return cls(
            risk_score_delta=float(d["risk_score_delta"]),
            decision_changed=bool(d["decision_changed"]),
        )


@dataclass(slots=True)
class SimulateResult:
    baseline: ValidateResult
    simulated: ValidateResult
    delta: SimulateDelta
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "SimulateResult":
        return cls(
            baseline=ValidateResult.from_dict(d["baseline"]),
            simulated=ValidateResult.from_dict(d["simulated"]),
            delta=SimulateDelta.from_dict(d["delta"]),
            raw=dict(d),
        )


@dataclass(slots=True)
class ReportOutcomeCounters:
    total: int
    by_outcome: Dict[str, int]
    pnl_reported_count: int
    pnl_mean: Optional[float] = None

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ReportOutcomeCounters":
        return cls(
            total=int(d.get("total", 0)),
            by_outcome=dict(d.get("by_outcome", {})),
            pnl_reported_count=int(d.get("pnl_reported_count", 0)),
            pnl_mean=(float(d["pnl_mean"]) if d.get("pnl_mean") is not None else None),
        )


@dataclass(slots=True)
class ReportResult:
    accepted: bool
    received_at: str
    request_id: str
    report_schema_version: Optional[str] = None
    engine_version: Optional[str] = None
    counters: Optional[ReportOutcomeCounters] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ReportResult":
        counters = None
        if isinstance(d.get("counters"), Mapping):
            counters = ReportOutcomeCounters.from_dict(d["counters"])
        return cls(
            accepted=bool(d.get("accepted", False)),
            received_at=str(d.get("received_at", "")),
            request_id=str(d.get("request_id", "")),
            report_schema_version=d.get("report_schema_version"),
            engine_version=d.get("engine_version"),
            counters=counters,
            raw=dict(d),
        )
