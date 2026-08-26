"""
TSC v2 (Typed Security Context) support for the Quesen SDK.

This is the ergonomic, frictionless surface for the Quesen "agent firewall":
one call before any high-risk agent action returns a deterministic
PASS / REVIEW / BLOCK / SKIP decision plus a signed-shaped audit receipt.

Maps 1:1 onto the engine's `POST /tsc/validate` route (ADR-042), which is
registered only when the engine runs with `QUESEN_TSC_V2_ENABLED=true`.

Design anchors (identical to the rest of the SDK):
- dataclasses + __slots__, no Pydantic, single runtime dep (`httpx`).
- fail-closed: a firewall caller can `require_pass()` and get an exception
  on anything that is not an explicit PASS.
- zero interpretation: builders only assemble a JSON object; the SDK never
  inspects or executes any string content. The engine is the sole authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

# ---------------------------------------------------------------------------
# Canonical vocabulary (mirrors quesen/tsc/normalize.py::ENUMS on the engine).
# Re-exported so integrators get autocomplete without guessing strings.
# ---------------------------------------------------------------------------

DECISIONS = ("PASS", "REVIEW", "BLOCK", "SKIP")

SUBJECT_KIND = ("agent", "human", "service", "unknown")
FRAMEWORK = ("langchain", "crewai", "autogen", "ag2", "mcp",
             "openai_assistants", "raw", "other", "unknown")
TRUST_TIER = ("trusted", "verified", "unverified", "unknown")
ACTION_KIND = ("tool_call", "http_request", "data_read", "data_write",
               "data_egress", "message_post", "payment", "code_exec",
               "file_access", "other")
TARGET_KIND = ("endpoint", "domain", "contract", "account", "file",
               "dataset", "recipient", "tool", "service", "other", "unknown")
CAPABILITY_CLASS = ("read", "write", "network", "exec", "financial",
                    "admin", "comms", "filesystem", "other")
DATA_CLASS = ("public", "internal", "confidential", "pii", "financial",
              "credential", "secret", "regulated", "unknown")
PROVENANCE_SOURCE = ("client_asserted", "adapter_derived", "engine_derived",
                     "trusted_metadata")

TSC_VERSION = "2.0"


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class TscReason:
    """A single deterministic reason emitted by the engine."""
    code: str
    severity: str
    message: str

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "TscReason":
        return cls(
            code=str(d.get("code", "")),
            severity=str(d.get("severity", "")),
            message=str(d.get("message", "")),
        )


class TscBlocked(Exception):
    """Raised by TscDecision.require_pass() when the action is not PASS.

    Carries the full decision so a firewall can log the audit receipt.
    """

    def __init__(self, decision: "TscDecision") -> None:
        self.decision = decision
        codes = ", ".join(decision.reason_codes) or "no_reasons"
        super().__init__(
            f"Quesen firewall {decision.decision} "
            f"(risk={decision.risk_score}, reasons=[{codes}], "
            f"request_id={decision.request_id})"
        )


@dataclass(slots=True)
class TscDecision:
    """Deterministic decision + audit receipt from POST /tsc/validate."""
    decision: str  # PASS | REVIEW | BLOCK | SKIP
    risk_score: float
    confidence: float
    reasons: List[TscReason]
    tags: List[str]
    tsc_version: str
    engine_version: str
    commit_sha: str
    input_snapshot_hash: str
    request_id: str
    latency_ms: int
    policy: Dict[str, Any] = field(default_factory=dict)
    provenance_summary: Dict[str, Any] = field(default_factory=dict)
    client_request_id: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    # ---- ergonomic predicates (firewall-friendly) ----
    @property
    def allowed(self) -> bool:
        """True ONLY for an explicit PASS. Fail-closed by construction."""
        return self.decision == "PASS"

    @property
    def blocked(self) -> bool:
        return self.decision == "BLOCK"

    @property
    def needs_review(self) -> bool:
        return self.decision == "REVIEW"

    @property
    def skipped(self) -> bool:
        return self.decision == "SKIP"

    @property
    def reason_codes(self) -> List[str]:
        return [r.code for r in self.reasons]

    def require_pass(self) -> "TscDecision":
        """Return self if PASS, else raise TscBlocked. Use as a hard gate:

            client.validate_tsc(ctx).require_pass()  # only PASS proceeds
        """
        if not self.allowed:
            raise TscBlocked(self)
        return self

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "TscDecision":
        return cls(
            decision=str(d["decision"]),
            risk_score=float(d.get("risk_score", 0.0)),
            confidence=float(d.get("confidence", 0.0)),
            reasons=[TscReason.from_dict(r) for r in d.get("reasons", [])],
            tags=list(d.get("tags", [])),
            tsc_version=str(d.get("tsc_version", TSC_VERSION)),
            engine_version=str(d.get("engine_version", "")),
            commit_sha=str(d.get("commit_sha", "")),
            input_snapshot_hash=str(d.get("input_snapshot_hash", "")),
            request_id=str(d.get("request_id", "")),
            latency_ms=int(d.get("latency_ms", 0)),
            policy=dict(d.get("policy", {}) or {}),
            provenance_summary=dict(d.get("provenance_summary", {}) or {}),
            client_request_id=d.get("client_request_id"),
            raw=dict(d),
        )


# ---------------------------------------------------------------------------
# Context builder — assembles a valid TSC v2 body with minimal ceremony.
# ---------------------------------------------------------------------------

def _clean(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


@dataclass(slots=True)
class TscContext:
    """Fluent builder for a Typed Security Context.

    You can pass a fully-formed dict to `client.validate_tsc(...)` instead;
    this builder just removes boilerplate and enforces the required sections
    (subject, action, provenance) so integrators never hand-write JSON.
    """
    subject: Dict[str, Any]
    action: Dict[str, Any]
    provenance: Dict[str, Any]
    target: Optional[Dict[str, Any]] = None
    tool: Optional[Dict[str, Any]] = None
    permissions: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None
    signals: Optional[Dict[str, Any]] = None
    policy: Optional[Dict[str, Any]] = None
    client_request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "tsc_version": TSC_VERSION,
            "subject": self.subject,
            "action": self.action,
            "provenance": self.provenance,
        }
        for name in ("target", "tool", "permissions", "data", "signals",
                     "policy"):
            val = getattr(self, name)
            if val:
                body[name] = val
        if self.client_request_id:
            body["client_request_id"] = self.client_request_id
        return body

    # ---- named scenario constructors (the common firewall cases) ----

    @classmethod
    def data_egress(
        cls,
        *,
        data_classes: Sequence[str],
        to: str,
        destination_trust: str = "unverified",
        subject_kind: str = "agent",
        framework: Optional[str] = None,
        provenance: str = "adapter_derived",
        client_request_id: Optional[str] = None,
    ) -> "TscContext":
        """Agent is about to send data OUT to some destination.

        Secret/credential -> untrusted destination deterministically BLOCKs.
        """
        return cls(
            subject=_clean({"kind": subject_kind, "framework": framework}),
            action={"kind": "data_egress"},
            provenance={"source": provenance},
            target={"kind": "endpoint", "identifier": to,
                    "trust_tier": destination_trust},
            data={"classes": list(data_classes),
                  "egress": {"to": to, "destination_trust": destination_trust}},
            client_request_id=client_request_id,
        )

    @classmethod
    def tool_call(
        cls,
        *,
        capability_class: str,
        granted_scopes: Optional[Sequence[str]] = None,
        requested_scopes: Optional[Sequence[str]] = None,
        policy_required: Optional[Sequence[str]] = None,
        subject_kind: str = "agent",
        trust_tier: str = "unknown",
        framework: Optional[str] = None,
        provenance: str = "adapter_derived",
        injection_suspected: Optional[bool] = None,
        injection_patterns: Optional[Sequence[str]] = None,
        client_request_id: Optional[str] = None,
    ) -> "TscContext":
        """Agent is about to invoke a tool/capability."""
        permissions = _clean({
            "granted": list(granted_scopes) if granted_scopes else None,
            "requested": list(requested_scopes) if requested_scopes else None,
            "policy_required": list(policy_required) if policy_required else None,
        })
        signals = None
        if injection_suspected is not None or injection_patterns:
            pi = _clean({
                "suspected": injection_suspected,
                "patterns": list(injection_patterns) if injection_patterns else None,
            })
            signals = {"prompt_injection": pi}
        return cls(
            subject=_clean({"kind": subject_kind, "trust_tier": trust_tier,
                            "framework": framework}),
            action={"kind": "tool_call"},
            provenance={"source": provenance},
            tool=_clean({
                "capability_class": capability_class,
                "granted_scopes": list(granted_scopes) if granted_scopes else None,
                "requested_scopes": list(requested_scopes) if requested_scopes else None,
            }),
            permissions=permissions or None,
            signals=signals,
            client_request_id=client_request_id,
        )

    @classmethod
    def payment(
        cls,
        *,
        granted_scopes: Optional[Sequence[str]] = None,
        trust_tier: str = "unverified",
        subject_kind: str = "agent",
        framework: Optional[str] = None,
        provenance: str = "client_asserted",
        client_request_id: Optional[str] = None,
    ) -> "TscContext":
        """Agent is about to move money / perform a financial action."""
        return cls(
            subject=_clean({"kind": subject_kind, "trust_tier": trust_tier,
                            "framework": framework}),
            action={"kind": "payment"},
            provenance={"source": provenance},
            tool=_clean({"capability_class": "financial",
                         "granted_scopes": list(granted_scopes) if granted_scopes else None}),
            permissions=_clean({"granted": list(granted_scopes) if granted_scopes else None}),
            client_request_id=client_request_id,
        )


__all__ = [
    "TscDecision", "TscReason", "TscBlocked", "TscContext",
    "DECISIONS", "TSC_VERSION", "SUBJECT_KIND", "FRAMEWORK", "TRUST_TIER",
    "ACTION_KIND", "TARGET_KIND", "CAPABILITY_CLASS", "DATA_CLASS",
    "PROVENANCE_SOURCE",
]
