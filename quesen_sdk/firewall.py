"""
QuesenFirewall — the highest-ergonomics surface for the agent firewall.

Reduces the distance from "interesting" to "I can try this" to a single call:

    from quesen_sdk import QuesenFirewall

    fw = QuesenFirewall(base_url="https://<engine>", api_key="sk_...")

    fw.require_pass(
        agent="my-agent",
        action="send_data",          # or: tool_call / payment / http_request ...
        target="https://external-api",
        data_class="secret",         # str or list[str]
    )                                 # raises TscBlocked on anything but PASS

This wraps `QuesenClient.validate_tsc` + the `TscContext` builders. It adds no
new decision logic — the engine remains the sole authority. It exists purely to
remove boilerplate for the three catastrophic-action shapes.
"""
from __future__ import annotations

from typing import Any, List, Optional, Sequence, Union

from .client import QuesenClient
from .tsc import TscContext, TscDecision

__all__ = ["QuesenFirewall"]

# friendly action aliases -> the TSC builder to use
_EGRESS_ACTIONS = {"send_data", "data_egress", "egress", "exfiltrate", "http_post", "upload"}
_PAYMENT_ACTIONS = {"payment", "pay", "transfer", "send_funds", "send_money"}
_TOOL_ACTIONS = {"tool_call", "tool", "invoke", "call_tool", "execute", "code_exec"}


def _as_list(v: Optional[Union[str, Sequence[str]]]) -> Optional[List[str]]:
    if v is None:
        return None
    return [v] if isinstance(v, str) else list(v)


class QuesenFirewall:
    """Ergonomic wrapper over the Quesen TSC v2 agent firewall."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        client: Optional[QuesenClient] = None,
        **client_kwargs: Any,
    ) -> None:
        self._client = client or QuesenClient(base_url=base_url, api_key=api_key, **client_kwargs)

    # ---- context construction from friendly kwargs ----
    def _build(
        self,
        *,
        agent: Optional[str] = None,
        action: str = "tool_call",
        target: Optional[str] = None,
        data_class: Optional[Union[str, Sequence[str]]] = None,
        capability_class: Optional[str] = None,
        granted_scopes: Optional[Sequence[str]] = None,
        requested_scopes: Optional[Sequence[str]] = None,
        trust_tier: str = "unknown",
        destination_trust: str = "unverified",
        framework: Optional[str] = None,
        provenance: Optional[str] = None,
        client_request_id: Optional[str] = None,
    ) -> TscContext:
        act = (action or "tool_call").lower()
        classes = _as_list(data_class)
        if act in _EGRESS_ACTIONS:
            return TscContext.data_egress(
                data_classes=classes or ["unknown"],
                to=target or "unknown",
                destination_trust=destination_trust,
                framework=framework,
                provenance=provenance or "adapter_derived",
                client_request_id=client_request_id,
            )
        if act in _PAYMENT_ACTIONS:
            return TscContext.payment(
                granted_scopes=granted_scopes,
                trust_tier=trust_tier if trust_tier != "unknown" else "unverified",
                framework=framework,
                provenance=provenance or "client_asserted",
                client_request_id=client_request_id,
            )
        # default: tool_call
        return TscContext.tool_call(
            capability_class=capability_class or "other",
            granted_scopes=granted_scopes,
            requested_scopes=requested_scopes,
            trust_tier=trust_tier,
            framework=framework,
            provenance=provenance or "adapter_derived",
            client_request_id=client_request_id,
        )

    def check(self, **kwargs: Any) -> TscDecision:
        """Return the raw TscDecision for a described action (no raising)."""
        return self._client.validate_tsc(self._build(**kwargs))

    def allows(self, **kwargs: Any) -> bool:
        """True only if the engine returned an explicit PASS (fail-closed)."""
        return self.check(**kwargs).allowed

    def require_pass(self, **kwargs: Any) -> TscDecision:
        """Raise TscBlocked unless the described action is a PASS.

        Drop this in front of any high-risk agent action:

            fw.require_pass(agent="a", action="send_data",
                            target=url, data_class="secret")
        """
        return self.check(**kwargs).require_pass()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "QuesenFirewall":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
