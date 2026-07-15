"""Async batch example — concurrent /validate calls, fail-closed on timeouts."""

import asyncio
from quesen_sdk import AsyncQuesenClient, QuesenTimeout

OPPORTUNITIES = [
    {"domain_age_days": 1, "engagement_ratio": 0.95, "scam_keyword_count": 4},
    {"domain_age_days": 800, "engagement_ratio": 0.5, "scam_keyword_count": 0},
    {"domain_age_days": 45, "engagement_ratio": 0.7, "scam_keyword_count": 1},
]


async def main() -> None:
    async with AsyncQuesenClient(
        base_url="https://<your-quesen-endpoint>",
        api_key="sk_live_abc",
        timeout=3.0,
        retries=2,
    ) as q:
        async def check(opp: dict) -> str:
            try:
                r = await q.validate(**opp)
            except QuesenTimeout:
                return "SKIP (fail-closed on timeout)"
            return f"{r.decision} risk={r.risk_score:.3f}"

        decisions = await asyncio.gather(*(check(o) for o in OPPORTUNITIES))
        for opp, d in zip(OPPORTUNITIES, decisions):
            print(opp, "->", d)


if __name__ == "__main__":
    asyncio.run(main())
