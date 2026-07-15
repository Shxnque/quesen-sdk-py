"""Minimal validate example — 30 seconds from `pip install quesen-sdk` to decision."""

from quesen_sdk import QuesenClient

client = QuesenClient(base_url="https://<your-quesen-endpoint>", api_key="sk_live_abc")

result = client.validate(
    domain_age_days=1,
    engagement_ratio=0.95,
    scam_keyword_count=4,
)

print("decision:", result.decision)
print("risk_score:", result.risk_score)
print("confidence:", result.confidence)
print("conflict_triggers:", result.conflict_triggers)
print("engine_version:", result.engine_version)
print("request_id (pass to .report() later):", result.request_id)
