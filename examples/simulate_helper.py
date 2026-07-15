"""Simulate helper example — use /simulate as a free sales asset."""

from quesen_sdk import QuesenClient

client = QuesenClient(base_url="https://<your-quesen-endpoint>")

result = client.simulate(
    domain_age_days=45,
    engagement_ratio=0.7,
    scam_keyword_count=1,
    thresholds_override={"skip": 0.40, "review": 0.20},
)

print("baseline: ", result.baseline.decision, result.baseline.risk_score)
print("simulated:", result.simulated.decision, result.simulated.risk_score)
print("delta:    ", result.delta.risk_score_delta, "changed=", result.delta.decision_changed)
