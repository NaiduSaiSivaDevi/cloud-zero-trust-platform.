from typing import List
from models import ZeroTrustPolicy


def score_policy(policy: ZeroTrustPolicy) -> dict:
    """
    Transparent cost-aware adaptive policy scoring model.
    Mandatory security controls are never weakened to save cost.
    Estimated monthly cost represents policy evaluation compute overhead only,
    NOT actual cloud provider billing.
    """
    # Security effectiveness score (0-100, higher is safer)
    base_security = 95.0 if policy.is_mandatory else 78.0
    if policy.effect == "DENY":
        base_security += 4.0
    elif policy.effect == "REVIEW":
        base_security += 2.0
    security_score = min(100.0, round(base_security, 2))
    risk_score = round(100.0 - security_score, 2)

    # Lower composite cost index is better: 55% risk weight + 25% latency + 20% estimated compute cost
    composite_index = round(
        (risk_score * 0.55) + (policy.latency_ms * 0.25) + (policy.monthly_est_cost * 0.20),
        2,
    )

    return {
        "policy_id": policy.id,
        "policy_name": policy.name,
        "effect": policy.effect,
        "is_mandatory": policy.is_mandatory,
        "is_active": policy.is_active,
        "security_score": security_score,
        "risk_score": risk_score,
        "latency_ms": policy.latency_ms,
        "cpu_utilization_pct": policy.cpu_cost,
        "memory_mb": policy.memory_mb,
        "estimated_monthly_cost": policy.monthly_est_cost,
        "composite_index": composite_index,
    }


def compare_policies(current_policy: ZeroTrustPolicy, candidates: List[ZeroTrustPolicy]) -> dict:
    evaluated = [score_policy(current_policy)]
    for cand in candidates:
        if cand.id != current_policy.id:
            evaluated.append(score_policy(cand))

    # Filter compliant policies: never recommend weakening mandatory security controls
    compliant = [p for p in evaluated if p["security_score"] >= (90.0 if current_policy.is_mandatory else 75.0)]
    if not compliant:
        compliant = evaluated

    recommended = min(compliant, key=lambda x: x["composite_index"])

    return {
        "current_policy": evaluated[0],
        "comparisons": evaluated,
        "recommended_policy": recommended,
        "cost_disclaimer": "Estimated monthly cost reflects policy engine compute overhead only, separate from actual cloud billing.",
    }
