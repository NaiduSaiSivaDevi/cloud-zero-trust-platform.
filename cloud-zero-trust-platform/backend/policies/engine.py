import time
from typing import List
from models import ZeroTrustPolicy
from schemas import AccessEvaluateRequest


def evaluate_zero_trust_request(
    req: AccessEvaluateRequest,
    active_policies: List[ZeroTrustPolicy],
) -> dict:
    """
    Deterministic Zero-Trust Policy Enforcement Engine.
    Evaluates identity, authentication status, role, permissions, action, and resource sensitivity,
    combined with active policy definitions from the database.
    Returns decision: ALLOW, DENY, or REVIEW.
    """
    start = time.perf_counter()
    checks = []

    auth = req.auth_status.strip().lower()
    role = req.user_role.strip().lower()
    action = req.action.strip().lower()
    sensitivity = req.resource_sensitivity.strip().lower()
    perms = {p.strip().lower() for p in req.assigned_permissions.split(",") if p.strip()}

    # 1. Authentication check
    if auth == "unauthenticated":
        checks.append("auth_status=unauthenticated (FAILED)")
        return {
            "decision": "DENY",
            "policy_name": "ZT-Mandatory-Auth",
            "reason": "Zero Trust requires verified authentication before any resource access.",
            "conditions_checked": "; ".join(checks),
            "latency_ms": round((time.perf_counter() - start) * 1000, 3),
        }
    checks.append(f"auth_status={auth} (OK)")

    # 2. Permission check
    has_permission = action in perms or "*" in perms or "admin" in perms
    if not has_permission:
        checks.append(f"permission_check({action} in {sorted(perms)}) (FAILED)")
        return {
            "decision": "DENY",
            "policy_name": "ZT-Least-Privilege-RBAC",
            "reason": f"Identity '{req.user_identity}' lacks assigned permission for action '{action}'.",
            "conditions_checked": "; ".join(checks),
            "latency_ms": round((time.perf_counter() - start) * 1000, 3),
        }
    checks.append(f"permission_check({action}) (OK)")

    # 3. MFA requirement for confidential/restricted or destructive actions
    if (sensitivity in {"confidential", "restricted"} or action in {"delete", "admin"}) and auth != "mfa_verified":
        checks.append(f"mfa_required(sensitivity={sensitivity}, action={action}, auth={auth}) (FAILED)")
        return {
            "decision": "DENY",
            "policy_name": "ZT-MFA-Enforcement",
            "reason": "MFA verification is mandatory for confidential/restricted resources or destructive actions.",
            "conditions_checked": "; ".join(checks),
            "latency_ms": round((time.perf_counter() - start) * 1000, 3),
        }
    checks.append("mfa_enforcement (OK)")

    # 4. Restricted resource review for non-admin roles even with MFA
    if sensitivity == "restricted" and role not in {"admin", "security_admin"}:
        checks.append(f"restricted_role_check(role={role}) (REQUIRES_REVIEW)")
        return {
            "decision": "REVIEW",
            "policy_name": "ZT-Restricted-JIT-Review",
            "reason": f"Role '{req.user_role}' accessing 'restricted' resource '{req.resource}' requires step-up approval.",
            "conditions_checked": "; ".join(checks),
            "latency_ms": round((time.perf_counter() - start) * 1000, 3),
        }

    # 5. Evaluate active custom DB policies ordered by priority
    for policy in sorted(active_policies, key=lambda p: p.priority):
        cond = policy.rule_condition.lower()
        if "delete" in cond and action == "delete" and role != "admin":
            checks.append(f"policy[{policy.name}] matched")
            return {
                "decision": policy.effect,
                "policy_name": policy.name,
                "reason": policy.description,
                "conditions_checked": "; ".join(checks),
                "latency_ms": round((time.perf_counter() - start) * 1000, 3),
            }
        if "confidential" in cond and sensitivity == "confidential" and action == "write":
            checks.append(f"policy[{policy.name}] matched")
            return {
                "decision": policy.effect,
                "policy_name": policy.name,
                "reason": policy.description,
                "conditions_checked": "; ".join(checks),
                "latency_ms": round((time.perf_counter() - start) * 1000, 3),
            }

    checks.append("all_zero_trust_checks (PASSED)")
    return {
        "decision": "ALLOW",
        "policy_name": "ZT-Baseline-Allow",
        "reason": f"Verified identity '{req.user_identity}' ({req.user_role}) permitted to '{action}' on '{req.resource}'.",
        "conditions_checked": "; ".join(checks),
        "latency_ms": round((time.perf_counter() - start) * 1000, 3),
    }
