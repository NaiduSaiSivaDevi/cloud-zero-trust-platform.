from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AccessDecision, Alert, AuditLog, User, ZeroTrustPolicy
from policies.engine import evaluate_zero_trust_request
from schemas import (
    AccessDecisionRead,
    AccessEvaluateRequest,
    PolicyCreate,
    PolicyRead,
    PolicyUpdate,
)

router = APIRouter(prefix="/api/zero-trust", tags=["Zero Trust Engine"])


@router.post("/evaluate", response_model=AccessDecisionRead)
def evaluate_access(
    payload: AccessEvaluateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    active_policies = db.query(ZeroTrustPolicy).filter(ZeroTrustPolicy.is_active == True).all()  # noqa: E712
    result = evaluate_zero_trust_request(payload, active_policies)

    decision_record = AccessDecision(
        user_identity=payload.user_identity,
        user_role=payload.user_role,
        auth_status=payload.auth_status,
        resource=payload.resource,
        action=payload.action,
        assigned_permissions=payload.assigned_permissions,
        resource_sensitivity=payload.resource_sensitivity,
        decision=result["decision"],
        policy_name=result["policy_name"],
        reason=result["reason"],
        conditions_checked=result["conditions_checked"],
        latency_ms=result["latency_ms"],
    )
    db.add(decision_record)

    if result["decision"] == "DENY":
        db.add(
            Alert(
                title=f"Zero-Trust Access Denied: {payload.user_identity}",
                severity="High",
                source="Zero-Trust Policy Engine",
                message=f"Denied {payload.action} on {payload.resource}: {result['reason']}",
            )
        )

    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="ZERO_TRUST_EVALUATION",
            resource=payload.resource,
            decision=result["decision"],
            severity="Warning" if result["decision"] != "ALLOW" else "Info",
            details=f"Identity={payload.user_identity}, Policy={result['policy_name']}, Reason={result['reason']}",
        )
    )
    db.commit()
    db.refresh(decision_record)
    return decision_record


@router.get("/decisions", response_model=List[AccessDecisionRead])
def list_decisions(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(AccessDecision).order_by(AccessDecision.created_at.desc()).limit(50).all()


@router.get("/policies", response_model=List[PolicyRead])
def list_policies(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(ZeroTrustPolicy).order_by(ZeroTrustPolicy.priority.asc()).all()


@router.post("/policies", response_model=PolicyRead, status_code=status.HTTP_201_CREATED)
def create_policy(
    payload: PolicyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if payload.effect not in {"ALLOW", "DENY", "REVIEW"}:
        raise HTTPException(status_code=400, detail="Effect must be ALLOW, DENY, or REVIEW")
    if db.query(ZeroTrustPolicy).filter(ZeroTrustPolicy.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Policy name already exists")

    policy = ZeroTrustPolicy(**payload.model_dump())
    db.add(policy)
    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="POLICY_CREATED",
            resource=policy.name,
            decision="ALLOW",
            severity="Info",
            details=f"Created Zero-Trust policy '{policy.name}' with effect {policy.effect}.",
        )
    )
    db.commit()
    db.refresh(policy)
    return policy


@router.put("/policies/{policy_id}", response_model=PolicyRead)
def update_policy(
    policy_id: int,
    payload: PolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policy = db.query(ZeroTrustPolicy).filter(ZeroTrustPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if policy.is_mandatory and payload.is_active is False:
        raise HTTPException(status_code=400, detail="Mandatory security policies cannot be deactivated.")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(policy, field, value)

    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="POLICY_UPDATED",
            resource=policy.name,
            decision="ALLOW",
            severity="Info",
            details=f"Updated policy '{policy.name}' (active={policy.is_active}).",
        )
    )
    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    policy = db.query(ZeroTrustPolicy).filter(ZeroTrustPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if policy.is_mandatory:
        raise HTTPException(status_code=400, detail="Mandatory security policies cannot be deleted.")

    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="POLICY_DELETED",
            resource=policy.name,
            decision="ALLOW",
            severity="Warning",
            details=f"Deleted policy '{policy.name}'.",
        )
    )
    db.delete(policy)
    db.commit()
    return None
