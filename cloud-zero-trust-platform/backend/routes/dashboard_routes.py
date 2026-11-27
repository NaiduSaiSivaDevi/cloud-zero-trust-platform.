from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import (
    AccessDecision,
    Alert,
    AuditLog,
    CloudProvider,
    Scan,
    SecurityFinding,
    User,
    ZeroTrustPolicy,
)

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

PROVIDER_DISPLAY_MAP = {
    "AWS": "AWS",
    "Azure": "Microsoft Azure",
    "GCP": "Google Cloud Platform",
}

SEVERITY_WEIGHTS = {
    "Critical": 15,
    "High": 10,
    "Medium": 5,
    "Low": 2,
}


@router.get("/provider-scores")
def provider_scores(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Calculate security scores (0-100) for AWS, Microsoft Azure, and Google Cloud Platform
    using actual scan results within the selected date window.
    """
    cutoff = datetime.utcnow() - timedelta(days=days)
    providers = db.query(CloudProvider).all()

    grouped: dict[str, dict] = {}
    for p in providers:
        scans = (
            db.query(Scan)
            .filter(Scan.provider_id == p.id, Scan.started_at >= cutoff)
            .all()
        )
        if not scans:
            continue

        label = PROVIDER_DISPLAY_MAP.get(p.provider_type, p.provider_type)
        entry = grouped.setdefault(label, {"resources": 0, "scan_ids": [], "scans": 0})
        entry["scans"] += len(scans)
        entry["resources"] += sum(max(s.total_resources, 0) for s in scans)
        entry["scan_ids"].extend(s.id for s in scans)

    if not grouped:
        return {"has_data": False, "days": days, "scores": {}, "details": {}}

    scores = {}
    details = {}
    for label in ["AWS", "Microsoft Azure", "Google Cloud Platform"]:
        if label not in grouped:
            continue
        info = grouped[label]
        open_findings = (
            db.query(SecurityFinding)
            .filter(
                SecurityFinding.scan_id.in_(info["scan_ids"]),
                SecurityFinding.status != "resolved",
            )
            .all()
        )
        penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 2) for f in open_findings)
        denom = max(info["resources"], 1)
        raw_score = 100.0 - (penalty / denom) * 10.0
        score = round(max(0.0, min(100.0, raw_score)), 1)
        scores[label] = score
        details[label] = {
            "scans": info["scans"],
            "resources": info["resources"],
            "unresolved_findings": len(open_findings),
            "score": score,
        }

    return {"has_data": bool(scores), "days": days, "scores": scores, "details": details}


@router.get("/policy-evaluation")
def policy_evaluation(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Evaluate Zero Trust policy coverage and enforcement across the 5 core pillars
    using actual ZeroTrustPolicy rules and AccessDecision logs.
    """
    cutoff = datetime.utcnow() - timedelta(days=days)
    policies = db.query(ZeroTrustPolicy).filter(ZeroTrustPolicy.is_active == True).all()  # noqa: E712
    decisions = db.query(AccessDecision).filter(AccessDecision.created_at >= cutoff).all()

    if not policies and not decisions:
        return {"has_data": False, "days": days, "pillars": {}}

    pillar_keywords = {
        "Identity Verification": ["mfa", "identity", "auth_status", "sso", "verify"],
        "Least Privilege Access": ["role", "privilege", "admin", "delete", "write", "jit", "sensitivity"],
        "Device Trust": ["device", "endpoint", "posture", "trust", "managed"],
        "Network Security": ["network", "ip", "vpc", "firewall", "ingress", "public", "confidential"],
        "Continuous Authentication": ["mfa", "continuous", "auth", "session", "token", "review", "jit"],
    }

    pillar_scores = {}
    total_active = max(len(policies), 1)

    for pillar, keywords in pillar_keywords.items():
        matched_policies = 0
        for p in policies:
            haystack = f"{p.name} {p.description} {p.rule_condition}".lower()
            if any(kw in haystack for kw in keywords):
                matched_policies += 1

        matched_decisions = 0
        enforced_decisions = 0
        for d in decisions:
            haystack = f"{d.policy_name} {d.auth_status} {d.action} {d.reason}".lower()
            if any(kw in haystack for kw in keywords):
                matched_decisions += 1
                if d.decision in {"DENY", "REVIEW", "ALLOW"}:
                    enforced_decisions += 1

        policy_coverage = (matched_policies / total_active) * 70.0
        decision_signal = min(30.0, (enforced_decisions / max(len(decisions), 1)) * 30.0) if decisions else (20.0 if matched_policies > 0 else 0.0)
        pillar_scores[pillar] = round(min(100.0, policy_coverage + decision_signal), 1)

    return {
        "has_data": any(v > 0 for v in pillar_scores.values()),
        "days": days,
        "pillars": pillar_scores,
        "active_policies": len(policies),
        "decisions_evaluated": len(decisions),
    }


@router.get("/misconfig-trends")
def misconfig_trends(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return daily counts of detected misconfigurations by severity for the past N days."""
    start_date = datetime.utcnow() - timedelta(days=days)
    rows = (
        db.query(
            func.date(SecurityFinding.detected_at).label("date"),
            SecurityFinding.severity,
            func.count(SecurityFinding.id),
        )
        .filter(SecurityFinding.detected_at >= start_date)
        .group_by(func.date(SecurityFinding.detected_at), SecurityFinding.severity)
        .order_by(func.date(SecurityFinding.detected_at))
        .all()
    )

    trends: dict[str, dict[str, int]] = {}
    for date_val, severity, cnt in rows:
        d = date_val.isoformat() if hasattr(date_val, "isoformat") else str(date_val)
        trends.setdefault(d, {"Critical": 0, "High": 0, "Medium": 0, "Low": 0})
        if severity in trends[d]:
            trends[d][severity] = cnt

    return {"has_data": bool(trends), "days": days, "trends": trends}


@router.get("/compliance")
def compliance_stats(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return counts of Compliant (resolved), Non-Compliant (open), and Pending (reviewed/pending) findings."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    base_q = db.query(SecurityFinding).filter(SecurityFinding.detected_at >= cutoff)

    compliant = base_q.filter(SecurityFinding.status == "resolved").count()
    non_compliant = base_q.filter(SecurityFinding.status == "open").count()
    pending = base_q.filter(SecurityFinding.status.in_(["reviewed", "pending"])).count()
    total = compliant + non_compliant + pending

    return {
        "has_data": total > 0,
        "days": days,
        "counts": {
            "Compliant": compliant,
            "Non-Compliant": non_compliant,
            "Pending": pending,
        },
        "total": total,
    }


@router.get("/risk-assessment")
def risk_assessment(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Calculate overall security risk score (0-100), critical issues, resolved, and unresolved counts."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    findings = db.query(SecurityFinding).filter(SecurityFinding.detected_at >= cutoff).all()
    scans = db.query(Scan).filter(Scan.started_at >= cutoff).all()

    if not findings and not scans:
        return {
            "has_data": False,
            "days": days,
            "overall_score": 0,
            "critical_issues": 0,
            "resolved_issues": 0,
            "unresolved_issues": 0,
            "breakdown": {},
        }

    resolved_issues = sum(1 for f in findings if f.status == "resolved")
    unresolved = [f for f in findings if f.status != "resolved"]
    unresolved_issues = len(unresolved)
    critical_issues = sum(1 for f in unresolved if f.severity == "Critical")

    breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    weighted_sum = 0
    for f in unresolved:
        if f.severity in breakdown:
            breakdown[f.severity] += 1
        weighted_sum += SEVERITY_WEIGHTS.get(f.severity, 1)

    total_resources = sum(max(s.total_resources, 0) for s in scans) or max(len(findings), 1)
    overall_score = round(min(100.0, (weighted_sum / total_resources) * 10.0), 1)

    return {
        "has_data": True,
        "days": days,
        "overall_score": overall_score,
        "critical_issues": critical_issues,
        "resolved_issues": resolved_issues,
        "unresolved_issues": unresolved_issues,
        "total_issues": len(findings),
        "breakdown": breakdown,
    }


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    total_providers = db.query(CloudProvider).count()
    connected_providers = db.query(CloudProvider).filter(CloudProvider.status == "connected").count()
    total_resources = db.query(func.coalesce(func.sum(CloudProvider.resource_count), 0)).scalar() or 0
    total_scans = db.query(Scan).count()
    total_findings = db.query(SecurityFinding).count()
    critical_findings = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.severity == "Critical", SecurityFinding.status != "resolved")
        .count()
    )
    high_findings = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.severity == "High", SecurityFinding.status != "resolved")
        .count()
    )
    allow_decisions = db.query(AccessDecision).filter(AccessDecision.decision == "ALLOW").count()
    deny_decisions = db.query(AccessDecision).filter(AccessDecision.decision == "DENY").count()
    review_decisions = db.query(AccessDecision).filter(AccessDecision.decision == "REVIEW").count()
    unread_alerts = db.query(Alert).filter(Alert.is_acknowledged == False).count()  # noqa: E712

    return {
        "total_providers": total_providers,
        "connected_providers": connected_providers,
        "total_scanned_resources": total_resources,
        "total_scans": total_scans,
        "detected_misconfigurations": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "allow_decisions": allow_decisions,
        "deny_decisions": deny_decisions,
        "review_decisions": review_decisions,
        "unread_alerts": unread_alerts,
    }


@router.get("/charts")
def dashboard_charts(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    sev_rows = db.query(SecurityFinding.severity, func.count(SecurityFinding.id)).group_by(SecurityFinding.severity).all()
    prov_rows = db.query(SecurityFinding.provider, func.count(SecurityFinding.id)).group_by(SecurityFinding.provider).all()
    dec_rows = db.query(AccessDecision.decision, func.count(AccessDecision.id)).group_by(AccessDecision.decision).all()
    recent_scans = db.query(Scan).order_by(Scan.started_at.desc()).limit(8).all()

    return {
        "findings_by_severity": {s: c for s, c in sev_rows},
        "findings_by_provider": {p: c for p, c in prov_rows},
        "access_decisions": {d: c for d, c in dec_rows},
        "scan_activity": [
            {
                "id": s.id,
                "environment": s.environment,
                "total_findings": s.total_findings,
                "total_resources": s.total_resources,
                "duration_ms": s.duration_ms,
                "started_at": s.started_at.isoformat(),
            }
            for s in reversed(recent_scans)
        ],
    }


@router.get("/activity")
def dashboard_activity(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(12).all()
    return [
        {
            "id": log.id,
            "actor_email": log.actor_email,
            "action": log.action,
            "resource": log.resource,
            "decision": log.decision,
            "severity": log.severity,
            "details": log.details,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]
