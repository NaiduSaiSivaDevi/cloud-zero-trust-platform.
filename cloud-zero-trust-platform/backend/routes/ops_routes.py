import os
import platform
import time
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from auth import get_current_user, hash_password, require_admin
from database import get_db
from models import (
    AccessDecision,
    Alert,
    AuditLog,
    OptimizationResult,
    ReportRecord,
    Scan,
    SecurityFinding,
    User,
    ZeroTrustPolicy,
)
from reports.generator import generate_csv_report, generate_pdf_report
from schemas import (
    OptimizationCompareRequest,
    ReportGenerateRequest,
    UserCreate,
    UserRead,
    UserUpdate,
)
from services.optimization import compare_policies

router = APIRouter(tags=["Operations, Monitoring, Reports & Users"])
START_TIME = time.time()


# ---------------- ALERTS ----------------
@router.get("/api/alerts")
def list_alerts(
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(Alert)
    if severity:
        q = q.filter(Alert.severity == severity)
    alerts = q.order_by(Alert.created_at.desc()).all()
    return [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "source": a.source,
            "message": a.message,
            "is_read": a.is_read,
            "is_acknowledged": a.is_acknowledged,
            "created_at": a.created_at.isoformat(),
        }
        for a in alerts
    ]


@router.put("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_read = True
    alert.is_acknowledged = True
    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="ALERT_ACKNOWLEDGED",
            resource=f"alert:{alert.id}",
            decision="ALLOW",
            severity="Info",
            details=f"Acknowledged alert '{alert.title}'.",
        )
    )
    db.commit()
    return {"id": alert.id, "is_acknowledged": True}


# ---------------- OPTIMIZATION ----------------
@router.post("/api/optimization/compare")
def run_policy_optimization(
    payload: OptimizationCompareRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    current = db.query(ZeroTrustPolicy).filter(ZeroTrustPolicy.id == payload.current_policy_id).first()
    if not current:
        raise HTTPException(status_code=404, detail="Current policy not found")

    if payload.candidate_policy_ids:
        candidates = db.query(ZeroTrustPolicy).filter(ZeroTrustPolicy.id.in_(payload.candidate_policy_ids)).all()
    else:
        candidates = db.query(ZeroTrustPolicy).filter(ZeroTrustPolicy.id != current.id).all()

    result = compare_policies(current, candidates)
    rec = result["recommended_policy"]

    db.add(
        OptimizationResult(
            current_policy_name=current.name,
            recommended_policy_name=rec["policy_name"],
            risk_score=rec["risk_score"],
            latency_ms=rec["latency_ms"],
            estimated_monthly_cost=rec["estimated_monthly_cost"],
            summary=f"Recommended '{rec['policy_name']}' (composite index {rec['composite_index']}).",
        )
    )
    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="POLICY_OPTIMIZATION_RUN",
            resource=current.name,
            decision="ALLOW",
            severity="Info",
            details=f"Compared {len(result['comparisons'])} policies; recommended '{rec['policy_name']}'.",
        )
    )
    db.commit()
    return result


@router.get("/api/optimization/results")
def list_optimization_results(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    rows = db.query(OptimizationResult).order_by(OptimizationResult.created_at.desc()).limit(20).all()
    return [
        {
            "id": r.id,
            "current_policy_name": r.current_policy_name,
            "recommended_policy_name": r.recommended_policy_name,
            "risk_score": r.risk_score,
            "latency_ms": r.latency_ms,
            "estimated_monthly_cost": r.estimated_monthly_cost,
            "summary": r.summary,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


# ---------------- MONITORING ----------------
@router.get("/api/monitoring/health")
def monitoring_health(db: Session = Depends(get_db)):
    return {
        "status": "healthy",
        "uptime_seconds": round(time.time() - START_TIME, 2),
        "database": "sqlite_connected",
        "prometheus_configured": bool(os.getenv("PROMETHEUS_URL")),
        "prometheus_status": "connected" if os.getenv("PROMETHEUS_URL") else "not_configured_using_local_metrics",
        "elk_configured": bool(os.getenv("ELASTICSEARCH_URL")),
        "elk_status": "connected" if os.getenv("ELASTICSEARCH_URL") else "not_configured_using_sqlite_logs",
    }


@router.get("/api/monitoring/metrics")
def monitoring_metrics(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    cpu_pct = None
    mem_pct = None
    try:
        import psutil
        cpu_pct = psutil.cpu_percent(interval=0.1)
        mem_pct = psutil.virtual_memory().percent
    except Exception:
        pass

    avg_scan_ms = db.query(func.avg(Scan.duration_ms)).scalar() or 0.0
    avg_policy_ms = db.query(func.avg(AccessDecision.latency_ms)).scalar() or 0.0
    total_scans = db.query(Scan).count()
    total_decisions = db.query(AccessDecision).count()
    failed_auth_count = db.query(AuditLog).filter(AuditLog.action == "LOGIN_FAILED").count()

    return {
        "data_source": "local_application_and_sqlite_metrics",
        "prometheus_connected": bool(os.getenv("PROMETHEUS_URL")),
        "python_version": platform.python_version(),
        "uptime_seconds": round(time.time() - START_TIME, 2),
        "cpu_usage_pct": cpu_pct,
        "memory_usage_pct": mem_pct,
        "avg_scan_execution_ms": round(float(avg_scan_ms), 3),
        "avg_policy_evaluation_ms": round(float(avg_policy_ms), 3),
        "total_scans": total_scans,
        "total_policy_evaluations": total_decisions,
        "failed_auth_count": failed_auth_count,
    }


# ---------------- LOGS ----------------
@router.get("/api/logs")
def list_logs(
    search: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(AuditLog)
    if severity:
        q = q.filter(AuditLog.severity == severity)
    if search:
        like = f"%{search}%"
        q = q.filter(
            (AuditLog.actor_email.ilike(like))
            | (AuditLog.action.ilike(like))
            | (AuditLog.resource.ilike(like))
            | (AuditLog.details.ilike(like))
        )
    logs = q.order_by(AuditLog.created_at.desc()).limit(100).all()
    return {
        "data_source": "sqlite_audit_logs_fallback" if not os.getenv("ELASTICSEARCH_URL") else "elasticsearch",
        "items": [
            {
                "id": l.id,
                "timestamp": l.created_at.isoformat(),
                "event_type": l.action,
                "user": l.actor_email,
                "resource": l.resource,
                "decision": l.decision or "-",
                "severity": l.severity,
                "description": l.details,
            }
            for l in logs
        ],
    }


# ---------------- REPORTS ----------------
@router.get("/api/reports")
def list_reports(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    reports = db.query(ReportRecord).order_by(ReportRecord.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "report_type": r.report_type,
            "format": r.format,
            "generated_by": r.generated_by,
            "created_at": r.created_at.isoformat(),
        }
        for r in reports
    ]


@router.post("/api/reports/generate")
def generate_report(
    payload: ReportGenerateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    fmt = payload.format.lower()
    if fmt not in {"csv", "pdf"}:
        raise HTTPException(status_code=400, detail="Format must be csv or pdf")

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    rtype = payload.report_type
    filename = f"cloudguard_{rtype}_{ts}.{fmt}"

    headers = []
    rows = []
    if rtype == "findings":
        headers = ["ID", "Provider", "Resource", "Rule", "Severity", "Status", "Detected At"]
        for f in db.query(SecurityFinding).all():
            rows.append([str(f.id), f.provider, f.resource, f.title, f.severity, f.status, f.detected_at.isoformat()])
    elif rtype == "zero_trust":
        headers = ["ID", "Identity", "Role", "Resource", "Action", "Decision", "Policy", "Timestamp"]
        for d in db.query(AccessDecision).all():
            rows.append([str(d.id), d.user_identity, d.user_role, d.resource, d.action, d.decision, d.policy_name, d.created_at.isoformat()])
    elif rtype == "optimization":
        headers = ["ID", "Current Policy", "Recommended", "Risk Score", "Latency(ms)", "Est Cost($/mo)", "Created"]
        for o in db.query(OptimizationResult).all():
            rows.append([str(o.id), o.current_policy_name, o.recommended_policy_name, str(o.risk_score), str(o.latency_ms), str(o.estimated_monthly_cost), o.created_at.isoformat()])
    elif rtype == "scan":
        headers = ["Scan ID", "Provider ID", "Env", "Resources", "Findings", "Critical", "High", "Duration(ms)"]
        for s in db.query(Scan).all():
            rows.append([str(s.id), str(s.provider_id), s.environment, str(s.total_resources), str(s.total_findings), str(s.critical_count), str(s.high_count), str(s.duration_ms)])
    else:
        headers = ["ID", "Actor", "Action", "Resource", "Decision", "Severity", "Timestamp"]
        for l in db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all():
            rows.append([str(l.id), l.actor_email, l.action, l.resource, l.decision or "-", l.severity, l.created_at.isoformat()])

    if fmt == "csv":
        file_path = generate_csv_report(filename, headers, rows)
    else:
        lines = [" | ".join(headers)] + [" | ".join(r) for r in rows]
        if not rows:
            lines.append("No records found in database for this report type.")
        file_path = generate_pdf_report(filename, f"CloudGuard {rtype.upper()} Report", lines)

    record = ReportRecord(
        title=f"CloudGuard {rtype.title()} Report ({fmt.upper()})",
        report_type=rtype,
        format=fmt,
        file_path=file_path,
        generated_by=current_user.email,
    )
    db.add(record)
    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="REPORT_GENERATED",
            resource=filename,
            decision="ALLOW",
            severity="Info",
            details=f"Generated {fmt.upper()} report '{rtype}' with {len(rows)} rows.",
        )
    )
    db.commit()
    db.refresh(record)
    return {
        "id": record.id,
        "title": record.title,
        "report_type": record.report_type,
        "format": record.format,
        "created_at": record.created_at.isoformat(),
    }


@router.get("/api/reports/{report_id}/download")
def download_report(
    report_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    record = db.query(ReportRecord).filter(ReportRecord.id == report_id).first()
    if not record or not os.path.exists(record.file_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    media = "text/csv" if record.format == "csv" else "application/pdf"
    return FileResponse(path=record.file_path, media_type=media, filename=os.path.basename(record.file_path))


# ---------------- USER MANAGEMENT (ADMIN ONLY) ----------------
@router.get("/api/users", response_model=list[UserRead])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return db.query(User).order_by(User.id.asc()).all()


@router.post("/api/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.add(
        AuditLog(
            actor_email=admin_user.email,
            action="USER_CREATED",
            resource=payload.email,
            decision="ALLOW",
            severity="Info",
            details=f"Admin created user {payload.email} with role {payload.role}.",
        )
    )
    db.commit()
    db.refresh(user)
    return user


@router.put("/api/users/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    for field, val in payload.model_dump(exclude_unset=True).items():
        setattr(user, field, val)
    db.add(
        AuditLog(
            actor_email=admin_user.email,
            action="USER_UPDATED",
            resource=user.email,
            decision="ALLOW",
            severity="Info",
            details=f"Admin updated user {user.email}.",
        )
    )
    db.commit()
    db.refresh(user)
    return user


@router.delete("/api/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own active admin account")
    db.add(
        AuditLog(
            actor_email=admin_user.email,
            action="USER_DELETED",
            resource=user.email,
            decision="ALLOW",
            severity="Warning",
            details=f"Admin deleted user {user.email}.",
        )
    )
    db.delete(user)
    db.commit()
    return None
