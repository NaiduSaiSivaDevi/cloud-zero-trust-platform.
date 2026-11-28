import time
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import Alert, AuditLog, CloudProvider, Scan, SecurityFinding, User
from scanner.engine import run_configuration_scan
from schemas import FindingRead, FindingStatusUpdate, ScanCreate, ScanRead

router = APIRouter(tags=["Scanner & Findings"])


@router.post("/api/scans", response_model=ScanRead)
def start_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    provider = db.query(CloudProvider).filter(CloudProvider.id == payload.provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Cloud provider not found")
    if provider.status != "connected":
        raise HTTPException(status_code=400, detail="Provider is disconnected. Connect it before scanning.")

    t0 = time.perf_counter()
    result = run_configuration_scan(provider.provider_type, payload.environment)
    duration_ms = round((time.perf_counter() - t0) * 1000, 3)

    findings_list = result["findings"]
    crit = sum(1 for f in findings_list if f["severity"] == "Critical")
    high = sum(1 for f in findings_list if f["severity"] == "High")
    med = sum(1 for f in findings_list if f["severity"] == "Medium")
    low = sum(1 for f in findings_list if f["severity"] == "Low")

    scan = Scan(
        provider_id=provider.id,
        owner_id=current_user.id,
        environment=payload.environment,
        status="completed",
        is_demo=True,
        total_resources=result["total_resources"],
        total_findings=len(findings_list),
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        duration_ms=duration_ms,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
    )
    db.add(scan)
    db.flush()

    for f in findings_list:
        db.add(
            SecurityFinding(
                scan_id=scan.id,
                provider=f["provider"],
                resource=f["resource"],
                rule_id=f["rule_id"],
                title=f["title"],
                description=f["description"],
                recommendation=f["recommendation"],
                severity=f["severity"],
                status="open",
                is_demo=True,
            )
        )
        if f["severity"] in {"Critical", "High"}:
            db.add(
                Alert(
                    title=f"{f['severity']} Misconfiguration: {f['title']}",
                    severity=f["severity"],
                    source=f"{f['provider']} Scanner (DEMO MODE)",
                    message=f"{f['resource']} — {f['description']}",
                )
            )

    provider.resource_count = result["total_resources"]
    provider.last_scan_at = datetime.utcnow()

    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="CONFIGURATION_SCAN_EXECUTED",
            resource=f"{provider.provider_type}:{payload.environment}",
            decision="ALLOW",
            severity="Warning" if (crit + high) > 0 else "Info",
            details=f"DEMO MODE scan #{scan.id} scanned {scan.total_resources} resources and detected {scan.total_findings} findings.",
        )
    )
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/api/scans", response_model=List[ScanRead])
def list_scans(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(Scan).order_by(Scan.started_at.desc()).all()


@router.get("/api/scans/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/api/findings", response_model=List[FindingRead])
def list_findings(
    severity: Optional[str] = None,
    provider: Optional[str] = None,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(SecurityFinding)
    if severity:
        q = q.filter(SecurityFinding.severity == severity)
    if provider:
        q = q.filter(SecurityFinding.provider == provider)
    if status_filter:
        q = q.filter(SecurityFinding.status == status_filter)
    return q.order_by(SecurityFinding.detected_at.desc()).all()


@router.put("/api/findings/{finding_id}/status", response_model=FindingRead)
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if payload.status not in {"open", "reviewed", "resolved"}:
        raise HTTPException(status_code=400, detail="Status must be open, reviewed, or resolved")
    finding = db.query(SecurityFinding).filter(SecurityFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = payload.status
    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="FINDING_STATUS_UPDATED",
            resource=finding.resource,
            decision="ALLOW",
            severity="Info",
            details=f"Finding #{finding.id} marked as '{payload.status}'.",
        )
    )
    db.commit()
    db.refresh(finding)
    return finding
