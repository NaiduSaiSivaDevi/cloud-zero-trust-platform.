from datetime import datetime
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst", nullable=False)  # admin, analyst, viewer
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    scans = relationship("Scan", back_populates="owner")


class CloudProvider(Base):
    __tablename__ = "cloud_providers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    provider_type = Column(String(50), nullable=False)  # AWS, Azure, GCP
    account_id = Column(String(120), nullable=False)
    environment = Column(String(50), default="production", nullable=False)
    status = Column(String(50), default="connected", nullable=False)  # connected, disconnected
    is_demo = Column(Boolean, default=True, nullable=False)
    resource_count = Column(Integer, default=0, nullable=False)
    last_scan_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scans = relationship("Scan", back_populates="provider", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(Integer, ForeignKey("cloud_providers.id"), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    environment = Column(String(50), default="production", nullable=False)
    status = Column(String(50), default="completed", nullable=False)
    is_demo = Column(Boolean, default=True, nullable=False)
    total_resources = Column(Integer, default=0, nullable=False)
    total_findings = Column(Integer, default=0, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    duration_ms = Column(Float, default=0.0, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    provider = relationship("CloudProvider", back_populates="scans")
    owner = relationship("User", back_populates="scans")
    findings = relationship("SecurityFinding", back_populates="scan", cascade="all, delete-orphan")


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    provider = Column(String(50), nullable=False)
    resource = Column(String(255), nullable=False)
    rule_id = Column(String(80), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)
    severity = Column(String(30), nullable=False)  # Critical, High, Medium, Low
    status = Column(String(30), default="open", nullable=False)  # open, reviewed, resolved
    is_demo = Column(Boolean, default=True, nullable=False)
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")


class ZeroTrustPolicy(Base):
    __tablename__ = "zero_trust_policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), unique=True, nullable=False)
    description = Column(Text, nullable=False)
    rule_condition = Column(Text, nullable=False)
    effect = Column(String(20), nullable=False)  # ALLOW, DENY, REVIEW
    priority = Column(Integer, default=100, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_mandatory = Column(Boolean, default=False, nullable=False)
    cpu_cost = Column(Float, default=1.5, nullable=False)
    memory_mb = Column(Float, default=32.0, nullable=False)
    latency_ms = Column(Float, default=12.0, nullable=False)
    monthly_est_cost = Column(Float, default=45.0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AccessDecision(Base):
    __tablename__ = "access_decisions"

    id = Column(Integer, primary_key=True, index=True)
    user_identity = Column(String(255), nullable=False)
    user_role = Column(String(80), nullable=False)
    auth_status = Column(String(50), nullable=False)
    resource = Column(String(255), nullable=False)
    action = Column(String(80), nullable=False)
    assigned_permissions = Column(String(255), nullable=False)
    resource_sensitivity = Column(String(50), nullable=False)
    decision = Column(String(20), nullable=False)  # ALLOW, DENY, REVIEW
    policy_name = Column(String(150), nullable=False)
    reason = Column(Text, nullable=False)
    conditions_checked = Column(Text, nullable=False)
    latency_ms = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(30), nullable=False)
    source = Column(String(80), nullable=False)
    message = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False, nullable=False)
    is_acknowledged = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class OptimizationResult(Base):
    __tablename__ = "optimization_results"

    id = Column(Integer, primary_key=True, index=True)
    current_policy_name = Column(String(150), nullable=False)
    recommended_policy_name = Column(String(150), nullable=False)
    risk_score = Column(Float, nullable=False)
    latency_ms = Column(Float, nullable=False)
    estimated_monthly_cost = Column(Float, nullable=False)
    summary = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor_email = Column(String(255), nullable=False)
    action = Column(String(120), nullable=False)
    resource = Column(String(255), nullable=False)
    decision = Column(String(50), nullable=True)
    severity = Column(String(30), default="Info", nullable=False)
    details = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ReportRecord(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    report_type = Column(String(80), nullable=False)
    format = Column(String(20), nullable=False)  # pdf, csv
    file_path = Column(String(500), nullable=False)
    generated_by = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
