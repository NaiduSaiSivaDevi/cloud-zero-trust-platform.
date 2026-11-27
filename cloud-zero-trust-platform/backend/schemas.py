from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class UserCreate(BaseModel):
    email: str
    full_name: str
    password: str = Field(..., min_length=6)
    role: str = "analyst"


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime


class ProviderCreate(BaseModel):
    name: str
    provider_type: str
    account_id: str
    environment: str = "production"
    is_demo: bool = True


class ProviderRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    provider_type: str
    account_id: str
    environment: str
    status: str
    is_demo: bool
    resource_count: int
    last_scan_at: Optional[datetime]
    created_at: datetime


class ScanCreate(BaseModel):
    provider_id: int
    environment: str = "production"


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    provider_id: int
    environment: str
    status: str
    is_demo: bool
    total_resources: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    duration_ms: float
    started_at: datetime
    completed_at: Optional[datetime]


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    provider: str
    resource: str
    rule_id: str
    title: str
    description: str
    recommendation: str
    severity: str
    status: str
    is_demo: bool
    detected_at: datetime


class FindingStatusUpdate(BaseModel):
    status: str


class PolicyCreate(BaseModel):
    name: str
    description: str
    rule_condition: str
    effect: str
    priority: int = 100
    is_active: bool = True
    is_mandatory: bool = False
    cpu_cost: float = 1.5
    memory_mb: float = 32.0
    latency_ms: float = 12.0
    monthly_est_cost: float = 45.0


class PolicyUpdate(BaseModel):
    description: Optional[str] = None
    rule_condition: Optional[str] = None
    effect: Optional[str] = None
    priority: Optional[int] = None
    is_active: Optional[bool] = None
    cpu_cost: Optional[float] = None
    memory_mb: Optional[float] = None
    latency_ms: Optional[float] = None
    monthly_est_cost: Optional[float] = None


class PolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: str
    rule_condition: str
    effect: str
    priority: int
    is_active: bool
    is_mandatory: bool
    cpu_cost: float
    memory_mb: float
    latency_ms: float
    monthly_est_cost: float
    created_at: datetime


class AccessEvaluateRequest(BaseModel):
    user_identity: str
    user_role: str
    auth_status: str  # mfa_verified, password_only, unauthenticated
    resource: str
    action: str  # read, write, delete, admin
    assigned_permissions: str  # comma-separated e.g. "read,write"
    resource_sensitivity: str  # public, internal, confidential, restricted


class AccessDecisionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    user_identity: str
    user_role: str
    auth_status: str
    resource: str
    action: str
    assigned_permissions: str
    resource_sensitivity: str
    decision: str
    policy_name: str
    reason: str
    conditions_checked: str
    latency_ms: float
    created_at: datetime


class OptimizationCompareRequest(BaseModel):
    current_policy_id: int
    candidate_policy_ids: List[int] = []


class ReportGenerateRequest(BaseModel):
    report_type: str  # scan, findings, zero_trust, optimization, audit
    format: str = "csv"  # csv or pdf
