from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, CloudProvider, User
from schemas import ProviderCreate, ProviderRead

router = APIRouter(prefix="/api/providers", tags=["Cloud Providers"])


@router.get("", response_model=List[ProviderRead])
def list_providers(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(CloudProvider).order_by(CloudProvider.id.asc()).all()


@router.post("", response_model=ProviderRead, status_code=status.HTTP_201_CREATED)
def create_provider(
    payload: ProviderCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if payload.provider_type not in {"AWS", "Azure", "GCP"}:
        raise HTTPException(status_code=400, detail="provider_type must be AWS, Azure, or GCP")

    default_resources = {"AWS": 6, "Azure": 4, "GCP": 4}.get(payload.provider_type, 4)
    provider = CloudProvider(
        name=payload.name,
        provider_type=payload.provider_type,
        account_id=payload.account_id,
        environment=payload.environment,
        status="connected",
        is_demo=True,  # Always mark local connections as DEMO MODE unless real SDK creds are verified
        resource_count=default_resources,
    )
    db.add(provider)
    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="PROVIDER_ADDED",
            resource=f"{payload.provider_type}:{payload.account_id}",
            decision="ALLOW",
            severity="Info",
            details=f"Added DEMO MODE cloud provider '{payload.name}'.",
        )
    )
    db.commit()
    db.refresh(provider)
    return provider


@router.get("/{provider_id}", response_model=ProviderRead)
def get_provider(provider_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    provider = db.query(CloudProvider).filter(CloudProvider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Cloud provider not found")
    return provider


@router.post("/{provider_id}/connect", response_model=ProviderRead)
def toggle_provider_connection(
    provider_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    provider = db.query(CloudProvider).filter(CloudProvider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Cloud provider not found")

    provider.status = "disconnected" if provider.status == "connected" else "connected"
    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="PROVIDER_STATUS_CHANGED",
            resource=f"{provider.provider_type}:{provider.account_id}",
            decision="ALLOW",
            severity="Info",
            details=f"Provider '{provider.name}' status set to '{provider.status}' (DEMO MODE).",
        )
    )
    db.commit()
    db.refresh(provider)
    return provider


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_provider(
    provider_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    provider = db.query(CloudProvider).filter(CloudProvider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Cloud provider not found")
    db.add(
        AuditLog(
            actor_email=current_user.email,
            action="PROVIDER_DELETED",
            resource=f"{provider.provider_type}:{provider.account_id}",
            decision="ALLOW",
            severity="Warning",
            details=f"Deleted cloud provider '{provider.name}'.",
        )
    )
    db.delete(provider)
    db.commit()
    return None
