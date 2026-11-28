from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth import create_access_token, get_current_user, hash_password, verify_password
from database import get_db
from models import AuditLog, User
from schemas import LoginRequest, TokenResponse, UserCreate, UserRead

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        db.add(
            AuditLog(
                actor_email=payload.email,
                action="LOGIN_FAILED",
                resource="/api/auth/login",
                decision="DENY",
                severity="Warning",
                details="Invalid email or password attempt.",
            )
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive")

    token = create_access_token(data={"sub": user.email, "role": user.role})
    db.add(
        AuditLog(
            actor_email=user.email,
            action="LOGIN_SUCCESS",
            resource="/api/auth/login",
            decision="ALLOW",
            severity="Info",
            details=f"User {user.email} ({user.role}) authenticated.",
        )
    )
    db.commit()
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active,
        },
    }


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    role = payload.role if payload.role in {"analyst", "viewer"} else "analyst"
    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.add(
        AuditLog(
            actor_email=payload.email,
            action="USER_REGISTERED",
            resource="/api/auth/register",
            decision="ALLOW",
            severity="Info",
            details=f"Registered new user with role '{role}'.",
        )
    )
    db.commit()
    db.refresh(user)
    return user


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_user)):
    return current_user
