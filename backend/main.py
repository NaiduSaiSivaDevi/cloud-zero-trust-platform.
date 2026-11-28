from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from database import Base, SessionLocal, engine
from routes import (
    auth_routes,
    dashboard_routes,
    ops_routes,
    policy_routes,
    provider_routes,
    scanner_routes,
)
from services.seed import seed_initial_data

# Initialize database tables and seed default records
Base.metadata.create_all(bind=engine)
with SessionLocal() as db:
    seed_initial_data(db)

app = FastAPI(
    title="CloudGuard — Cloud Access Misconfiguration & Zero Trust API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router)
app.include_router(dashboard_routes.router)
app.include_router(provider_routes.router)
app.include_router(scanner_routes.router)
app.include_router(policy_routes.router)
app.include_router(ops_routes.router)


@app.get("/", include_in_schema=False)
def root():
    return {
        "message": "CloudGuard Zero Trust API",
        "health": "/health",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
def health():
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ok", "database": "ok"}
