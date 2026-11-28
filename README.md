# CloudGuard — Cloud Access Misconfiguration Detection via Zero-Trust Policy Enforcement

Full-stack web application built with **HTML5, CSS3, Vanilla JavaScript** (frontend) and **Python FastAPI + SQLAlchemy + SQLite** (backend).

## Project Structure

```text
.
├── .gitignore
├── .python-version
├── app.py
├── backend/
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── auth.py
│   ├── requirements.txt
│   ├── routes/
│   │   ├── auth_routes.py
│   │   ├── dashboard_routes.py
│   │   ├── provider_routes.py
│   │   ├── scanner_routes.py
│   │   ├── policy_routes.py
│   │   └── ops_routes.py
│   ├── scanner/
│   │   └── engine.py
│   ├── policies/
│   │   └── engine.py
│   ├── reports/
│   │   └── generator.py
│   └── services/
│       ├── optimization.py
│       └── seed.py
├── frontend/
│   ├── index.html
│   ├── login.html
│   ├── dashboard.html
│   ├── providers.html
│   ├── scanner.html
│   ├── findings.html
│   ├── policies.html
│   ├── optimization.html
│   ├── monitoring.html
│   ├── logs.html
│   ├── reports.html
│   ├── users.html
│   ├── serve.mjs
│   ├── css/styles.css
│   └── js/
│       ├── api.js
│       └── layout.js
├── package-lock.json
├── requirements.txt
└── README.md
```

## Running Locally

### 1. Backend (Python 3.10+ Required)
```powershell
cd d:\project\cloud-zero-trust-platform\backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
- API Docs: `http://127.0.0.1:8000/docs`
- SQLite DB (`cloud_zero_trust.db`) is created and seeded automatically on startup.

### 2. Frontend (HTML5 / CSS3 / Vanilla JS)
```powershell
cd d:\project\cloud-zero-trust-platform\frontend
node serve.mjs
```
- Frontend URL: `http://localhost:5600/`

## Deploying to Vercel

Deploy from the repository root. Vercel detects the root `app.py` FastAPI entrypoint and `requirements.txt`; the backend serves the frontend files from `frontend/`.

Before deploying, add these environment variables in the Vercel project settings for each environment:

- `DATABASE_URL`: a persistent PostgreSQL connection string. Vercel's local filesystem and SQLite database are not persistent.
- `JWT_SECRET_KEY`: a long, randomly generated secret.
- `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD`: strong credentials for the deployment admin. These are required on startup; known demo accounts are disabled or reset.

The local demo credentials are not seeded on Vercel, and protected API routes require authentication there. Generated reports use temporary storage on Vercel and are not guaranteed to survive across function instances; use persistent object storage for durable report downloads.

## Seeded Demo Accounts
- **Admin:** `admin@cloudguard.io` / `admin123`
- **Analyst:** `analyst@cloudguard.io` / `analyst123`
