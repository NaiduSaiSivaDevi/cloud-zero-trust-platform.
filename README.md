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

Deploy the repository root as one Vercel project. Set **Root Directory** to the repository root (not `backend/` or `frontend/`). Vercel's Python runtime detects the root `app.py` FastAPI entrypoint and installs `requirements.txt`; the API and frontend are served from the same origin. No `vercel.json` is required for this layout. Keep the **Python Version** at 3.12, matching `.python-version`, and do not set a separate build output directory.

Add these environment variables in Vercel project settings for Production and any Preview environment that should run:

- `DATABASE_URL`: a persistent PostgreSQL connection string. Vercel's local filesystem and SQLite database are not persistent.
- `JWT_SECRET_KEY`: a long, randomly generated secret.
- `INITIAL_ADMIN_EMAIL`: email address for the deployment admin.
- `INITIAL_ADMIN_PASSWORD`: a strong unique password, not `admin123` or `analyst123`.

The local demo credentials are not seeded on Vercel, and protected API routes require authentication there. Generated reports use temporary storage on Vercel and are not guaranteed to survive across function instances; use persistent object storage for durable report downloads.
The deployment admin signs in at `/login.html` using `INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD`. Unauthenticated users are redirected to sign-in in deployed environments; local demo mode remains accessible without login.

The included `backend/.env.example` shows the required variable names; do not commit real credentials. An unset database/JWT/admin variable causes an explicit startup failure, which appears as a Vercel `FUNCTION_INVOCATION_FAILED`.

### Frontend API origin

The bundled frontend defaults to the current origin, which is correct when the root project serves both the frontend and API. If the frontend remains in a separate Vercel project, set the API origin once in that browser's developer console:

```js
localStorage.setItem("cg_api_base", "https://YOUR-BACKEND-DEPLOYMENT.vercel.app");
location.reload();
```

The browser-side static frontend cannot read Vercel environment variables at runtime; the persistent `cg_api_base` override is the existing configuration mechanism. Requests from that frontend to the backend are allowed by the current CORS configuration.
For a deployment-specific script configuration instead, define `window.CLOUDGUARD_API_BASE` to that same URL before loading `js/api.js`.

### Local verification

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

Check `http://127.0.0.1:8000/`, `http://127.0.0.1:8000/health`, and `http://127.0.0.1:8000/docs`. `/health` reports database readiness after successfully running a simple query.

For a separate frontend project, set the API base to the backend deployment URL as described above; do not set the frontend project as the backend's Root Directory.

### Vercel deploy and smoke-test

After adding the environment variables, deploy from the repository root with `vercel --prod` or push the branch connected to Vercel. Test `https://YOUR-BACKEND-DEPLOYMENT.vercel.app/`, `/health`, and `/docs`; then use `/api/providers` (requires deployment login/token) to check a seeded API route. A successful local test does not imply the Vercel deployment succeeded.

## Seeded Demo Accounts
- **Admin:** `admin@cloudguard.io` / `admin123`
- **Analyst:** `analyst@cloudguard.io` / `analyst123`
