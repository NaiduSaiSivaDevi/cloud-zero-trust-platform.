import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = PROJECT_DIR / "backend"
if not (BACKEND_DIR / "main.py").is_file():
    BACKEND_DIR = PROJECT_DIR / "cloud-zero-trust-platform" / "backend"

if not (BACKEND_DIR / "main.py").is_file():
    raise FileNotFoundError("Could not locate backend/main.py from the Vercel project root.")

sys.path.insert(0, str(BACKEND_DIR))

from main import app
