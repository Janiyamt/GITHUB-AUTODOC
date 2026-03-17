"""
CONFIG LOADER
=============
Reads all settings from .env file
Every component imports from here
"""

import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# ── Oracle DB ──────────────────────────────
DB_USER     = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_DSN      = os.getenv("DB_DSN")

# ── GitHub ─────────────────────────────────
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

# ── OCI ────────────────────────────────────
OCI_COMPARTMENT_ID = os.getenv("OCI_COMPARTMENT_ID")
OCI_REGION         = os.getenv("OCI_REGION")
OCI_VAULT_ID       = os.getenv("OCI_VAULT_ID")
OCI_VAULT_KEY_ID   = os.getenv("OCI_VAULT_KEY_ID")
OCI_GENAI_ENDPOINT = os.getenv("OCI_GENAI_ENDPOINT")
OCI_GENAI_MODEL    = os.getenv("OCI_GENAI_MODEL")

# ── Validate all required values are set ───
def validate():
    required = {
        "DB_USER":     DB_USER,
        "DB_PASSWORD": DB_PASSWORD,
        "DB_DSN":      DB_DSN,
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        raise ValueError(f"Missing config values: {missing}")
    print("✅ Config loaded successfully")

if __name__ == "__main__":
    validate()