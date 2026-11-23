import os
import hashlib
import secrets
import datetime
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

# L'adresse de ta base de données Neon (sur Render)
DATABASE_URL = os.environ.get("DATABASE_URL", "TON_LIEN_NEON_ICI")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "Mickaelcssr26")

app = FastAPI(title="License API")

def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id SERIAL PRIMARY KEY,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            type TEXT NOT NULL,
            expires_at TIMESTAMPTZ,
            max_activations INTEGER NOT NULL DEFAULT 1,
            activations INTEGER NOT NULL DEFAULT 0,
            hwid TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TIMESTAMPTZ NOT NULL
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()

def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def generate_key() -> str:
    blocks = [secrets.token_hex(2).upper() for _ in range(4)]
    return "NCH-" + "-".join(blocks)

def require_admin(x_admin_token: Optional[str]):
    if not x_admin_token or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="unauthorized")

def is_expired(expires_at) -> bool:
    if not expires_at:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    return expires_at < now_utc()

# --- MODELES ---
class CreateLicense(BaseModel):
    type: str
    duration_minutes: Optional[int] = None  # MODIFIÉ ICI : duration_minutes au lieu de duration_days
    max_activations: int = 1

class KeyRequest(BaseModel):
    key: str
    hwid: str

class RevokeRequest(BaseModel):
    key: str

@app.on_event("startup")
def startup_event():
    init_db()

# --- ENDPOINTS ---
@app.post("/admin/licenses")
def create_license(body: CreateLicense, x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    if body.type not in ("temporary", "permanent"):
        raise HTTPException(status_code=400, detail="type must be temporary or permanent")

    expires_at = None
    if body.type == "temporary":
        if body.duration_minutes is None or body.duration_minutes <= 0:
            raise HTTPException(status_code=400, detail="duration_minutes required for temporary")
        # MODIFIÉ ICI : calcul en minutes
        expires_at = now_utc() + datetime.timedelta(minutes=body.duration_minutes)

    key = generate_key()
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO licenses (key_hash, key_prefix, type, expires_at, max_activations, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (hash_key(key), key[:8], body.type, expires_at, body.max_activations, now_utc())
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    return {"key": key, "type": body.type, "expires_at": expires_at}

@app.post("/activate")
def activate(body: KeyRequest):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute("SELECT * FROM licenses WHERE key_hash = %s", (hash_key(body.key),))
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="invalid key")
        if row["status"] != "active":
            raise HTTPException(status_code=403, detail="revoked")
        if is_expired(row["expires_at"]):
            raise HTTPException(status_code=403, detail="expired")

        if row["hwid"] is None:
            if row["activations"] >= row["max_activations"]:
                raise HTTPException(status_code=403, detail="max activations reached")
            cursor.execute(
                "UPDATE licenses SET hwid = %s, activations = activations + 1 WHERE id = %s",
                (body.hwid, row["id"])
            )
            conn.commit()
        elif row["hwid"] != body.hwid:
            raise HTTPException(status_code=403, detail="hwid mismatch")

        return {"ok": True, "expires_at": row["expires_at"]}
    finally:
        cursor.close()
        conn.close()

@app.post("/validate")
def validate(body: KeyRequest):
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute("SELECT * FROM licenses WHERE key_hash = %s", (hash_key(body.key),))
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="invalid key")
        if row["status"] != "active":
            raise HTTPException(status_code=403, detail="revoked")
        if is_expired(row["expires_at"]):
            raise HTTPException(status_code=403, detail="expired")
        if row["hwid"] != body.hwid:
            raise HTTPException(status_code=403, detail="hwid mismatch")

        return {"ok": True, "expires_at": row["expires_at"]}
    finally:
        cursor.close()
        conn.close()

@app.post("/admin/revoke")
def revoke(body: RevokeRequest, x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE licenses SET status = 'revoked' WHERE key_hash = %s", (hash_key(body.key),))
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="key not found")
        return {"ok": True}
    finally:
        cursor.close()
        conn.close()

@app.get("/admin/licenses")
def list_licenses(x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute("""
            SELECT id, key_prefix, type, expires_at, max_activations,
                   activations, hwid, status, created_at
            FROM licenses
            ORDER BY id DESC
        """)
        return [dict(r) for r in cursor.fetchall()]
    finally:
        cursor.close()
        conn.close()
