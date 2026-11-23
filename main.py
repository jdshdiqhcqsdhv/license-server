import os
import sqlite3
import hashlib
import secrets
import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "licenses.db")
# Ton mot de passe admin est ici par défaut
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "Mickaelcssr26")

app = FastAPI(title="License API")


def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            type TEXT NOT NULL,
            expires_at TEXT,
            max_activations INTEGER NOT NULL DEFAULT 1,
            activations INTEGER NOT NULL DEFAULT 0,
            hwid TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_key() -> str:
    blocks = [secrets.token_hex(2).upper() for _ in range(4)]
    return "NCH-" + "-".join(blocks)


def require_admin(x_admin_token: Optional[str]):
    if not x_admin_token or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="unauthorized")


def is_expired(row) -> bool:
    if not row["expires_at"]:
        return False
    exp = datetime.datetime.fromisoformat(row["expires_at"])
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=datetime.timezone.utc)
    return exp < now_utc()


class CreateLicense(BaseModel):
    type: str
    duration_days: Optional[int] = None
    max_activations: int = 1


class KeyRequest(BaseModel):
    key: str
    hwid: str


class RevokeRequest(BaseModel):
    key: str


@app.on_event("startup")
def startup_event():
    init_db()


@app.post("/admin/licenses")
def create_license(body: CreateLicense, x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    if body.type not in ("temporary", "permanent"):
        raise HTTPException(status_code=400, detail="type must be temporary or permanent")

    expires_at = None
    if body.type == "temporary":
        if body.duration_days is None or body.duration_days <= 0:
            raise HTTPException(status_code=400, detail="duration_days required for temporary")
        expires_at = (now_utc() + datetime.timedelta(days=body.duration_days)).isoformat()

    key = generate_key()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO licenses (key_hash, key_prefix, type, expires_at, max_activations, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (hash_key(key), key[:8], body.type, expires_at, body.max_activations, now_utc().isoformat())
        )
        conn.commit()
    finally:
        conn.close()

    return {"key": key, "type": body.type, "expires_at": expires_at}


@app.post("/activate")
def activate(body: KeyRequest):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM licenses WHERE key_hash = ?",
            (hash_key(body.key),)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="invalid key")
        if row["status"] != "active":
            raise HTTPException(status_code=403, detail="revoked")
        if is_expired(row):
            raise HTTPException(status_code=403, detail="expired")

        if row["hwid"] is None:
            if row["activations"] >= row["max_activations"]:
                raise HTTPException(status_code=403, detail="max activations reached")
            conn.execute(
                "UPDATE licenses SET hwid = ?, activations = activations + 1 WHERE id = ?",
                (body.hwid, row["id"])
            )
            conn.commit()
        elif row["hwid"] != body.hwid:
            raise HTTPException(status_code=403, detail="hwid mismatch")

        return {"ok": True, "expires_at": row["expires_at"]}
    finally:
        conn.close()


@app.post("/validate")
def validate(body: KeyRequest):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM licenses WHERE key_hash = ?",
            (hash_key(body.key),)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="invalid key")
        if row["status"] != "active":
            raise HTTPException(status_code=403, detail="revoked")
        if is_expired(row):
            raise HTTPException(status_code=403, detail="expired")
        if row["hwid"] != body.hwid:
            raise HTTPException(status_code=403, detail="hwid mismatch")

        return {"ok": True, "expires_at": row["expires_at"]}
    finally:
        conn.close()


@app.post("/admin/revoke")
def revoke(body: RevokeRequest, x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    conn = get_db()
    try:
        cur = conn.execute(
            "UPDATE licenses SET status = 'revoked' WHERE key_hash = ?",
            (hash_key(body.key),)
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="key not found")
        return {"ok": True}
    finally:
        conn.close()


@app.get("/admin/licenses")
def list_licenses(x_admin_token: Optional[str] = Header(default=None)):
    require_admin(x_admin_token)
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT id, key_prefix, type, expires_at, max_activations,
                   activations, hwid, status, created_at
            FROM licenses
            ORDER BY id DESC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()