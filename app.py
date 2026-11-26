
import os
import time
import secrets
import hashlib
import sqlite3

from pathlib import Path
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


# ==================================
# CONFIGURATION
# ==================================

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "xo_arena.db"

WELCOME_COINS = 10
SESSION_DAYS = 7

app = FastAPI(
    title="XO Arena",
    description="Premium Tic Tac Toe Gaming Platform",
    version="1.0.0"
)


# ==================================
# DATABASE
# ==================================

@contextmanager
def get_db():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout = 30000")

    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def setup_database():

    with get_db() as con:

        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            coins INTEGER NOT NULL DEFAULT 10,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            coins INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)


setup_database()


# ==================================
# PASSWORD SECURITY
# ==================================

def hash_password(password):

    salt = secrets.token_hex(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200000
    ).hex()

    return salt + "$" + hashed


def verify_password(password, stored):

    try:
        salt, old_hash = stored.split("$", 1)

        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            200000
        ).hex()

        return secrets.compare_digest(
            new_hash,
            old_hash
        )

    except (ValueError, TypeError):
        return False


# ==================================
# INPUT MODELS
# ==================================

class RegisterData(BaseModel):
    username: str = Field(min_length=3, max_length=20)
    password: str = Field(min_length=8, max_length=100)


class LoginData(BaseModel):
    username: str = Field(min_length=3, max_length=20)
    password: str = Field(min_length=8, max_length=100)


class AmountData(BaseModel):
    coins: int = Field(gt=0, le=10000)


# ==================================
# AUTHENTICATION
# ==================================

def get_user(authorization):

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Please login first"
        )

    token = authorization.split(" ", 1)[1].strip()

    with get_db() as con:

        user = con.execute("""
            SELECT users.id, users.username, users.coins
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ?
            AND sessions.expires > ?
        """, (token, int(time.time()))).fetchone()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Session expired. Please login again"
        )

    return user


# ==================================
# HOME PAGE
# ==================================

@app.get("/")
def home():

    index_file = STATIC_DIR / "index.html"

    if not index_file.is_file():
        raise HTTPException(
            status_code=404,
            detail="Website file not found"
        )

    return FileResponse(index_file)


# ==================================
# HEALTH CHECK
# ==================================

@app.get("/api/health")
def health():

    return {
        "success": True,
        "status": "online",
        "app": "XO Arena",
        "version": "1.0.0"
    }


# ==================================
# REGISTER
# ==================================

@app.post("/api/register")
def register(data: RegisterData):

    username = data.username.strip().lower()

    if not username.replace("_", "").isalnum():
        raise HTTPException(
            status_code=400,
            detail="Username can contain letters, numbers and underscore only"
        )

    with get_db() as con:

        try:

            cursor = con.execute("""
                INSERT INTO users (username, password, coins)
                VALUES (?, ?, ?)
            """, (
                username,
                hash_password(data.password),
                WELCOME_COINS
            ))

            user_id = cursor.lastrowid

            con.execute("""
                INSERT INTO transactions
                (user_id, type, coins, status)
                VALUES (?, ?, ?, ?)
            """, (
                user_id,
                "Welcome Bonus",
                WELCOME_COINS,
                "Completed"
            ))

        except sqlite3.IntegrityError:

            raise HTTPException(
                status_code=409,
                detail="Username already exists"
            )

    return {
        "success": True,
        "message": "Account created successfully!",
        "welcome_coins": WELCOME_COINS,
        "coins": WELCOME_COINS
    }


# ==================================
# LOGIN
# ==================================

@app.post("/api/login")
def login(data: LoginData):

    username = data.username.strip().lower()

    with get_db() as con:

        user = con.execute("""
            SELECT * FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        if not user or not verify_password(
            data.password,
            user["password"]
        ):
            raise HTTPException(
                status_code=401,
                detail="Incorrect username or password"
            )

        token = secrets.token_urlsafe(32)

        expires = int(time.time()) + (
            SESSION_DAYS * 24 * 60 * 60
        )

        con.execute("""
            INSERT INTO sessions
            (token, user_id, expires)
            VALUES (?, ?, ?)
        """, (
            token,
            user["id"],
            expires
        ))

        return {
            "success": True,
            "message": "Login successful",
            "token": token,
            "username": user["username"],
            "coins": user["coins"]
        }


# ==================================
# USER PROFILE
# ==================================

@app.get("/api/me")
def me(authorization: str | None = Header(default=None)):

    user = get_user(authorization)

    return {
        "success": True,
        "username": user["username"],
        "coins": user["coins"],
        "demo_balance": user["coins"],
        "currency": "DEMO COINS"
    }


# ==================================
# DEMO DEPOSIT
# ==================================

@app.post("/api/wallet/deposit")
def deposit(
    data: AmountData,
    authorization: str | None = Header(default=None)
):

    user = get_user(authorization)

    with get_db() as con:

        con.execute("""
            UPDATE users
            SET coins = coins + ?
            WHERE id = ?
        """, (
            data.coins,
            user["id"]
        ))

        con.execute("""
            INSERT INTO transactions
            (user_id, type, coins, status)
            VALUES (?, ?, ?, ?)
        """, (
            user["id"],
            "Demo Deposit",
            data.coins,
            "Completed"
        ))

    return {
        "success": True,
        "message": "Demo coins added successfully",
        "added_coins": data.coins
    }


# ==================================
# DEMO WITHDRAWAL
# ==================================

@app.post("/api/wallet/withdraw")
def withdraw(
    data: AmountData,
    authorization: str | None = Header(default=None)
):

    user = get_user(authorization)

    with get_db() as con:

        cursor = con.execute("""
            UPDATE users
            SET coins = coins - ?
            WHERE id = ?
            AND coins >= ?
        """, (
            data.coins,
            user["id"],
            data.coins
        ))

        if cursor.rowcount == 0:

            raise HTTPException(
                status_code=400,
                detail="Insufficient demo coins"
            )

        con.execute("""
            INSERT INTO transactions
            (user_id, type, coins, status)
            VALUES (?, ?, ?, ?)
        """, (
            user["id"],
            "Demo Withdrawal",
            data.coins,
            "Demo Request"
        ))

    return {
        "success": True,
        "message": "Demo withdrawal recorded",
        "requested_coins": data.coins,
        "status": "Demo Request"
    }


# ==================================
# TRANSACTION HISTORY
# ==================================

@app.get("/api/wallet/history")
def history(
    authorization: str | None = Header(default=None)
):

    user = get_user(authorization)

    with get_db() as con:

        rows = con.execute("""
            SELECT type, coins, status, created_at
            FROM transactions
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user["id"],)).fetchall()

    return {
        "success": True,
        "transactions": [
            dict(row) for row in rows
        ]
    }


# ==================================
# LOGOUT
# ==================================

@app.post("/api/logout")
def logout(
    authorization: str | None = Header(default=None)
):

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please login first")

    token = authorization.split(" ", 1)[1].strip()

    with get_db() as con:

        con.execute(
            "DELETE FROM sessions WHERE token = ?",
            (token,)
        )

    return {
        "success": True,
        "message": "Logged out successfully"
    }


# ==================================
# STATIC FILES
# ==================================

if STATIC_DIR.is_dir():

    app.mount(
        "/static",
        StaticFiles(directory=STATIC_DIR),
        name="static"
        )
