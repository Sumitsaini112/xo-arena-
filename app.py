
import os
import sqlite3
import hashlib
import secrets
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "xo_arena.db"

app = FastAPI(title="XO Arena")

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def setup_database():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        coins INTEGER DEFAULT 10
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        coins INTEGER NOT NULL,
        status TEXT DEFAULT 'Completed',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    con.commit()
    con.close()

setup_database()

class RegisterData(BaseModel):
    username: str = Field(min_length=3, max_length=20)
    password: str = Field(min_length=8, max_length=100)

class LoginData(BaseModel):
    username: str
    password: str

class AmountData(BaseModel):
    coins: int = Field(gt=0, le=10000)

def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200000
    ).hex()
    return salt + "$" + hashed

def verify_password(password, stored):
    salt, old_hash = stored.split("$")
    new_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200000
    ).hex()
    return secrets.compare_digest(new_hash, old_hash)

def get_user(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please login first")

    token = authorization.split(" ", 1)[1]

    con = db()
    row = con.execute("""
        SELECT users.* FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ? AND sessions.expires > ?
    """, (token, int(time.time()))).fetchone()
    con.close()

    if not row:
        raise HTTPException(401, "Session expired. Please login again")

    return row

@app.get("/")
def home():
    return HTMLResponse("""
    <h1>XO ARENA</h1>
    <p>Premium Tic Tac Toe Gaming Website</p>
    <p>Backend is running successfully!</p>
    """)

@app.get("/api/health")
def health():
    return {"status": "online", "app": "XO Arena"}

@app.post("/api/register")
def register(data: RegisterData):
    username = data.username.strip().lower()

    if not username.replace("_", "").isalnum():
        raise HTTPException(400, "Use letters, numbers or underscore")

    con = db()

    try:
        cur = con.execute(
            "INSERT INTO users (username, password, coins) VALUES (?, ?, 10)",
            (username, hash_password(data.password))
        )
        user_id = cur.lastrowid

        con.execute("""
            INSERT INTO transactions (user_id, type, coins, status)
            VALUES (?, 'Welcome Bonus', 10, 'Completed')
        """, (user_id,))

        con.commit()
        return {
            "success": True,
            "message": "Account created! 10 demo coins received.",
            "coins": 10
        }

    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already exists")
    finally:
        con.close()

@app.post("/api/login")
def login(data: LoginData):
    username = data.username.strip().lower()

    con = db()
    user = con.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user or not verify_password(data.password, user["password"]):
        con.close()
        raise HTTPException(401, "Incorrect username or password")

    token = secrets.token_urlsafe(32)
    expires = int(time.time()) + 7 * 24 * 60 * 60

    con.execute(
        "INSERT INTO sessions (token, user_id, expires) VALUES (?, ?, ?)",
        (token, user["id"], expires)
    )
    con.commit()
    con.close()

    return {
        "success": True,
        "token": token,
        "username": username,
        "coins": user["coins"]
    }

@app.get("/api/me")
def me(authorization: str = Header(None)):
    user = get_user(authorization)

    return {
        "username": user["username"],
        "coins": user["coins"],
        "demo_balance": user["coins"],
        "currency": "DEMO ONLY"
    }

@app.post("/api/wallet/deposit")
def deposit(
    data: AmountData,
    authorization: str = Header(None)
):
    user = get_user(authorization)

    con = db()
    con.execute(
        "UPDATE users SET coins = coins + ? WHERE id = ?",
        (data.coins, user["id"])
    )
    con.execute("""
        INSERT INTO transactions (user_id, type, coins, status)
        VALUES (?, 'Demo Deposit', ?, 'Completed')
    """, (user["id"], data.coins))

    con.commit()
    con.close()

    return {
        "success": True,
        "message": "Demo coins added",
        "added_coins": data.coins
    }

@app.post("/api/wallet/withdraw")
def withdraw(
    data: AmountData,
    authorization: str = Header(None)
):
    user = get_user(authorization)

    con = db()
    current = con.execute(
        "SELECT coins FROM users WHERE id = ?", (user["id"],)
    ).fetchone()

    if current["coins"] < data.coins:
        con.close()
        raise HTTPException(400, "Insufficient demo coins")

    con.execute(
        "UPDATE users SET coins = coins - ? WHERE id = ?",
        (data.coins, user["id"])
    )

    con.execute("""
        INSERT INTO transactions (user_id, type, coins, status)
        VALUES (?, 'Demo Withdrawal', ?, 'Demo Request')
    """, (user["id"], data.coins))

    con.commit()
    con.close()

    return {
        "success": True,
        "message": "Demo withdrawal request recorded",
        "requested_coins": data.coins,
        "status": "Demo Request"
    }

@app.get("/api/wallet/history")
def history(authorization: str = Header(None)):
    user = get_user(authorization)

    con = db()
    rows = con.execute("""
        SELECT type, coins, status, created_at
        FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user["id"],)).fetchall()
    con.close()

    return {"transactions": [dict(row) for row in rows]}
