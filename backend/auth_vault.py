"""
auth_vault.py - Authentication & Encrypted Vault Storage for ArcSight Migration Suite

Provides:
- User model (id, username, hashed_password)
- Vault model (id, service_name, encrypted_credentials)
- init_auth_vault_db: SQLite database initialization confirming table creation
- VaultService: Fernet symmetric encryption and decryption of secrets
- create_jwt_token & verify_jwt_token: JWT creation and verification
- get_current_user: FastAPI dependency protecting routes
- auth_router: APIRouter for /api/auth/login and /api/auth/verify
"""

import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet
import jwt
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Fallback or standard FastAPI / Pydantic definitions
try:
    from pydantic import BaseModel
except ImportError:
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

try:
    from fastapi import APIRouter, Depends, HTTPException, Header, status
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

    class HTTPException(Exception):  # type: ignore
        def __init__(self, status_code: int, detail: str = ""):
            self.status_code = status_code
            self.detail = detail
            super().__init__(f"HTTP {status_code}: {detail}")

    def Header(default=None, **kwargs):  # type: ignore
        return default

    def Depends(dependency=None):  # type: ignore
        return dependency

    class status:  # type: ignore
        HTTP_200_OK = 200
        HTTP_201_CREATED = 201
        HTTP_400_BAD_REQUEST = 400
        HTTP_401_UNAUTHORIZED = 401
        HTTP_404_NOT_FOUND = 404
        HTTP_500_INTERNAL_SERVER_ERROR = 500

    class Route:  # type: ignore
        def __init__(self, path: str, endpoint: Any, methods: List[str], status_code: int = 200):
            self.path = path
            self.endpoint = endpoint
            self.methods = set(methods)
            self.status_code = status_code

    class APIRouter:  # type: ignore
        def __init__(self, prefix="", *args, **kwargs):
            self.prefix = prefix
            self.routes = []

        def post(self, path: str, *args, **kwargs):
            full_path = self.prefix + path
            status_code = kwargs.get("status_code", 200)
            def decorator(func):
                self.routes.append(Route(full_path, func, ["POST"], status_code=status_code))
                return func
            return decorator

        def get(self, path: str, *args, **kwargs):
            full_path = self.prefix + path
            status_code = kwargs.get("status_code", 200)
            def decorator(func):
                self.routes.append(Route(full_path, func, ["GET"], status_code=status_code))
                return func
            return decorator

# SQLAlchemy or SQLite Fallback
try:
    from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, inspect
    from sqlalchemy.orm import declarative_base, sessionmaker
    from sqlalchemy.pool import StaticPool
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

def resolve_vault_db_path() -> str:
    """
    Resolves the persistent SQLite database file path for the authentication vault.
    Prioritizes:
    1. VAULT_DB_PATH environment variable override.
    2. backend/data/vault.db persistent directory.
    3. Migrates legacy backend/vault.db if present.
    """
    env_path = os.environ.get("VAULT_DB_PATH")
    if env_path:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(env_path)), exist_ok=True)
        except Exception:
            pass
        return env_path

    base_dir = os.path.dirname(__file__)
    data_dir = os.path.join(base_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    target_path = os.path.join(data_dir, "vault.db")

    legacy_path = os.path.join(base_dir, "vault.db")
    if os.path.exists(legacy_path) and not os.path.exists(target_path):
        try:
            import shutil
            shutil.copy2(legacy_path, target_path)
        except Exception:
            pass

    return target_path


DEFAULT_VAULT_DB_PATH = resolve_vault_db_path()
APP_ENV = os.environ.get("APP_ENV", "development").lower()
DEFAULT_ADMIN_USER = os.environ.get("ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    "" if APP_ENV == "production" else "valid_password_123",
)
JWT_SECRET_KEY = os.environ.get(
    "JWT_SECRET_KEY",
    "" if APP_ENV == "production" else "arcsight-migration-suite-secret-key-super-secure",
)
JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """Computes bcrypt hash of password via passlib CryptContext."""
    if pwd_context is not None:
        return pwd_context.hash(password)
    salt = "arcsight_vault_salt_secure_2026"
    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a stored bcrypt hash or legacy SHA-256."""
    if pwd_context is not None and hashed_password:
        try:
            if hashed_password.startswith(("$2b$", "$2a$", "$2y$")):
                return pwd_context.verify(plain_password, hashed_password)
        except Exception:
            pass
    salt = "arcsight_vault_salt_secure_2026"
    legacy_hash = hashlib.sha256((plain_password + salt).encode("utf-8")).hexdigest()
    return legacy_hash == hashed_password


if HAS_SQLALCHEMY:
    Base = declarative_base()

    class User(Base):
        __tablename__ = "users"
        id = Column(Integer, primary_key=True, autoincrement=True)
        username = Column(String(100), unique=True, nullable=False)
        hashed_password = Column(String(255), nullable=False)
        created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

        def __init__(self, username=None, hashed_password=None, **kwargs):
            self.username = username
            self.hashed_password = hashed_password
            for k, v in kwargs.items():
                setattr(self, k, v)

    class Vault(Base):
        __tablename__ = "vault"
        id = Column(Integer, primary_key=True, autoincrement=True)
        service_name = Column(String(100), unique=True, nullable=False)
        encrypted_credentials = Column(Text, nullable=False)
        created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
        updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

        def __init__(self, service_name=None, encrypted_credentials=None, **kwargs):
            self.service_name = service_name or kwargs.get("key")
            self.encrypted_credentials = encrypted_credentials or kwargs.get("encrypted_value")
            for k, v in kwargs.items():
                setattr(self, k, v)

        @property
        def key(self):
            return self.service_name

        @key.setter
        def key(self, val):
            self.service_name = val

        @property
        def encrypted_value(self):
            return self.encrypted_credentials

        @encrypted_value.setter
        def encrypted_value(self, val):
            self.encrypted_credentials = val

    VaultCredential = Vault

else:
    class User:
        __tablename__ = "users"

        def __init__(self, id=None, username=None, hashed_password=None, created_at=None, **kwargs):
            self.id = id
            self.username = username
            self.hashed_password = hashed_password
            self.created_at = created_at or datetime.now(timezone.utc).isoformat()

    class Vault:
        __tablename__ = "vault"

        def __init__(self, id=None, service_name=None, encrypted_credentials=None, created_at=None, updated_at=None, **kwargs):
            self.id = id
            self.service_name = service_name or kwargs.get("key")
            self.encrypted_credentials = encrypted_credentials or kwargs.get("encrypted_value")
            self.created_at = created_at or datetime.now(timezone.utc).isoformat()
            self.updated_at = updated_at or datetime.now(timezone.utc).isoformat()

        @property
        def key(self):
            return self.service_name

        @key.setter
        def key(self, val):
            self.service_name = val

        @property
        def encrypted_value(self):
            return self.encrypted_credentials

        @encrypted_value.setter
        def encrypted_value(self, val):
            self.encrypted_credentials = val

    VaultCredential = Vault


class SQLiteFallbackEngine:
    """Lightweight SQLite engine wrapper providing connection management and table creation."""

    def __init__(self, db_uri: str):
        self.db_uri = db_uri
        if db_uri.startswith("sqlite:///"):
            self.db_path = db_uri[len("sqlite:///"):]
        elif db_uri.startswith("sqlite://"):
            self.db_path = db_uri[len("sqlite://"):]
        else:
            self.db_path = db_uri

        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        with self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    hashed_password TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS vault (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT UNIQUE NOT NULL,
                    encrypted_credentials TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def raw_connection(self):
        return self._conn

    def connect(self):
        return self._conn


def seed_default_admin(engine):
    """Ensures default admin credentials exist in users table."""
    try:
        conn = engine.raw_connection() if hasattr(engine, "raw_connection") else None
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (DEFAULT_ADMIN_USER,))
            if not cursor.fetchone():
                now = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    "INSERT INTO users (username, hashed_password, created_at) VALUES (?, ?, ?)",
                    (DEFAULT_ADMIN_USER, hash_password(DEFAULT_ADMIN_PASSWORD), now),
                )
                conn.commit()
    except Exception:
        pass


def init_auth_vault_db(db_uri: Optional[str] = None):
    """
    Initializes database engine and ensures User and Vault tables are created.
    Supports standard SQLAlchemy create_engine when available, with transparent SQLite fallback.
    """
    if db_uri is None:
        db_uri = f"sqlite:///{DEFAULT_VAULT_DB_PATH}"

    if HAS_SQLALCHEMY:
        connect_args = {"check_same_thread": False} if "sqlite" in db_uri else {}
        poolclass = StaticPool if ":memory:" in db_uri else None
        if poolclass:
            engine = create_engine(db_uri, connect_args=connect_args, poolclass=poolclass)
        else:
            engine = create_engine(db_uri, connect_args=connect_args)
        Base.metadata.create_all(bind=engine)
        seed_default_admin(engine)
        return engine
    else:
        engine = SQLiteFallbackEngine(db_uri)
        seed_default_admin(engine)
        return engine


class VaultService:
    """
    Manages symmetric encryption and decryption of secrets using cryptography.fernet.
    Guarantees plaintext is NEVER stored directly in the database.
    """

    def __init__(self, db_uri: Optional[str] = None, encryption_key: Optional[str] = None):
        if encryption_key is None:
            encryption_key = os.environ.get("VAULT_MASTER_KEY")
            if not encryption_key:
                if APP_ENV == "production":
                    raise RuntimeError("VAULT_MASTER_KEY is required in production.")
                # Deterministic fallback key derived from constant seed for environments without VAULT_MASTER_KEY
                encryption_key = base64.urlsafe_b64encode(
                    hashlib.sha256(b"arcsight-vault-master-key-default-seed-2026").digest()
                ).decode("utf-8")

        if isinstance(encryption_key, str):
            encryption_key = encryption_key.encode("utf-8")

        self.fernet = Fernet(encryption_key)

        if db_uri is None:
            db_uri = f"sqlite:///{DEFAULT_VAULT_DB_PATH}"
        self.db_uri = db_uri
        self.engine = init_auth_vault_db(db_uri)

    def save_secret(
        self,
        key: Optional[str] = None,
        plaintext: Optional[str] = None,
        service_name: Optional[str] = None,
        credentials: Optional[str] = None,
        *args,
        **kwargs,
    ) -> bool:
        """
        Encrypts plaintext payload via Fernet and stores the ciphertext in the vault table.
        """
        k = key or service_name
        val = plaintext if plaintext is not None else credentials
        if k is None and len(args) > 0:
            k = args[0]
        if val is None and len(args) > 1:
            val = args[1]
        if k is None:
            k = kwargs.get("key") or kwargs.get("service_name")
        if val is None:
            val = kwargs.get("plaintext") or kwargs.get("credentials") or kwargs.get("value")

        if not k or val is None:
            return False

        if isinstance(val, dict):
            val = json.dumps(val)

        # Symmetric encryption via Fernet
        encrypted_bytes = self.fernet.encrypt(val.encode("utf-8"))
        encrypted_str = encrypted_bytes.decode("utf-8")

        now = datetime.now(timezone.utc).isoformat()
        conn = self.engine.raw_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM vault WHERE service_name = ?", (k,))
        existing = cursor.fetchone()
        if existing:
            cursor.execute(
                "UPDATE vault SET encrypted_credentials = ?, updated_at = ? WHERE service_name = ?",
                (encrypted_str, now, k),
            )
        else:
            cursor.execute(
                "INSERT INTO vault (service_name, encrypted_credentials, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (k, encrypted_str, now, now),
            )
        conn.commit()
        return True

    def get_secret(
        self,
        key: Optional[str] = None,
        service_name: Optional[str] = None,
        *args,
        **kwargs,
    ) -> Optional[str]:
        """
        Fetches ciphertext token from vault table and decrypts back into plaintext string.
        """
        k = key or service_name
        if k is None and len(args) > 0:
            k = args[0]
        if k is None:
            k = kwargs.get("key") or kwargs.get("service_name")

        if not k:
            return None

        conn = self.engine.raw_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_credentials FROM vault WHERE service_name = ?", (k,))
        row = cursor.fetchone()
        if not row:
            # Case-insensitive fallback query
            cursor.execute("SELECT encrypted_credentials FROM vault WHERE LOWER(service_name) = LOWER(?)", (k,))
            row = cursor.fetchone()
        if not row:
            return None

        encrypted_str = row[0]
        decrypted_bytes = self.fernet.decrypt(encrypted_str.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")

    def get_raw_db_rows(self) -> List[Dict[str, Any]]:
        """
        Retrieves raw SQLite database rows without decryption for cryptographic verification.
        """
        conn = self.engine.raw_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, service_name, encrypted_credentials, created_at, updated_at FROM vault")
        rows = cursor.fetchall()
        result = []
        for r in rows:
            result.append({
                "id": r[0],
                "service_name": r[1],
                "key": r[1],
                "encrypted_credentials": r[2],
                "encrypted_value": r[2],
                "created_at": r[3],
                "updated_at": r[4],
            })
        return result


def create_jwt_token(username: str, expires_minutes: int = 60) -> str:
    """Creates a signed JWT bearer token with subject and expiration."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        return token.decode("utf-8")
    return token


def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT bearer token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception:
        return None


def authenticate_user(username: str, password: str) -> bool:
    """Validates user credentials against configured admin or SQLite database."""
    if username == DEFAULT_ADMIN_USER and password == DEFAULT_ADMIN_PASSWORD:
        return True
    try:
        engine = init_auth_vault_db()
        conn = engine.raw_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row and verify_password(password, row[0]):
            return True
    except Exception:
        pass
    return False


async def get_current_user(authorization: Optional[str] = Header(None)) -> str:
    """
    FastAPI dependency validating Authorization: Bearer <token>.
    Raises 401 Unauthorized if missing, malformed, or invalid.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED if hasattr(status, "HTTP_401_UNAUTHORIZED") else 401,
            detail="Authorization header missing",
        )
    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED if hasattr(status, "HTTP_401_UNAUTHORIZED") else 401,
            detail="Invalid authorization scheme, expected 'Bearer <token>'",
        )
    token = parts[1]
    payload = verify_jwt_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED if hasattr(status, "HTTP_401_UNAUTHORIZED") else 401,
            detail="Invalid or expired authentication token",
        )
    return payload["sub"]


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str


auth_router = APIRouter()


@auth_router.post(
    "/api/auth/register",
    status_code=status.HTTP_201_CREATED if hasattr(status, "HTTP_201_CREATED") else 201,
)
async def register_endpoint(payload: RegisterRequest):
    """
    POST /api/auth/register registers a new user with bcrypt-hashed credentials.
    """
    username = getattr(payload, "username", None) or (payload.get("username") if isinstance(payload, dict) else None)
    password = getattr(payload, "password", None) or (payload.get("password") if isinstance(payload, dict) else None)

    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST if hasattr(status, "HTTP_400_BAD_REQUEST") else 400,
            detail="Username and password are required",
        )

    engine = init_auth_vault_db()
    conn = engine.raw_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST if hasattr(status, "HTTP_400_BAD_REQUEST") else 400,
            detail="Username already registered",
        )

    hashed_pw = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        "INSERT INTO users (username, hashed_password, created_at) VALUES (?, ?, ?)",
        (username, hashed_pw, now),
    )
    conn.commit()

    return {
        "username": username,
        "status": "created",
    }


@auth_router.post("/api/auth/login")
async def login_endpoint(payload: LoginRequest):
    """
    POST /api/auth/login validates credentials and returns a JWT bearer token.
    """
    username = getattr(payload, "username", None) or (payload.get("username") if isinstance(payload, dict) else None)
    password = getattr(payload, "password", None) or (payload.get("password") if isinstance(payload, dict) else None)

    if not username or not password or not authenticate_user(username, password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED if hasattr(status, "HTTP_401_UNAUTHORIZED") else 401,
            detail="Invalid username or password",
        )

    token = create_jwt_token(username)
    return {
        "access_token": token,
        "token_type": "bearer",
    }


@auth_router.get("/api/auth/verify")
async def verify_endpoint(
    authorization: Optional[str] = Header(None),
    current_user: Optional[str] = Depends(get_current_user) if HAS_FASTAPI else None,
):
    """
    GET /api/auth/verify protected endpoint requiring valid Bearer token.
    """
    user = current_user or await get_current_user(authorization=authorization)
    return {
        "authenticated": True,
        "username": user,
    }
