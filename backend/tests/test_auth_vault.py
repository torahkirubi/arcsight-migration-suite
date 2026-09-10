"""
test_auth_vault.py - TDD unit tests for JWT Authentication, SQLAlchemy SQLite Database Initialization, and Fernet Encrypted Vault Storage
"""

import os
import sqlite3
import unittest
from unittest.mock import patch, MagicMock
from cryptography.fernet import Fernet
import jwt

from backend.app import app

try:
    from fastapi.testclient import TestClient
except ImportError:
    class TestResponse:
        """Fallback TestResponse when fastapi is not installed in the test environment."""

        def __init__(self, status_code: int, data: dict):
            self.status_code = status_code
            self._data = data

        def json(self):
            return self._data if isinstance(self._data, dict) else {}

    class TestClient:
        """Fallback TestClient when fastapi.testclient is not installed in the test environment."""

        def __init__(self, app=None):
            self.app = app

        def _dispatch(self, method: str, url: str, json: dict = None, headers: dict = None, params: dict = None):
            if self.app is None:
                return TestResponse(404, {"detail": "Endpoint not found (app is None)"})

            routes = getattr(self.app, "routes", [])
            for route in routes:
                route_path = getattr(route, "path", None)
                route_methods = getattr(route, "methods", set())
                if route_path == url and method in route_methods:
                    endpoint = getattr(route, "endpoint", None)
                    if endpoint:
                        import inspect
                        import asyncio

                        sig = inspect.signature(endpoint)
                        kwargs = {}
                        for name, param in sig.parameters.items():
                            if name in ("payload", "body", "credentials", "login_data", "request"):
                                ann = param.annotation
                                if ann != inspect.Parameter.empty and callable(ann):
                                    try:
                                        kwargs[name] = ann(**(json or {}))
                                    except Exception:
                                        kwargs[name] = json
                                else:
                                    kwargs[name] = json
                            elif name in ("authorization", "token"):
                                auth_header = (headers or {}).get("Authorization") or (headers or {}).get("authorization")
                                kwargs[name] = auth_header
                            elif params and name in params:
                                kwargs[name] = params[name]

                        try:
                            if inspect.iscoroutinefunction(endpoint):
                                res = asyncio.run(endpoint(**kwargs))
                            else:
                                res = endpoint(**kwargs)
                            status_code = getattr(route, "status_code", 200)
                            if hasattr(res, "status_code"):
                                status_code = res.status_code
                            if hasattr(res, "body"):
                                import json as json_mod
                                try:
                                    res_data = json_mod.loads(res.body)
                                except Exception:
                                    res_data = {}
                            else:
                                res_data = res if isinstance(res, (dict, list)) else {}
                            return TestResponse(status_code, res_data)
                        except Exception as exc:
                            status_code = getattr(exc, "status_code", 500)
                            detail = getattr(exc, "detail", str(exc))
                            return TestResponse(status_code, {"detail": detail, "error": str(exc)})

            return TestResponse(404, {"detail": f"Route {url} not found"})

        def post(self, url: str, json: dict = None, headers: dict = None):
            return self._dispatch("POST", url, json=json, headers=headers)

        def get(self, url: str, headers: dict = None, params: dict = None):
            return self._dispatch("GET", url, headers=headers, params=params)


try:
    from backend.auth_vault import (
        init_auth_vault_db,
        User,
        VaultCredential,
        VaultService,
        create_jwt_token,
        verify_jwt_token,
    )
except ImportError:
    init_auth_vault_db = None
    User = None
    VaultCredential = None
    VaultService = None
    create_jwt_token = None
    verify_jwt_token = None


class TestAuthVault(unittest.TestCase):
    """Test suite for JWT authentication, SQLAlchemy SQLite initialization, and Fernet encrypted vault."""

    def setUp(self):
        self.client = TestClient(app)
        self.valid_credentials = {
            "username": "admin",
            "password": "valid_password_123",
        }
        self.invalid_credentials = {
            "username": "admin",
            "password": "wrong_password",
        }
        try:
            if init_auth_vault_db is not None:
                engine = init_auth_vault_db()
                conn = engine.raw_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM users WHERE username IN (?, ?, ?)",
                    ("secops_analyst_1", "duplicate_analyst", "login_test_analyst"),
                )
                conn.commit()
        except Exception:
            pass

    # =========================================================================
    # 1. JWT Authentication Requirements
    # =========================================================================

    def test_login_success_returns_jwt_token(self):
        """Verify POST /api/auth/login accepts valid credentials and returns a valid JWT bearer token."""
        response = self.client.post("/api/auth/login", json=self.valid_credentials)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn("access_token", data)
        self.assertEqual(data.get("token_type", "").lower(), "bearer")

        # Verify JWT token structure (3 segments: header.payload.signature)
        token = data["access_token"]
        segments = token.split(".")
        self.assertEqual(len(segments), 3, "JWT token must consist of header, payload, and signature")

    def test_login_failure_invalid_credentials_returns_401(self):
        """Verify POST /api/auth/login returns 401 Unauthorized when credentials are invalid."""
        response = self.client.post("/api/auth/login", json=self.invalid_credentials)
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn("detail", data)

    def test_protected_route_requires_bearer_token(self):
        """Verify protected GET /api/auth/verify rejects requests without a valid token with 401 Unauthorized."""
        # Case 1: No Authorization header
        response_no_token = self.client.get("/api/auth/verify")
        self.assertEqual(response_no_token.status_code, 401)

        # Case 2: Invalid/malformed Bearer token
        response_bad_token = self.client.get(
            "/api/auth/verify",
            headers={"Authorization": "Bearer invalid.malformed.token"},
        )
        self.assertEqual(response_bad_token.status_code, 401)

    def test_protected_route_succeeds_with_valid_bearer_token(self):
        """Verify protected GET /api/auth/verify succeeds with 200 OK when a valid Bearer token is provided."""
        login_response = self.client.post("/api/auth/login", json=self.valid_credentials)
        self.assertEqual(login_response.status_code, 200)

        token = login_response.json().get("access_token")
        self.assertIsNotNone(token)

        response = self.client.get(
            "/api/auth/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("authenticated", False))
        self.assertEqual(data.get("username"), "admin")

    # =========================================================================
    # 1B. User Registration Requirements (passlib + bcrypt)
    # =========================================================================

    def test_user_registration_creates_user_with_bcrypt_hash(self):
        """Test POST /api/auth/register creates a user with passlib bcrypt hashed password in SQLite."""
        new_user_data = {
            "username": "secops_analyst_1",
            "password": "SuperSecretPassword456!",
        }
        response = self.client.post("/api/auth/register", json=new_user_data)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn("username", data)
        self.assertEqual(data["username"], "secops_analyst_1")

        # Verify in SQLite database directly
        engine = init_auth_vault_db()
        conn = engine.raw_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_password FROM users WHERE username = ?", ("secops_analyst_1",))
        row = cursor.fetchone()
        self.assertIsNotNone(row, "User must exist in users table")
        stored_hash = row[0]

        # Assert plaintext password is NEVER stored directly
        self.assertNotEqual(stored_hash, new_user_data["password"])

        # Assert hash format is valid bcrypt (starts with $2b$, $2a$, or $2y$)
        self.assertTrue(
            stored_hash.startswith(("$2b$", "$2a$", "$2y$")),
            f"Stored password hash must be a valid bcrypt hash, got: {stored_hash}",
        )

        # Assert passlib / bcrypt verification succeeds
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.assertTrue(
            pwd_context.verify(new_user_data["password"], stored_hash),
            "Stored hash must be verifiable by passlib bcrypt CryptContext",
        )

    def test_user_registration_duplicate_username_returns_400(self):
        """Test that submitting an already registered username returns 400 Bad Request."""
        user_data = {
            "username": "duplicate_analyst",
            "password": "InitialPassword123!",
        }
        # First registration
        res1 = self.client.post("/api/auth/register", json=user_data)
        self.assertEqual(res1.status_code, 201)

        # Duplicate registration with same username
        res2 = self.client.post("/api/auth/register", json=user_data)
        self.assertEqual(res2.status_code, 400)
        data = res2.json()
        self.assertIn("detail", data)

    def test_user_registered_can_immediately_login(self):
        """Assert that a user created via POST /api/auth/register can immediately authenticate via POST /api/auth/login."""
        registered_user = {
            "username": "login_test_analyst",
            "password": "ValidLoginPassword789!",
        }
        reg_response = self.client.post("/api/auth/register", json=registered_user)
        self.assertEqual(reg_response.status_code, 201)

        # Attempt login with newly registered credentials
        login_response = self.client.post("/api/auth/login", json=registered_user)
        self.assertEqual(login_response.status_code, 200)

        token_data = login_response.json()
        self.assertIn("access_token", token_data)
        self.assertEqual(token_data.get("token_type", "").lower(), "bearer")

        # Verify the access token against protected /api/auth/verify
        verify_response = self.client.get(
            "/api/auth/verify",
            headers={"Authorization": f"Bearer {token_data['access_token']}"},
        )
        self.assertEqual(verify_response.status_code, 200)
        self.assertEqual(verify_response.json().get("username"), "login_test_analyst")

    # =========================================================================
    # 2. Database Initialization Requirements (SQLAlchemy + SQLite)
    # =========================================================================

    def test_database_initialization_creates_user_and_vault_tables(self):
        """Verify SQLAlchemy SQLite database initializes correctly and confirms creation of User and Vault tables."""
        if init_auth_vault_db is None:
            self.fail("init_auth_vault_db is not implemented in backend.auth_vault")

        # Initialize in-memory or temp SQLite engine via SQLAlchemy
        engine = init_auth_vault_db("sqlite:///:memory:")
        self.assertIsNotNone(engine)

        # Inspect table names created in the SQLite database
        try:
            from sqlalchemy import inspect
            inspector = inspect(engine)
            table_names = inspector.get_table_names()
        except Exception:
            # Fallback direct inspection if running without full sqlalchemy inspection
            raw_conn = engine.raw_connection() if hasattr(engine, "raw_connection") else None
            if raw_conn:
                cursor = raw_conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                table_names = [row[0] for row in cursor.fetchall()]
            else:
                table_names = []

        # Confirm creation of User table and Vault table
        has_user_table = any("user" in t.lower() for t in table_names)
        has_vault_table = any("vault" in t.lower() for t in table_names)

        self.assertTrue(has_user_table, f"Expected User table in database, found tables: {table_names}")
        self.assertTrue(has_vault_table, f"Expected Vault table in database, found tables: {table_names}")

    # =========================================================================
    # 3. Encrypted Storage Requirements (Fernet Encryption)
    # =========================================================================

    @patch.object(Fernet, "encrypt", autospec=True, side_effect=Fernet.encrypt)
    def test_encrypted_storage_encrypts_credentials_before_writing_to_db(self, mock_encrypt):
        """Verify credentials (Azure secrets, Gemini API keys) are encrypted via Fernet before being written to SQLite."""
        if VaultService is None:
            self.fail("VaultService is not implemented in backend.auth_vault")

        encryption_key = Fernet.generate_key().decode()
        vault = VaultService(db_uri="sqlite:///:memory:", encryption_key=encryption_key)

        secret_name = "AZURE_CLIENT_SECRET"
        plaintext_secret = "super-sensitive-azure-client-secret-xyz"

        # Save secret to vault
        save_success = vault.save_secret(key=secret_name, plaintext=plaintext_secret)
        self.assertTrue(save_success)

        # Verify Fernet.encrypt was invoked
        mock_encrypt.assert_called()

        # Query the underlying SQLite database directly to confirm plaintext is NEVER written to disk
        raw_rows = vault.get_raw_db_rows()
        self.assertGreater(len(raw_rows), 0)

        stored_raw_value = raw_rows[0].get("encrypted_value")
        self.assertIsNotNone(stored_raw_value)
        self.assertNotEqual(stored_raw_value, plaintext_secret, "Plaintext secret must NEVER be stored directly in the database")
        self.assertTrue(stored_raw_value.startswith("gAAAAA"), "Stored secret must be a valid Fernet ciphertext token")

    @patch.object(Fernet, "decrypt", autospec=True, side_effect=Fernet.decrypt)
    def test_encrypted_storage_decrypts_credentials_when_read_into_memory(self, mock_decrypt):
        """Verify encrypted credentials stored in SQLite are decrypted back into plaintext when read into memory."""
        if VaultService is None:
            self.fail("VaultService is not implemented in backend.auth_vault")

        encryption_key = Fernet.generate_key().decode()
        vault = VaultService(db_uri="sqlite:///:memory:", encryption_key=encryption_key)

        gemini_secret_name = "GEMINI_API_KEY"
        gemini_plaintext = "AIzaSy-sample-production-gemini-key-999"

        vault.save_secret(key=gemini_secret_name, plaintext=gemini_plaintext)

        # Read back into memory
        retrieved_secret = vault.get_secret(key=gemini_secret_name)

        # Confirm decrypted value matches the original plaintext
        self.assertEqual(retrieved_secret, gemini_plaintext)
        mock_decrypt.assert_called()

    def test_vault_db_persistent_directory_resolution(self):
        """Verify that vault.db resolves to a persistent data directory and respects VAULT_DB_PATH."""
        from backend.auth_vault import resolve_vault_db_path

        # 1. Test custom environment variable override
        with patch.dict(os.environ, {"VAULT_DB_PATH": "/app/backend/data/custom_vault.db"}):
            self.assertEqual(resolve_vault_db_path(), "/app/backend/data/custom_vault.db")

        # 2. Test default resolution points into a persistent data directory
        with patch.dict(os.environ, {}, clear=True):
            resolved = resolve_vault_db_path()
            self.assertTrue(
                resolved.endswith(os.path.join("data", "vault.db")),
                f"Expected path ending with data/vault.db, got: {resolved}",
            )


if __name__ == "__main__":
    unittest.main()

