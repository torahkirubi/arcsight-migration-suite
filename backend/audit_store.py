"""
audit_store.py - Persistent SQLite Audit Log for ArcSight Migrations

Tracks every translation, coverage validation, threat analysis run,
and live Splunk search with timestamps, pass/fail status, and details.
Persists to a SQLite database designed to be volume-mounted in Docker.
"""

from datetime import datetime, timezone
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional


DEFAULT_DB_PATH = os.environ.get("AUDIT_DB_PATH", os.path.join(os.path.dirname(__file__), "audit_history.db"))


def mask_sensitive(data: Any) -> Any:
    """Recursively redacts sensitive credentials (api_key, secret, password, token, auth) from audit records."""
    if isinstance(data, dict):
        masked = {}
        for k, v in data.items():
            if any(term in k.lower() for term in ("api_key", "secret", "password", "token", "auth", "credential")):
                masked[k] = "[REDACTED]"
            else:
                masked[k] = mask_sensitive(v)
        return masked
    elif isinstance(data, list):
        return [mask_sensitive(x) for x in data]
    return data


class AuditStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    provider TEXT,
                    model TEXT,
                    outcome TEXT NOT NULL,
                    coverage_pct REAL,
                    details_json TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_rule ON audit_logs(rule_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp DESC)")
            conn.commit()

    def log_event(
        self,
        rule_name: str,
        endpoint: str,
        outcome: str,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        coverage_pct: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        Record a migration event into the audit trail.
        Returns the inserted record ID.
        """
        now = datetime.now(timezone.utc).isoformat()
        safe_details = mask_sensitive(details or {})
        details_str = json.dumps(safe_details, default=str)

        with self._get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO audit_logs (
                    timestamp, rule_name, endpoint, provider, model, outcome, coverage_pct, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (now, rule_name, endpoint, provider, model, outcome, coverage_pct, details_str),
            )
            conn.commit()
            return cur.lastrowid

    def get_history(
        self,
        limit: int = 50,
        offset: int = 0,
        rule_name_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent audit events with pagination."""
        with self._get_connection() as conn:
            if rule_name_filter:
                query = """
                    SELECT * FROM audit_logs
                    WHERE rule_name LIKE ?
                    ORDER BY id DESC LIMIT ? OFFSET ?
                """
                cursor = conn.execute(query, (f"%{rule_name_filter}%", limit, offset))
            else:
                query = """
                    SELECT * FROM audit_logs
                    ORDER BY id DESC LIMIT ? OFFSET ?
                """
                cursor = conn.execute(query, (limit, offset))

            rows = cursor.fetchall()
            results = []
            for r in rows:
                try:
                    details = json.loads(r["details_json"]) if r["details_json"] else {}
                except Exception:
                    details = {}
                results.append({
                    "id": r["id"],
                    "timestamp": r["timestamp"],
                    "rule_name": r["rule_name"],
                    "endpoint": r["endpoint"],
                    "provider": r["provider"],
                    "model": r["model"],
                    "outcome": r["outcome"],
                    "coverage_pct": r["coverage_pct"],
                    "details": details,
                })
            return results

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate stats on total runs, pass rate, and recent counts."""
        with self._get_connection() as conn:
            total_count = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
            passed_count = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE outcome = 'passed' OR outcome = 'success'").fetchone()[0]
            failed_count = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE outcome = 'failed' OR outcome = 'error'").fetchone()[0]
            avg_cov = conn.execute("SELECT AVG(coverage_pct) FROM audit_logs WHERE coverage_pct IS NOT NULL").fetchone()[0]

            return {
                "total_events": total_count,
                "passed_count": passed_count,
                "failed_count": failed_count,
                "average_coverage_pct": round(avg_cov or 0.0, 1),
            }


# Default singleton instance
audit_store = AuditStore()

