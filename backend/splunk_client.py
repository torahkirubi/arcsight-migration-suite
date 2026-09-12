"""
splunk_client.py - Read-Only Splunk REST API Client for SPL Validation

Executes bounded 'oneshot' search jobs against a real Splunk instance
REST API (port 8089 by default) to fetch:
- Real hit counts
- Sample events
- Splunk's exact parser and syntax errors

CRITICAL SAFETY BOUNDARY:
This client is STRICTLY READ-ONLY. It never creates, schedules, or modifies
saved searches, alerts, indexes, or configurations in Splunk.
"""

import os
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional
import warnings

# Suppress insecure HTTPS / self-signed certificate warnings in logs
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

warnings.filterwarnings("ignore", message=".*Unverified HTTPS request.*")
warnings.filterwarnings("ignore", message=".*certificate verify failed.*")

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    import urllib.request
    import urllib.error
    import ssl


class SplunkError(Exception):
    pass


class SplunkTestClient:
    """
    Read-only test runner interfacing with Splunk's REST API endpoint:
    POST /services/search/jobs/export or POST /services/search/v2/jobs (exec_mode=oneshot)
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        verify_ssl: bool = False,
    ):
        # Fetch host/URL from parameter or environment (SPLUNK_HOST)
        raw_host = (host or "").strip() or os.environ.get("SPLUNK_HOST", "https://splunk:8089").strip()
        if raw_host.startswith("http://") or raw_host.startswith("https://"):
            parsed = urllib.parse.urlparse(raw_host)
            self.base_url = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
            self.host = parsed.hostname or raw_host
            self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        else:
            self.host = raw_host
            self.port = port or int(os.environ.get("SPLUNK_PORT", "8089"))
            self.base_url = f"https://{self.host}:{self.port}"

        # Fetch credentials from parameter or environment (SPLUNK_USER or SPLUNK_USERNAME, SPLUNK_PASSWORD)
        self.username = (
            (username or "").strip()
            or os.environ.get("SPLUNK_USER", "").strip()
            or os.environ.get("SPLUNK_USERNAME", "admin").strip()
            or "admin"
        )
        self.password = (
            (password or "").strip()
            or os.environ.get("SPLUNK_PASSWORD", "").strip()
        )
        self.token = (token or "").strip() or os.environ.get("SPLUNK_TOKEN", "").strip()

        # Since local Docker Splunk instance uses a self-signed certificate, bypass SSL verification
        self.verify_ssl = os.environ.get("SPLUNK_VERIFY_SSL", "false").lower() == "true"

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _get_auth(self) -> Optional[tuple]:
        if not self.token and self.username and self.password:
            return (self.username, self.password)
        return None

    @staticmethod
    def validate_read_only_query(query: str) -> None:
        """Reject SPL commands that mutate Splunk or access unapproved indexes."""
        if not query.strip():
            raise SplunkError("SPL query cannot be empty")
        lowered = query.lower()
        if ";" in query:
            raise SplunkError("Multiple SPL statements are not allowed")
        forbidden = (
            "loadjob", "savedsearch", "script", "map", "rest", "inputlookup",
            "outputlookup", "collect", "sendemail", "delete",
        )
        if any(token in lowered for token in forbidden):
            raise SplunkError("SPL command is not permitted by the read-only policy")
        indexes = re.findall(r"\bindex\s*=\s*([A-Za-z0-9_.-]+)", query, re.IGNORECASE)
        allowed_indexes = {
            value.strip() for value in os.environ.get(
                "SPLUNK_ALLOWED_INDEXES", "main,security,notable"
            ).split(",") if value.strip()
        }
        if not indexes or any(index not in allowed_indexes for index in indexes):
            raise SplunkError(
                "SPL query must target an approved index. Configure SPLUNK_ALLOWED_INDEXES."
            )

    @staticmethod
    def _parse_splunk_error(text: str, status_code: int) -> str:
        """Extracts clean, readable error message from Splunk's JSON or XML response."""
        clean = text.strip()
        if not clean:
            return f"Splunk returned HTTP {status_code}"

        # Try JSON message extraction
        try:
            import json
            data = json.loads(clean)
            if isinstance(data, dict) and "messages" in data:
                msgs = [m.get("text") for m in data["messages"] if isinstance(m, dict) and m.get("text")]
                if msgs:
                    return "; ".join(msgs)
        except Exception:
            pass

        # Try XML message extraction
        if "<msg" in clean:
            matches = re.findall(r'<msg[^>]*>([^<]+)</msg>', clean)
            if matches:
                return "; ".join(matches)

        return f"Splunk HTTP {status_code}: {clean[:200]}"

    async def test_connection(self) -> Dict[str, Any]:
        """
        Tests connectivity to Splunk REST API using /services/server/info.
        """
        start = time.time()
        url = f"{self.base_url}/services/server/info?output_mode=json"

        if HAS_HTTPX:
            try:
                async with httpx.AsyncClient(verify=self.verify_ssl, timeout=5.0) as client:
                    resp = await client.get(
                        url,
                        headers=self._get_headers(),
                        auth=self._get_auth(),
                    )
                    latency = round((time.time() - start) * 1000, 1)
                    if resp.status_code == 200:
                        data = resp.json()
                        entry = data.get("entry", [{}])
                        content = entry[0].get("content", {}) if entry and isinstance(entry[0], dict) else {}
                        return {
                            "status": "connected",
                            "server_name": content.get("serverName", self.host),
                            "version": content.get("version", "unknown"),
                            "license_state": content.get("licenseState", "unknown"),
                            "latency_ms": latency,
                        }
                    elif resp.status_code in (401, 403):
                        return {
                            "status": "unauthorized",
                            "error": "Authentication failed (invalid credentials/token)",
                            "latency_ms": latency,
                        }
                    else:
                        error_msg = self._parse_splunk_error(resp.text, resp.status_code)
                        return {
                            "status": "degraded",
                            "error": error_msg,
                            "latency_ms": latency,
                        }
            except Exception as e:
                latency = round((time.time() - start) * 1000, 1)
                return {
                    "status": "unreachable",
                    "error": str(e),
                    "latency_ms": latency,
                }
        else:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers=self._get_headers())
                if not self.token and self.username and self.password:
                    import base64
                    creds = f"{self.username}:{self.password}".encode("ascii")
                    req.add_header("Authorization", f"Basic {base64.b64encode(creds).decode('ascii')}")

                with urllib.request.urlopen(req, context=ctx, timeout=5.0) as resp:
                    latency = round((time.time() - start) * 1000, 1)
                    return {
                        "status": "connected",
                        "server_name": self.host,
                        "version": "unknown",
                        "latency_ms": latency,
                    }
            except Exception as e:
                latency = round((time.time() - start) * 1000, 1)
                return {
                    "status": "unreachable",
                    "error": str(e),
                    "latency_ms": latency,
                }

    async def execute_oneshot_search(
        self,
        spl_query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_events: int = 25,
    ) -> Dict[str, Any]:
        """
        Executes a strictly bounded oneshot search job.
        Does NOT modify or schedule any resources in Splunk.
        """
        # Aggressively sanitize query to eliminate markdown code fences / tickmarks
        query = spl_query.strip()
        if "```" in query:
            lines = [l for l in query.splitlines() if not re.match(r"^\s*```[a-zA-Z0-9_-]*\s*$", l.strip())]
            query = "\n".join(lines).strip()
            query = re.sub(r"```[a-zA-Z0-9_-]*", "", query)
            query = query.replace("```", "").strip()

        if query.startswith("`") and query.endswith("`") and len(query) > 2:
            inner = query[1:-1].strip()
            if any(c in inner for c in ["\n", "|", " "]):
                query = inner

        self.validate_read_only_query(query)

        # Ensure query starts with search if not piped
        if not query.startswith("|") and not query.startswith("search"):
            query = f"search {query}"

        url = f"{self.base_url}/services/search/jobs/export"
        payload = {
            "search": query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "max_count": max_events,
            "output_mode": "json",
            "exec_mode": "oneshot",
        }

        if HAS_HTTPX:
            try:
                async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
                    resp = await client.post(
                        url,
                        data=payload,
                        headers=self._get_headers(),
                        auth=self._get_auth(),
                    )
                    if resp.status_code == 200:
                        # Splunk exports JSON lines
                        lines = resp.text.strip().splitlines()
                        events = []
                        import json
                        for line in lines:
                            line_str = line.strip()
                            if not line_str:
                                continue
                            try:
                                obj = json.loads(line_str)
                                if "result" in obj:
                                    events.append(obj["result"])
                                elif "messages" in obj:
                                    pass
                            except Exception:
                                pass

                        return {
                            "success": True,
                            "query": query,
                            "hit_count": len(events),
                            "sample_events": events[:max_events],
                            "messages": [],
                        }
                    else:
                        error_msg = self._parse_splunk_error(resp.text, resp.status_code)
                        return {
                            "success": False,
                            "query": query,
                            "hit_count": 0,
                            "error": error_msg,
                            "sample_events": [],
                        }
            except Exception as exc:
                return {
                    "success": False,
                    "query": query,
                    "hit_count": 0,
                    "error": str(exc),
                    "sample_events": [],
                }
        else:
            return {
                "success": False,
                "query": query,
                "hit_count": 0,
                "error": "httpx library not available in environment",
                "sample_events": [],
            }
