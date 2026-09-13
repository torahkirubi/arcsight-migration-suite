"""
llm_client.py - Dual-Model Routing LLM Client

Supports dynamic on-the-fly toggling between:
1. Local Model: LM Studio (or Ollama/LocalAI) via OpenAI-compatible endpoint
   (LM_STUDIO_BASE_URL default: http://localhost:1234/v1 or host.docker.internal:1234/v1)
2. Cloud APIs: OpenAI, Anthropic, Gemini, or custom OpenAI-compatible cloud endpoints.

Features:
- Structured exception hierarchy (LLMConnectionError, LLMTruncationError, LLMAuthError)
- Dynamic request-level provider/model/api_key overrides without restarting server
- Health check inspection for active model and endpoint latency
"""

import os
import json
import re
import time
import logging
from typing import Any, Dict, List, Optional
from abc import ABC, abstractmethod
from urllib.parse import quote

logger = logging.getLogger(__name__)

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    import urllib.request
    import urllib.error


class LLMError(Exception):
    """Base exception for LLM client errors."""
    pass


class LLMConnectionError(LLMError):
    """Raised when the LLM service cannot be reached (e.g. LM Studio not running)."""
    pass


class LLMTruncationError(LLMError):
    """Raised when the LLM response was truncated due to context limit (finish_reason == 'length')."""
    pass


class LLMAuthError(LLMError):
    """Raised when authentication fails with cloud provider (e.g. invalid or missing API key)."""
    pass


class BaseLLMClient(ABC):
    """Abstract interface for LLM client implementations."""

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        model_override: Optional[str] = None,
        api_key_override: Optional[str] = None,
        response_schema: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Submit a completion request and return the text response."""
        pass

    @abstractmethod
    async def health_check(self, api_key_override: Optional[str] = None) -> Dict[str, Any]:
        """Probe connectivity and return status dict."""
        pass


class OpenAICompatibleClient(BaseLLMClient):
    """
    Client for OpenAI-compatible REST APIs (/v1/chat/completions).
    Works with LM Studio, Ollama, vLLM, OpenAI, Groq, Together, DeepSeek, etc.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        default_model: Optional[str] = None,
        provider_name: str = "LM Studio",
        allow_environment_key: bool = True,
    ):
        self.base_url = (
            base_url
            or os.environ.get("LM_STUDIO_BASE_URL")
            or "http://localhost:1234/v1"
        ).rstrip("/")

        # Clean and store the dynamically supplied API key
        raw_key = (api_key or "").strip()
        is_cloud_provider = (
            "cloud" in provider_name.lower()
            or "gemini" in provider_name.lower()
            or "google" in provider_name.lower()
        )
        if not raw_key and allow_environment_key and "cloud" in provider_name.lower():
            raw_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
        elif not raw_key and allow_environment_key and ("gemini" in provider_name.lower() or "google" in provider_name.lower()):
            raw_key = (os.environ.get("GEMINI_API_KEY") or os.environ.get("gemini_api_key") or "").strip()

        if raw_key.lower().startswith("bearer "):
            raw_key = raw_key[7:].strip()

        # Only fall back to 'not-needed' for local servers; cloud servers preserve empty key to signal missing auth
        if raw_key:
            self.api_key = raw_key
        elif is_cloud_provider:
            self.api_key = ""
        else:
            self.api_key = "not-needed"

        self.default_model = (
            default_model
            or os.environ.get("DEFAULT_LLM_MODEL")
            or "qwen2.5-coder-7b-instruct"
        )
        self.provider_name = provider_name
        self.allow_environment_key = allow_environment_key

    def _resolve_api_key(self, api_key_override: Optional[str] = None) -> str:
        """Dynamically resolves the API key with priority: override -> instance -> environment."""
        key = (api_key_override or "").strip()
        if not key:
            key = (self.api_key or "").strip()
        if key == "not-needed":
            return key
        if not key and "cloud" in self.provider_name.lower() and self.allow_environment_key:
            key = (os.environ.get("OPENAI_API_KEY") or "").strip()
        if not key and self.allow_environment_key and ("gemini" in self.provider_name.lower() or "google" in self.provider_name.lower()):
            key = (os.environ.get("GEMINI_API_KEY") or os.environ.get("gemini_api_key") or "").strip()
        if key.lower().startswith("bearer "):
            key = key[7:].strip()
        return key

    async def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.1,
        max_tokens: int = 8192,
        model_override: Optional[str] = None,
        api_key_override: Optional[str] = None,
        response_schema: Optional[Dict[str, Any]] = None,
    ) -> str:
        model = model_override or self.default_model
        is_gemini = (
            "gemini" in self.provider_name.lower()
            or "google" in self.provider_name.lower()
            or "generativelanguage" in self.base_url.lower()
        )
        has_openai_compat_path = bool(re.search(r"/openai(?:/|$)", self.base_url, re.IGNORECASE))
        native_gemini = is_gemini and not has_openai_compat_path
        native_base_url = re.sub(r"/openai/?$", "", self.base_url, flags=re.IGNORECASE).rstrip("/")
        endpoint = (
            f"{native_base_url}/models/{model}:generateContent"
            if native_gemini
            else f"{self.base_url}/chat/completions"
        )
        effective_key = self._resolve_api_key(api_key_override)
        if effective_key and effective_key != "not-needed":
            effective_key = effective_key.strip().strip('"').strip("'")
            if effective_key.lower().startswith("bearer "):
                effective_key = effective_key[7:].strip()

        # If Gemini provider, ensure API key is configured or raise descriptive error
        if is_gemini:
            if not effective_key:
                raise LLMError("Gemini API key is not configured in vault or environment")
            # For Gemini endpoints, append ?key=<api_key> if key is a standard Google API key (not an Auth key starting with AQ.)
            # and not already in endpoint
            if native_gemini and "key=" not in endpoint:
                separator = "&" if "?" in endpoint else "?"
                endpoint = f"{endpoint}{separator}key={quote(effective_key, safe='')}"

        # Fail fast with clear error if cloud provider is chosen with no API key
        if not effective_key and "cloud" in self.provider_name.lower():
            raise LLMAuthError(
                f"Authentication failed: No API key provided for {self.provider_name}. "
                "Please enter an API key in the Model Engine settings or set the OPENAI_API_KEY environment variable."
            )

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        payload = (
            {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": temperature,
                    "maxOutputTokens": max_tokens,
                },
            }
            if native_gemini
            else {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
        )
        if response_schema:
            schema_name = response_schema.get("title", "structured_response")
            if native_gemini:
                payload["generationConfig"] = {
                    **payload.get("generationConfig", {}),
                    "responseMimeType": "application/json",
                    "responseSchema": response_schema,
                }
            else:
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": schema_name,
                        "strict": True,
                        "schema": response_schema,
                    },
                }

        headers = {
            "Content-Type": "application/json",
        }
        if effective_key and effective_key != "not-needed":
            if not native_gemini:
                headers["Authorization"] = f"Bearer {effective_key}"
            if is_gemini:
                headers["x-goog-api-key"] = effective_key

        redacted_key = (
            effective_key[:6] + "..." if effective_key and len(effective_key) > 6 else (effective_key or "<empty>")
        )

        if HAS_HTTPX:
            timeout_cfg = httpx.Timeout(120.0, connect=60.0, read=120.0, write=60.0, pool=60.0)
            async with httpx.AsyncClient(timeout=timeout_cfg) as client:
                try:
                    response = await client.post(endpoint, json=payload, headers=headers)
                except (httpx.ConnectError, httpx.NetworkError, httpx.RemoteProtocolError) as exc:
                    raise LLMConnectionError(
                        f"Cannot connect to {self.provider_name} at {self.base_url}. "
                        f"Ensure {self.provider_name} is running and reachable. Error: {exc}"
                    ) from exc
                except httpx.TimeoutException as exc:
                    raise LLMConnectionError(
                        f"Request to {self.provider_name} at {self.base_url} timed out: {exc}"
                    ) from exc

                if response.status_code in (401, 403):
                    logger.error(
                        f"Auth error from {self.provider_name} (HTTP {response.status_code}): "
                        f"endpoint={endpoint}, key_prefix={redacted_key}, response={response.text}"
                    )
                    raise LLMAuthError(
                        f"{response.status_code} Unauthorized from {self.provider_name}: Invalid or missing API key. "
                        f"URL: {endpoint}, Key: {redacted_key}. Response: {response.text[:200]}"
                    )
                elif response.status_code == 400 and ("Invalid Auth key" in response.text or "API_KEY_SERVICE_BLOCKED" in response.text):
                    logger.error(
                        f"Google Gemini key is blocked or unauthorized for generativelanguage.googleapis.com. "
                        f"Key prefix: {redacted_key}. Generate a new key in Google AI Studio: https://aistudio.google.com/apikey"
                    )
                    raise LLMAuthError(
                        f"400 Invalid Auth key from Google Gemini (API_KEY_SERVICE_BLOCKED). "
                        f"The configured key ({redacted_key}) is blocked or lacks permission for Generative Language API. "
                        f"Generate a fresh key at https://aistudio.google.com/apikey and update GEMINI_API_KEY."
                    )
                elif response.status_code == 429:
                    logger.error(
                        f"Rate limit from {self.provider_name} (HTTP 429): "
                        f"endpoint={endpoint}, key_prefix={redacted_key}, response={response.text}"
                    )
                    raise LLMConnectionError(
                        f"Rate limit exceeded (429) from {self.provider_name}: {response.text[:200]}"
                    )
                elif response.status_code >= 400:
                    logger.error(
                        f"{self.provider_name} HTTP {response.status_code}: "
                        f"endpoint={endpoint}, key_prefix={redacted_key}, response={response.text}"
                    )
                    raise LLMError(
                        f"{self.provider_name} returned error {response.status_code} "
                        f"(URL: {endpoint}, Key: {redacted_key}): {response.text}"
                    )

                data = response.json()
        else:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=120.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                err_body = ""
                try:
                    err_body = exc.read().decode("utf-8")
                except Exception:
                    pass
                logger.error(
                    f"{self.provider_name} HTTP {exc.code}: "
                    f"endpoint={endpoint}, key_prefix={redacted_key}, response={err_body}"
                )
                if exc.code in (401, 403):
                    raise LLMAuthError(
                        f"{exc.code} Unauthorized from {self.provider_name}: Invalid or missing API key. "
                        f"URL: {endpoint}, Key: {redacted_key}. Response: {err_body[:200]}"
                    ) from exc
                elif exc.code == 400 and ("Invalid Auth key" in err_body or "API_KEY_SERVICE_BLOCKED" in err_body):
                    logger.error(
                        f"Google Gemini key is blocked or unauthorized for generativelanguage.googleapis.com. "
                        f"Key prefix: {redacted_key}. Generate a new key in Google AI Studio: https://aistudio.google.com/apikey"
                    )
                    raise LLMAuthError(
                        f"400 Invalid Auth key from Google Gemini (API_KEY_SERVICE_BLOCKED). "
                        f"The configured key ({redacted_key}) is blocked or lacks permission for Generative Language API. "
                        f"Generate a fresh key at https://aistudio.google.com/apikey and update GEMINI_API_KEY."
                    ) from exc
                raise LLMError(
                    f"{self.provider_name} returned error {exc.code} "
                    f"(URL: {endpoint}, Key: {redacted_key}): {err_body}"
                ) from exc
            except urllib.error.URLError as exc:
                raise LLMConnectionError(
                    f"Cannot connect to {self.provider_name} at {self.base_url}. Error: {exc}"
                ) from exc

        choices = data.get("choices", [])
        if native_gemini:
            candidates = data.get("candidates", [])
            content = (
                candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                if candidates else ""
            )
            finish_reason = candidates[0].get("finishReason") if candidates else None
        else:
            content = ""
            finish_reason = None
        if not choices and not native_gemini:
            raise LLMError(f"Empty choices received from {self.provider_name}: {data}")

        if choices:
            choice = choices[0]
            finish_reason = choice.get("finish_reason")
            content = choice.get("message", {}).get("content", "") or ""
        if not content and native_gemini:
            raise LLMError(f"Empty candidates received from {self.provider_name}: {data}")
        if finish_reason == "length":
            logger.warning(
                f"{self.provider_name} response hit token boundary (finish_reason='length'). "
                f"Returning accumulated content (length: {len(content)})."
            )
            if not content.strip():
                raise LLMTruncationError(
                    f"{self.provider_name} response was truncated and empty (finish_reason='length'). "
                    "Consider increasing max_tokens or reducing rule context size."
                )

        return content.strip()

    async def health_check(self, api_key_override: Optional[str] = None) -> Dict[str, Any]:
        """
        Check if the endpoint is reachable by querying /v1/models with dynamic API key.
        """
        effective_key = self._resolve_api_key(api_key_override)
        is_gemini = "gemini" in self.provider_name.lower() or "google" in self.provider_name.lower()

        # If it's a cloud service and no key has been entered yet, signal unauthorized gracefully
        if not effective_key and (is_gemini or "cloud" in self.provider_name.lower()):
            return {
                "status": "unauthorized",
                "provider": self.provider_name,
                "base_url": self.base_url,
                "error": "Gemini API key is not configured in vault or environment" if is_gemini else "API key required. Configure API key in Model Engine settings.",
                "latency_ms": 0,
            }

        start = time.time()
        models_endpoint = f"{self.base_url}/models"
        if is_gemini and effective_key:
            separator = "&" if "?" in models_endpoint else "?"
            models_endpoint = f"{models_endpoint}{separator}key={effective_key}"
        headers = {}
        if effective_key:
            headers["Authorization"] = f"Bearer {effective_key}"

        if HAS_HTTPX:
            try:
                async with httpx.AsyncClient(timeout=4.0) as client:
                    resp = await client.get(models_endpoint, headers=headers)
                    latency = round((time.time() - start) * 1000, 1)
                    if resp.status_code == 200:
                        data = resp.json()
                        model_ids = [m.get("id") for m in data.get("data", []) if m.get("id")]
                        active_model = model_ids[0] if model_ids else self.default_model
                        return {
                            "status": "connected",
                            "provider": self.provider_name,
                            "base_url": self.base_url,
                            "active_model": active_model,
                            "available_models": model_ids,
                            "latency_ms": latency,
                        }
                    elif resp.status_code in (401, 403):
                        return {
                            "status": "unauthorized",
                            "provider": self.provider_name,
                            "base_url": self.base_url,
                            "error": f"401 Unauthorized: Invalid API key provided for {self.provider_name}",
                            "latency_ms": latency,
                        }
                    else:
                        return {
                            "status": "degraded",
                            "provider": self.provider_name,
                            "base_url": self.base_url,
                            "error": f"HTTP {resp.status_code}: {resp.text[:100]}",
                            "latency_ms": latency,
                        }
            except Exception as e:
                latency = round((time.time() - start) * 1000, 1)
                return {
                    "status": "unreachable",
                    "provider": self.provider_name,
                    "base_url": self.base_url,
                    "error": str(e),
                    "latency_ms": latency,
                }
        else:
            try:
                req = urllib.request.Request(models_endpoint, headers=headers)
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    latency = round((time.time() - start) * 1000, 1)
                    data = json.loads(resp.read().decode("utf-8"))
                    model_ids = [m.get("id") for m in data.get("data", []) if m.get("id")]
                    active_model = model_ids[0] if model_ids else self.default_model
                    return {
                        "status": "connected",
                        "provider": self.provider_name,
                        "base_url": self.base_url,
                        "active_model": active_model,
                        "available_models": model_ids,
                        "latency_ms": latency,
                    }
            except urllib.error.HTTPError as exc:
                latency = round((time.time() - start) * 1000, 1)
                if exc.code in (401, 403):
                    return {
                        "status": "unauthorized",
                        "provider": self.provider_name,
                        "base_url": self.base_url,
                        "error": f"401 Unauthorized: Invalid API key provided for {self.provider_name}",
                        "latency_ms": latency,
                    }
                return {
                    "status": "degraded",
                    "provider": self.provider_name,
                    "base_url": self.base_url,
                    "error": f"HTTP {exc.code}",
                    "latency_ms": latency,
                }
            except Exception as e:
                latency = round((time.time() - start) * 1000, 1)
                return {
                    "status": "unreachable",
                    "provider": self.provider_name,
                    "base_url": self.base_url,
                    "error": str(e),
                    "latency_ms": latency,
                }


def get_llm_client(
    provider: str = "lm_studio",
    custom_base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    model_name: Optional[str] = None,
) -> BaseLLMClient:
    """
    Factory to obtain an LLM client dynamically on a per-request basis.
    - provider: "lm_studio" | "cloud_openai" | "cloud_custom"
    - api_key: passed dynamically from client request or environment variable
    """
    provider_clean = (provider or "lm_studio").lower()

    # Clean API key received from request
    clean_key = (api_key or "").strip()
    if clean_key.lower().startswith("bearer "):
        clean_key = clean_key[7:].strip()

    if provider_clean in ("lm_studio", "local"):
        base_url = (custom_base_url or os.environ.get("LM_STUDIO_BASE_URL", "http://localhost:1234/v1")).strip()
        return OpenAICompatibleClient(
            base_url=base_url,
            api_key=clean_key or "lm-studio",
            default_model=model_name or "qwen2.5-coder-7b-instruct",
            provider_name="LM Studio (Local)",
        )
    elif provider_clean in ("cloud_openai", "openai"):
        base_url = (custom_base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")).strip()
        env_key = "" if custom_base_url else (os.environ.get("OPENAI_API_KEY") or "").strip()
        resolved_key = clean_key if clean_key else env_key
        return OpenAICompatibleClient(
            base_url=base_url,
            api_key=resolved_key,
            default_model=model_name or "gpt-4o",
            provider_name="Cloud OpenAI",
            allow_environment_key=not bool(custom_base_url),
        )
    elif provider_clean in ("cloud_custom", "custom"):
        base_url = (custom_base_url or "http://localhost:11434/v1").strip()
        return OpenAICompatibleClient(
            base_url=base_url,
            api_key=clean_key,
            default_model=model_name or "default-model",
            provider_name="Custom Endpoint",
        )
    elif provider_clean in ("gemini", "google"):
        base_url = (
            custom_base_url
            or os.environ.get("GEMINI_BASE_URL")
            or "https://generativelanguage.googleapis.com/v1beta"
        ).strip().rstrip("/")
        env_key = "" if custom_base_url else (os.environ.get("GEMINI_API_KEY") or "").strip()
        resolved_key = clean_key if clean_key else env_key
        return OpenAICompatibleClient(
            base_url=base_url,
            api_key=resolved_key,
            default_model=model_name or os.environ.get("GEMINI_MODEL") or "gemini-2.5-flash",
            provider_name="Google Gemini",
            allow_environment_key=not bool(custom_base_url),
        )
    else:
        # Treat unknown providers as user-configured OpenAI-compatible endpoints.
        # This supports vendors such as Claude, Kimi, and gateway services without
        # hard-coding their model catalogs or API identities.
        base_url = (custom_base_url or "").strip()
        return OpenAICompatibleClient(
            base_url=base_url,
            api_key=clean_key,
            default_model=model_name or "default-model",
            provider_name=provider or "Custom Endpoint",
        )
