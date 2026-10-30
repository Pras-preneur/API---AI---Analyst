"""Centralized evidence and data sanitization for API Security Testing Assistant.

Ensures that credentials, API keys, session tokens, authorization headers,
cookies, and personally identifiable information (PII) are scrubbed before
being stored in findings, serialized in API responses, included in logs,
or rendered in security reports.
"""

import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Union


# ---------------------------------------------------------------------------
# Redaction Constants and Patterns
# ---------------------------------------------------------------------------

REDACTED_MARKER = "[REDACTED]"

# Key names in dictionaries or query parameters that contain credentials
SENSITIVE_KEY_NAMES: Set[str] = {
    "auth",
    "authorization",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
    "api_key",
    "apikey",
    "key",
    "password",
    "passwd",
    "pwd",
    "credential",
    "credentials",
    "cookie",
    "cookies",
    "set-cookie",
    "session",
    "session_id",
    "sessionid",
    "private_key",
    "client_secret",
    "secret_key",
    "cvv",
    "credit_card",
    "ssn",
    "pin",
}

# Regex patterns for matching sensitive values inside unstructured strings
_EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*")
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*")
_BASIC_PATTERN = re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{6,}={0,2}")

# Match key-value credential assignments in freeform text:
# Key: password, token, api_key, secret, authorization, cookie, session, etc.
# Separator: '=', ':', with optional surrounding whitespace
# Value: quoted string, Bearer token, Basic token, or unquoted string token
_KV_SECRET_PATTERN = re.compile(
    r'(?i)\b('
    r'password|passwd|pwd|'
    r'token|access_token|refresh_token|id_token|'
    r'api_key|apikey|key|'
    r'secret|secret_key|client_secret|private_key|'
    r'authorization|auth|credential|credentials|'
    r'cookie|cookies|set-cookie|session|session_id|sessionid|'
    r'sig|signature'
    r')(\s*[:=]\s*)('
    r'Bearer\s+[^\s,;&"\'\(\)\{\}]+|'
    r'Basic\s+[^\s,;&"\'\(\)\{\}]+|'
    r'"[^"\r\n]*"|'
    r"'[^'\r\n]*'|"
    r'[^\s,;&"\'\(\)\{\}\[\]]+'
    r')'
)


def _mask_kv_secret(match: re.Match) -> str:
    key = match.group(1)
    sep = match.group(2)
    val = match.group(3)
    val_strip = val.strip()

    # Already masked
    if REDACTED_MARKER in val or val_strip.lower() in {"bearer", "basic"}:
        return match.group(0)

    # Authorization formats
    if val_strip.lower().startswith("bearer "):
        return f"{key}{sep}Bearer {REDACTED_MARKER}"
    if val_strip.lower().startswith("basic "):
        return f"{key}{sep}Basic {REDACTED_MARKER}"

    # Quoted values
    if val_strip.startswith('"') and val_strip.endswith('"'):
        return f'{key}{sep}"{REDACTED_MARKER}"'
    if val_strip.startswith("'") and val_strip.endswith("'"):
        return f"{key}{sep}'{REDACTED_MARKER}'"

    return f"{key}{sep}{REDACTED_MARKER}"


def _is_sensitive_key(key: str) -> bool:
    """Return True if key name matches any known sensitive credential pattern."""
    key_lower = str(key).strip().lower()
    return any(s in key_lower for s in SENSITIVE_KEY_NAMES)


def sanitize_string(val: str) -> str:
    """Sanitize freeform text by replacing emails, JWTs, auth headers, and secrets."""
    if not val:
        return val

    # 1. Redact email addresses to prevent PII exposure
    val = _EMAIL_PATTERN.sub(REDACTED_MARKER, val)

    # 2. Redact JWT tokens
    val = _JWT_PATTERN.sub(REDACTED_MARKER, val)

    # 3. Redact Bearer and Basic authentication headers
    val = _BEARER_PATTERN.sub("Bearer [REDACTED]", val)
    val = _BASIC_PATTERN.sub("Basic [REDACTED]", val)

    # 4. Redact key-value assignments (e.g. password=Secret123, api_key: "abc", token=xyz)
    val = _KV_SECRET_PATTERN.sub(_mask_kv_secret, val)

    return val


def sanitize_data(data: Any, max_depth: int = 15) -> Any:
    """Recursively sanitize arbitrary data structures (dicts, lists, primitives).

    - Redacts values of dictionary keys matching sensitive patterns.
    - Recursively processes nested dictionaries and lists up to max_depth.
    - Sanitizes string values for emails, tokens, and credentials.
    """
    if max_depth <= 0:
        return REDACTED_MARKER

    if isinstance(data, dict):
        sanitized: Dict[str, Any] = {}
        for k, v in data.items():
            k_str = str(k)
            if _is_sensitive_key(k_str):
                # If value is a container (e.g. list of tokens or dict of credentials),
                # recurse so child objects are sanitized without losing structural shape
                if isinstance(v, (dict, list, tuple)):
                    sanitized[k_str] = sanitize_data(v, max_depth - 1)
                else:
                    sanitized[k_str] = REDACTED_MARKER
            else:
                sanitized[k_str] = sanitize_data(v, max_depth - 1)
        return sanitized

    if isinstance(data, list):
        return [sanitize_data(item, max_depth - 1) for item in data]

    if isinstance(data, tuple):
        return tuple(sanitize_data(item, max_depth - 1) for item in data)

    if isinstance(data, str):
        return sanitize_string(data)

    # Primitives (int, float, bool, None) remain intact
    return data


def sanitize_url(url: str) -> str:
    """Sanitize URL by masking sensitive query parameter values and basic auth credentials."""
    if not url:
        return url
    try:
        parsed = urllib.parse.urlsplit(url)

        # Sanitize authority if it contains embedded userinfo (e.g. http://user:pass@host)
        netloc = parsed.netloc
        if "@" in netloc:
            userinfo, _, hostpart = netloc.rpartition("@")
            if ":" in userinfo:
                username, _, _ = userinfo.partition(":")
                netloc = f"{username}:{REDACTED_MARKER}@{hostpart}"
            else:
                netloc = f"{REDACTED_MARKER}@{hostpart}"

        if not parsed.query:
            return urllib.parse.urlunsplit((
                parsed.scheme,
                netloc,
                parsed.path,
                "",
                parsed.fragment,
            ))

        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        sanitized_params = []
        for key, val in params:
            # Handle encoded parameter names (e.g. %74%6f%6b%65%6e -> token)
            decoded_key = urllib.parse.unquote(key)
            if _is_sensitive_key(decoded_key):
                sanitized_params.append((key, REDACTED_MARKER))
            else:
                sanitized_params.append((key, sanitize_string(val)))
        new_query = urllib.parse.urlencode(sanitized_params)
        return urllib.parse.urlunsplit((
            parsed.scheme,
            netloc,
            parsed.path,
            new_query,
            parsed.fragment,
        ))
    except Exception:
        return sanitize_string(url)


def sanitize_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize request or response headers.

    - Excludes or redacts 'Authorization' header to avoid credential leakage.
    - Redacts any header containing 'auth', 'token', 'key', 'secret', or 'cookie'.
    - Sanitizes string values in remaining headers.
    """
    safe_headers: Dict[str, Any] = {}
    for k, v in headers.items():
        k_lower = str(k).lower()
        # Strictly omit raw Authorization header to satisfy security and existing tests
        if k_lower == "authorization":
            continue
        if any(s in k_lower for s in ["auth", "token", "key", "secret", "cookie", "session"]):
            safe_headers[k] = REDACTED_MARKER
        else:
            safe_headers[k] = sanitize_data(v)
    return safe_headers


def sanitize_request(method: str, url: str, headers: Dict[str, Any], body: Any = None) -> Dict[str, Any]:
    """Return a sanitized request dictionary suitable for Evidence storage."""
    req: Dict[str, Any] = {
        "method": method.upper(),
        "url": sanitize_url(url),
        "headers": sanitize_headers(headers),
    }
    if body is not None:
        req["body"] = sanitize_data(body)
    return req


def sanitize_response(resp: Any) -> Dict[str, Any]:
    """Extract and sanitize HTTP response data for Evidence storage.

    Accepts an httpx.Response object or a dictionary.
    """
    if resp is None:
        return {"status_code": 0, "body": {}}

    status_code = getattr(resp, "status_code", 0)
    if isinstance(resp, dict):
        status_code = resp.get("status_code", 0)
        raw_body = resp.get("body", {})
    else:
        # httpx.Response-like object
        try:
            raw_body = resp.json()
        except Exception:
            text = getattr(resp, "text", "")
            if not text:
                text = ""
            raw_body = text[:500]

    sanitized_body = sanitize_data(raw_body)
    return {
        "status_code": status_code,
        "body": sanitized_body,
    }


def sanitize_error_message(error: Union[str, Exception]) -> str:
    """Sanitize error or exception messages to prevent token or file credential leaks."""
    error_str = str(error)
    return sanitize_string(error_str)
