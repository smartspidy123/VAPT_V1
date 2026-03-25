"""
VAPT-AI V2.0 - Smart HTTP Client
=================================
An intelligent, async HTTP client built on httpx for security testing.

Features:
- Session management with persistent cookies
- Automatic JWT/Bearer token handling
- Request/Response history logging
- User-Agent rotation
- Proxy support (Burp Suite integration)
- Configurable rate limiting
- Response analysis for vulnerability indicators
- Form extraction and submission
- CSRF token extraction
- Link and resource discovery
"""

import asyncio
import hashlib
import json
import re
import time
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import httpx
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

SQL_ERROR_PATTERNS: List[re.Pattern] = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:.*mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"microsoft ole db provider for sql server", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"SQLite3?::SQLException", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r"pg_query\(\):.*ERROR", re.IGNORECASE),
    re.compile(r"System\.Data\.SqlClient\.SqlException", re.IGNORECASE),
    re.compile(r"SQLSTATE\[", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"mysqli_", re.IGNORECASE),
    re.compile(r"PDOException", re.IGNORECASE),
    re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
    re.compile(r"valid MySQL result", re.IGNORECASE),
    re.compile(r"com\.mysql\.jdbc", re.IGNORECASE),
    re.compile(r"Hibernate.*SQL", re.IGNORECASE),
    re.compile(r"org\.hibernate\.exception", re.IGNORECASE),
]

ERROR_PAGE_PATTERNS: List[re.Pattern] = [
    re.compile(r"internal server error", re.IGNORECASE),
    re.compile(r"500 error", re.IGNORECASE),
    re.compile(r"stack ?trace", re.IGNORECASE),
    re.compile(r"traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"<b>Fatal error</b>", re.IGNORECASE),
    re.compile(r"Unhandled Exception", re.IGNORECASE),
    re.compile(r"Application Error", re.IGNORECASE),
    re.compile(r"Server Error in", re.IGNORECASE),
    re.compile(r"RuntimeError", re.IGNORECASE),
    re.compile(r"SyntaxError", re.IGNORECASE),
    re.compile(r"TypeError", re.IGNORECASE),
    re.compile(r"ValueError", re.IGNORECASE),
    re.compile(r"NullPointerException", re.IGNORECASE),
    re.compile(r"java\.lang\.", re.IGNORECASE),
    re.compile(r"at [\w\.$]+\([\w]+\.java:\d+\)", re.IGNORECASE),
    re.compile(r"Microsoft \.NET Framework", re.IGNORECASE),
    re.compile(r"ASP\.NET.*error", re.IGNORECASE),
    re.compile(r"Debug mode.*SECURITY WARNING", re.IGNORECASE),
]

SENSITIVE_DATA_PATTERNS: Dict[str, re.Pattern] = {
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "api_key_generic": re.compile(r"(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})", re.IGNORECASE),
    "password_field": re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"&\s]+)", re.IGNORECASE),
    "database_url": re.compile(r"(?:mysql|postgres|mongodb|redis|sqlite):\/\/[^\s'\"]+", re.IGNORECASE),
}

CSRF_TOKEN_NAMES: List[str] = [
    "csrf_token", "csrftoken", "csrf", "_csrf",
    "csrfmiddlewaretoken", "_token", "authenticity_token",
    "anti_csrf_token", "anticsrf", "__requestverificationtoken",
    "x-csrf-token", "x-xsrf-token", "xsrf_token",
]

AUTH_INDICATOR_PATTERNS: List[re.Pattern] = [
    re.compile(r"log\s*out", re.IGNORECASE),
    re.compile(r"sign\s*out", re.IGNORECASE),
    re.compile(r"my\s*account", re.IGNORECASE),
    re.compile(r"dashboard", re.IGNORECASE),
    re.compile(r"profile", re.IGNORECASE),
    re.compile(r"welcome(?:\s*back)?[,\s]", re.IGNORECASE),
]

UNAUTH_INDICATOR_PATTERNS: List[re.Pattern] = [
    re.compile(r"log\s*in", re.IGNORECASE),
    re.compile(r"sign\s*in", re.IGNORECASE),
    re.compile(r"register", re.IGNORECASE),
    re.compile(r"forgot\s*password", re.IGNORECASE),
    re.compile(r"unauthorized", re.IGNORECASE),
    re.compile(r"access\s*denied", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FormField:
    """Represents a single HTML form field."""
    name: str
    field_type: str  # text, password, hidden, email, submit, etc.
    value: str = ""
    required: bool = False
    options: List[str] = field(default_factory=list)  # for <select> elements

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.field_type,
            "value": self.value,
            "required": self.required,
            "options": self.options,
        }


@dataclass
class ExtractedForm:
    """Represents an HTML form extracted from a page."""
    action: str
    method: str  # GET or POST
    fields: List[FormField] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"
    form_id: str = ""
    form_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "enctype": self.enctype,
            "form_id": self.form_id,
            "form_name": self.form_name,
            "fields": [f.to_dict() for f in self.fields],
        }

    def get_field_names(self) -> List[str]:
        return [f.name for f in self.fields if f.name]

    def get_hidden_fields(self) -> Dict[str, str]:
        return {f.name: f.value for f in self.fields if f.field_type == "hidden" and f.name}

    def get_default_data(self) -> Dict[str, str]:
        """Return a dict of field_name → default_value for every named field."""
        return {f.name: f.value for f in self.fields if f.name}

    def has_password_field(self) -> bool:
        return any(f.field_type == "password" for f in self.fields)

    def has_file_upload(self) -> bool:
        return any(f.field_type == "file" for f in self.fields)


@dataclass
class ExtractedLink:
    """Represents a link extracted from a page."""
    url: str
    text: str = ""
    link_type: str = "anchor"  # anchor, form_action, script_src, img_src, redirect
    is_internal: bool = True
    is_resource: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "text": self.text,
            "type": self.link_type,
            "is_internal": self.is_internal,
            "is_resource": self.is_resource,
        }


@dataclass
class RequestRecord:
    """A logged request-response pair."""
    timestamp: float
    method: str
    url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    status_code: int
    response_headers: Dict[str, str]
    response_body: str
    response_size: int
    elapsed_ms: float
    request_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status_code": self.status_code,
            "response_headers": self.response_headers,
            "response_body_length": len(self.response_body),
            "response_size": self.response_size,
            "elapsed_ms": self.elapsed_ms,
        }

    def to_full_dict(self) -> Dict[str, Any]:
        """Include response body – use for detailed export."""
        d = self.to_dict()
        d["response_body"] = self.response_body
        d["request_body"] = self.request_body
        return d


# ---------------------------------------------------------------------------
# SmartResponse
# ---------------------------------------------------------------------------

class SmartResponse:
    """
    Wraps an ``httpx.Response`` with rich analysis helpers designed for
    security testing.  Every ``SmartHTTPClient`` request returns one of these.
    """

    def __init__(self, httpx_response: httpx.Response, base_url: str = "") -> None:
        self._raw: httpx.Response = httpx_response
        self._base_url: str = base_url

        # Core data
        self.status_code: int = httpx_response.status_code
        self.headers: Dict[str, str] = dict(httpx_response.headers)
        self.url: str = str(httpx_response.url)

        # Safe elapsed time extraction
        try:
            self.elapsed_ms: float = httpx_response.elapsed.total_seconds() * 1000
        except Exception:
            self.elapsed_ms: float = 0.0

        # Safe cookie extraction
        try:
            self.cookies: Dict[str, str] = {k: v for k, v in httpx_response.cookies.items()}
        except Exception:
            self.cookies: Dict[str, str] = {}

        # Body (safe decode)
        try:
            self.body: str = httpx_response.text
        except Exception:
            try:
                self.body: str = httpx_response.content.decode("utf-8", errors="replace")
            except Exception:
                self.body: str = ""

        # Content bytes (safe)
        try:
            self.content_bytes: bytes = httpx_response.content
        except Exception:
            self.content_bytes: bytes = self.body.encode("utf-8", errors="replace")

        self.content_length: int = len(self.content_bytes)

        # Lazy-parsed caches
        self._json_data: Optional[Any] = None
        self._json_parsed: bool = False
        self._soup: Optional[BeautifulSoup] = None
        self._forms: Optional[List[ExtractedForm]] = None
        self._links: Optional[List[ExtractedLink]] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def json_data(self) -> Optional[Any]:
        """Lazily parse JSON from the response body. Returns *None* on failure."""
        if not self._json_parsed:
            self._json_parsed = True
            content_type = self.headers.get("content-type", "")
            if "json" in content_type or self.body.strip().startswith(("{", "[")):
                try:
                    self._json_data = json.loads(self.body)
                except (json.JSONDecodeError, ValueError):
                    self._json_data = None
        return self._json_data

    @property
    def soup(self) -> BeautifulSoup:
        """Lazily parse HTML with BeautifulSoup."""
        if self._soup is None:
            self._soup = BeautifulSoup(self.body, "lxml")
        return self._soup

    @property
    def forms(self) -> List[ExtractedForm]:
        """Extract all ``<form>`` elements from the page."""
        if self._forms is None:
            self._forms = self._extract_forms()
        return self._forms

    @property
    def links(self) -> List[ExtractedLink]:
        """Extract all links/resources from the page."""
        if self._links is None:
            self._links = self._extract_links()
        return self._links

    # ------------------------------------------------------------------
    # Vulnerability indicator helpers
    # ------------------------------------------------------------------

    def has_error_indicators(self) -> bool:
        """Return *True* if the body contains common error / stack-trace patterns."""
        for pat in ERROR_PAGE_PATTERNS:
            if pat.search(self.body):
                return True
        return False

    def get_error_details(self) -> List[str]:
        """Return list of matched error pattern strings found in the body."""
        matches: List[str] = []
        for pat in ERROR_PAGE_PATTERNS:
            m = pat.search(self.body)
            if m:
                start = max(0, m.start() - 40)
                end = min(len(self.body), m.end() + 40)
                matches.append(self.body[start:end].strip())
        return matches

    def has_sqli_indicators(self) -> bool:
        """Return *True* if the body contains common SQL error messages."""
        for pat in SQL_ERROR_PATTERNS:
            if pat.search(self.body):
                return True
        return False

    def get_sqli_details(self) -> List[str]:
        """Return matched SQL-error snippets found in the body."""
        matches: List[str] = []
        for pat in SQL_ERROR_PATTERNS:
            m = pat.search(self.body)
            if m:
                start = max(0, m.start() - 60)
                end = min(len(self.body), m.end() + 60)
                matches.append(self.body[start:end].strip())
        return matches

    def has_xss_reflection(self, payload: str) -> bool:
        """Check whether *payload* appears unencoded in the response body."""
        if not payload:
            return False
        # Direct reflection
        if payload in self.body:
            return True
        # Check if the payload is reflected without angle brackets being encoded
        # (common partial encoding)
        core = payload.replace("<", "").replace(">", "")
        if core and core in self.body:
            # Check if the raw angle brackets also survived
            if payload in self.body:
                return True
        return False

    def has_xss_reflection_context(self, payload: str) -> Dict[str, Any]:
        """
        Determine *where* a payload is reflected.

        Returns a dict with keys:
        - reflected (bool)
        - in_html_body (bool)
        - in_attribute (bool)
        - in_script (bool)
        - in_comment (bool)
        - encoded (bool)  – whether the reflection appears entity-encoded
        """
        result: Dict[str, Any] = {
            "reflected": False,
            "in_html_body": False,
            "in_attribute": False,
            "in_script": False,
            "in_comment": False,
            "encoded": False,
        }
        if not payload:
            return result

        body = self.body

        if payload in body:
            result["reflected"] = True
            idx = body.find(payload)
            # Rough heuristic: look at surrounding context
            before = body[max(0, idx - 200):idx]
            after = body[idx:idx + len(payload) + 200]

            if "<script" in before.lower() and "</script>" in after.lower():
                result["in_script"] = True
            if "<!--" in before and "-->" in after:
                result["in_comment"] = True
            # Attribute context: look for an = and quote before the payload
            attr_pattern = re.compile(r'''[a-zA-Z\-]+=\s*['"]?\s*$''')
            if attr_pattern.search(before):
                result["in_attribute"] = True
            if not (result["in_script"] or result["in_comment"] or result["in_attribute"]):
                result["in_html_body"] = True
        else:
            # Check for HTML-entity encoded version
            import html as html_mod
            encoded = html_mod.escape(payload)
            if encoded in body and encoded != payload:
                result["reflected"] = True
                result["encoded"] = True

        return result

    def has_sensitive_data(self) -> Dict[str, List[str]]:
        """Scan for sensitive data patterns in the response body."""
        found: Dict[str, List[str]] = {}
        for name, pat in SENSITIVE_DATA_PATTERNS.items():
            matches = pat.findall(self.body)
            if matches:
                # Deduplicate
                found[name] = list(set(matches[:20]))  # cap at 20
        return found

    # ------------------------------------------------------------------
    # Authentication state detection
    # ------------------------------------------------------------------

    def detect_auth_state(self) -> Dict[str, Any]:
        """
        Analyse response to determine whether the user appears to be
        authenticated or unauthenticated.

        Returns::

            {
                "authenticated": True | False | None,
                "confidence": "high" | "medium" | "low",
                "indicators": [...]
            }
        """
        auth_hits: List[str] = []
        unauth_hits: List[str] = []

        for pat in AUTH_INDICATOR_PATTERNS:
            m = pat.search(self.body)
            if m:
                auth_hits.append(m.group(0))

        for pat in UNAUTH_INDICATOR_PATTERNS:
            m = pat.search(self.body)
            if m:
                unauth_hits.append(m.group(0))

        # Status code hints
        if self.status_code == 401:
            unauth_hits.append("HTTP 401")
        if self.status_code == 403:
            unauth_hits.append("HTTP 403")

        # Decide
        if auth_hits and not unauth_hits:
            return {"authenticated": True, "confidence": "high", "indicators": auth_hits}
        if unauth_hits and not auth_hits:
            return {"authenticated": False, "confidence": "high", "indicators": unauth_hits}
        if auth_hits and unauth_hits:
            # Both present – go with majority
            if len(auth_hits) > len(unauth_hits):
                return {"authenticated": True, "confidence": "low", "indicators": auth_hits}
            return {"authenticated": False, "confidence": "low", "indicators": unauth_hits}

        return {"authenticated": None, "confidence": "low", "indicators": []}

    # ------------------------------------------------------------------
    # Token / CSRF extraction
    # ------------------------------------------------------------------

    def extract_jwt_from_response(self) -> Optional[str]:
        """
        Try to find a JWT in:
        1. ``Authorization`` response header
        2. JSON body fields (token, access_token, jwt, id_token)
        3. Set-Cookie headers
        4. Raw body regex
        """
        # 1. Authorization header
        auth_header = self.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
            if self._looks_like_jwt(token):
                return token

        # 2. JSON body
        if self.json_data and isinstance(self.json_data, dict):
            for key in ("token", "access_token", "accessToken", "jwt",
                        "id_token", "idToken", "auth_token", "authToken"):
                val = self.json_data.get(key)
                if val and isinstance(val, str) and self._looks_like_jwt(val):
                    return val
                # Nested: data.token
                nested = self.json_data.get("data")
                if isinstance(nested, dict):
                    val = nested.get(key)
                    if val and isinstance(val, str) and self._looks_like_jwt(val):
                        return val

        # 3. Set-Cookie
        for cookie_val in self.headers.get("set-cookie", "").split(","):
            parts = cookie_val.strip().split(";")
            if parts:
                kv = parts[0].split("=", 1)
                if len(kv) == 2 and self._looks_like_jwt(kv[1]):
                    return kv[1]

        # 4. Regex over body
        jwt_pat = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
        m = jwt_pat.search(self.body)
        if m:
            return m.group(0)

        return None

    def extract_csrf_token(self) -> Optional[str]:
        """
        Extract a CSRF / anti-forgery token from:
        1. Hidden form fields
        2. Meta tags
        3. Response headers (X-CSRF-Token)
        4. Cookie (csrftoken, XSRF-TOKEN)
        """
        # 1. Hidden fields
        for form in self.forms:
            for fld in form.fields:
                if fld.field_type == "hidden" and fld.name.lower().replace("-", "_") in [
                    n.replace("-", "_") for n in CSRF_TOKEN_NAMES
                ]:
                    if fld.value:
                        return fld.value

        # 2. Meta tags   <meta name="csrf-token" content="...">
        for meta in self.soup.find_all("meta"):
            meta_name = (meta.get("name") or "").lower().replace("-", "_")
            if meta_name in [n.replace("-", "_") for n in CSRF_TOKEN_NAMES]:
                content = meta.get("content", "")
                if content:
                    return content

        # 3. Response header
        for header_name in ("x-csrf-token", "x-xsrf-token"):
            val = self.headers.get(header_name)
            if val:
                return val

        # 4. Cookie
        for cname in ("csrftoken", "csrf_token", "XSRF-TOKEN", "_csrf"):
            if cname in self.cookies:
                return self.cookies[cname]

        return None

    def extract_all_tokens(self) -> Dict[str, Optional[str]]:
        """Extract JWT and CSRF tokens in one call."""
        return {
            "jwt": self.extract_jwt_from_response(),
            "csrf": self.extract_csrf_token(),
        }

    # ------------------------------------------------------------------
    # Content type helpers
    # ------------------------------------------------------------------

    @property
    def is_html(self) -> bool:
        ct = self.headers.get("content-type", "")
        return "html" in ct

    @property
    def is_json(self) -> bool:
        ct = self.headers.get("content-type", "")
        return "json" in ct

    @property
    def is_xml(self) -> bool:
        ct = self.headers.get("content-type", "")
        return "xml" in ct

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600

    @property
    def redirect_url(self) -> Optional[str]:
        """Return the ``Location`` header value if this is a redirect."""
        if self.is_redirect:
            loc = self.headers.get("location")
            if loc:
                return urljoin(self.url, loc)
        return None

    # ------------------------------------------------------------------
    # Security header analysis
    # ------------------------------------------------------------------

    def analyse_security_headers(self) -> Dict[str, Any]:
        """
        Check for the presence of common security headers and report
        missing / misconfigured ones.
        """
        headers_lower = {k.lower(): v for k, v in self.headers.items()}

        checks: Dict[str, Any] = {}

        # X-Content-Type-Options
        val = headers_lower.get("x-content-type-options")
        checks["x-content-type-options"] = {
            "present": val is not None,
            "value": val,
            "secure": val and val.lower() == "nosniff",
        }

        # X-Frame-Options
        val = headers_lower.get("x-frame-options")
        checks["x-frame-options"] = {
            "present": val is not None,
            "value": val,
            "secure": val and val.lower() in ("deny", "sameorigin"),
        }

        # Strict-Transport-Security
        val = headers_lower.get("strict-transport-security")
        checks["strict-transport-security"] = {
            "present": val is not None,
            "value": val,
            "secure": val is not None,
        }

        # Content-Security-Policy
        val = headers_lower.get("content-security-policy")
        checks["content-security-policy"] = {
            "present": val is not None,
            "value": val,
            "secure": val is not None and "unsafe-inline" not in (val or ""),
        }

        # X-XSS-Protection (legacy but still checked)
        val = headers_lower.get("x-xss-protection")
        checks["x-xss-protection"] = {
            "present": val is not None,
            "value": val,
            "secure": val and val.startswith("1"),
        }

        # Referrer-Policy
        val = headers_lower.get("referrer-policy")
        checks["referrer-policy"] = {
            "present": val is not None,
            "value": val,
            "secure": val is not None,
        }

        # Permissions-Policy
        val = headers_lower.get("permissions-policy")
        checks["permissions-policy"] = {
            "present": val is not None,
            "value": val,
            "secure": val is not None,
        }

        # Cookie flags on Set-Cookie
        set_cookie = headers_lower.get("set-cookie", "")
        checks["cookie_flags"] = {
            "httponly": "httponly" in set_cookie.lower(),
            "secure": "secure" in set_cookie.lower() if set_cookie else False,
            "samesite": "samesite" in set_cookie.lower() if set_cookie else False,
        }

        missing = [name for name, info in checks.items()
                    if isinstance(info, dict) and "present" in info and not info["present"]]
        checks["missing_headers"] = missing

        return checks

    # ------------------------------------------------------------------
    # Server / technology fingerprinting
    # ------------------------------------------------------------------

    def detect_technologies(self) -> Dict[str, str]:
        """Best-effort server/technology detection from headers and body."""
        techs: Dict[str, str] = {}

        server = self.headers.get("server")
        if server:
            techs["server"] = server

        powered_by = self.headers.get("x-powered-by")
        if powered_by:
            techs["x-powered-by"] = powered_by

        asp_version = self.headers.get("x-aspnet-version")
        if asp_version:
            techs["asp.net"] = asp_version

        # Body hints
        if "wp-content" in self.body or "wordpress" in self.body.lower():
            techs["cms"] = "WordPress"
        elif "Drupal" in self.body:
            techs["cms"] = "Drupal"
        elif "Joomla" in self.body:
            techs["cms"] = "Joomla"

        if "react" in self.body.lower() and ("_react" in self.body or "reactDOM" in self.body):
            techs["js_framework"] = "React"
        elif "ng-app" in self.body or "angular" in self.body.lower():
            techs["js_framework"] = "Angular"
        elif "__NEXT_DATA__" in self.body:
            techs["js_framework"] = "Next.js"
        elif "nuxt" in self.body.lower():
            techs["js_framework"] = "Nuxt.js"
        elif "vue" in self.body.lower() and ("v-app" in self.body or "__vue__" in self.body):
            techs["js_framework"] = "Vue.js"

        return techs

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_forms(self) -> List[ExtractedForm]:
        """Parse all ``<form>`` elements from HTML."""
        forms_out: List[ExtractedForm] = []
        if not self.is_html:
            return forms_out

        for form_tag in self.soup.find_all("form"):
            action_raw = form_tag.get("action", "")
            action = urljoin(self.url, action_raw) if action_raw else self.url
            method = (form_tag.get("method") or "GET").upper()
            enctype = form_tag.get("enctype", "application/x-www-form-urlencoded")
            form_id = form_tag.get("id", "")
            form_name = form_tag.get("name", "")

            fields: List[FormField] = []

            # <input> elements
            for inp in form_tag.find_all("input"):
                name = inp.get("name", "")
                ftype = (inp.get("type") or "text").lower()
                value = inp.get("value", "")
                required = inp.has_attr("required")
                fields.append(FormField(name=name, field_type=ftype, value=value, required=required))

            # <textarea>
            for ta in form_tag.find_all("textarea"):
                name = ta.get("name", "")
                value = ta.string or ""
                required = ta.has_attr("required")
                fields.append(FormField(name=name, field_type="textarea", value=value, required=required))

            # <select>
            for sel in form_tag.find_all("select"):
                name = sel.get("name", "")
                required = sel.has_attr("required")
                options = []
                first_val = ""
                for opt in sel.find_all("option"):
                    opt_val = opt.get("value", opt.string or "")
                    options.append(opt_val)
                    if not first_val and opt_val:
                        first_val = opt_val
                fields.append(FormField(
                    name=name, field_type="select", value=first_val,
                    required=required, options=options,
                ))

            # <button type=submit>
            for btn in form_tag.find_all("button", {"type": "submit"}):
                name = btn.get("name", "")
                value = btn.get("value", "")
                if name:
                    fields.append(FormField(name=name, field_type="submit", value=value))

            forms_out.append(ExtractedForm(
                action=action,
                method=method,
                fields=fields,
                enctype=enctype,
                form_id=form_id,
                form_name=form_name,
            ))

        return forms_out

    def _extract_links(self) -> List[ExtractedLink]:
        """Extract anchor hrefs, script srcs, form actions, img srcs."""
        links_out: List[ExtractedLink] = []
        seen: set = set()

        base_domain = urlparse(self._base_url or self.url).netloc

        def _add(raw_url: str, text: str = "", link_type: str = "anchor",
                 is_resource: bool = False) -> None:
            if not raw_url or raw_url.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                return
            absolute = urljoin(self.url, raw_url)
            if absolute in seen:
                return
            seen.add(absolute)
            parsed = urlparse(absolute)
            internal = parsed.netloc == base_domain or not parsed.netloc
            links_out.append(ExtractedLink(
                url=absolute, text=text.strip(), link_type=link_type,
                is_internal=internal, is_resource=is_resource,
            ))

        if not self.is_html:
            return links_out

        # <a>
        for a in self.soup.find_all("a", href=True):
            _add(a["href"], text=a.get_text(separator=" ", strip=True))

        # <form action>
        for form_tag in self.soup.find_all("form", action=True):
            _add(form_tag["action"], link_type="form_action")

        # <script src>
        for s in self.soup.find_all("script", src=True):
            _add(s["src"], link_type="script_src", is_resource=True)

        # <link href>
        for l in self.soup.find_all("link", href=True):
            _add(l["href"], link_type="link_href", is_resource=True)

        # <img src>
        for img in self.soup.find_all("img", src=True):
            _add(img["src"], link_type="img_src", is_resource=True)

        # <iframe src>
        for iframe in self.soup.find_all("iframe", src=True):
            _add(iframe["src"], link_type="iframe_src")

        return links_out

    @staticmethod
    def _looks_like_jwt(token: str) -> bool:
        """Quick check that *token* has the three-part base64url structure of a JWT."""
        parts = token.split(".")
        if len(parts) != 3:
            return False
        if not parts[0].startswith("eyJ"):
            return False
        return True

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the response (without full body) for logging / state."""
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "elapsed_ms": self.elapsed_ms,
            "content_type": self.headers.get("content-type", ""),
            "cookies": self.cookies,
            "is_html": self.is_html,
            "is_json": self.is_json,
            "has_errors": self.has_error_indicators(),
            "has_sqli": self.has_sqli_indicators(),
        }

    def __repr__(self) -> str:
        return (
            f"<SmartResponse [{self.status_code}] url={self.url!r} "
            f"length={self.content_length} elapsed={self.elapsed_ms:.0f}ms>"
        )


# ---------------------------------------------------------------------------
# SmartHTTPClient
# ---------------------------------------------------------------------------

class SmartHTTPClient:
    """
    An async HTTP client purpose-built for security testing.

    Features
    --------
    - Persistent cookie jar (session-based)
    - Automatic Bearer / JWT injection
    - Request/response history for every call
    - Configurable rate limiting
    - Proxy support (point at Burp Suite, ZAP, etc.)
    - User-Agent rotation
    - SSL verification can be disabled
    - Form submission helper with CSRF-token handling
    """

    def __init__(
        self,
        base_url: str,
        proxy: Optional[str] = None,
        rate_limit: int = 10,
        verify_ssl: bool = False,
        timeout: float = 30.0,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        user_agent: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Parameters
        ----------
        base_url : str
            The target application base URL (e.g. ``https://example.com``).
        proxy : str, optional
            Proxy URL (e.g. ``http://127.0.0.1:8080`` for Burp).
        rate_limit : int
            Maximum requests per second. ``0`` disables rate limiting.
        verify_ssl : bool
            Whether to verify TLS certificates.  Default ``False`` for
            pentesting convenience.
        timeout : float
            Default request timeout in seconds.
        follow_redirects : bool
            Automatically follow redirects.
        max_redirects : int
            Max redirect hops when ``follow_redirects`` is True.
        user_agent : str, optional
            Fixed User-Agent string.  If ``None``, agents are rotated.
        custom_headers : dict, optional
            Extra headers to include in every request.
        """
        self.base_url: str = base_url.rstrip("/")
        self.proxy: Optional[str] = proxy
        self.rate_limit: int = rate_limit
        self.verify_ssl: bool = verify_ssl
        self.timeout: float = timeout
        self.follow_redirects: bool = follow_redirects
        self.max_redirects: int = max_redirects

        # Authentication state
        self._auth_token: Optional[str] = None
        self._auth_token_type: str = "Bearer"
        self._custom_headers: Dict[str, str] = custom_headers or {}

        # User-Agent handling
        self._fixed_user_agent: Optional[str] = user_agent
        self._ua_index: int = 0

        # History & metrics
        self._history: List[RequestRecord] = []
        self._total_requests: int = 0
        self._total_bytes_sent: int = 0
        self._total_bytes_received: int = 0

        # Rate limiting internals
        self._rate_lock: asyncio.Lock = asyncio.Lock()
        self._last_request_time: float = 0.0
        self._min_interval: float = (1.0 / rate_limit) if rate_limit > 0 else 0.0

        # The underlying httpx client (created lazily / via context manager)
        self._client: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "SmartHTTPClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def _ensure_client(self) -> None:
        """Create the ``httpx.AsyncClient`` if it does not exist yet."""
        if self._client is None or self._client.is_closed:
            transport_kwargs: Dict[str, Any] = {}
            if self.proxy:
                transport_kwargs["proxy"] = self.proxy

            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=self.follow_redirects,
                max_redirects=self.max_redirects,
                verify=self.verify_ssl,
                **transport_kwargs,
            )

    async def close(self) -> None:
        """Close the underlying HTTP client gracefully."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Header helpers
    # ------------------------------------------------------------------

    def _get_next_user_agent(self) -> str:
        """Return the next User-Agent in rotation, or the fixed one."""
        if self._fixed_user_agent:
            return self._fixed_user_agent
        ua = DEFAULT_USER_AGENTS[self._ua_index % len(DEFAULT_USER_AGENTS)]
        self._ua_index += 1
        return ua

    def _build_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Build the final header dict for a request."""
        headers: Dict[str, str] = {
            "User-Agent": self._get_next_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        # Merge custom headers
        headers.update(self._custom_headers)

        # Auth token
        if self._auth_token:
            headers["Authorization"] = f"{self._auth_token_type} {self._auth_token}"

        # Per-request overrides
        if extra:
            headers.update(extra)

        return headers

    # ------------------------------------------------------------------
    # Auth / session management
    # ------------------------------------------------------------------

    def set_auth_token(self, token: str, token_type: str = "Bearer") -> None:
        """
        Store a Bearer / JWT token that will be automatically added to
        the ``Authorization`` header of every subsequent request.
        """
        self._auth_token = token
        self._auth_token_type = token_type

    def clear_auth_token(self) -> None:
        """Remove the stored auth token."""
        self._auth_token = None

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """
        Manually inject cookies into the client's cookie jar.

        These persist across subsequent requests.
        """
        if self._client:
            for name, value in cookies.items():
                self._client.cookies.set(name, value)

    def get_cookies(self) -> Dict[str, str]:
        """Return a snapshot of all cookies currently in the jar."""
        if self._client:
            return {k: v for k, v in self._client.cookies.items()}
        return {}

    def set_custom_header(self, name: str, value: str) -> None:
        """Add or overwrite a header that will be sent with every request."""
        self._custom_headers[name] = value

    def remove_custom_header(self, name: str) -> None:
        """Remove a previously set custom header."""
        self._custom_headers.pop(name, None)

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    async def _apply_rate_limit(self) -> None:
        """Block until enough time has passed since the last request."""
        if self._min_interval <= 0:
            return
        async with self._rate_lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_request_time
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_request_time = asyncio.get_event_loop().time()

    # ------------------------------------------------------------------
    # Core request method
    # ------------------------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Union[Dict[str, Any], str]] = None,
        json_body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        content: Optional[bytes] = None,
        follow_redirects: Optional[bool] = None,
        timeout: Optional[float] = None,
    ) -> SmartResponse:
        """
        Execute an HTTP request and return a ``SmartResponse``.

        All convenience methods (``get``, ``post``, etc.) delegate here.
        """
        await self._ensure_client()
        assert self._client is not None

        # Rate limit
        await self._apply_rate_limit()

        # Resolve URL
        if url.startswith(("http://", "https://")):
            full_url = url
        else:
            full_url = f"{self.base_url}/{url.lstrip('/')}"

        # Build headers
        merged_headers = self._build_headers(headers)

        # Adjust Content-Type when sending JSON
        if json_body is not None and "Content-Type" not in merged_headers:
            merged_headers["Content-Type"] = "application/json"

        # Build kwargs for httpx
        request_kwargs: Dict[str, Any] = {
            "method": method.upper(),
            "url": full_url,
            "headers": merged_headers,
        }
        if params:
            request_kwargs["params"] = params
        if data is not None:
            request_kwargs["data"] = data
        if json_body is not None:
            request_kwargs["json"] = json_body
        if cookies:
            request_kwargs["cookies"] = cookies
        if files:
            request_kwargs["files"] = files
        if content is not None:
            request_kwargs["content"] = content
        if follow_redirects is not None:
            request_kwargs["follow_redirects"] = follow_redirects
        if timeout is not None:
            request_kwargs["timeout"] = timeout

        # Compute request body size for metrics
        body_for_log: Optional[str] = None
        sent_bytes = 0
        if json_body is not None:
            body_for_log = json.dumps(json_body)
            sent_bytes = len(body_for_log.encode())
        elif isinstance(data, str):
            body_for_log = data
            sent_bytes = len(data.encode())
        elif isinstance(data, dict):
            body_for_log = urlencode(data)
            sent_bytes = len(body_for_log.encode())
        elif content is not None:
            body_for_log = f"<binary {len(content)} bytes>"
            sent_bytes = len(content)

        # Execute request
        timestamp = time.time()
        try:
            raw_resp: httpx.Response = await self._client.request(**request_kwargs)
        except httpx.TimeoutException:
            # Return a synthetic timeout response
            return self._make_timeout_response(full_url, method, merged_headers, body_for_log, timestamp)
        except httpx.ConnectError as exc:
            return self._make_error_response(full_url, method, merged_headers, body_for_log,
                                             timestamp, 0, f"Connection error: {exc}")
        except Exception as exc:
            return self._make_error_response(full_url, method, merged_headers, body_for_log,
                                             timestamp, 0, f"Request error: {exc}")

        # Wrap in SmartResponse
        smart = SmartResponse(raw_resp, base_url=self.base_url)

        # Auto-capture JWT from responses
        jwt = smart.extract_jwt_from_response()
        if jwt and self._auth_token is None:
            # Only auto-set if we don't already have a token
            pass  # Agent layer decides whether to call set_auth_token

        # Update metrics
        self._total_requests += 1
        self._total_bytes_sent += sent_bytes
        self._total_bytes_received += smart.content_length

        # Generate request ID
        request_id = hashlib.md5(
            f"{timestamp}{method}{full_url}".encode()
        ).hexdigest()[:12]

        # Log
        record = RequestRecord(
            timestamp=timestamp,
            method=method.upper(),
            url=full_url,
            request_headers=merged_headers,
            request_body=body_for_log,
            status_code=smart.status_code,
            response_headers=smart.headers,
            response_body=smart.body,
            response_size=smart.content_length,
            elapsed_ms=smart.elapsed_ms,
            request_id=request_id,
        )
        self._history.append(record)

        return smart

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    async def get(self, url: str, **kwargs: Any) -> SmartResponse:
        """Send a GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(
        self,
        url: str,
        data: Optional[Union[Dict[str, Any], str]] = None,
        json_body: Optional[Any] = None,
        **kwargs: Any,
    ) -> SmartResponse:
        """Send a POST request with form data or JSON."""
        return await self.request("POST", url, data=data, json_body=json_body, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> SmartResponse:
        """Send a PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> SmartResponse:
        """Send a DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> SmartResponse:
        """Send a PATCH request."""
        return await self.request("PATCH", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> SmartResponse:
        """Send an OPTIONS request."""
        return await self.request("OPTIONS", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> SmartResponse:
        """Send a HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    # ------------------------------------------------------------------
    # Form submission
    # ------------------------------------------------------------------

    async def submit_form(
        self,
        form: ExtractedForm,
        field_values: Optional[Dict[str, str]] = None,
        auto_csrf: bool = True,
        source_response: Optional[SmartResponse] = None,
    ) -> SmartResponse:
        """
        Submit an ``ExtractedForm``.

        Parameters
        ----------
        form : ExtractedForm
            The form object (typically from ``SmartResponse.forms``).
        field_values : dict, optional
            Values to fill in.  Any field not specified uses its default
            value from the form HTML.
        auto_csrf : bool
            If True and the form has a CSRF field, attempt to fill it
            from the *source_response*.
        source_response : SmartResponse, optional
            The response from which the form was extracted.  Used for
            CSRF extraction if *auto_csrf* is True.
        """
        form_data = form.get_default_data()

        # Merge caller-supplied values
        if field_values:
            form_data.update(field_values)

        # Auto-fill CSRF
        if auto_csrf and source_response:
            csrf = source_response.extract_csrf_token()
            if csrf:
                for fld in form.fields:
                    if fld.field_type == "hidden" and fld.name.lower().replace("-", "_") in [
                        n.replace("-", "_") for n in CSRF_TOKEN_NAMES
                    ]:
                        form_data[fld.name] = csrf
                        break

        # Remove submit buttons without values (they pollute data)
        cleaned: Dict[str, str] = {}
        for k, v in form_data.items():
            if not k:
                continue
            # Keep submit values only if they were explicitly given
            field_obj = next((f for f in form.fields if f.name == k), None)
            if field_obj and field_obj.field_type == "submit" and k not in (field_values or {}):
                continue
            cleaned[k] = v

        if form.method == "GET":
            return await self.get(form.action, params=cleaned)

        # POST
        if form.enctype == "multipart/form-data" or form.has_file_upload():
            # Use multipart encoding
            return await self.request(
                "POST", form.action,
                data=cleaned,
                headers={"Content-Type": None},  # let httpx set boundary
            )

        return await self.post(form.action, data=cleaned)

    # ------------------------------------------------------------------
    # Utility: crawl helpers
    # ------------------------------------------------------------------

    async def fetch_and_extract(self, url: str) -> SmartResponse:
        """GET a URL and eagerly parse forms + links (triggers lazy properties)."""
        resp = await self.get(url)
        # Force evaluation of lazy properties so callers can access immediately
        _ = resp.forms
        _ = resp.links
        return resp

    async def get_all_internal_links(self, url: str) -> List[str]:
        """Convenience: fetch *url* and return only internal link URLs."""
        resp = await self.get(url)
        return [link.url for link in resp.links if link.is_internal and not link.is_resource]

    # ------------------------------------------------------------------
    # History / metrics
    # ------------------------------------------------------------------

    def get_request_history(self) -> List[RequestRecord]:
        """Return the full list of ``RequestRecord`` objects."""
        return list(self._history)

    def get_history_summary(self) -> List[Dict[str, Any]]:
        """Return lightweight summaries (no body) for each request."""
        return [r.to_dict() for r in self._history]

    def export_history(self, include_bodies: bool = False) -> List[Dict[str, Any]]:
        """
        Export entire history for reporting.

        Parameters
        ----------
        include_bodies : bool
            If True, include full response bodies (can be large).
        """
        if include_bodies:
            return [r.to_full_dict() for r in self._history]
        return [r.to_dict() for r in self._history]

    def get_metrics(self) -> Dict[str, Any]:
        """Return aggregate request metrics."""
        status_codes: Dict[int, int] = {}
        for r in self._history:
            status_codes[r.status_code] = status_codes.get(r.status_code, 0) + 1

        return {
            "total_requests": self._total_requests,
            "total_bytes_sent": self._total_bytes_sent,
            "total_bytes_received": self._total_bytes_received,
            "unique_urls": len(set(r.url for r in self._history)),
            "status_code_distribution": status_codes,
            "average_response_time_ms": (
                sum(r.elapsed_ms for r in self._history) / len(self._history)
                if self._history else 0.0
            ),
            "error_count": sum(
                1 for r in self._history if r.status_code >= 400
            ),
        }

    def find_requests_by_url(self, url_pattern: str) -> List[RequestRecord]:
        """Return all records whose URL contains *url_pattern*."""
        return [r for r in self._history if url_pattern in r.url]

    def find_requests_by_status(self, status_code: int) -> List[RequestRecord]:
        """Return all records with the given status code."""
        return [r for r in self._history if r.status_code == status_code]

    def clear_history(self) -> None:
        """Clear all recorded request history and reset metrics."""
        self._history.clear()
        self._total_requests = 0
        self._total_bytes_sent = 0
        self._total_bytes_received = 0

    # ------------------------------------------------------------------
    # Synthetic error responses (for timeouts, connection errors, etc.)
    # ------------------------------------------------------------------

    def _make_timeout_response(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body_for_log: Optional[str],
        timestamp: float,
    ) -> SmartResponse:
        """Build a SmartResponse representing a timeout."""
        return self._make_error_response(
            url, method, headers, body_for_log, timestamp,
            status_override=408,
            error_msg=f"Request timed out after {self.timeout}s",
        )

    def _make_error_response(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body_for_log: Optional[str],
        timestamp: float,
        status_override: int,
        error_msg: str,
    ) -> SmartResponse:
        """
        Fabricate a ``SmartResponse`` for a failed request so the caller
        always receives a consistent type.
        """
        # Create a mock httpx.Response
        mock_resp = httpx.Response(
            status_code=status_override,
            headers={"x-vapt-error": error_msg},
            text=json.dumps({"error": error_msg}),
            request=httpx.Request(method, url),
        )
        smart = SmartResponse(mock_resp, base_url=self.base_url)

        # Record it
        self._total_requests += 1
        request_id = hashlib.md5(
            f"{timestamp}{method}{url}".encode()
        ).hexdigest()[:12]
        record = RequestRecord(
            timestamp=timestamp,
            method=method.upper(),
            url=url,
            request_headers=headers,
            request_body=body_for_log,
            status_code=status_override,
            response_headers=dict(mock_resp.headers),
            response_body=smart.body,
            response_size=smart.content_length,
            elapsed_ms=0.0,
            request_id=request_id,
        )
        self._history.append(record)

        return smart

    # ------------------------------------------------------------------
    # repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<SmartHTTPClient base_url={self.base_url!r} "
            f"requests={self._total_requests} "
            f"auth={'yes' if self._auth_token else 'no'}>"
        )