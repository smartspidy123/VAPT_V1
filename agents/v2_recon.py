"""
VAPT-AI V2.0 - Enhanced Reconnaissance Agent
=============================================
Replaces old agents/recon.py with deep browser-based recon,
JavaScript analysis, API endpoint mapping, and sensitive file detection.
"""

import asyncio
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, unquote

from utils.logger import setup_logger
from config.settings import (
    TOOL_PATHS,
    SCAN_CONFIG,
    AGENT_CONFIG,
    TASK_MODEL_MAPPING,
    DATA_DIR,
)
from core.tool_engine import SecurityToolsEngine
from core.browser_engine import BrowserEngine, NetworkRequest, DiscoveredEndpoint, PageData
from core.http_client import SmartHTTPClient, SmartResponse
from core.state_manager import StateManager, EndpointRecord, VulnerabilityRecord
from core.llm_router import SmartLLMRouter as LLMRouter

from pathlib import Path
logger = setup_logger(name="v2_recon", log_dir=Path("logs"))


# ============================================
# CONSTANTS
# ============================================

SENSITIVE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/security.txt",
    "/.well-known/security.txt", "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]

BACKUP_EXTENSIONS = [
    ".bak", ".old", ".swp", ".sav", ".save", ".tmp",
    ".temp", ".orig", ".copy", ".backup", "~",
    ".dist", ".sample", ".example",
]

CONFIG_FILES = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.staging", "/.env.backup", "/.env.old",
    "/config.json", "/config.yaml", "/config.yml",
    "/config.xml", "/config.ini", "/config.php",
    "/configuration.php", "/settings.json", "/settings.yaml",
    "/wp-config.php", "/wp-config.php.bak",
    "/web.config", "/appsettings.json",
    "/application.properties", "/application.yml",
    "/database.yml", "/database.json",
    "/credentials.json", "/secrets.json",
    "/firebase.json", "/firebaseConfig.js",
]

LOG_FILES = [
    "/error.log", "/access.log", "/debug.log",
    "/application.log", "/app.log", "/server.log",
    "/logs/error.log", "/logs/access.log", "/logs/debug.log",
    "/log/error.log", "/log/access.log",
    "/var/log/error.log",
]

DATABASE_FILES = [
    "/database.db", "/data.db", "/app.db",
    "/sqlite.db", "/sqlite3.db", "/database.sqlite",
    "/database.sqlite3", "/data.sqlite", "/data.sqlite3",
    "/db.sqlite", "/db.sqlite3",
    "/backup.sql", "/dump.sql", "/database.sql",
    "/data.sql", "/db.sql",
]

HIDDEN_DIRS = [
    "/.git/", "/.git/config", "/.git/HEAD",
    "/.svn/", "/.svn/entries",
    "/.hg/", "/.bzr/",
    "/.DS_Store",
    "/node_modules/", "/vendor/",
]

INTERESTING_PATHS = [
    "/ftp", "/backup", "/backups", "/bkp",
    "/api-docs", "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api/swagger", "/api/docs", "/api/v1/docs",
    "/redoc", "/api-doc",
    "/metrics", "/prometheus", "/prometheus/metrics",
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/info", "/actuator/beans", "/actuator/configprops",
    "/actuator/mappings", "/actuator/trace", "/actuator/heapdump",
    "/debug", "/debug/vars", "/debug/pprof",
    "/console", "/admin", "/admin/login",
    "/administrator", "/phpmyadmin", "/pma",
    "/adminer", "/adminer.php",
    "/graphql", "/graphiql", "/graphql/console",
    "/wp-admin", "/wp-login.php",
    "/.well-known/", "/info", "/info.php",
    "/phpinfo.php", "/server-info", "/server-status",
    "/status", "/health", "/healthcheck", "/health-check",
    "/package.json", "/package-lock.json",
    "/composer.json", "/composer.lock",
    "/Gemfile", "/Gemfile.lock",
    "/webpack.config.js", "/tsconfig.json",
    "/Dockerfile", "/docker-compose.yml",
    "/.dockerenv", "/Procfile",
    "/Makefile", "/Gruntfile.js", "/Gulpfile.js",
    "/manifest.json", "/browserconfig.xml",
    "/humans.txt", "/changelog.txt", "/readme.txt",
    "/README.md", "/CHANGELOG.md", "/LICENSE",
    "/CONTRIBUTING.md", "/TODO.md",
    "/trace.axd", "/elmah.axd",
    "/_profiler/", "/_debugbar/",
    "/telescope", "/horizon",
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/rest/", "/rest/v1/", "/rest/v2/",
    "/cgi-bin/", "/cgi-bin/test",
    "/test", "/testing", "/staging",
    "/tmp/", "/temp/", "/cache/",
    "/uploads/", "/upload/", "/files/",
    "/images/", "/img/", "/media/",
    "/static/", "/assets/", "/public/",
    "/private/", "/internal/", "/secret/",
]

JS_SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{8,})["\']', "API Key"),
    (r'(?:secret|secret[_-]?key)\s*[:=]\s*["\']([^"\']{8,})["\']', "Secret Key"),
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "Password"),
    (r'(?:token|auth[_-]?token|access[_-]?token)\s*[:=]\s*["\']([^"\']{8,})["\']', "Token"),
    (r'(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\']([A-Z0-9]{20})["\']', "AWS Access Key"),
    (r'(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS Secret Key"),
    (r'(?:firebase|google)[_-]?api[_-]?key\s*[:=]\s*["\']([^"\']{20,})["\']', "Firebase/Google Key"),
    (r'(?:stripe)[_-]?(?:publishable|secret)[_-]?key\s*[:=]\s*["\']([^"\']{20,})["\']', "Stripe Key"),
    (r'(?:github|gh)[_-]?token\s*[:=]\s*["\']([^"\']{20,})["\']', "GitHub Token"),
    (r'(?:slack)[_-]?(?:token|webhook)\s*[:=]\s*["\']([^"\']{20,})["\']', "Slack Token"),
    (r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)', "Bearer Token"),
    (r'Basic\s+([A-Za-z0-9+/]+=*)', "Basic Auth"),
    (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "JWT Token"),
    (r'(?:mongodb(?:\+srv)?://[^\s"\']+)', "MongoDB URI"),
    (r'(?:postgres(?:ql)?://[^\s"\']+)', "PostgreSQL URI"),
    (r'(?:mysql://[^\s"\']+)', "MySQL URI"),
    (r'(?:redis://[^\s"\']+)', "Redis URI"),
    (r'(?:smtp://[^\s"\']+)', "SMTP URI"),
]

JS_ROUTE_PATTERNS = [
    r'path\s*:\s*["\'](/[^"\']*)["\']',
    r'route\s*\(\s*["\'](/[^"\']*)["\']',
    r'router\.\w+\s*\(\s*["\'](/[^"\']*)["\']',
    r'app\.\w+\s*\(\s*["\'](/[^"\']*)["\']',
    r'express\.Router\(\).*?\.\w+\s*\(\s*["\'](/[^"\']*)["\']',
    r'navigateByUrl\s*\(\s*["\'](/[^"\']*)["\']',
    r'this\.router\.navigate\s*\(\s*\[\s*["\'](/[^"\']*)["\']',
    r'navigate\s*\(\s*["\'](/[^"\']*)["\']',
    r'to\s*[:=]\s*["\'](/[^"\']*)["\']',
    r'redirect\s*[:=]\s*["\'](/[^"\']*)["\']',
    r'href\s*[:=]\s*["\'](/[^"\']*)["\']',
    r'url\s*[:=]\s*["\'](/[^"\']*)["\']',
]

JS_API_PATTERNS = [
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
    r'\$\.(?:ajax|get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
    r'\.(?:get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\']+)["\']',
    r'XMLHttpRequest.*?\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
    r'(?:api[_-]?url|base[_-]?url|endpoint|api[_-]?endpoint)\s*[:=]\s*["\']([^"\']+)["\']',
    r'(?:API_URL|BASE_URL|ENDPOINT|API_ENDPOINT)\s*[:=]\s*["\']([^"\']+)["\']',
    r'url\s*:\s*["\'](/[^"\']+)["\']',
    r'(?:apiBase|apiRoot|serverUrl)\s*[:=]\s*["\']([^"\']+)["\']',
]

JS_VALIDATION_PATTERNS = [
    (r'(?:minLength|minlength)\s*[:=]\s*(\d+)', "min_length"),
    (r'(?:maxLength|maxlength)\s*[:=]\s*(\d+)', "max_length"),
    (r'(?:pattern|regex)\s*[:=]\s*["\'/]([^"\'\/]+)["\'/]', "regex_pattern"),
    (r'(?:required)\s*[:=]\s*(true|false)', "required"),
    (r'(?:min)\s*[:=]\s*(\d+)', "min_value"),
    (r'(?:max)\s*[:=]\s*(\d+)', "max_value"),
    (r'(?:type)\s*[:=]\s*["\'](\w+)["\']', "field_type"),
    (r'(?:accept)\s*[:=]\s*["\']([^"\']+)["\']', "file_accept"),
    (r'(?:allowedTypes|allowed_types)\s*[:=]\s*\[([^\]]+)\]', "allowed_file_types"),
    (r'(?:maxSize|max_size|maxFileSize)\s*[:=]\s*(\d+)', "max_file_size"),
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Feature-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cache-Control",
    "Pragma",
    "X-Permitted-Cross-Domain-Policies",
]

DB_ERROR_SIGNATURES = {
    "mysql": [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "unclosed quotation mark",
        "mysql_fetch",
        "mysqli_",
        "mysqlnd",
        "com.mysql.jdbc",
        "mariadb",
    ],
    "postgresql": [
        "pg_query",
        "pg_exec",
        "pg_connect",
        "unterminated quoted string",
        "org.postgresql",
        "psql:",
        "pgsql",
        "ERROR:  syntax error at or near",
    ],
    "mssql": [
        "microsoft sql server",
        "sqlserver",
        "unclosed quotation mark after the character string",
        "incorrect syntax near",
        "[microsoft][odbc sql server driver]",
        "system.data.sqlclient",
        "mssql_",
    ],
    "oracle": [
        "ora-",
        "oracle error",
        "oracle driver",
        "quoted string not properly terminated",
        "oracleexception",
        "oracle.jdbc",
    ],
    "sqlite": [
        "sqlite3.operationalerror",
        "sqlite_error",
        "unable to open database file",
        "unrecognized token",
        "sqlite3::",
        "sqliteexception",
        "system.data.sqlite",
    ],
    "mongodb": [
        "mongoerror",
        "mongo_",
        "mongodb",
        "bson",
        "objectid",
    ],
}


# ============================================
# HELPER DATACLASSES
# ============================================

@dataclass
class JSAnalysisResult:
    """Result of analyzing a single JavaScript file."""
    url: str = ""
    routes: List[Dict[str, str]] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict[str, str]] = field(default_factory=list)
    validation_rules: List[Dict[str, Any]] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    interesting_strings: List[str] = field(default_factory=list)
    size_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "routes": self.routes,
            "api_endpoints": self.api_endpoints,
            "secrets": self.secrets,
            "validation_rules": self.validation_rules,
            "comments": self.comments,
            "interesting_strings": self.interesting_strings,
            "size_bytes": self.size_bytes,
        }


@dataclass
class ReconResult:
    """Aggregated result of all recon operations."""
    target_url: str = ""
    technologies: List[str] = field(default_factory=list)
    waf_detected: str = ""
    server_info: str = ""
    framework_info: str = ""
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    security_headers: Dict[str, Any] = field(default_factory=dict)
    missing_headers: List[str] = field(default_factory=list)
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    api_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    js_analysis: List[Dict[str, Any]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    sensitive_files: List[Dict[str, Any]] = field(default_factory=list)
    directories: List[Dict[str, Any]] = field(default_factory=list)
    secrets_found: List[Dict[str, str]] = field(default_factory=list)
    db_type_hints: List[str] = field(default_factory=list)
    login_endpoints: List[str] = field(default_factory=list)
    register_endpoints: List[str] = field(default_factory=list)
    hidden_paths: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "technologies": self.technologies,
            "waf_detected": self.waf_detected,
            "server_info": self.server_info,
            "framework_info": self.framework_info,
            "open_ports": self.open_ports,
            "security_headers": self.security_headers,
            "missing_headers": self.missing_headers,
            "endpoints_count": len(self.endpoints),
            "api_endpoints_count": len(self.api_endpoints),
            "js_files_count": len(self.js_files),
            "forms_count": len(self.forms),
            "sensitive_files_count": len(self.sensitive_files),
            "secrets_found_count": len(self.secrets_found),
            "db_type_hints": self.db_type_hints,
            "login_endpoints": self.login_endpoints,
            "register_endpoints": self.register_endpoints,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
        }


# ============================================
# V2 RECON AGENT
# ============================================

class V2ReconAgent:
    """
    Enhanced Reconnaissance Agent for VAPT-AI V2.0.

    Capabilities:
    - Technology, WAF, port scanning (via external tools)
    - Security header analysis
    - Browser-based SPA crawling
    - JavaScript deep analysis (routes, APIs, secrets)
    - API endpoint mapping with auth detection
    - Directory/file bruteforcing (ffuf)
    - Sensitive file detection
    """

    def __init__(
        self,
        target_url: str,
        state_manager: StateManager,
        tool_engine: SecurityToolsEngine,
        llm_router: LLMRouter,
        browser_engine: Optional[BrowserEngine] = None,
        http_client: Optional[SmartHTTPClient] = None,
        scan_intensity: str = "medium",
    ) -> None:
        self.target_url: str = target_url.rstrip("/")
        self.state: StateManager = state_manager
        self.tools: SecurityToolsEngine = tool_engine
        self.llm: LLMRouter = llm_router
        self.browser: Optional[BrowserEngine] = browser_engine
        self.http: Optional[SmartHTTPClient] = http_client
        self.scan_intensity: str = scan_intensity

        parsed = urlparse(self.target_url)
        self.target_host: str = parsed.hostname or ""
        self.target_port: int = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.target_scheme: str = parsed.scheme or "http"
        self.base_domain: str = self.target_host

        self._owns_browser: bool = False
        self._owns_http: bool = False

        self.result: ReconResult = ReconResult(target_url=self.target_url)

        self._discovered_urls: Set[str] = set()
        self._discovered_api_urls: Set[str] = set()
        self._discovered_js_urls: Set[str] = set()
        self._checked_paths: Set[str] = set()

        self._max_concurrent: int = SCAN_CONFIG.get("max_concurrent_tools", 3)
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(self._max_concurrent)

        logger.info(f"V2ReconAgent initialized for target: {self.target_url}")

    # ============================================
    # LIFECYCLE
    # ============================================

    async def _ensure_browser(self) -> BrowserEngine:
        """Ensure browser engine is available and started."""
        if self.browser is None:
            logger.info("Creating new BrowserEngine instance")
            self.browser = BrowserEngine(
                headless=True,
                proxy=None,
                default_timeout=30000,
            )
            self._owns_browser = True
        try:
            await self.browser._ensure_started()
        except Exception:
            await self.browser.start()
        return self.browser

    async def _ensure_http(self) -> SmartHTTPClient:
        """Ensure HTTP client is available."""
        if self.http is None:
            logger.info("Creating new SmartHTTPClient instance")
            self.http = SmartHTTPClient(
                base_url=self.target_url,
                timeout=30,
                max_retries=2,
                rate_limit=SCAN_CONFIG.get("target_rps", {}).get(self.scan_intensity, 15),
            )
            self._owns_http = True
        await self.http._ensure_client()
        return self.http

    async def _cleanup(self) -> None:
        """Clean up owned resources."""
        if self._owns_browser and self.browser is not None:
            try:
                await self.browser.stop()
            except Exception as e:
                logger.warning(f"Error stopping browser: {e}")
        if self._owns_http and self.http is not None:
            try:
                await self.http.close()
            except Exception as e:
                logger.warning(f"Error closing HTTP client: {e}")

    # ============================================
    # MAIN ENTRY POINT
    # ============================================

    async def run(self) -> ReconResult:
        """
        Execute full reconnaissance pipeline.

        Order:
        1. Basic recon (whatweb, wafw00f, nmap, headers) — parallel
        2. Browser-based discovery (SPA crawl, network intercept)
        3. JavaScript deep analysis
        4. API endpoint mapping
        5. Directory/file discovery (ffuf + custom checks)
        6. Sensitive file detection

        Returns a ReconResult with all discovery data and updates StateManager.
        """
        start_time = time.time()
        logger.info(f"{'='*60}")
        logger.info(f"V2 RECON STARTING for {self.target_url}")
        logger.info(f"Intensity: {self.scan_intensity}")
        logger.info(f"{'='*60}")

        self.state.set_scan_status("recon_running")

        try:
            # ------- PHASE 1: Basic Recon (Parallel) -------
            logger.info("[PHASE 1] Basic Reconnaissance (parallel)")
            await self._phase1_basic_recon()

            # ------- PHASE 2: Browser-Based Discovery -------
            logger.info("[PHASE 2] Browser-Based Discovery")
            await self._phase2_browser_discovery()

            # ------- PHASE 3: JavaScript Deep Analysis -------
            logger.info("[PHASE 3] JavaScript Deep Analysis")
            await self._phase3_js_analysis()

            # ------- PHASE 4: API Endpoint Mapping -------
            logger.info("[PHASE 4] API Endpoint Mapping")
            await self._phase4_api_mapping()

            # ------- PHASE 5: Directory / File Discovery -------
            logger.info("[PHASE 5] Directory & File Discovery")
            await self._phase5_directory_discovery()

            # ------- PHASE 6: Sensitive File Detection -------
            logger.info("[PHASE 6] Sensitive File Detection")
            await self._phase6_sensitive_files()

            # ------- Finalize -------
            self.result.duration_seconds = time.time() - start_time
            await self._sync_results_to_state()
            self.state.set_scan_status("recon_complete")

            logger.info(f"{'='*60}")
            logger.info(f"V2 RECON COMPLETE in {self.result.duration_seconds:.1f}s")
            logger.info(f"Endpoints: {len(self.result.endpoints)}")
            logger.info(f"API Endpoints: {len(self.result.api_endpoints)}")
            logger.info(f"JS Files: {len(self.result.js_files)}")
            logger.info(f"Forms: {len(self.result.forms)}")
            logger.info(f"Sensitive Files: {len(self.result.sensitive_files)}")
            logger.info(f"Secrets Found: {len(self.result.secrets_found)}")
            logger.info(f"{'='*60}")

        except Exception as e:
            logger.error(f"Recon failed with error: {e}", exc_info=True)
            self.result.errors.append(f"Fatal recon error: {str(e)}")
            self.state.set_scan_status("recon_error")
        finally:
            await self._cleanup()

        return self.result

    # ============================================
    # PHASE 1: BASIC RECON (PARALLEL)
    # ============================================

    async def _phase1_basic_recon(self) -> None:
        """Run whatweb, wafw00f, nmap, and header analysis concurrently."""
        tasks = [
            self._run_whatweb(),
            self._run_wafw00f(),
            self._run_nmap(),
            self._analyze_security_headers(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                task_names = ["whatweb", "wafw00f", "nmap", "headers"]
                err_msg = f"Phase1 {task_names[i]} failed: {str(res)}"
                logger.warning(err_msg)
                self.result.errors.append(err_msg)

    async def _run_whatweb(self) -> None:
        """Detect technologies using whatweb."""
        async with self._semaphore:
            logger.info("Running whatweb for technology detection...")
            try:
                cmd = self.tools.build_whatweb_command(self.target_url)
                tool_result = await self.tools.execute_command(
                    command=cmd,
                    tool_name="whatweb",
                    timeout=60,
                )

                if tool_result.success and tool_result.output:
                    parsed = self.tools._parse_whatweb(tool_result.output)
                    techs = parsed.get("technologies", [])
                    server = parsed.get("server", "")
                    framework = parsed.get("framework", "")

                    if techs:
                        self.result.technologies.extend(techs)
                        logger.info(f"WhatWeb detected technologies: {techs}")
                    if server:
                        self.result.server_info = server
                        logger.info(f"WhatWeb detected server: {server}")
                    if framework:
                        self.result.framework_info = framework
                        logger.info(f"WhatWeb detected framework: {framework}")

                    self.state.set_target_info(
                        technologies=techs if techs else None,
                        server_info=server if server else None,
                        framework_info=framework if framework else None,
                    )
                else:
                    logger.warning(f"WhatWeb returned no usable output. Error: {tool_result.error}")
            except Exception as e:
                logger.error(f"WhatWeb execution error: {e}")
                self.result.errors.append(f"WhatWeb error: {str(e)}")

    async def _run_wafw00f(self) -> None:
        """Detect WAF using wafw00f."""
        async with self._semaphore:
            logger.info("Running wafw00f for WAF detection...")
            try:
                cmd = self.tools.build_wafw00f_command(self.target_url)
                tool_result = await self.tools.execute_command(
                    command=cmd,
                    tool_name="wafw00f",
                    timeout=60,
                )

                if tool_result.success and tool_result.output:
                    parsed = self.tools._parse_wafw00f(tool_result.output)
                    waf = parsed.get("waf", "")
                    if waf and waf.lower() not in ("none", "no waf", "generic", ""):
                        self.result.waf_detected = waf
                        self.state.set_target_info(waf_detected=waf)
                        logger.info(f"WAF detected: {waf}")

                        self.state.add_finding(
                            vulnerability={
                                "category": "info",
                                "severity": "info",
                                "title": f"WAF Detected: {waf}",
                                "endpoint": self.target_url,
                                "parameter": "",
                                "payload": "",
                                "evidence": f"wafw00f identified WAF: {waf}",
                                "description": f"A Web Application Firewall ({waf}) is in front of the target. "
                                               f"Attack payloads may need WAF bypass techniques.",
                                "remediation": "WAF is a defense mechanism, not a vulnerability.",
                            },
                            confirmed=True,
                        )
                    else:
                        self.result.waf_detected = "None"
                        self.state.set_target_info(waf_detected="None")
                        logger.info("No WAF detected")
                else:
                    logger.warning(f"wafw00f returned no output. Error: {tool_result.error}")
            except Exception as e:
                logger.error(f"wafw00f execution error: {e}")
                self.result.errors.append(f"wafw00f error: {str(e)}")

    async def _run_nmap(self) -> None:
        """Scan top ports using nmap."""
        async with self._semaphore:
            logger.info("Running nmap port scan...")
            try:
                port_count = {
                    "low": "100",
                    "medium": "1000",
                    "high": "5000",
                    "aggressive": "10000",
                }.get(self.scan_intensity, "1000")

                cmd = self.tools.build_nmap_command(
                    target=self.target_host,
                    scan_type="default",
                    ports=f"--top-ports {port_count}",
                )
                tool_result = await self.tools.execute_command(
                    command=cmd,
                    tool_name="nmap",
                    timeout=180,
                )

                if tool_result.success and tool_result.output:
                    parsed = self.tools._parse_nmap(tool_result.output)
                    open_ports = parsed.get("open_ports", [])
                    if open_ports:
                        self.result.open_ports = open_ports
                        logger.info(f"Nmap found {len(open_ports)} open ports")
                        for port_info in open_ports:
                            port_num = port_info.get("port", "")
                            service = port_info.get("service", "")
                            version = port_info.get("version", "")
                            if service:
                                tech_str = f"{service}"
                                if version:
                                    tech_str += f" {version}"
                                self.result.technologies.append(tech_str)
                            logger.info(f"  Port {port_num}: {service} {version}")
                    else:
                        logger.info("Nmap found no open ports (or parsing failed)")
                else:
                    logger.warning(f"Nmap returned no output. Error: {tool_result.error}")
            except Exception as e:
                logger.error(f"Nmap execution error: {e}")
                self.result.errors.append(f"Nmap error: {str(e)}")

    async def _analyze_security_headers(self) -> None:
        """Fetch target and analyze security headers."""
        logger.info("Analyzing security headers...")
        try:
            http = await self._ensure_http()
            resp: SmartResponse = await http.get(self.target_url)

            if resp is None:
                logger.warning("Could not fetch target for header analysis")
                return

            header_analysis = resp.analyse_security_headers()
            self.result.security_headers = header_analysis

            present = header_analysis.get("present", {})
            missing = header_analysis.get("missing", [])
            self.result.missing_headers = missing

            if missing:
                logger.info(f"Missing security headers: {missing}")
                missing_str = ", ".join(missing)
                self.state.add_finding(
                    vulnerability={
                        "category": "misconfiguration",
                        "severity": "low",
                        "title": "Missing Security Headers",
                        "endpoint": self.target_url,
                        "parameter": "",
                        "payload": "",
                        "evidence": f"Missing headers: {missing_str}",
                        "description": f"The following security headers are missing: {missing_str}. "
                                       f"This may allow various attacks depending on the context.",
                        "remediation": "Add the missing security headers to all HTTP responses. "
                                       "Key headers: Strict-Transport-Security, Content-Security-Policy, "
                                       "X-Content-Type-Options, X-Frame-Options.",
                    },
                    confirmed=True,
                )

            tech_detection = resp.detect_technologies()
            if tech_detection:
                for tech_name, tech_val in tech_detection.items():
                    if tech_val:
                        combined = f"{tech_name}: {tech_val}" if tech_val != "true" else tech_name
                        self.result.technologies.append(combined)

            server_header = resp.headers.get("Server", "") or resp.headers.get("server", "")
            if server_header and not self.result.server_info:
                self.result.server_info = server_header
                self.state.set_target_info(server_info=server_header)

            x_powered = resp.headers.get("X-Powered-By", "") or resp.headers.get("x-powered-by", "")
            if x_powered:
                self.result.technologies.append(f"X-Powered-By: {x_powered}")

        except Exception as e:
            logger.error(f"Security header analysis error: {e}")
            self.result.errors.append(f"Header analysis error: {str(e)}")

    # ============================================
    # UTILITY: Add discovered URL as endpoint
    # ============================================

    def _add_endpoint(
        self,
        url: str,
        method: str = "GET",
        params: Optional[List[str]] = None,
        auth_required: bool = False,
        response_code: int = 0,
        content_type: str = "",
        source: str = "recon",
    ) -> bool:
        """Add a discovered URL to the results and state, deduplicating."""
        normalized = self._normalize_url(url)
        key = f"{method.upper()}|{normalized}"
        if key in self._discovered_urls:
            return False
        self._discovered_urls.add(key)

        ep_dict = {
            "url": normalized,
            "method": method.upper(),
            "params": params or [],
            "auth_required": auth_required,
            "response_code": response_code,
            "content_type": content_type,
            "source": source,
        }

        self.result.endpoints.append(ep_dict)

        url_lower = normalized.lower()
        api_indicators = ["/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/",
                          "/ajax/", "/json/", "/rpc/"]
        if any(ind in url_lower for ind in api_indicators):
            if normalized not in self._discovered_api_urls:
                self._discovered_api_urls.add(normalized)
                self.result.api_endpoints.append(ep_dict)

        self.state.add_endpoint(endpoint=ep_dict)
        return True

    def _normalize_url(self, url: str) -> str:
        """Normalize a URL: ensure absolute, remove fragments, trailing slash."""
        if url.startswith("//"):
            url = f"{self.target_scheme}:{url}"
        elif url.startswith("/"):
            url = urljoin(self.target_url, url)
        elif not url.startswith(("http://", "https://")):
            url = urljoin(self.target_url + "/", url)

        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    def _is_same_origin(self, url: str) -> bool:
        """Check if a URL belongs to the same origin as target."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            return host == self.target_host or host.endswith(f".{self.base_domain}")
        except Exception:
            return False

    def _extract_params_from_url(self, url: str) -> List[str]:
        """Extract query parameter names from a URL."""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return list(params.keys())
        except Exception:
            return []

    def _detect_db_from_text(self, text: str) -> List[str]:
        """Detect database types from error messages or response text."""
        text_lower = text.lower()
        detected = []
        for db_type, signatures in DB_ERROR_SIGNATURES.items():
            for sig in signatures:
                if sig in text_lower:
                    if db_type not in detected:
                        detected.append(db_type)
                    break
        return detected

    def _detect_auth_endpoints(self, url: str) -> None:
        """Detect if a URL is a login or registration endpoint."""
        url_lower = url.lower()
        path = urlparse(url_lower).path

        login_keywords = ["/login", "/signin", "/sign-in", "/auth/login",
                          "/api/login", "/api/auth/login", "/api/signin",
                          "/user/login", "/account/login", "/session",
                          "/api/session", "/authenticate", "/api/authenticate"]
        register_keywords = ["/register", "/signup", "/sign-up", "/auth/register",
                             "/api/register", "/api/auth/register", "/api/signup",
                             "/user/register", "/account/register", "/create-account",
                             "/api/users", "/join"]

        for kw in login_keywords:
            if kw in path:
                if url not in self.result.login_endpoints:
                    self.result.login_endpoints.append(url)
                    self.state.set_login_endpoint(url)
                    logger.info(f"Login endpoint detected: {url}")
                break

        for kw in register_keywords:
            if kw in path:
                if url not in self.result.register_endpoints:
                    self.result.register_endpoints.append(url)
                    self.state.set_register_endpoint(url)
                    logger.info(f"Register endpoint detected: {url}")
                break

    # ============================================
    # SYNC RESULTS TO STATE
    # ============================================

    async def _sync_results_to_state(self) -> None:
        """Push all aggregated results into StateManager."""
        deduped_techs = list(set(t for t in self.result.technologies if t))
        if deduped_techs:
            self.state.set_target_info(technologies=deduped_techs)

        for js_url in self.result.js_files:
            self.state.add_js_file(js_url)

        for path in self.result.hidden_paths:
            self.state.add_hidden_path(path)

        for form_data in self.result.forms:
            self.state.add_form(form_data)

        if self.result.db_type_hints:
            deduped_db = list(set(self.result.db_type_hints))
            for db in deduped_db:
                self.state.set_target_info(technologies=[f"Database: {db}"])

        for secret_info in self.result.secrets_found:
            self.state.add_finding(
                vulnerability={
                    "category": "information_disclosure",
                    "severity": "high",
                    "title": f"Hardcoded Secret Found: {secret_info.get('type', 'Unknown')}",
                    "endpoint": secret_info.get("source", self.target_url),
                    "parameter": "",
                    "payload": "",
                    "evidence": f"Type: {secret_info.get('type', '')}, "
                                f"Value: {secret_info.get('value', '')[:20]}...",
                    "description": f"A hardcoded secret ({secret_info.get('type', '')}) was found in "
                                   f"JavaScript source code at {secret_info.get('source', '')}.",
                    "remediation": "Remove hardcoded secrets from client-side code. "
                                   "Use environment variables and server-side configuration.",
                },
                confirmed=True,
            )

        for sf in self.result.sensitive_files:
            self.state.add_finding(
                vulnerability={
                    "category": "information_disclosure",
                    "severity": sf.get("severity", "medium"),
                    "title": f"Sensitive File Exposed: {sf.get('path', '')}",
                    "endpoint": sf.get("url", self.target_url),
                    "parameter": "",
                    "payload": "",
                    "evidence": f"HTTP {sf.get('status_code', '?')} - {sf.get('content_type', '')} "
                                f"- Size: {sf.get('size', 0)} bytes",
                    "description": f"Sensitive file found at {sf.get('path', '')}. "
                                   f"Type: {sf.get('file_type', 'unknown')}.",
                    "remediation": "Remove sensitive files from the web root or restrict access "
                                   "via server configuration.",
                },
                confirmed=True,
            )

        logger.info("All recon results synced to StateManager")
        
    # ============================================
    # PHASE 2: BROWSER-BASED DISCOVERY
    # ============================================

    async def _phase2_browser_discovery(self) -> None:
        """
        Use headless browser to:
        1. Navigate to target
        2. Intercept ALL network requests
        3. Click through navigation elements
        4. Extract endpoints from network log
        5. Extract forms from DOM
        6. Detect technologies from DOM
        """
        try:
            browser = await self._ensure_browser()
        except Exception as e:
            logger.warning(f"Browser engine unavailable, skipping Phase 2: {e}")
            self.result.errors.append(f"Browser unavailable: {str(e)}")
            return

        try:
            # Step 1: Navigate and intercept
            logger.info("[Phase2] Navigating to target with network interception...")
            await self._browser_navigate_and_intercept(browser)

            # Step 2: Click navigation elements to discover more pages
            logger.info("[Phase2] Clicking through navigation elements...")
            await self._browser_click_navigation(browser)

            # Step 3: Extract endpoints from network log
            logger.info("[Phase2] Extracting endpoints from network log...")
            self._extract_endpoints_from_network_log(browser)

            # Step 4: Extract forms from DOM
            logger.info("[Phase2] Extracting forms from DOM...")
            await self._browser_extract_forms(browser)

            # Step 5: Extract JS file URLs
            logger.info("[Phase2] Extracting JavaScript file URLs...")
            await self._browser_extract_js_urls(browser)

            # Step 6: Detect technologies from DOM
            logger.info("[Phase2] Detecting technologies from DOM...")
            await self._browser_detect_technologies(browser)

            logger.info(f"[Phase2] Complete. Network requests captured: {len(browser.get_network_log())}")

        except Exception as e:
            logger.error(f"Phase 2 browser discovery error: {e}", exc_info=True)
            self.result.errors.append(f"Browser discovery error: {str(e)}")

    async def _browser_navigate_and_intercept(self, browser: BrowserEngine) -> None:
        """Navigate to target and capture network traffic."""
        try:
            page_data: PageData = await browser.navigate(
                url=self.target_url,
                wait_for="networkidle",
            )

            if page_data:
                if page_data.title:
                    logger.info(f"Page title: {page_data.title}")
                if page_data.technologies:
                    self.result.technologies.extend(page_data.technologies)

                for link in page_data.links:
                    full_url = self._normalize_url(link)
                    if self._is_same_origin(full_url):
                        self._add_endpoint(
                            url=full_url,
                            method="GET",
                            source="browser_link",
                        )
                        self._detect_auth_endpoints(full_url)

                for script_src in page_data.script_sources:
                    abs_src = self._normalize_url(script_src)
                    if abs_src not in self._discovered_js_urls:
                        self._discovered_js_urls.add(abs_src)
                        self.result.js_files.append(abs_src)

                if page_data.forms:
                    for form in page_data.forms:
                        form_dict = form if isinstance(form, dict) else form.to_dict()
                        self.result.forms.append(form_dict)
                        action = form_dict.get("action", "")
                        if action:
                            abs_action = self._normalize_url(action)
                            method = form_dict.get("method", "POST").upper()
                            field_names = []
                            for f in form_dict.get("fields", []):
                                name = f.get("name", "")
                                if name:
                                    field_names.append(name)
                            self._add_endpoint(
                                url=abs_action,
                                method=method,
                                params=field_names,
                                source="browser_form",
                            )
                            self._detect_auth_endpoints(abs_action)

            # Wait extra time to capture late-loading API calls
            logger.info("[Phase2] Waiting 10 seconds for late API calls...")
            await asyncio.sleep(10)

        except Exception as e:
            logger.error(f"Browser navigate and intercept error: {e}")
            self.result.errors.append(f"Browser navigation error: {str(e)}")

    async def _browser_click_navigation(self, browser: BrowserEngine) -> None:
        """Click navigation elements to discover more pages and API calls."""
        try:
            await browser._click_navigation_elements(self.target_url)
            await asyncio.sleep(5)
        except Exception as e:
            logger.warning(f"Navigation clicking error: {e}")

        # Also try to discover endpoints via the browser's built-in method
        try:
            discovered: List[DiscoveredEndpoint] = await browser.discover_endpoints(
                url=self.target_url,
                click_depth=2,
                wait_seconds=15,
            )
            for ep in discovered:
                ep_dict = ep.to_dict() if hasattr(ep, "to_dict") else ep
                url = ep_dict.get("url", "")
                method = ep_dict.get("method", "GET")
                if url and self._is_same_origin(url):
                    self._add_endpoint(
                        url=url,
                        method=method,
                        source="browser_discover",
                    )
                    self._detect_auth_endpoints(url)
        except Exception as e:
            logger.warning(f"Browser endpoint discovery error: {e}")

    def _extract_endpoints_from_network_log(self, browser: BrowserEngine) -> None:
        """Extract all API endpoints and page navigations from network log."""
        network_log: List[NetworkRequest] = browser.get_network_log()
        api_calls: List[NetworkRequest] = browser.get_api_calls()

        logger.info(f"Processing {len(network_log)} network requests, {len(api_calls)} API calls")

        for req in network_log:
            req_dict = req.to_dict() if hasattr(req, "to_dict") else req
            url = req_dict.get("url", "")
            method = req_dict.get("method", "GET")
            status = req_dict.get("status", 0)
            resource_type = req_dict.get("resource_type", "")
            content_type = req_dict.get("content_type", "")

            if not url or not self._is_same_origin(url):
                continue

            # Skip static resources
            if resource_type in ("image", "font", "stylesheet", "media"):
                continue
            url_lower = url.lower()
            skip_extensions = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                               ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
                               ".mp3", ".webp", ".avif")
            if any(url_lower.endswith(ext) for ext in skip_extensions):
                continue

            # JS files — record separately
            if url_lower.endswith(".js") or resource_type == "script":
                if url not in self._discovered_js_urls:
                    self._discovered_js_urls.add(url)
                    self.result.js_files.append(url)
                continue

            params = self._extract_params_from_url(url)
            self._add_endpoint(
                url=url,
                method=method.upper(),
                params=params,
                response_code=status,
                content_type=content_type,
                source="network_log",
            )
            self._detect_auth_endpoints(url)

        # Process API calls specifically
        for req in api_calls:
            req_dict = req.to_dict() if hasattr(req, "to_dict") else req
            url = req_dict.get("url", "")
            method = req_dict.get("method", "GET")
            status = req_dict.get("status", 0)
            content_type = req_dict.get("content_type", "")

            if not url or not self._is_same_origin(url):
                continue

            params = self._extract_params_from_url(url)

            # Try to extract body params from POST request data
            body = req_dict.get("post_data", "") or req_dict.get("request_body", "")
            body_params = self._extract_params_from_body(body)
            all_params = list(set(params + body_params))

            if url not in self._discovered_api_urls:
                self._discovered_api_urls.add(url)
                ep_dict = {
                    "url": url,
                    "method": method.upper(),
                    "params": all_params,
                    "auth_required": False,
                    "response_code": status,
                    "content_type": content_type,
                    "source": "api_intercept",
                }
                self.result.api_endpoints.append(ep_dict)
                self.state.add_endpoint(endpoint=ep_dict)
                self._detect_auth_endpoints(url)

        logger.info(f"Extracted {len(self.result.api_endpoints)} API endpoints from network log")

    def _extract_params_from_body(self, body: str) -> List[str]:
        """Extract parameter names from a request body (JSON or form-encoded)."""
        if not body:
            return []
        params = []

        # Try JSON
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                params.extend(data.keys())
                return list(params)
        except (json.JSONDecodeError, TypeError):
            pass

        # Try form-encoded
        try:
            from urllib.parse import parse_qs as pqs
            parsed = pqs(body)
            params.extend(parsed.keys())
        except Exception:
            pass

        return list(set(params))

    async def _browser_extract_forms(self, browser: BrowserEngine) -> None:
        """Extract forms from current DOM state."""
        try:
            forms = await browser._extract_forms_from_dom()
            for form in forms:
                form_dict = form.to_dict() if hasattr(form, "to_dict") else form
                already_exists = False
                for existing in self.result.forms:
                    if (existing.get("action") == form_dict.get("action") and
                            existing.get("method") == form_dict.get("method")):
                        already_exists = True
                        break
                if not already_exists:
                    self.result.forms.append(form_dict)

                    action = form_dict.get("action", "")
                    if action:
                        abs_action = self._normalize_url(action)
                        method = form_dict.get("method", "POST").upper()
                        field_names = []
                        for f_info in form_dict.get("fields", []):
                            name = f_info.get("name", "")
                            if name:
                                field_names.append(name)
                        self._add_endpoint(
                            url=abs_action,
                            method=method,
                            params=field_names,
                            source="dom_form",
                        )
                        self._detect_auth_endpoints(abs_action)

                        has_password = any(
                            f_info.get("type") == "password"
                            for f_info in form_dict.get("fields", [])
                        )
                        if has_password:
                            has_email_or_user = any(
                                f_info.get("type") in ("email", "text") or
                                f_info.get("name", "").lower() in (
                                    "email", "username", "user", "login", "name"
                                )
                                for f_info in form_dict.get("fields", [])
                            )
                            if has_email_or_user:
                                field_count = len([
                                    f_info for f_info in form_dict.get("fields", [])
                                    if f_info.get("type") not in ("hidden", "submit", "button")
                                ])
                                if field_count <= 3:
                                    if abs_action not in self.result.login_endpoints:
                                        self.result.login_endpoints.append(abs_action)
                                        self.state.set_login_endpoint(abs_action)
                                        logger.info(f"Login form detected at: {abs_action}")
                                elif field_count > 3:
                                    if abs_action not in self.result.register_endpoints:
                                        self.result.register_endpoints.append(abs_action)
                                        self.state.set_register_endpoint(abs_action)
                                        logger.info(f"Registration form detected at: {abs_action}")

            logger.info(f"Extracted {len(self.result.forms)} forms from DOM")
        except Exception as e:
            logger.warning(f"Form extraction error: {e}")

    async def _browser_extract_js_urls(self, browser: BrowserEngine) -> None:
        """Extract JavaScript file URLs from the page."""
        try:
            script_sources = await browser._extract_script_sources()
            for src in script_sources:
                abs_src = self._normalize_url(src)
                if abs_src not in self._discovered_js_urls:
                    self._discovered_js_urls.add(abs_src)
                    self.result.js_files.append(abs_src)
            logger.info(f"Total JS files discovered: {len(self.result.js_files)}")
        except Exception as e:
            logger.warning(f"JS URL extraction error: {e}")

    async def _browser_detect_technologies(self, browser: BrowserEngine) -> None:
        """Detect technologies from the DOM."""
        try:
            techs = await browser._detect_technologies()
            if techs:
                for tech in techs:
                    if tech and tech not in self.result.technologies:
                        self.result.technologies.append(tech)
                logger.info(f"Browser detected technologies: {techs}")
        except Exception as e:
            logger.warning(f"Browser tech detection error: {e}")

    # ============================================
    # PHASE 3: JAVASCRIPT DEEP ANALYSIS
    # ============================================

    async def _phase3_js_analysis(self) -> None:
        """
        Download and analyze all discovered JavaScript files for:
        - Route definitions
        - API endpoint strings
        - Hardcoded secrets
        - Client-side validation rules
        - Commented-out sensitive code
        """
        if not self.result.js_files:
            logger.info("[Phase3] No JavaScript files to analyze")
            return

        # Deduplicate and limit
        js_urls = list(set(self.result.js_files))
        max_js = {
            "low": 10,
            "medium": 25,
            "high": 50,
            "aggressive": 100,
        }.get(self.scan_intensity, 25)

        if len(js_urls) > max_js:
            logger.info(f"Limiting JS analysis from {len(js_urls)} to {max_js} files")
            js_urls = js_urls[:max_js]

        logger.info(f"[Phase3] Analyzing {len(js_urls)} JavaScript files...")

        # Analyze JS files concurrently (with semaphore)
        tasks = [self._analyze_single_js(url) for url in js_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_api_endpoints_from_js: Set[str] = set()
        all_routes_from_js: List[Dict[str, str]] = []

        for i, res in enumerate(results):
            if isinstance(res, Exception):
                logger.warning(f"JS analysis failed for {js_urls[i]}: {res}")
                continue
            if res is None:
                continue

            js_result: JSAnalysisResult = res
            self.result.js_analysis.append(js_result.to_dict())

            # Process routes
            for route in js_result.routes:
                route_path = route.get("path", "")
                if route_path:
                    full_url = self._normalize_url(route_path)
                    if self._is_same_origin(full_url):
                        self._add_endpoint(
                            url=full_url,
                            method="GET",
                            source="js_route",
                        )
                        self._detect_auth_endpoints(full_url)
                    all_routes_from_js.append(route)

            # Process API endpoints
            for api_url in js_result.api_endpoints:
                if api_url.startswith("/") or api_url.startswith("http"):
                    full_url = self._normalize_url(api_url)
                    if self._is_same_origin(full_url):
                        all_api_endpoints_from_js.add(full_url)
                        self._add_endpoint(
                            url=full_url,
                            method="GET",
                            source="js_api",
                        )
                        self._detect_auth_endpoints(full_url)

            # Process secrets
            for secret in js_result.secrets:
                secret["source"] = js_result.url
                self.result.secrets_found.append(secret)

            # Process validation rules
            if js_result.validation_rules:
                logger.info(f"Found {len(js_result.validation_rules)} validation rules in {js_result.url}")

        logger.info(
            f"[Phase3] JS Analysis complete. "
            f"Routes: {len(all_routes_from_js)}, "
            f"API endpoints: {len(all_api_endpoints_from_js)}, "
            f"Secrets: {len(self.result.secrets_found)}"
        )

        # Use LLM to analyze interesting JS findings if secrets were found
        if self.result.secrets_found:
            await self._llm_analyze_js_secrets()

    async def _analyze_single_js(self, js_url: str) -> Optional[JSAnalysisResult]:
        """Download and analyze a single JavaScript file."""
        async with self._semaphore:
            try:
                http = await self._ensure_http()
                resp: SmartResponse = await http.get(js_url)

                if resp is None or not resp.is_success:
                    return None

                js_content = resp.text
                if not js_content or len(js_content) < 10:
                    return None

                result = JSAnalysisResult(
                    url=js_url,
                    size_bytes=len(js_content),
                )

                # 1. Extract routes
                result.routes = self._extract_routes_from_js_content(js_content)

                # 2. Extract API endpoints
                result.api_endpoints = self._extract_api_endpoints_from_js_content(js_content)

                # 3. Find hardcoded secrets
                result.secrets = self._find_secrets_in_js_content(js_content)

                # 4. Extract validation rules
                result.validation_rules = self._extract_validation_rules_from_js(js_content)

                # 5. Extract interesting comments
                result.comments = self._extract_comments_from_js(js_content)

                # 6. Find interesting strings (emails, IPs, etc)
                result.interesting_strings = self._find_interesting_strings_in_js(js_content)

                total_findings = (
                    len(result.routes) + len(result.api_endpoints) +
                    len(result.secrets) + len(result.validation_rules)
                )
                if total_findings > 0:
                    logger.info(
                        f"JS [{js_url.split('/')[-1]}]: "
                        f"routes={len(result.routes)}, "
                        f"apis={len(result.api_endpoints)}, "
                        f"secrets={len(result.secrets)}, "
                        f"validations={len(result.validation_rules)}"
                    )

                return result

            except Exception as e:
                logger.warning(f"Error analyzing JS {js_url}: {e}")
                return None

    def _extract_routes_from_js_content(self, js_content: str) -> List[Dict[str, str]]:
        """Extract route definitions from JavaScript content."""
        routes: List[Dict[str, str]] = []
        seen_paths: Set[str] = set()

        for pattern in JS_ROUTE_PATTERNS:
            try:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    path = match.strip()
                    if not path or path in seen_paths:
                        continue
                    if len(path) < 2 or len(path) > 200:
                        continue
                    # Filter obvious non-routes
                    if any(path.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg")):
                        continue
                    if path.startswith("data:") or path.startswith("javascript:"):
                        continue

                    seen_paths.add(path)
                    routes.append({
                        "path": path,
                        "source": "js_regex",
                    })
            except re.error:
                continue

        # Also look for Angular/React/Vue specific route configs
        routes.extend(self._extract_framework_routes(js_content, seen_paths))

        return routes

    def _extract_framework_routes(
        self, js_content: str, seen_paths: Set[str]
    ) -> List[Dict[str, str]]:
        """Extract routes from framework-specific patterns."""
        routes: List[Dict[str, str]] = []

        # Angular: { path: 'something', component: SomethingComponent }
        angular_pattern = r'\{\s*path\s*:\s*["\']([^"\']*)["\']'
        try:
            for match in re.findall(angular_pattern, js_content):
                path = f"/{match.strip()}" if not match.startswith("/") else match.strip()
                if path and path not in seen_paths and len(path) < 200:
                    seen_paths.add(path)
                    routes.append({"path": path, "source": "angular_route"})
        except re.error:
            pass

        # React Router: <Route path="/something" />
        react_pattern = r'<Route\s+[^>]*path\s*=\s*["\']([^"\']+)["\']'
        try:
            for match in re.findall(react_pattern, js_content):
                path = match.strip()
                if path and path not in seen_paths and len(path) < 200:
                    seen_paths.add(path)
                    routes.append({"path": path, "source": "react_route"})
        except re.error:
            pass

        # Vue Router: { path: '/something', name: ... }
        vue_pattern = r'path\s*:\s*["\'](/[^"\']*)["\'](?:\s*,\s*name\s*:\s*["\'][^"\']*["\'])?'
        try:
            for match in re.findall(vue_pattern, js_content):
                path = match.strip()
                if path and path not in seen_paths and len(path) < 200:
                    seen_paths.add(path)
                    routes.append({"path": path, "source": "vue_route"})
        except re.error:
            pass

        # Express.js: app.get('/path', ...)
        express_pattern = r'(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
        try:
            for method, path in re.findall(express_pattern, js_content, re.IGNORECASE):
                if path and path not in seen_paths and len(path) < 200:
                    seen_paths.add(path)
                    routes.append({"path": path, "source": "express_route", "method": method.upper()})
        except re.error:
            pass

        return routes

    def _extract_api_endpoints_from_js_content(self, js_content: str) -> List[str]:
        """Extract API endpoint URLs from JavaScript content."""
        endpoints: List[str] = []
        seen: Set[str] = set()

        for pattern in JS_API_PATTERNS:
            try:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    url = match.strip()
                    if not url or url in seen:
                        continue
                    if len(url) < 2 or len(url) > 500:
                        continue
                    # Filter out non-URL strings
                    if url.startswith("data:") or url.startswith("javascript:"):
                        continue
                    if url.startswith("#") or url.startswith("mailto:"):
                        continue
                    # Must look like a path or URL
                    if not (url.startswith("/") or url.startswith("http") or url.startswith("./")):
                        continue
                    # Filter static assets
                    if any(url.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg",
                                                          ".gif", ".ico", ".woff", ".woff2")):
                        continue

                    seen.add(url)
                    endpoints.append(url)
            except re.error:
                continue

        # Look for string concatenation patterns like baseUrl + '/users'
        concat_pattern = r'(?:baseUrl|apiUrl|API_URL|BASE_URL|apiBase)\s*\+\s*["\']([^"\']+)["\']'
        try:
            for match in re.findall(concat_pattern, js_content, re.IGNORECASE):
                path = match.strip()
                if path and path not in seen and path.startswith("/"):
                    seen.add(path)
                    endpoints.append(path)
        except re.error:
            pass

        # Template literal patterns: `${baseUrl}/users`
        template_pattern = r'\$\{[^}]*\}(/[a-zA-Z0-9/_\-]+)'
        try:
            for match in re.findall(template_pattern, js_content):
                path = match.strip()
                if path and path not in seen:
                    seen.add(path)
                    endpoints.append(path)
        except re.error:
            pass

        return endpoints

    def _find_secrets_in_js_content(self, js_content: str) -> List[Dict[str, str]]:
        """Find hardcoded secrets in JavaScript content."""
        secrets: List[Dict[str, str]] = []
        seen_values: Set[str] = set()

        for pattern, secret_type in JS_SECRET_PATTERNS:
            try:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    value = match.strip()
                    if not value or value in seen_values:
                        continue
                    if len(value) < 4:
                        continue
                    # Filter obvious false positives
                    if value.lower() in ("password", "secret", "token", "api_key",
                                         "your_api_key", "xxx", "yyy", "zzz",
                                         "placeholder", "example", "test", "demo",
                                         "changeme", "todo", "fixme", "null",
                                         "undefined", "true", "false"):
                        continue
                    if all(c == value[0] for c in value):
                        continue

                    seen_values.add(value)
                    secrets.append({
                        "type": secret_type,
                        "value": value,
                        "pattern": pattern[:50],
                    })
            except re.error:
                continue

        return secrets

    def _extract_validation_rules_from_js(self, js_content: str) -> List[Dict[str, Any]]:
        """Extract client-side validation rules from JavaScript."""
        rules: List[Dict[str, Any]] = []

        for pattern, rule_type in JS_VALIDATION_PATTERNS:
            try:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    rules.append({
                        "type": rule_type,
                        "value": match.strip(),
                    })
            except re.error:
                continue

        # Look for form validation objects
        validation_object_pattern = (
            r'(?:validation|validators|rules|constraints)\s*[:=]\s*\{([^}]{10,500})\}'
        )
        try:
            for match in re.findall(validation_object_pattern, js_content, re.IGNORECASE):
                rules.append({
                    "type": "validation_object",
                    "value": match.strip()[:200],
                })
        except re.error:
            pass

        # Look for file upload restrictions
        file_pattern = r'(?:accept|allowedTypes|allowed_extensions)\s*[:=]\s*[\["\']([^"\'\]]+)'
        try:
            for match in re.findall(file_pattern, js_content, re.IGNORECASE):
                rules.append({
                    "type": "file_restriction",
                    "value": match.strip(),
                })
        except re.error:
            pass

        return rules

    def _extract_comments_from_js(self, js_content: str) -> List[str]:
        """Extract potentially sensitive comments from JavaScript."""
        interesting_comments: List[str] = []

        sensitive_keywords = [
            "todo", "fixme", "hack", "bug", "xxx",
            "password", "secret", "token", "key",
            "api", "admin", "debug", "test",
            "temporary", "remove", "deprecated",
            "vulnerability", "insecure", "unsafe",
            "backdoor", "bypass", "workaround",
            "hardcoded", "credential",
        ]

        # Single-line comments
        single_line_pattern = r'//\s*(.+)$'
        try:
            for match in re.findall(single_line_pattern, js_content, re.MULTILINE):
                comment = match.strip()
                if len(comment) < 5 or len(comment) > 500:
                    continue
                comment_lower = comment.lower()
                if any(kw in comment_lower for kw in sensitive_keywords):
                    interesting_comments.append(comment)
        except re.error:
            pass

        # Multi-line comments
        multi_line_pattern = r'/\*\s*([\s\S]*?)\s*\*/'
        try:
            for match in re.findall(multi_line_pattern, js_content):
                comment = match.strip()
                if len(comment) < 5 or len(comment) > 1000:
                    continue
                comment_lower = comment.lower()
                if any(kw in comment_lower for kw in sensitive_keywords):
                    interesting_comments.append(comment[:300])
        except re.error:
            pass

        return interesting_comments[:50]  # Limit to 50

    def _find_interesting_strings_in_js(self, js_content: str) -> List[str]:
        """Find interesting strings like emails, IPs, internal URLs in JS."""
        interesting: List[str] = []
        seen: Set[str] = set()

        # Email addresses
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        try:
            for match in re.findall(email_pattern, js_content):
                if match not in seen and not match.endswith((".png", ".jpg", ".svg")):
                    seen.add(match)
                    interesting.append(f"Email: {match}")
        except re.error:
            pass

        # Internal IP addresses
        ip_pattern = r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
        try:
            for match in re.findall(ip_pattern, js_content):
                if match not in seen:
                    seen.add(match)
                    interesting.append(f"Internal IP: {match}")
        except re.error:
            pass

        # localhost references
        localhost_pattern = r'(?:localhost|127\.0\.0\.1)(?::(\d+))?'
        try:
            for match in re.findall(localhost_pattern, js_content):
                entry = f"Localhost ref port: {match}" if match else "Localhost reference"
                if entry not in seen:
                    seen.add(entry)
                    interesting.append(entry)
        except re.error:
            pass

        # S3 bucket references
        s3_pattern = r'(?:s3[.-]|s3\.amazonaws\.com/)([a-zA-Z0-9._-]+)'
        try:
            for match in re.findall(s3_pattern, js_content):
                entry = f"S3 Bucket: {match}"
                if entry not in seen:
                    seen.add(entry)
                    interesting.append(entry)
        except re.error:
            pass

        return interesting[:30]

    async def _llm_analyze_js_secrets(self) -> None:
        """Use LLM to analyze discovered JS secrets for severity assessment."""
        if not self.result.secrets_found:
            return

        secrets_summary = []
        for s in self.result.secrets_found[:10]:
            secrets_summary.append(
                f"- Type: {s.get('type', 'unknown')}, "
                f"Value (partial): {s.get('value', '')[:30]}..., "
                f"Source: {s.get('source', 'unknown')}"
            )

        prompt = (
            "You are a security analyst reviewing hardcoded secrets found in JavaScript files.\n"
            "Analyze these findings and rate each one's severity (critical/high/medium/low/false_positive).\n"
            "Also explain the potential impact.\n\n"
            "Secrets found:\n"
            + "\n".join(secrets_summary)
            + "\n\nRespond in JSON format:\n"
            '{"analysis": [{"type": "...", "severity": "...", "impact": "...", "false_positive": true/false}]}'
        )

        try:
            response = await self.llm.generate(
                prompt=prompt,
                task_type="code_analysis",
                temperature=0.1,
            )
            if response:
                logger.info(f"LLM JS secret analysis: {response[:200]}")
        except Exception as e:
            logger.warning(f"LLM JS analysis failed: {e}")

    # ============================================
    # PHASE 4: API ENDPOINT MAPPING
    # ============================================

    async def _phase4_api_mapping(self) -> None:
        """
        For each discovered endpoint:
        - Determine HTTP method support
        - Identify parameters
        - Check if authentication required (401/403)
        - Identify parameter types
        - Create full API map
        """
        # Combine all discovered endpoints that look like APIs
        api_urls_to_probe: Set[str] = set()

        for ep in self.result.api_endpoints:
            url = ep.get("url", "")
            if url:
                api_urls_to_probe.add(url)

        for ep in self.result.endpoints:
            url = ep.get("url", "")
            url_lower = url.lower()
            if any(ind in url_lower for ind in ("/api/", "/rest/", "/graphql",
                                                  "/v1/", "/v2/", "/v3/")):
                api_urls_to_probe.add(url)

        if not api_urls_to_probe:
            logger.info("[Phase4] No API endpoints to probe")
            return

        max_probe = {
            "low": 20,
            "medium": 50,
            "high": 100,
            "aggressive": 200,
        }.get(self.scan_intensity, 50)

        urls_to_probe = list(api_urls_to_probe)[:max_probe]
        logger.info(f"[Phase4] Probing {len(urls_to_probe)} API endpoints...")

        tasks = [self._probe_api_endpoint(url) for url in urls_to_probe]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        probed_count = 0
        auth_required_count = 0
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                logger.warning(f"API probe failed for {urls_to_probe[i]}: {res}")
                continue
            if res is None:
                continue
            probed_count += 1
            if res.get("auth_required", False):
                auth_required_count += 1

        logger.info(
            f"[Phase4] Probed {probed_count} endpoints. "
            f"{auth_required_count} require authentication."
        )

    async def _probe_api_endpoint(self, url: str) -> Optional[Dict[str, Any]]:
        """Probe a single API endpoint to determine its characteristics."""
        async with self._semaphore:
            try:
                http = await self._ensure_http()
                probe_result: Dict[str, Any] = {
                    "url": url,
                    "methods_allowed": [],
                    "auth_required": False,
                    "params": [],
                    "param_types": {},
                    "content_type": "",
                    "response_code": 0,
                }

                # Step 1: OPTIONS request to determine allowed methods
                try:
                    options_resp: SmartResponse = await http.options(url)
                    if options_resp and options_resp.is_success:
                        allow_header = (
                            options_resp.headers.get("Allow", "") or
                            options_resp.headers.get("allow", "") or
                            options_resp.headers.get("Access-Control-Allow-Methods", "") or
                            options_resp.headers.get("access-control-allow-methods", "")
                        )
                        if allow_header:
                            methods = [m.strip().upper() for m in allow_header.split(",")]
                            probe_result["methods_allowed"] = methods
                except Exception:
                    pass

                # Step 2: GET request to check auth and response
                try:
                    get_resp: SmartResponse = await http.get(url)
                    if get_resp:
                        probe_result["response_code"] = get_resp.status_code
                        probe_result["content_type"] = get_resp.content_type

                        if get_resp.status_code in (401, 403):
                            probe_result["auth_required"] = True
                        elif get_resp.status_code == 200:
                            auth_state = get_resp.detect_auth_state()
                            if auth_state.get("requires_auth", False):
                                probe_result["auth_required"] = True

                        # Try to detect parameter types from JSON response
                        if get_resp.is_json and get_resp.json_data is not None:
                            json_data = get_resp.json_data
                            if isinstance(json_data, dict):
                                for key, value in json_data.items():
                                    if isinstance(value, int):
                                        probe_result["param_types"][key] = "integer"
                                    elif isinstance(value, float):
                                        probe_result["param_types"][key] = "float"
                                    elif isinstance(value, bool):
                                        probe_result["param_types"][key] = "boolean"
                                    elif isinstance(value, str):
                                        if "@" in value and "." in value:
                                            probe_result["param_types"][key] = "email"
                                        elif re.match(r'^\d{4}-\d{2}-\d{2}', value):
                                            probe_result["param_types"][key] = "date"
                                        elif re.match(r'^https?://', value):
                                            probe_result["param_types"][key] = "url"
                                        else:
                                            probe_result["param_types"][key] = "string"
                                    elif isinstance(value, list):
                                        probe_result["param_types"][key] = "array"
                                    elif isinstance(value, dict):
                                        probe_result["param_types"][key] = "object"

                        # Detect DB type from error messages
                        if get_resp.has_error_indicators:
                            db_hints = self._detect_db_from_text(get_resp.text)
                            if db_hints:
                                self.result.db_type_hints.extend(db_hints)

                except Exception as e:
                    logger.debug(f"GET probe failed for {url}: {e}")

                # Step 3: Update endpoint in state with probe results
                existing_params = self._extract_params_from_url(url)
                probe_result["params"] = list(set(
                    existing_params + list(probe_result["param_types"].keys())
                ))

                # Update the endpoint in state
                self.state.add_endpoint(endpoint={
                    "url": url,
                    "method": "GET",
                    "params": probe_result["params"],
                    "auth_required": probe_result["auth_required"],
                    "response_code": probe_result["response_code"],
                    "content_type": probe_result["content_type"],
                    "source": "api_probe",
                    "methods_allowed": probe_result.get("methods_allowed", []),
                    "param_types": probe_result.get("param_types", {}),
                })

                return probe_result

            except Exception as e:
                logger.warning(f"API probe error for {url}: {e}")
                return None        


    # ============================================
    # PHASE 5: DIRECTORY / FILE DISCOVERY
    # ============================================

    async def _phase5_directory_discovery(self) -> None:
        """
        Run directory/file discovery using:
        1. ffuf wordlist scan
        2. Custom interesting path checks
        3. Hidden directory checks
        """
        # Step 1: ffuf wordlist scan
        logger.info("[Phase5] Running ffuf directory bruteforce...")
        await self._run_ffuf()

        # Step 2: Check interesting paths concurrently
        logger.info("[Phase5] Checking interesting paths...")
        await self._check_interesting_paths()

        # Step 3: Check hidden directories
        logger.info("[Phase5] Checking hidden directories...")
        await self._check_hidden_dirs()

        logger.info(
            f"[Phase5] Directory discovery complete. "
            f"Found {len(self.result.directories)} directories/files."
        )

    async def _run_ffuf(self) -> None:
        """Run ffuf directory bruteforce scan."""
        async with self._semaphore:
            try:
                wordlist_paths = [
                    "/usr/share/wordlists/dirb/common.txt",
                    "/usr/share/seclists/Discovery/Web-Content/common.txt",
                    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
                    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
                    "/usr/share/dirb/wordlists/common.txt",
                ]

                wordlist = None
                for wl_path in wordlist_paths:
                    if os.path.exists(wl_path):
                        wordlist = wl_path
                        break

                if not wordlist:
                    logger.warning("No wordlist found for ffuf. Skipping directory bruteforce.")
                    self.result.errors.append("No wordlist found for ffuf")
                    return

                rate_limit = {
                    "low": "10",
                    "medium": "30",
                    "high": "50",
                    "aggressive": "100",
                }.get(self.scan_intensity, "30")

                target_with_fuzz = f"{self.target_url}/FUZZ"
                cmd = self.tools.build_ffuf_command(
                    url=target_with_fuzz,
                    wordlist=wordlist,
                )

                # Add rate limit and extra options
                if f"-rate {rate_limit}" not in cmd:
                    cmd += f" -rate {rate_limit}"
                if "-mc" not in cmd:
                    cmd += " -mc 200,201,204,301,302,307,308,401,403,405"
                if "-o" not in cmd:
                    ffuf_output = os.path.join(str(DATA_DIR), "ffuf_output.json")
                    cmd += f" -o {ffuf_output} -of json"

                tool_result = await self.tools.execute_command(
                    command=cmd,
                    tool_name="ffuf",
                    timeout=300,
                )

                if tool_result.success and tool_result.output:
                    parsed = self.tools._parse_ffuf(tool_result.output)
                    found_dirs = parsed.get("results", [])

                    if not found_dirs:
                        # Try reading JSON output file
                        ffuf_output = os.path.join(str(DATA_DIR), "ffuf_output.json")
                        if os.path.exists(ffuf_output):
                            try:
                                with open(ffuf_output, "r") as f:
                                    ffuf_json = json.load(f)
                                results_list = ffuf_json.get("results", [])
                                for item in results_list:
                                    found_dirs.append({
                                        "path": item.get("input", {}).get("FUZZ", ""),
                                        "status": item.get("status", 0),
                                        "length": item.get("length", 0),
                                        "words": item.get("words", 0),
                                        "lines": item.get("lines", 0),
                                        "content_type": item.get("content-type", ""),
                                    })
                            except (json.JSONDecodeError, IOError) as e:
                                logger.warning(f"Error reading ffuf output: {e}")

                    for item in found_dirs:
                        path = item.get("path", "") or item.get("url", "")
                        status = item.get("status", 0) or item.get("status_code", 0)
                        length = item.get("length", 0) or item.get("size", 0)
                        content_type = item.get("content_type", "") or item.get("content-type", "")

                        if not path:
                            continue

                        if not path.startswith("/"):
                            path = f"/{path}"

                        full_url = f"{self.target_url}{path}"

                        dir_info = {
                            "path": path,
                            "url": full_url,
                            "status_code": status,
                            "size": length,
                            "content_type": content_type,
                            "source": "ffuf",
                        }
                        self.result.directories.append(dir_info)

                        self._add_endpoint(
                            url=full_url,
                            method="GET",
                            response_code=status,
                            content_type=content_type,
                            source="ffuf",
                        )
                        self._detect_auth_endpoints(full_url)

                        if path not in self.result.hidden_paths:
                            self.result.hidden_paths.append(path)

                    logger.info(f"ffuf found {len(found_dirs)} directories/files")
                else:
                    logger.warning(f"ffuf returned no output. Error: {tool_result.error}")

            except Exception as e:
                logger.error(f"ffuf execution error: {e}")
                self.result.errors.append(f"ffuf error: {str(e)}")

    async def _check_interesting_paths(self) -> None:
        """Check a curated list of interesting paths."""
        paths_to_check = [p for p in INTERESTING_PATHS if p not in self._checked_paths]

        batch_size = {
            "low": 10,
            "medium": 20,
            "high": 30,
            "aggressive": 50,
        }.get(self.scan_intensity, 20)

        for i in range(0, len(paths_to_check), batch_size):
            batch = paths_to_check[i:i + batch_size]
            tasks = [self._check_single_path(path, "interesting_path") for path in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for j, res in enumerate(results):
                if isinstance(res, Exception):
                    logger.debug(f"Path check failed for {batch[j]}: {res}")

    async def _check_hidden_dirs(self) -> None:
        """Check for hidden directories like .git, .svn, etc."""
        paths_to_check = [p for p in HIDDEN_DIRS if p not in self._checked_paths]

        tasks = [self._check_single_path(path, "hidden_dir") for path in paths_to_check]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, res in enumerate(results):
            if isinstance(res, Exception):
                logger.debug(f"Hidden dir check failed for {paths_to_check[i]}: {res}")

    async def _check_single_path(
        self, path: str, source: str
    ) -> Optional[Dict[str, Any]]:
        """Check if a single path exists on the target."""
        async with self._semaphore:
            if path in self._checked_paths:
                return None
            self._checked_paths.add(path)

            full_url = f"{self.target_url}{path}" if path.startswith("/") else f"{self.target_url}/{path}"

            try:
                http = await self._ensure_http()
                resp: SmartResponse = await http.get(full_url)

                if resp is None:
                    return None

                status = resp.status_code
                content_length = len(resp.text) if resp.text else 0
                content_type = resp.content_type

                # Consider it found if status is not 404 and has reasonable content
                if status in (200, 201, 204, 301, 302, 307, 308):
                    result_info = {
                        "path": path,
                        "url": full_url,
                        "status_code": status,
                        "size": content_length,
                        "content_type": content_type,
                        "source": source,
                    }

                    self.result.directories.append(result_info)
                    self._add_endpoint(
                        url=full_url,
                        method="GET",
                        response_code=status,
                        content_type=content_type,
                        source=source,
                    )
                    self._detect_auth_endpoints(full_url)

                    if path not in self.result.hidden_paths:
                        self.result.hidden_paths.append(path)

                    logger.info(f"Found: {path} (HTTP {status}, {content_length} bytes)")

                    # Special handling for certain paths
                    await self._handle_special_path(path, full_url, resp)

                    return result_info

                elif status in (401, 403):
                    # Path exists but access denied
                    result_info = {
                        "path": path,
                        "url": full_url,
                        "status_code": status,
                        "size": content_length,
                        "content_type": content_type,
                        "source": source,
                        "note": "access_denied",
                    }
                    self.result.directories.append(result_info)
                    self._add_endpoint(
                        url=full_url,
                        method="GET",
                        auth_required=True,
                        response_code=status,
                        content_type=content_type,
                        source=source,
                    )

                    if path not in self.result.hidden_paths:
                        self.result.hidden_paths.append(path)

                    logger.info(f"Found (access denied): {path} (HTTP {status})")
                    return result_info

                return None

            except Exception as e:
                logger.debug(f"Error checking path {path}: {e}")
                return None

    async def _handle_special_path(
        self, path: str, url: str, resp: SmartResponse
    ) -> None:
        """Handle special paths that need additional processing."""
        path_lower = path.lower()
        text = resp.text or ""

        # .git/HEAD — confirms git repo exposure
        if "/.git/head" in path_lower or "/.git/config" in path_lower:
            if text and ("ref:" in text.lower() or "[core]" in text.lower()):
                self.state.add_finding(
                    vulnerability={
                        "category": "information_disclosure",
                        "severity": "critical",
                        "title": "Git Repository Exposed",
                        "endpoint": url,
                        "parameter": "",
                        "payload": "",
                        "evidence": f"Git file accessible: {path}. Content: {text[:200]}",
                        "description": "The .git directory is publicly accessible. "
                                       "An attacker can download the entire source code repository.",
                        "remediation": "Block access to .git directory in web server configuration. "
                                       "Add rules to deny access to hidden files/directories.",
                    },
                    confirmed=True,
                )
                logger.warning(f"CRITICAL: Git repository exposed at {url}")

        # .env file
        elif "/.env" in path_lower:
            if text and ("=" in text) and len(text) > 10:
                has_secrets = any(
                    kw in text.lower()
                    for kw in ("password", "secret", "key", "token", "db_", "database",
                               "api_key", "app_secret", "mail_", "smtp_")
                )
                severity = "critical" if has_secrets else "high"
                self.state.add_finding(
                    vulnerability={
                        "category": "information_disclosure",
                        "severity": severity,
                        "title": "Environment File Exposed (.env)",
                        "endpoint": url,
                        "parameter": "",
                        "payload": "",
                        "evidence": f"Env file accessible. First 200 chars: {text[:200]}",
                        "description": "The .env file is publicly accessible and may contain "
                                       "database credentials, API keys, and other secrets.",
                        "remediation": "Block access to .env files in web server configuration. "
                                       "Move sensitive configuration out of the web root.",
                    },
                    confirmed=True,
                )
                logger.warning(f"CRITICAL: .env file exposed at {url}")

                # Try to extract credentials from .env
                self._extract_credentials_from_env(text, url)

        # Swagger / API docs
        elif any(s in path_lower for s in ("/swagger", "/api-docs", "/openapi", "/redoc")):
            self.state.add_finding(
                vulnerability={
                    "category": "information_disclosure",
                    "severity": "low",
                    "title": f"API Documentation Exposed: {path}",
                    "endpoint": url,
                    "parameter": "",
                    "payload": "",
                    "evidence": f"API docs accessible at {path} (HTTP {resp.status_code})",
                    "description": "API documentation is publicly accessible. "
                                   "This reveals all endpoints, parameters, and data models.",
                    "remediation": "Restrict API documentation access in production. "
                                   "Require authentication to view API docs.",
                },
                confirmed=True,
            )

            # Try to extract API endpoints from swagger JSON
            if resp.is_json and resp.json_data:
                await self._extract_endpoints_from_swagger(resp.json_data, url)

        # Actuator endpoints (Spring Boot)
        elif "/actuator" in path_lower:
            severity = "high"
            if any(s in path_lower for s in ("/env", "/heapdump", "/configprops", "/beans")):
                severity = "critical"
            self.state.add_finding(
                vulnerability={
                    "category": "information_disclosure",
                    "severity": severity,
                    "title": f"Spring Boot Actuator Exposed: {path}",
                    "endpoint": url,
                    "parameter": "",
                    "payload": "",
                    "evidence": f"Actuator endpoint accessible (HTTP {resp.status_code})",
                    "description": "Spring Boot Actuator endpoints are publicly accessible. "
                                   "This can expose environment variables, heap dumps, "
                                   "and internal application details.",
                    "remediation": "Disable actuator endpoints in production or secure them "
                                   "with authentication. Set management.endpoints.web.exposure.include "
                                   "to only necessary endpoints.",
                },
                confirmed=True,
            )

        # robots.txt — extract disallowed paths
        elif "/robots.txt" in path_lower:
            if text:
                disallowed = self._parse_robots_txt(text)
                for disallowed_path in disallowed:
                    full_disallowed = self._normalize_url(disallowed_path)
                    if self._is_same_origin(full_disallowed):
                        self._add_endpoint(
                            url=full_disallowed,
                            method="GET",
                            source="robots_txt",
                        )
                        if disallowed_path not in self.result.hidden_paths:
                            self.result.hidden_paths.append(disallowed_path)

        # sitemap.xml — extract URLs
        elif "/sitemap" in path_lower:
            if text:
                sitemap_urls = self._parse_sitemap(text)
                for surl in sitemap_urls:
                    if self._is_same_origin(surl):
                        self._add_endpoint(
                            url=surl,
                            method="GET",
                            source="sitemap",
                        )

        # package.json — extract dependencies
        elif "/package.json" in path_lower:
            if resp.is_json and resp.json_data:
                pkg = resp.json_data
                deps = {}
                deps.update(pkg.get("dependencies", {}))
                deps.update(pkg.get("devDependencies", {}))
                for dep_name, dep_version in deps.items():
                    tech_str = f"npm:{dep_name}@{dep_version}"
                    if tech_str not in self.result.technologies:
                        self.result.technologies.append(tech_str)
                self.state.add_finding(
                    vulnerability={
                        "category": "information_disclosure",
                        "severity": "medium",
                        "title": "package.json Exposed",
                        "endpoint": url,
                        "parameter": "",
                        "payload": "",
                        "evidence": f"package.json accessible. {len(deps)} dependencies found.",
                        "description": "The package.json file is publicly accessible, "
                                       "revealing all application dependencies and versions.",
                        "remediation": "Remove package.json from the web root or block access "
                                       "in web server configuration.",
                    },
                    confirmed=True,
                )

        # phpinfo
        elif "phpinfo" in path_lower or "info.php" in path_lower:
            if "phpinfo()" in text.lower() or "php version" in text.lower():
                self.state.add_finding(
                    vulnerability={
                        "category": "information_disclosure",
                        "severity": "high",
                        "title": "PHP Info Page Exposed",
                        "endpoint": url,
                        "parameter": "",
                        "payload": "",
                        "evidence": f"phpinfo() page accessible at {path}",
                        "description": "A phpinfo() page is publicly accessible, "
                                       "exposing PHP version, server configuration, "
                                       "environment variables, and installed modules.",
                        "remediation": "Remove phpinfo() pages from production servers.",
                    },
                    confirmed=True,
                )

        # Debug / profiler endpoints
        elif any(s in path_lower for s in ("/debug", "/_profiler", "/_debugbar", "/telescope")):
            self.state.add_finding(
                vulnerability={
                    "category": "information_disclosure",
                    "severity": "high",
                    "title": f"Debug/Profiler Interface Exposed: {path}",
                    "endpoint": url,
                    "parameter": "",
                    "payload": "",
                    "evidence": f"Debug interface accessible at {path} (HTTP {resp.status_code})",
                    "description": "A debug or profiler interface is publicly accessible. "
                                   "This may expose internal application state, SQL queries, "
                                   "session data, and other sensitive information.",
                    "remediation": "Disable debug/profiler interfaces in production. "
                                   "Ensure APP_DEBUG=false and remove debug routes.",
                },
                confirmed=True,
            )

        # GraphQL — check for introspection
        elif "/graphql" in path_lower or "/graphiql" in path_lower:
            self.state.add_finding(
                vulnerability={
                    "category": "information_disclosure",
                    "severity": "medium",
                    "title": f"GraphQL Endpoint Found: {path}",
                    "endpoint": url,
                    "parameter": "",
                    "payload": "",
                    "evidence": f"GraphQL endpoint accessible at {path}",
                    "description": "A GraphQL endpoint is exposed. If introspection is enabled, "
                                   "the full API schema can be extracted.",
                    "remediation": "Disable GraphQL introspection in production. "
                                   "Implement proper authentication and authorization.",
                },
                confirmed=True,
            )

    def _extract_credentials_from_env(self, env_text: str, source_url: str) -> None:
        """Extract credentials from .env file content."""
        for line in env_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue

            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if not value or len(value) < 2:
                continue

            key_lower = key.lower()
            is_credential = any(
                kw in key_lower
                for kw in ("password", "passwd", "pwd", "secret",
                            "token", "key", "api_key", "apikey",
                            "db_pass", "database_password", "mail_password",
                            "smtp_password", "auth_secret", "jwt_secret")
            )

            if is_credential:
                self.result.secrets_found.append({
                    "type": f"ENV: {key}",
                    "value": value,
                    "source": source_url,
                })
                logger.info(f"Extracted credential from .env: {key}=****")

    async def _extract_endpoints_from_swagger(
        self, swagger_data: Any, source_url: str
    ) -> None:
        """Extract API endpoints from Swagger/OpenAPI JSON."""
        try:
            paths = swagger_data.get("paths", {})
            base_path = swagger_data.get("basePath", "")

            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue

                full_path = f"{base_path}{path}" if base_path else path

                for method, details in methods.items():
                    method_upper = method.upper()
                    if method_upper not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                        continue

                    params = []
                    if isinstance(details, dict):
                        param_list = details.get("parameters", [])
                        for p in param_list:
                            if isinstance(p, dict):
                                param_name = p.get("name", "")
                                if param_name:
                                    params.append(param_name)

                    full_url = self._normalize_url(full_path)
                    self._add_endpoint(
                        url=full_url,
                        method=method_upper,
                        params=params,
                        source="swagger",
                    )
                    self._detect_auth_endpoints(full_url)

            endpoint_count = sum(
                len([m for m in methods if m.upper() in
                     ("GET", "POST", "PUT", "DELETE", "PATCH")])
                for methods in paths.values()
                if isinstance(methods, dict)
            )
            logger.info(f"Extracted {endpoint_count} endpoints from Swagger/OpenAPI docs")

        except Exception as e:
            logger.warning(f"Error parsing Swagger data: {e}")

    def _parse_robots_txt(self, text: str) -> List[str]:
        """Parse robots.txt and extract disallowed paths."""
        paths: List[str] = []
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    paths.append(path)
            elif line.lower().startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    paths.append(path)
            elif line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                if sitemap_url.startswith("http"):
                    paths.append(sitemap_url)
        return paths

    def _parse_sitemap(self, text: str) -> List[str]:
        """Parse sitemap.xml and extract URLs."""
        urls: List[str] = []
        try:
            loc_pattern = r'<loc>\s*(.*?)\s*</loc>'
            for match in re.findall(loc_pattern, text, re.IGNORECASE):
                url = match.strip()
                if url and url.startswith("http"):
                    urls.append(url)
        except Exception:
            pass
        return urls

    # ============================================
    # PHASE 6: SENSITIVE FILE DETECTION
    # ============================================

    async def _phase6_sensitive_files(self) -> None:
        """
        Check for sensitive files:
        1. Backup files (.bak, .old, .swp, ~)
        2. Config files exposed
        3. Log files accessible
        4. Database files (.db, .sqlite)
        5. Sensitive meta paths (robots.txt, security.txt, etc.)
        """
        # Step 1: Check sensitive meta paths
        logger.info("[Phase6] Checking sensitive meta paths...")
        await self._check_sensitive_meta_paths()

        # Step 2: Check config files
        logger.info("[Phase6] Checking config files...")
        await self._check_file_list(CONFIG_FILES, "config_file", "high")

        # Step 3: Check log files
        logger.info("[Phase6] Checking log files...")
        await self._check_file_list(LOG_FILES, "log_file", "medium")

        # Step 4: Check database files
        logger.info("[Phase6] Checking database files...")
        await self._check_file_list(DATABASE_FILES, "database_file", "critical")

        # Step 5: Check backup variants of known pages
        logger.info("[Phase6] Checking backup file variants...")
        await self._check_backup_variants()

        logger.info(
            f"[Phase6] Sensitive file detection complete. "
            f"Found {len(self.result.sensitive_files)} sensitive files."
        )

    async def _check_sensitive_meta_paths(self) -> None:
        """Check sensitive meta paths like robots.txt, security.txt."""
        tasks = []
        for path in SENSITIVE_PATHS:
            if path not in self._checked_paths:
                tasks.append(self._check_single_sensitive_file(path, "meta_file", "info"))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_file_list(
        self, file_list: List[str], file_type: str, severity: str
    ) -> None:
        """Check a list of files concurrently."""
        paths_to_check = [p for p in file_list if p not in self._checked_paths]

        batch_size = {
            "low": 5,
            "medium": 10,
            "high": 20,
            "aggressive": 30,
        }.get(self.scan_intensity, 10)

        for i in range(0, len(paths_to_check), batch_size):
            batch = paths_to_check[i:i + batch_size]
            tasks = [
                self._check_single_sensitive_file(path, file_type, severity)
                for path in batch
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_single_sensitive_file(
        self, path: str, file_type: str, severity: str
    ) -> Optional[Dict[str, Any]]:
        """Check if a single sensitive file exists."""
        async with self._semaphore:
            if path in self._checked_paths:
                return None
            self._checked_paths.add(path)

            full_url = f"{self.target_url}{path}" if path.startswith("/") else f"{self.target_url}/{path}"

            try:
                http = await self._ensure_http()
                resp: SmartResponse = await http.get(full_url)

                if resp is None:
                    return None

                status = resp.status_code
                content_length = len(resp.text) if resp.text else 0
                content_type = resp.content_type

                if status == 200 and content_length > 0:
                    # Verify it's not a custom 404 page
                    if self._is_likely_custom_404(resp):
                        return None

                    file_info = {
                        "path": path,
                        "url": full_url,
                        "status_code": status,
                        "size": content_length,
                        "content_type": content_type,
                        "file_type": file_type,
                        "severity": severity,
                    }

                    self.result.sensitive_files.append(file_info)
                    logger.info(
                        f"Sensitive file found: {path} "
                        f"(HTTP {status}, {content_length} bytes, type: {file_type})"
                    )

                    # Handle special processing
                    await self._handle_special_path(path, full_url, resp)

                    # Detect DB type from file content
                    if resp.text:
                        db_hints = self._detect_db_from_text(resp.text)
                        if db_hints:
                            self.result.db_type_hints.extend(db_hints)

                    return file_info

                return None

            except Exception as e:
                logger.debug(f"Error checking sensitive file {path}: {e}")
                return None

    async def _check_backup_variants(self) -> None:
        """Check for backup file variants of discovered pages."""
        # Get known paths from discovered endpoints
        known_paths: Set[str] = set()
        for ep in self.result.endpoints:
            url = ep.get("url", "")
            try:
                parsed = urlparse(url)
                path = parsed.path
                if path and path != "/" and "." in path.split("/")[-1]:
                    known_paths.add(path)
            except Exception:
                continue

        # Also add some common file names
        common_files = [
            "/index.php", "/index.html", "/config.php",
            "/wp-config.php", "/web.config", "/app.py",
            "/main.py", "/server.js", "/app.js",
            "/database.php", "/db.php", "/connect.php",
            "/login.php", "/admin.php", "/settings.php",
        ]
        for cf in common_files:
            known_paths.add(cf)

        # Generate backup variants
        backup_paths: List[str] = []
        for path in known_paths:
            for ext in BACKUP_EXTENSIONS:
                backup_path = f"{path}{ext}"
                if backup_path not in self._checked_paths:
                    backup_paths.append(backup_path)

            # Also check without extension + backup ext
            path_no_ext = os.path.splitext(path)[0]
            for ext in [".bak", ".old", ".backup", ".save", ".orig"]:
                backup_path = f"{path_no_ext}{ext}"
                if backup_path not in self._checked_paths:
                    backup_paths.append(backup_path)

        # Limit based on intensity
        max_checks = {
            "low": 20,
            "medium": 50,
            "high": 100,
            "aggressive": 200,
        }.get(self.scan_intensity, 50)

        backup_paths = backup_paths[:max_checks]

        if backup_paths:
            logger.info(f"Checking {len(backup_paths)} backup file variants...")
            batch_size = self._max_concurrent * 2
            for i in range(0, len(backup_paths), batch_size):
                batch = backup_paths[i:i + batch_size]
                tasks = [
                    self._check_single_sensitive_file(path, "backup_file", "high")
                    for path in batch
                ]
                await asyncio.gather(*tasks, return_exceptions=True)

    def _is_likely_custom_404(self, resp: SmartResponse) -> bool:
        """Detect if a 200 response is actually a custom 404 page."""
        if not resp.text:
            return True

        text_lower = resp.text.lower()
        content_length = len(resp.text)

        # Very small content is suspicious
        if content_length < 50:
            return False  # Could be a real small file

        # Check for 404 indicators in content
        not_found_indicators = [
            "page not found",
            "404 not found",
            "not found",
            "file not found",
            "the page you requested",
            "does not exist",
            "could not be found",
            "was not found",
            "no such file",
            "404 error",
            "page doesn't exist",
            "page does not exist",
        ]

        matches = sum(1 for ind in not_found_indicators if ind in text_lower)
        if matches >= 2:
            return True

        # Check title
        title_match = re.search(r'<title[^>]*>(.*?)</title>', text_lower, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            if any(ind in title for ind in ("404", "not found", "error")):
                return True

        return False

    # ============================================
    # LLM-ASSISTED ANALYSIS
    # ============================================

    async def _llm_analyze_recon_results(self) -> Optional[str]:
        """Use LLM to analyze overall recon results and suggest attack vectors."""
        summary = {
            "target": self.target_url,
            "technologies": self.result.technologies[:20],
            "waf": self.result.waf_detected,
            "server": self.result.server_info,
            "framework": self.result.framework_info,
            "open_ports": len(self.result.open_ports),
            "endpoints_count": len(self.result.endpoints),
            "api_endpoints_count": len(self.result.api_endpoints),
            "forms_count": len(self.result.forms),
            "js_files_count": len(self.result.js_files),
            "sensitive_files_count": len(self.result.sensitive_files),
            "secrets_found_count": len(self.result.secrets_found),
            "missing_headers": self.result.missing_headers,
            "db_hints": self.result.db_type_hints,
            "login_endpoints": self.result.login_endpoints,
            "register_endpoints": self.result.register_endpoints,
        }

        prompt = (
            "You are an expert penetration tester analyzing reconnaissance results.\n"
            "Based on these findings, identify the top attack vectors and prioritize them.\n\n"
            f"Recon Summary:\n{json.dumps(summary, indent=2)}\n\n"
            "Provide your analysis in JSON format:\n"
            '{\n'
            '  "attack_vectors": [\n'
            '    {"type": "...", "priority": "high/medium/low", "reason": "...", '
            '"target_endpoints": ["..."]}\n'
            '  ],\n'
            '  "recommended_order": ["sqli", "xss", "idor", ...],\n'
            '  "waf_bypass_needed": true/false,\n'
            '  "auth_testing_priority": "high/medium/low",\n'
            '  "notes": "..."\n'
            '}'
        )

        try:
            response = await self.llm.generate(
                prompt=prompt,
                task_type="attack_surface_mapping",
                temperature=0.2,
            )
            if response:
                logger.info(f"LLM recon analysis: {response[:300]}")
                return response
        except Exception as e:
            logger.warning(f"LLM recon analysis failed: {e}")

        return None

    # ============================================
    # PUBLIC UTILITY METHODS
    # ============================================

    def get_result(self) -> ReconResult:
        """Return the current recon result."""
        return self.result

    def get_result_dict(self) -> Dict[str, Any]:
        """Return the current recon result as a dictionary."""
        return self.result.to_dict()

    def get_all_discovered_urls(self) -> List[str]:
        """Return all unique discovered URLs."""
        urls = set()
        for ep in self.result.endpoints:
            url = ep.get("url", "")
            if url:
                urls.add(url)
        return sorted(urls)

    def get_api_map(self) -> List[Dict[str, Any]]:
        """Return the full API endpoint map."""
        return self.result.api_endpoints

    def get_forms(self) -> List[Dict[str, Any]]:
        """Return all discovered forms."""
        return self.result.forms

    def get_login_endpoints(self) -> List[str]:
        """Return discovered login endpoints."""
        return self.result.login_endpoints

    def get_register_endpoints(self) -> List[str]:
        """Return discovered registration endpoints."""
        return self.result.register_endpoints

    def get_technologies(self) -> List[str]:
        """Return deduplicated list of discovered technologies."""
        return list(set(self.result.technologies))

    def get_secrets(self) -> List[Dict[str, str]]:
        """Return discovered secrets."""
        return self.result.secrets_found

    def get_db_hints(self) -> List[str]:
        """Return database type hints."""
        return list(set(self.result.db_type_hints))

    def get_sensitive_files(self) -> List[Dict[str, Any]]:
        """Return discovered sensitive files."""
        return self.result.sensitive_files

    def get_summary(self) -> str:
        """Return a human-readable summary of recon findings."""
        lines = [
            f"{'='*60}",
            f"RECON SUMMARY - {self.target_url}",
            f"{'='*60}",
            f"Duration: {self.result.duration_seconds:.1f} seconds",
            f"",
            f"INFRASTRUCTURE:",
            f"  Server: {self.result.server_info or 'Unknown'}",
            f"  WAF: {self.result.waf_detected or 'None detected'}",
            f"  Framework: {self.result.framework_info or 'Unknown'}",
            f"  Technologies: {len(self.result.technologies)}",
            f"  Open Ports: {len(self.result.open_ports)}",
            f"",
            f"ATTACK SURFACE:",
            f"  Total Endpoints: {len(self.result.endpoints)}",
            f"  API Endpoints: {len(self.result.api_endpoints)}",
            f"  Forms: {len(self.result.forms)}",
            f"  JS Files Analyzed: {len(self.result.js_files)}",
            f"",
            f"AUTHENTICATION:",
            f"  Login Endpoints: {len(self.result.login_endpoints)}",
            f"  Register Endpoints: {len(self.result.register_endpoints)}",
            f"",
            f"FINDINGS:",
            f"  Sensitive Files: {len(self.result.sensitive_files)}",
            f"  Secrets Found: {len(self.result.secrets_found)}",
            f"  DB Type Hints: {', '.join(set(self.result.db_type_hints)) or 'None'}",
            f"  Hidden Paths: {len(self.result.hidden_paths)}",
            f"  Directories Found: {len(self.result.directories)}",
            f"",
            f"SECURITY HEADERS MISSING: {len(self.result.missing_headers)}",
        ]

        if self.result.missing_headers:
            for h in self.result.missing_headers:
                lines.append(f"  - {h}")

        if self.result.login_endpoints:
            lines.append(f"")
            lines.append(f"LOGIN ENDPOINTS:")
            for ep in self.result.login_endpoints:
                lines.append(f"  - {ep}")

        if self.result.register_endpoints:
            lines.append(f"")
            lines.append(f"REGISTER ENDPOINTS:")
            for ep in self.result.register_endpoints:
                lines.append(f"  - {ep}")

        if self.result.secrets_found:
            lines.append(f"")
            lines.append(f"SECRETS FOUND:")
            for s in self.result.secrets_found[:10]:
                lines.append(
                    f"  - {s.get('type', '?')}: {s.get('value', '')[:20]}... "
                    f"(source: {s.get('source', '?').split('/')[-1]})"
                )

        if self.result.sensitive_files:
            lines.append(f"")
            lines.append(f"SENSITIVE FILES:")
            for sf in self.result.sensitive_files[:15]:
                lines.append(
                    f"  - [{sf.get('severity', '?').upper()}] {sf.get('path', '?')} "
                    f"(HTTP {sf.get('status_code', '?')}, {sf.get('size', 0)} bytes)"
                )

        if self.result.errors:
            lines.append(f"")
            lines.append(f"ERRORS ({len(self.result.errors)}):")
            for err in self.result.errors[:10]:
                lines.append(f"  - {err}")

        lines.append(f"{'='*60}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"V2ReconAgent(target={self.target_url}, "
            f"endpoints={len(self.result.endpoints)}, "
            f"apis={len(self.result.api_endpoints)}, "
            f"forms={len(self.result.forms)})"
        )            