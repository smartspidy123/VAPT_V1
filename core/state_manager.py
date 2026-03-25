"""
VAPT-AI V2.0 - State Manager
==============================
Persistent, thread-safe state management for scan progress.

This module remembers EVERYTHING discovered during a scan so that
agents can use previous findings to guide future attacks.

Features:
- Thread-safe storage (multiple agents access simultaneously)
- Persistent to disk (JSON) — survives tool restart
- Auto-save on every update
- Rich query methods for agents to find untested endpoints,
  retrieve credentials, check attack progress, chain findings
- Integrates with: orchestrator, all agents, attack modules

State Flow:
    recon_agent → add_endpoint() → scanner_agent reads get_untested_endpoints()
    auth_agent → add_credential() → exploiter reads get_authenticated_token()
    scanner_agent → add_finding() → exploiter reads for chaining
    exploiter → add_to_attack_chain() → reporter reads get_attack_summary()

Storage Location:
    ~/vapt-ai/data/scan_state_{domain}.json
"""

import copy
import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_DATA_DIR: str = os.path.join(os.path.expanduser("~"), "vapt-ai", "data")

SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

VULNERABILITY_CATEGORIES: List[str] = [
    "sqli", "xss", "idor", "auth_bypass", "jwt_attack",
    "xxe", "ssrf", "file_upload", "nosql", "input_validation",
    "csrf", "cors", "open_redirect", "information_disclosure",
    "broken_access_control", "security_misconfiguration",
    "sensitive_data_exposure", "command_injection", "path_traversal",
    "rate_limiting", "session_management", "other",
]

ATTACK_TEST_TYPES: List[str] = [
    "sqli_error_based", "sqli_blind_boolean", "sqli_blind_time",
    "sqli_union", "sqli_stacked",
    "xss_reflected", "xss_stored", "xss_dom",
    "idor_horizontal", "idor_vertical",
    "auth_bypass_direct", "auth_bypass_token_manipulation",
    "jwt_none_alg", "jwt_weak_secret", "jwt_key_confusion",
    "xxe_basic", "xxe_blind", "xxe_oob",
    "ssrf_basic", "ssrf_blind",
    "file_upload_extension", "file_upload_content_type", "file_upload_webshell",
    "nosql_injection", "nosql_operator",
    "input_validation_length", "input_validation_type", "input_validation_encoding",
    "csrf_missing_token", "csrf_token_reuse",
    "cors_misconfiguration",
    "open_redirect",
    "command_injection",
    "path_traversal",
    "header_injection",
    "recon_basic", "recon_deep",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class EndpointRecord:
    """A discovered endpoint / route."""
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    content_type: str = ""
    auth_required: bool = False
    source: str = ""  # how it was discovered
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    discovered_at: str = ""
    endpoint_id: str = ""  # auto-generated hash

    def __post_init__(self) -> None:
        if not self.discovered_at:
            self.discovered_at = datetime.now(timezone.utc).isoformat()
        if not self.endpoint_id:
            raw = f"{self.method.upper()}|{self.url}"
            self.endpoint_id = hashlib.md5(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "EndpointRecord":
        return EndpointRecord(**{
            k: v for k, v in data.items()
            if k in EndpointRecord.__dataclass_fields__
        })


@dataclass
class VulnerabilityRecord:
    """A discovered vulnerability."""
    vuln_id: str = ""
    title: str = ""
    category: str = ""  # sqli, xss, idor, etc.
    severity: str = "info"  # critical, high, medium, low, info
    endpoint: str = ""
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""  # response snippet or screenshot path
    description: str = ""
    remediation: str = ""
    confirmed: bool = True
    cvss_score: float = 0.0
    cwe_id: str = ""
    request_data: str = ""
    response_snippet: str = ""
    screenshot_path: str = ""
    discovered_at: str = ""
    discovered_by: str = ""  # which agent found it
    chained_from: str = ""  # vuln_id of finding that led to this

    def __post_init__(self) -> None:
        if not self.discovered_at:
            self.discovered_at = datetime.now(timezone.utc).isoformat()
        if not self.vuln_id:
            raw = f"{self.category}|{self.endpoint}|{self.parameter}|{self.payload}"
            self.vuln_id = hashlib.md5(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "VulnerabilityRecord":
        return VulnerabilityRecord(**{
            k: v for k, v in data.items()
            if k in VulnerabilityRecord.__dataclass_fields__
        })


@dataclass
class CredentialRecord:
    """A discovered or registered credential."""
    email: str = ""
    username: str = ""
    password: str = ""
    role: str = "user"  # user, admin, moderator, etc.
    token: str = ""  # JWT or session token
    token_type: str = "Bearer"
    cookies: Dict[str, str] = field(default_factory=dict)
    is_valid: bool = True
    source: str = ""  # registered, discovered, cracked, etc.
    discovered_at: str = ""
    credential_id: str = ""

    def __post_init__(self) -> None:
        if not self.discovered_at:
            self.discovered_at = datetime.now(timezone.utc).isoformat()
        if not self.credential_id:
            raw = f"{self.email}|{self.username}|{self.password}"
            self.credential_id = hashlib.md5(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "CredentialRecord":
        return CredentialRecord(**{
            k: v for k, v in data.items()
            if k in CredentialRecord.__dataclass_fields__
        })


@dataclass
class TokenRecord:
    """A discovered token (JWT, API key, secret)."""
    token_value: str = ""
    token_type: str = ""  # jwt, api_key, session, bearer, secret
    source: str = ""  # where it was found
    endpoint: str = ""
    decoded_payload: Dict[str, Any] = field(default_factory=dict)
    is_valid: bool = True
    expires_at: str = ""
    discovered_at: str = ""
    token_id: str = ""

    def __post_init__(self) -> None:
        if not self.discovered_at:
            self.discovered_at = datetime.now(timezone.utc).isoformat()
        if not self.token_id:
            raw = f"{self.token_type}|{self.token_value[:32]}"
            self.token_id = hashlib.md5(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "TokenRecord":
        return TokenRecord(**{
            k: v for k, v in data.items()
            if k in TokenRecord.__dataclass_fields__
        })


@dataclass
class AttackChainStep:
    """One step in an attack chain."""
    step_number: int = 0
    action: str = ""
    finding_used: str = ""  # vuln_id or credential_id
    result: str = ""
    new_finding: str = ""  # vuln_id of what was discovered
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "AttackChainStep":
        return AttackChainStep(**{
            k: v for k, v in data.items()
            if k in AttackChainStep.__dataclass_fields__
        })


@dataclass
class FailedAttempt:
    """A test that was tried but did not find a vulnerability."""
    endpoint: str = ""
    test_type: str = ""
    payload: str = ""
    reason: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "FailedAttempt":
        return FailedAttempt(**{
            k: v for k, v in data.items()
            if k in FailedAttempt.__dataclass_fields__
        })


# ---------------------------------------------------------------------------
# ScanState — the complete scan state
# ---------------------------------------------------------------------------

@dataclass
class ScanState:
    """Complete scan state — everything discovered during a scan."""

    # Target Information
    target_url: str = ""
    target_domain: str = ""
    technologies: List[str] = field(default_factory=list)
    waf_detected: str = ""
    server_info: str = ""
    framework_info: str = ""

    # Authentication State
    registered_users: List[Dict[str, Any]] = field(default_factory=list)
    admin_token: str = ""
    active_session: Dict[str, Any] = field(default_factory=dict)
    login_endpoint: str = ""
    register_endpoint: str = ""
    auth_mechanism: str = ""  # jwt, session, basic, oauth

    # Discovery
    all_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    api_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    hidden_paths: List[str] = field(default_factory=list)

    # Findings
    confirmed_vulns: List[Dict[str, Any]] = field(default_factory=list)
    potential_vulns: List[Dict[str, Any]] = field(default_factory=list)
    failed_attempts: List[Dict[str, Any]] = field(default_factory=list)

    # Credentials & Tokens
    discovered_tokens: List[Dict[str, Any]] = field(default_factory=list)
    discovered_creds: List[Dict[str, Any]] = field(default_factory=list)
    jwt_secret: str = ""

    # Attack Progress
    tested_endpoints: Dict[str, List[str]] = field(default_factory=dict)
    attack_chain: List[Dict[str, Any]] = field(default_factory=list)

    # Statistics
    total_requests: int = 0
    total_findings: int = 0
    scan_start_time: str = ""
    last_update_time: str = ""
    scan_status: str = "initialized"  # initialized, running, paused, completed

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ScanState":
        return ScanState(**{
            k: v for k, v in data.items()
            if k in ScanState.__dataclass_fields__
        })


# ---------------------------------------------------------------------------
# StateManager — the main class
# ---------------------------------------------------------------------------

class StateManager:
    """
    Thread-safe, persistent state manager for VAPT-AI scans.

    Every piece of information discovered during a scan is stored here.
    Agents read from this state to decide their next actions. The
    orchestrator uses this to track overall progress and chain attacks.

    Thread Safety:
        All write operations acquire a ``threading.Lock``.
        Read operations return deep copies to prevent concurrent
        modification bugs.

    Persistence:
        State is saved to ``~/vapt-ai/data/scan_state_{domain}.json``
        after every modification. Scans can be resumed after restart.

    Usage::

        state = StateManager("https://target.com")
        state.add_endpoint(EndpointRecord(url="/api/users", method="GET"))
        state.add_credential(CredentialRecord(email="admin@test.com", password="pass"))

        untested = state.get_untested_endpoints("sqli_error_based")
        token = state.get_authenticated_token()
    """

    def __init__(
        self,
        target_url: str,
        data_dir: Optional[str] = None,
        auto_save: bool = True,
        auto_load: bool = True,
    ) -> None:
        """
        Parameters
        ----------
        target_url : str
            The target application URL.
        data_dir : str, optional
            Directory for state files. Default ``~/vapt-ai/data/``.
        auto_save : bool
            Automatically save to disk after every state change.
        auto_load : bool
            Automatically load existing state from disk on init.
        """
        self._lock: threading.RLock = threading.RLock()
        self._auto_save: bool = auto_save

        # Parse target
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path
        domain_clean = domain.replace(":", "_").replace("/", "_")

        # Data directory
        self._data_dir: str = data_dir or DEFAULT_DATA_DIR
        os.makedirs(self._data_dir, exist_ok=True)

        # State file path
        self._state_file: str = os.path.join(
            self._data_dir, f"scan_state_{domain_clean}.json"
        )

        # Initialize state
        self._state: ScanState = ScanState(
            target_url=target_url,
            target_domain=domain,
            scan_start_time=datetime.now(timezone.utc).isoformat(),
            last_update_time=datetime.now(timezone.utc).isoformat(),
        )

        # Index sets for fast deduplication (not persisted — rebuilt on load)
        self._endpoint_ids: Set[str] = set()
        self._vuln_ids: Set[str] = set()
        self._credential_ids: Set[str] = set()
        self._token_ids: Set[str] = set()

        # Load existing state if available
        if auto_load:
            self.load_from_disk()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _touch(self) -> None:
        """Update timestamp and auto-save."""
        self._state.last_update_time = datetime.now(timezone.utc).isoformat()
        if self._auto_save:
            self._save_no_lock()

    def _save_no_lock(self) -> None:
        """Save state to disk (caller must hold lock or call from locked context)."""
        try:
            state_dict = self._state.to_dict()
            temp_file = self._state_file + ".tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(state_dict, f, indent=2, default=str, ensure_ascii=False)
            # Atomic rename
            os.replace(temp_file, self._state_file)
        except Exception as e:
            # Never crash on save failure
            print(f"[StateManager] Warning: Failed to save state: {e}")

    def _rebuild_indexes(self) -> None:
        """Rebuild deduplication indexes from current state."""
        self._endpoint_ids = set()
        for ep in self._state.all_endpoints:
            ep_id = ep.get("endpoint_id", "")
            if ep_id:
                self._endpoint_ids.add(ep_id)

        self._vuln_ids = set()
        for v in self._state.confirmed_vulns:
            vid = v.get("vuln_id", "")
            if vid:
                self._vuln_ids.add(vid)
        for v in self._state.potential_vulns:
            vid = v.get("vuln_id", "")
            if vid:
                self._vuln_ids.add(vid)

        self._credential_ids = set()
        for c in self._state.registered_users:
            cid = c.get("credential_id", "")
            if cid:
                self._credential_ids.add(cid)
        for c in self._state.discovered_creds:
            cid = c.get("credential_id", "")
            if cid:
                self._credential_ids.add(cid)

        self._token_ids = set()
        for t in self._state.discovered_tokens:
            tid = t.get("token_id", "")
            if tid:
                self._token_ids.add(tid)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_to_disk(self) -> bool:
        """Manually save the current state to disk."""
        with self._lock:
            try:
                self._save_no_lock()
                return True
            except Exception:
                return False

    def load_from_disk(self) -> bool:
        """Load state from disk if a save file exists."""
        with self._lock:
            if not os.path.exists(self._state_file):
                return False

            try:
                with open(self._state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Preserve target info from init
                target_url = self._state.target_url
                target_domain = self._state.target_domain

                self._state = ScanState.from_dict(data)

                # Ensure target info is correct
                if not self._state.target_url:
                    self._state.target_url = target_url
                if not self._state.target_domain:
                    self._state.target_domain = target_domain

                self._rebuild_indexes()
                return True

            except Exception as e:
                print(f"[StateManager] Warning: Failed to load state: {e}")
                return False

    def delete_state_file(self) -> bool:
        """Delete the state file from disk."""
        with self._lock:
            try:
                if os.path.exists(self._state_file):
                    os.remove(self._state_file)
                return True
            except Exception:
                return False

    def reset_state(self) -> None:
        """Reset all state to initial values (keeps target info)."""
        with self._lock:
            target_url = self._state.target_url
            target_domain = self._state.target_domain

            self._state = ScanState(
                target_url=target_url,
                target_domain=target_domain,
                scan_start_time=datetime.now(timezone.utc).isoformat(),
                last_update_time=datetime.now(timezone.utc).isoformat(),
            )

            self._endpoint_ids.clear()
            self._vuln_ids.clear()
            self._credential_ids.clear()
            self._token_ids.clear()

            self._touch()

    # ------------------------------------------------------------------
    # Target Information
    # ------------------------------------------------------------------

    def set_target_info(
        self,
        technologies: Optional[List[str]] = None,
        waf_detected: Optional[str] = None,
        server_info: Optional[str] = None,
        framework_info: Optional[str] = None,
    ) -> None:
        """Update target information."""
        with self._lock:
            if technologies is not None:
                # Merge — don't replace
                existing = set(self._state.technologies)
                for tech in technologies:
                    if tech and tech not in existing:
                        self._state.technologies.append(tech)
                        existing.add(tech)
            if waf_detected is not None:
                self._state.waf_detected = waf_detected
            if server_info is not None:
                self._state.server_info = server_info
            if framework_info is not None:
                self._state.framework_info = framework_info
            self._touch()

    def get_target_info(self) -> Dict[str, Any]:
        """Return target information."""
        with self._lock:
            return {
                "target_url": self._state.target_url,
                "target_domain": self._state.target_domain,
                "technologies": list(self._state.technologies),
                "waf_detected": self._state.waf_detected,
                "server_info": self._state.server_info,
                "framework_info": self._state.framework_info,
            }

    # ------------------------------------------------------------------
    # Endpoint management
    # ------------------------------------------------------------------

    def add_endpoint(self, endpoint: Union[EndpointRecord, Dict[str, Any]]) -> bool:
        """
        Add a discovered endpoint to the state.

        Returns True if the endpoint was new, False if duplicate.
        """
        with self._lock:
            if isinstance(endpoint, EndpointRecord):
                ep_dict = endpoint.to_dict()
                ep_id = endpoint.endpoint_id
            else:
                rec = EndpointRecord(**{
                    k: v for k, v in endpoint.items()
                    if k in EndpointRecord.__dataclass_fields__
                })
                ep_dict = rec.to_dict()
                ep_id = rec.endpoint_id

            if ep_id in self._endpoint_ids:
                return False

            self._endpoint_ids.add(ep_id)
            self._state.all_endpoints.append(ep_dict)

            # Also add to api_endpoints if it's an API endpoint
            url_lower = ep_dict.get("url", "").lower()
            api_indicators = ["/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/",
                              "/ajax/", "/json/", "/rpc/"]
            if any(ind in url_lower for ind in api_indicators):
                self._state.api_endpoints.append(ep_dict)

            self._touch()
            return True

    def add_endpoints_bulk(self, endpoints: List[Union[EndpointRecord, Dict[str, Any]]]) -> int:
        """Add multiple endpoints at once. Returns count of new endpoints added."""
        added = 0
        with self._lock:
            for endpoint in endpoints:
                if isinstance(endpoint, EndpointRecord):
                    ep_dict = endpoint.to_dict()
                    ep_id = endpoint.endpoint_id
                else:
                    rec = EndpointRecord(**{
                        k: v for k, v in endpoint.items()
                        if k in EndpointRecord.__dataclass_fields__
                    })
                    ep_dict = rec.to_dict()
                    ep_id = rec.endpoint_id

                if ep_id not in self._endpoint_ids:
                    self._endpoint_ids.add(ep_id)
                    self._state.all_endpoints.append(ep_dict)
                    added += 1

                    url_lower = ep_dict.get("url", "").lower()
                    api_indicators = ["/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/"]
                    if any(ind in url_lower for ind in api_indicators):
                        self._state.api_endpoints.append(ep_dict)

            if added > 0:
                self._touch()

        return added

    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        """Return all discovered endpoints (deep copy)."""
        with self._lock:
            return copy.deepcopy(self._state.all_endpoints)

    def get_api_endpoints(self) -> List[Dict[str, Any]]:
        """Return only API endpoints (deep copy)."""
        with self._lock:
            return copy.deepcopy(self._state.api_endpoints)

    def get_endpoints_by_method(self, method: str) -> List[Dict[str, Any]]:
        """Return endpoints filtered by HTTP method."""
        with self._lock:
            return [
                copy.deepcopy(ep) for ep in self._state.all_endpoints
                if ep.get("method", "").upper() == method.upper()
            ]

    def get_endpoints_requiring_auth(self) -> List[Dict[str, Any]]:
        """Return endpoints that require authentication."""
        with self._lock:
            return [
                copy.deepcopy(ep) for ep in self._state.all_endpoints
                if ep.get("auth_required", False)
            ]

    # ------------------------------------------------------------------
    # Endpoint testing progress
    # ------------------------------------------------------------------

    def mark_endpoint_tested(
        self,
        endpoint_url: str,
        test_type: str,
        result: str = "no_finding",
        details: str = "",
    ) -> None:
        """
        Record that a specific test was performed on an endpoint.

        Parameters
        ----------
        endpoint_url : str
            The endpoint that was tested.
        test_type : str
            The type of test performed (e.g. ``sqli_error_based``).
        result : str
            ``"vulnerable"``, ``"not_vulnerable"``, ``"error"``, ``"no_finding"``
        details : str
            Additional details about the test result.
        """
        with self._lock:
            if endpoint_url not in self._state.tested_endpoints:
                self._state.tested_endpoints[endpoint_url] = []

            test_record = {
                "test_type": test_type,
                "result": result,
                "details": details,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self._state.tested_endpoints[endpoint_url].append(test_record)

            # If not vulnerable, add to failed attempts
            if result in ("not_vulnerable", "no_finding"):
                self._state.failed_attempts.append(FailedAttempt(
                    endpoint=endpoint_url,
                    test_type=test_type,
                    reason=details or result,
                ).to_dict())

            self._touch()

    def get_untested_endpoints(self, test_type: str) -> List[Dict[str, Any]]:
        """
        Return all endpoints that have NOT been tested with *test_type*.

        This is the primary method agents use to decide what to test next.
        """
        with self._lock:
            untested = []
            for ep in self._state.all_endpoints:
                url = ep.get("url", "")
                tests_done = self._state.tested_endpoints.get(url, [])
                already_tested = any(
                    t.get("test_type") == test_type for t in tests_done
                )
                if not already_tested:
                    untested.append(copy.deepcopy(ep))
            return untested

    def get_tested_endpoints(self, test_type: Optional[str] = None) -> Dict[str, List[Dict]]:
        """
        Return tested endpoints and their test results.

        Parameters
        ----------
        test_type : str, optional
            Filter to a specific test type. If None, return all.
        """
        with self._lock:
            if test_type is None:
                return copy.deepcopy(self._state.tested_endpoints)

            filtered: Dict[str, List[Dict]] = {}
            for url, tests in self._state.tested_endpoints.items():
                matching = [t for t in tests if t.get("test_type") == test_type]
                if matching:
                    filtered[url] = copy.deepcopy(matching)
            return filtered

    def is_endpoint_tested(self, endpoint_url: str, test_type: str) -> bool:
        """Check if a specific test has been run on an endpoint."""
        with self._lock:
            tests = self._state.tested_endpoints.get(endpoint_url, [])
            return any(t.get("test_type") == test_type for t in tests)

    def get_vulnerable_endpoints(self) -> List[str]:
        """Return URLs of endpoints where vulnerabilities were found."""
        with self._lock:
            vuln_urls: Set[str] = set()
            for v in self._state.confirmed_vulns:
                ep = v.get("endpoint", "")
                if ep:
                    vuln_urls.add(ep)
            return list(vuln_urls)

    # ------------------------------------------------------------------
    # Vulnerability management
    # ------------------------------------------------------------------

    def add_finding(
        self,
        vulnerability: Union[VulnerabilityRecord, Dict[str, Any]],
        confirmed: bool = True,
    ) -> bool:
        """
        Add a discovered vulnerability.

        Returns True if the finding was new, False if duplicate.
        """
        with self._lock:
            if isinstance(vulnerability, VulnerabilityRecord):
                vuln_dict = vulnerability.to_dict()
                vuln_id = vulnerability.vuln_id
            else:
                rec = VulnerabilityRecord(**{
                    k: v for k, v in vulnerability.items()
                    if k in VulnerabilityRecord.__dataclass_fields__
                })
                vuln_dict = rec.to_dict()
                vuln_id = rec.vuln_id

            if vuln_id in self._vuln_ids:
                return False

            self._vuln_ids.add(vuln_id)
            vuln_dict["confirmed"] = confirmed

            if confirmed:
                self._state.confirmed_vulns.append(vuln_dict)
            else:
                self._state.potential_vulns.append(vuln_dict)

            self._state.total_findings += 1
            self._touch()
            return True

    def confirm_finding(self, vuln_id: str) -> bool:
        """Move a potential vulnerability to confirmed."""
        with self._lock:
            for i, v in enumerate(self._state.potential_vulns):
                if v.get("vuln_id") == vuln_id:
                    v["confirmed"] = True
                    self._state.confirmed_vulns.append(v)
                    self._state.potential_vulns.pop(i)
                    self._touch()
                    return True
            return False

    def get_confirmed_vulns(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Return confirmed vulnerabilities, optionally filtered.

        Parameters
        ----------
        category : str, optional
            Filter by category (e.g. ``"sqli"``, ``"xss"``).
        severity : str, optional
            Filter by minimum severity (e.g. ``"high"`` returns high + critical).
        """
        with self._lock:
            results = self._state.confirmed_vulns

            if category:
                results = [v for v in results if v.get("category") == category]

            if severity:
                max_order = SEVERITY_ORDER.get(severity.lower(), 4)
                results = [
                    v for v in results
                    if SEVERITY_ORDER.get(v.get("severity", "info").lower(), 4) <= max_order
                ]

            return copy.deepcopy(results)

    def get_potential_vulns(self) -> List[Dict[str, Any]]:
        """Return potential (unconfirmed) vulnerabilities."""
        with self._lock:
            return copy.deepcopy(self._state.potential_vulns)

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Return all findings (confirmed + potential), sorted by severity."""
        with self._lock:
            all_vulns = self._state.confirmed_vulns + self._state.potential_vulns
            sorted_vulns = sorted(
                all_vulns,
                key=lambda v: SEVERITY_ORDER.get(v.get("severity", "info").lower(), 4),
            )
            return copy.deepcopy(sorted_vulns)

    def get_findings_by_endpoint(self, endpoint_url: str) -> List[Dict[str, Any]]:
        """Return all findings for a specific endpoint."""
        with self._lock:
            all_vulns = self._state.confirmed_vulns + self._state.potential_vulns
            return [
                copy.deepcopy(v) for v in all_vulns
                if v.get("endpoint") == endpoint_url
            ]

    def has_finding_for(self, endpoint: str, category: str) -> bool:
        """Check if a specific type of vulnerability exists for an endpoint."""
        with self._lock:
            all_vulns = self._state.confirmed_vulns + self._state.potential_vulns
            return any(
                v.get("endpoint") == endpoint and v.get("category") == category
                for v in all_vulns
            )

    # ------------------------------------------------------------------
    # Credential management
    # ------------------------------------------------------------------

    def add_credential(
        self,
        credential: Union[CredentialRecord, Dict[str, Any]],
        is_registered: bool = False,
    ) -> bool:
        """
        Add a discovered or registered credential.

        Parameters
        ----------
        credential : CredentialRecord or dict
            The credential to add.
        is_registered : bool
            If True, this is a user we registered (not discovered).

        Returns True if the credential was new.
        """
        with self._lock:
            if isinstance(credential, CredentialRecord):
                cred_dict = credential.to_dict()
                cred_id = credential.credential_id
            else:
                rec = CredentialRecord(**{
                    k: v for k, v in credential.items()
                    if k in CredentialRecord.__dataclass_fields__
                })
                cred_dict = rec.to_dict()
                cred_id = rec.credential_id

            if cred_id in self._credential_ids:
                return False

            self._credential_ids.add(cred_id)

            if is_registered:
                cred_dict["source"] = cred_dict.get("source") or "registered"
                self._state.registered_users.append(cred_dict)
            else:
                cred_dict["source"] = cred_dict.get("source") or "discovered"
                self._state.discovered_creds.append(cred_dict)

            # If admin, store token
            if cred_dict.get("role", "").lower() == "admin" and cred_dict.get("token"):
                self._state.admin_token = cred_dict["token"]

            self._touch()
            return True

    def update_credential_token(
        self,
        email: str = "",
        username: str = "",
        token: str = "",
        cookies: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Update the token/cookies for an existing credential."""
        with self._lock:
            all_creds = self._state.registered_users + self._state.discovered_creds
            for cred in all_creds:
                if ((email and cred.get("email") == email) or
                        (username and cred.get("username") == username)):
                    if token:
                        cred["token"] = token
                    if cookies:
                        cred["cookies"] = cookies
                    cred["is_valid"] = True
                    self._touch()
                    return True
            return False

    def get_all_credentials(self) -> List[Dict[str, Any]]:
        """Return all credentials (registered + discovered)."""
        with self._lock:
            all_creds = self._state.registered_users + self._state.discovered_creds
            return copy.deepcopy(all_creds)

    def get_registered_users(self) -> List[Dict[str, Any]]:
        """Return credentials for users we registered."""
        with self._lock:
            return copy.deepcopy(self._state.registered_users)

    def get_discovered_credentials(self) -> List[Dict[str, Any]]:
        """Return credentials that were discovered (not registered by us)."""
        with self._lock:
            return copy.deepcopy(self._state.discovered_creds)

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def add_token(self, token: Union[TokenRecord, Dict[str, Any]]) -> bool:
        """Add a discovered token. Returns True if new."""
        with self._lock:
            if isinstance(token, TokenRecord):
                token_dict = token.to_dict()
                token_id = token.token_id
            else:
                rec = TokenRecord(**{
                    k: v for k, v in token.items()
                    if k in TokenRecord.__dataclass_fields__
                })
                token_dict = rec.to_dict()
                token_id = rec.token_id

            if token_id in self._token_ids:
                return False

            self._token_ids.add(token_id)
            self._state.discovered_tokens.append(token_dict)
            self._touch()
            return True

    def get_discovered_tokens(self) -> List[Dict[str, Any]]:
        """Return all discovered tokens."""
        with self._lock:
            return copy.deepcopy(self._state.discovered_tokens)

    def set_jwt_secret(self, secret: str) -> None:
        """Store a cracked JWT secret."""
        with self._lock:
            self._state.jwt_secret = secret
            self._touch()

    def get_jwt_secret(self) -> str:
        """Return the cracked JWT secret (empty string if not found)."""
        with self._lock:
            return self._state.jwt_secret

    # ------------------------------------------------------------------
    # Authentication state
    # ------------------------------------------------------------------

    def get_authenticated_token(self) -> Optional[str]:
        """
        Return the best available authentication token.

        Priority:
        1. Admin token
        2. Active session token
        3. Most recently registered user's token
        4. Most recently discovered credential's token
        """
        with self._lock:
            # 1. Admin token
            if self._state.admin_token:
                return self._state.admin_token

            # 2. Active session
            session_token = self._state.active_session.get("token")
            if session_token:
                return session_token

            # 3. Registered users (most recent first)
            for cred in reversed(self._state.registered_users):
                if cred.get("token") and cred.get("is_valid", True):
                    return cred["token"]

            # 4. Discovered creds
            for cred in reversed(self._state.discovered_creds):
                if cred.get("token") and cred.get("is_valid", True):
                    return cred["token"]

            return None

    def get_authenticated_cookies(self) -> Dict[str, str]:
        """Return the best available session cookies."""
        with self._lock:
            # Active session
            session_cookies = self._state.active_session.get("cookies", {})
            if session_cookies:
                return dict(session_cookies)

            # Registered users
            for cred in reversed(self._state.registered_users):
                if cred.get("cookies") and cred.get("is_valid", True):
                    return dict(cred["cookies"])

            # Discovered creds
            for cred in reversed(self._state.discovered_creds):
                if cred.get("cookies") and cred.get("is_valid", True):
                    return dict(cred["cookies"])

            return {}

    def set_active_session(
        self,
        token: str = "",
        cookies: Optional[Dict[str, str]] = None,
        token_type: str = "Bearer",
    ) -> None:
        """Set the currently active session."""
        with self._lock:
            self._state.active_session = {
                "token": token,
                "token_type": token_type,
                "cookies": cookies or {},
                "set_at": datetime.now(timezone.utc).isoformat(),
            }
            self._touch()

    def has_admin_access(self) -> bool:
        """Check if admin-level access has been achieved."""
        with self._lock:
            if self._state.admin_token:
                return True
            for cred in self._state.registered_users + self._state.discovered_creds:
                if cred.get("role", "").lower() == "admin" and cred.get("is_valid", True):
                    return True
            return False

    def has_any_auth(self) -> bool:
        """Check if any authentication credentials are available."""
        with self._lock:
            return bool(
                self._state.admin_token
                or self._state.active_session.get("token")
                or any(c.get("token") for c in self._state.registered_users)
                or any(c.get("token") for c in self._state.discovered_creds)
            )

    def set_login_endpoint(self, url: str) -> None:
        """Store the discovered login endpoint."""
        with self._lock:
            self._state.login_endpoint = url
            self._touch()

    def set_register_endpoint(self, url: str) -> None:
        """Store the discovered register endpoint."""
        with self._lock:
            self._state.register_endpoint = url
            self._touch()

    def get_login_endpoint(self) -> str:
        """Return the login endpoint URL."""
        with self._lock:
            return self._state.login_endpoint

    def get_register_endpoint(self) -> str:
        """Return the registration endpoint URL."""
        with self._lock:
            return self._state.register_endpoint

    def set_auth_mechanism(self, mechanism: str) -> None:
        """Store the detected auth mechanism (jwt, session, basic, oauth)."""
        with self._lock:
            self._state.auth_mechanism = mechanism
            self._touch()

    # ------------------------------------------------------------------
    # Discovery helpers
    # ------------------------------------------------------------------

    def add_form(self, form_data: Dict[str, Any]) -> None:
        """Add a discovered HTML form."""
        with self._lock:
            # Simple dedup by action + method
            key = f"{form_data.get('action', '')}|{form_data.get('method', '')}"
            existing_keys = {
                f"{f.get('action', '')}|{f.get('method', '')}"
                for f in self._state.forms
            }
            if key not in existing_keys:
                self._state.forms.append(form_data)
                self._touch()

    def get_forms(self) -> List[Dict[str, Any]]:
        """Return all discovered forms."""
        with self._lock:
            return copy.deepcopy(self._state.forms)

    def get_login_forms(self) -> List[Dict[str, Any]]:
        """Return forms that look like login forms."""
        with self._lock:
            return [
                copy.deepcopy(f) for f in self._state.forms
                if f.get("is_login_form") or f.get("has_password")
            ]

    def add_js_file(self, url: str) -> None:
        """Add a discovered JavaScript file URL."""
        with self._lock:
            if url not in self._state.js_files:
                self._state.js_files.append(url)
                self._touch()

    def get_js_files(self) -> List[str]:
        """Return all discovered JavaScript file URLs."""
        with self._lock:
            return list(self._state.js_files)

    def add_hidden_path(self, path: str) -> None:
        """Add a discovered hidden path/directory."""
        with self._lock:
            if path not in self._state.hidden_paths:
                self._state.hidden_paths.append(path)
                self._touch()

    def get_hidden_paths(self) -> List[str]:
        """Return all discovered hidden paths."""
        with self._lock:
            return list(self._state.hidden_paths)

    # ------------------------------------------------------------------
    # Attack chaining
    # ------------------------------------------------------------------

    def add_to_attack_chain(
        self,
        action: str,
        finding_used: str = "",
        result: str = "",
        new_finding: str = "",
    ) -> None:
        """
        Add a step to the attack chain.

        This tracks how one finding led to another, showing the
        logical progression of the penetration test.
        """
        with self._lock:
            step_number = len(self._state.attack_chain) + 1
            step = AttackChainStep(
                step_number=step_number,
                action=action,
                finding_used=finding_used,
                result=result,
                new_finding=new_finding,
            )
            self._state.attack_chain.append(step.to_dict())
            self._touch()

    def get_attack_chain(self) -> List[Dict[str, Any]]:
        """Return the complete attack chain."""
        with self._lock:
            return copy.deepcopy(self._state.attack_chain)

    # ------------------------------------------------------------------
    # Statistics and metrics
    # ------------------------------------------------------------------

    def increment_requests(self, count: int = 1) -> None:
        """Increment the total request counter."""
        with self._lock:
            self._state.total_requests += count
            self._touch()

    def set_scan_status(self, status: str) -> None:
        """Update scan status (initialized, running, paused, completed)."""
        with self._lock:
            self._state.scan_status = status
            self._touch()

    def get_scan_status(self) -> str:
        """Return current scan status."""
        with self._lock:
            return self._state.scan_status

    def get_statistics(self) -> Dict[str, Any]:
        """Return scan statistics."""
        with self._lock:
            severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for v in self._state.confirmed_vulns:
                sev = v.get("severity", "info").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

            category_counts: Dict[str, int] = {}
            for v in self._state.confirmed_vulns:
                cat = v.get("category", "other")
                category_counts[cat] = category_counts.get(cat, 0) + 1

            total_endpoints = len(self._state.all_endpoints)
            tested_count = len(self._state.tested_endpoints)

            return {
                "target": self._state.target_url,
                "scan_status": self._state.scan_status,
                "scan_start_time": self._state.scan_start_time,
                "last_update_time": self._state.last_update_time,
                "total_requests": self._state.total_requests,
                "total_endpoints": total_endpoints,
                "tested_endpoints": tested_count,
                "untested_endpoints": total_endpoints - tested_count,
                "coverage_percent": (
                    round((tested_count / total_endpoints) * 100, 1)
                    if total_endpoints > 0 else 0.0
                ),
                "confirmed_vulns": len(self._state.confirmed_vulns),
                "potential_vulns": len(self._state.potential_vulns),
                "total_findings": self._state.total_findings,
                "severity_distribution": severity_counts,
                "category_distribution": category_counts,
                "failed_attempts": len(self._state.failed_attempts),
                "credentials_found": len(self._state.discovered_creds),
                "users_registered": len(self._state.registered_users),
                "tokens_found": len(self._state.discovered_tokens),
                "attack_chain_steps": len(self._state.attack_chain),
                "has_auth": self.has_any_auth(),
                "has_admin": self.has_admin_access(),
            }

    # ------------------------------------------------------------------
    # Summary for LLM / Orchestrator
    # ------------------------------------------------------------------

    def get_attack_summary(self) -> Dict[str, Any]:
        """
        Generate a comprehensive summary of the scan for the orchestrator.

        This is the primary method the LLM agent uses to understand
        current scan progress and decide next steps.
        """
        with self._lock:
            # What has been found
            vuln_summary = []
            for v in self._state.confirmed_vulns:
                vuln_summary.append({
                    "vuln_id": v.get("vuln_id"),
                    "title": v.get("title"),
                    "category": v.get("category"),
                    "severity": v.get("severity"),
                    "endpoint": v.get("endpoint"),
                    "parameter": v.get("parameter"),
                })

            # What credentials are available
            cred_summary = []
            for c in (self._state.registered_users + self._state.discovered_creds):
                cred_summary.append({
                    "email": c.get("email"),
                    "role": c.get("role"),
                    "has_token": bool(c.get("token")),
                    "source": c.get("source"),
                })

            # What hasn't been tested yet
            untested_summary: Dict[str, int] = {}
            for test_type in ["sqli_error_based", "xss_reflected", "idor_horizontal",
                              "auth_bypass_direct", "jwt_none_alg"]:
                count = len(self.get_untested_endpoints(test_type))
                if count > 0:
                    untested_summary[test_type] = count

            return {
                "target": self._state.target_url,
                "status": self._state.scan_status,
                "technologies": self._state.technologies,
                "waf": self._state.waf_detected,
                "total_endpoints": len(self._state.all_endpoints),
                "total_api_endpoints": len(self._state.api_endpoints),
                "confirmed_vulns": vuln_summary,
                "confirmed_count": len(self._state.confirmed_vulns),
                "potential_count": len(self._state.potential_vulns),
                "credentials": cred_summary,
                "has_admin_access": bool(self._state.admin_token),
                "auth_mechanism": self._state.auth_mechanism,
                "untested_areas": untested_summary,
                "attack_chain": copy.deepcopy(self._state.attack_chain),
                "failed_attempts_count": len(self._state.failed_attempts),
                "recommendations": self._generate_recommendations(),
            }

    def get_context_for_agent(self, agent_type: str) -> Dict[str, Any]:
        """
        Return relevant state context for a specific agent type.

        Parameters
        ----------
        agent_type : str
            One of: ``"recon"``, ``"auth"``, ``"scanner"``, ``"exploiter"``, ``"reporter"``
        """
        with self._lock:
            base = {
                "target_url": self._state.target_url,
                "technologies": list(self._state.technologies),
                "waf": self._state.waf_detected,
                "has_auth": self.has_any_auth(),
            }

            if agent_type == "recon":
                base.update({
                    "known_endpoints": len(self._state.all_endpoints),
                    "js_files": list(self._state.js_files),
                    "hidden_paths": list(self._state.hidden_paths),
                })

            elif agent_type == "auth":
                base.update({
                    "login_endpoint": self._state.login_endpoint,
                    "register_endpoint": self._state.register_endpoint,
                    "auth_mechanism": self._state.auth_mechanism,
                    "registered_users": copy.deepcopy(self._state.registered_users),
                    "login_forms": [
                        f for f in self._state.forms if f.get("is_login_form")
                    ],
                })

            elif agent_type == "scanner":
                base.update({
                    "all_endpoints": copy.deepcopy(self._state.all_endpoints),
                    "api_endpoints": copy.deepcopy(self._state.api_endpoints),
                    "tested_endpoints": copy.deepcopy(self._state.tested_endpoints),
                    "auth_token": self.get_authenticated_token(),
                    "confirmed_vulns_count": len(self._state.confirmed_vulns),
                })

            elif agent_type == "exploiter":
                base.update({
                    "confirmed_vulns": copy.deepcopy(self._state.confirmed_vulns),
                    "credentials": copy.deepcopy(
                        self._state.registered_users + self._state.discovered_creds
                    ),
                    "tokens": copy.deepcopy(self._state.discovered_tokens),
                    "jwt_secret": self._state.jwt_secret,
                    "auth_token": self.get_authenticated_token(),
                    "attack_chain": copy.deepcopy(self._state.attack_chain),
                })

            elif agent_type == "reporter":
                base.update({
                    "confirmed_vulns": copy.deepcopy(self._state.confirmed_vulns),
                    "potential_vulns": copy.deepcopy(self._state.potential_vulns),
                    "statistics": self.get_statistics(),
                    "attack_chain": copy.deepcopy(self._state.attack_chain),
                    "credentials": copy.deepcopy(
                        self._state.registered_users + self._state.discovered_creds
                    ),
                })

            return base

    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on current state."""
        recs: List[str] = []

        # No auth yet
        if not self.has_any_auth():
            if self._state.login_endpoint:
                recs.append("Authentication not established. Try registering or brute-forcing login.")
            else:
                recs.append("No login endpoint found. Run deeper recon to find auth pages.")

        # Untested endpoints exist
        total_ep = len(self._state.all_endpoints)
        tested_ep = len(self._state.tested_endpoints)
        if total_ep > 0 and tested_ep < total_ep:
            recs.append(f"{total_ep - tested_ep}/{total_ep} endpoints untested. Continue scanning.")

        # SQLi found — try to dump data
        sqli_vulns = [v for v in self._state.confirmed_vulns if v.get("category") == "sqli"]
        if sqli_vulns:
            recs.append("SQLi found. Attempt data extraction and credential discovery.")

        # Creds found — try privilege escalation
        if self._state.discovered_creds and not self.has_admin_access():
            recs.append("Credentials discovered. Try IDOR or privilege escalation.")

        # JWT secret cracked
        if self._state.jwt_secret:
            recs.append("JWT secret known. Forge admin tokens for privilege escalation.")

        # No findings yet
        if not self._state.confirmed_vulns and not self._state.potential_vulns:
            if total_ep > 0:
                recs.append("No findings yet. Ensure all test categories are covered.")

        # API endpoints exist but not tested
        api_count = len(self._state.api_endpoints)
        if api_count > 0:
            tested_apis = sum(
                1 for ep in self._state.api_endpoints
                if ep.get("url") in self._state.tested_endpoints
            )
            if tested_apis < api_count:
                recs.append(f"{api_count - tested_apis} API endpoints need testing.")

        return recs

    # ------------------------------------------------------------------
    # Full state access (for debugging / export)
    # ------------------------------------------------------------------

    def get_full_state(self) -> Dict[str, Any]:
        """Return the complete state as a dictionary (deep copy)."""
        with self._lock:
            return copy.deepcopy(self._state.to_dict())

    def get_state_file_path(self) -> str:
        """Return the path to the state file on disk."""
        return self._state_file

    # ------------------------------------------------------------------
    # repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<StateManager target={self._state.target_domain!r} "
            f"endpoints={len(self._state.all_endpoints)} "
            f"vulns={len(self._state.confirmed_vulns)} "
            f"status={self._state.scan_status}>"
        )