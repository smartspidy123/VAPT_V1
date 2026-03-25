"""
VAPT-AI V2.0 - Browser Engine
===============================
A headless browser engine built on Playwright for testing Single Page
Applications (Angular, React, Vue, Next.js, Nuxt.js, etc.).

Capabilities:
- Full JavaScript rendering and DOM extraction
- Route/endpoint discovery from JS source files
- Network request interception (XHR, fetch, WebSocket)
- Form discovery, filling, and submission
- Cookie, localStorage, sessionStorage access
- JavaScript execution in page context
- Screenshot capture for evidence
- SPA-aware navigation and crawling

Integration:
- Feeds discovered endpoints to state_manager
- Works alongside SmartHTTPClient for hybrid testing
- Provides rendered DOM to scanner agents
- Captures evidence for reporter agent
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse

try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Playwright,
        Request as PWRequest,
        Response as PWResponse,
        Route,
        Error as PlaywrightError,
        TimeoutError as PlaywrightTimeoutError,
    )
except ImportError:
    raise ImportError(
        "Playwright is required. Install with:\n"
        "  pip install playwright\n"
        "  playwright install chromium"
    )

from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Constants: Route extraction patterns
# ---------------------------------------------------------------------------

# Patterns to find API endpoint strings in JavaScript source code
JS_API_ENDPOINT_PATTERNS: List[re.Pattern] = [
    # Fetch API calls:  fetch('/api/users', ...)  fetch("/api/users")
    re.compile(r"""fetch\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    # Axios calls:  axios.get('/api/users')  axios.post("/api/data")
    re.compile(r"""axios\s*\.\s*(?:get|post|put|delete|patch|options|head|request)\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    # jQuery AJAX:  $.ajax({url: '/api/users'})  $.get('/api/users')
    re.compile(r"""\$\s*\.\s*(?:ajax|get|post|put|getJSON)\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    re.compile(r"""url\s*:\s*['"`]([^'"`\s]*(?:api|rest|graphql|v\d)[^'"`\s]*)['"`]""", re.IGNORECASE),
    # Angular $http:  $http.get('/api/users')  $http({url: '/api/users'})
    re.compile(r"""\$http\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    re.compile(r"""\$http\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    # XMLHttpRequest:  xhr.open('GET', '/api/users')
    re.compile(r"""\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    # Generic /api/ or /rest/ paths in strings
    re.compile(r"""['"`](\/(?:api|rest|graphql|v[1-9])\/[^'"`\s]{1,200})['"`]""", re.IGNORECASE),
    # Endpoint definitions:  endpoint: '/api/users'   url: '/api/data'
    re.compile(r"""(?:endpoint|baseURL|base_url|apiUrl|api_url)\s*[:=]\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
]

# Patterns to find route definitions in JS frameworks
JS_ROUTE_PATTERNS: List[re.Pattern] = [
    # Angular route:  { path: 'admin', component: AdminComponent }
    re.compile(r"""path\s*:\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    # React Router:  <Route path="/admin" ...>   path="/admin"
    re.compile(r"""<Route\s+[^>]*path\s*=\s*['"`{]([^'"`}]+)['"`}]""", re.IGNORECASE),
    re.compile(r"""path\s*:\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    # Vue Router:  { path: '/admin', component: Admin }
    re.compile(r"""path\s*:\s*['"`](\/[^'"`]*)['"`]""", re.IGNORECASE),
    # Next.js / Nuxt.js pages derive from file structure, but router.push calls:
    re.compile(r"""router\.push\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    re.compile(r"""navigate\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    # window.location or href assignments
    re.compile(r"""(?:window\.location|location\.href|location\.assign)\s*=\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    re.compile(r"""href\s*:\s*['"`](\/[^'"`]*)['"`]""", re.IGNORECASE),
]

# Resource extensions to ignore during crawling
IGNORED_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".webm",
    ".pdf", ".zip", ".gz", ".tar", ".rar",
    ".map",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class NetworkRequest:
    """A captured network request from browser interception."""
    timestamp: float
    method: str
    url: str
    resource_type: str  # xhr, fetch, document, script, stylesheet, etc.
    request_headers: Dict[str, str]
    request_body: Optional[str]
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    response_size: int = 0
    elapsed_ms: float = 0.0
    is_api_call: bool = False
    failed: bool = False
    failure_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "method": self.method,
            "url": self.url,
            "resource_type": self.resource_type,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status_code": self.status_code,
            "response_headers": self.response_headers,
            "response_body_length": len(self.response_body) if self.response_body else 0,
            "response_size": self.response_size,
            "elapsed_ms": self.elapsed_ms,
            "is_api_call": self.is_api_call,
            "failed": self.failed,
            "failure_reason": self.failure_reason,
        }

    def to_full_dict(self) -> Dict[str, Any]:
        """Include response body — use for detailed export."""
        d = self.to_dict()
        d["response_body"] = self.response_body
        return d


@dataclass
class DiscoveredEndpoint:
    """An endpoint discovered through JS analysis or network interception."""
    url: str
    method: str = "GET"
    source: str = ""  # "network_intercept", "js_analysis", "route_definition", "html_link"
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    requires_auth: bool = False
    content_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "source": self.source,
            "parameters": self.parameters,
            "headers": self.headers,
            "body": self.body,
            "requires_auth": self.requires_auth,
            "content_type": self.content_type,
        }


@dataclass
class BrowserForm:
    """A form discovered in the rendered DOM."""
    action: str
    method: str
    fields: List[Dict[str, Any]] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"
    form_id: str = ""
    form_name: str = ""
    selector: str = ""  # CSS selector to locate this form
    has_password: bool = False
    has_file_upload: bool = False
    is_login_form: bool = False
    is_registration_form: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "fields": self.fields,
            "enctype": self.enctype,
            "form_id": self.form_id,
            "form_name": self.form_name,
            "selector": self.selector,
            "has_password": self.has_password,
            "has_file_upload": self.has_file_upload,
            "is_login_form": self.is_login_form,
            "is_registration_form": self.is_registration_form,
        }

    def get_field_names(self) -> List[str]:
        return [f.get("name", "") for f in self.fields if f.get("name")]


@dataclass
class PageData:
    """Complete data extracted from a page load."""
    url: str
    final_url: str  # after redirects
    status_code: int
    title: str
    rendered_html: str
    forms: List[BrowserForm]
    links: List[str]
    scripts: List[str]  # script src URLs
    meta_tags: Dict[str, str]
    cookies: List[Dict[str, Any]]
    local_storage: Dict[str, str]
    session_storage: Dict[str, str]
    network_requests: List[NetworkRequest]
    console_logs: List[str]
    technologies: List[str]
    load_time_ms: float
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "title": self.title,
            "rendered_html_length": len(self.rendered_html),
            "forms_count": len(self.forms),
            "links_count": len(self.links),
            "scripts_count": len(self.scripts),
            "meta_tags": self.meta_tags,
            "cookies_count": len(self.cookies),
            "local_storage_keys": list(self.local_storage.keys()),
            "session_storage_keys": list(self.session_storage.keys()),
            "network_requests_count": len(self.network_requests),
            "console_logs_count": len(self.console_logs),
            "technologies": self.technologies,
            "load_time_ms": self.load_time_ms,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# BrowserEngine
# ---------------------------------------------------------------------------

class BrowserEngine:
    """
    Headless browser engine for testing Single Page Applications.

    Uses Playwright's async API with Chromium to render JavaScript-heavy
    applications, intercept network requests, discover API endpoints,
    interact with forms, and capture evidence.

    Usage::

        engine = BrowserEngine(headless=True)
        await engine.start()

        page_data = await engine.navigate("https://target.com")
        endpoints = await engine.discover_endpoints("https://target.com")

        await engine.stop()

    Or as an async context manager::

        async with BrowserEngine() as engine:
            page_data = await engine.navigate("https://target.com")
    """

    def __init__(
        self,
        headless: bool = True,
        proxy: Optional[str] = None,
        timeout: int = 30000,
        disable_resources: bool = False,
        user_agent: Optional[str] = None,
        viewport_width: int = 1920,
        viewport_height: int = 1080,
        ignore_https_errors: bool = True,
    ) -> None:
        """
        Parameters
        ----------
        headless : bool
            Run browser without GUI. Default True.
        proxy : str, optional
            Proxy URL (e.g. ``http://127.0.0.1:8080`` for Burp Suite).
        timeout : int
            Default timeout for operations in milliseconds.
        disable_resources : bool
            Block images, CSS, fonts for faster loading.
        user_agent : str, optional
            Custom User-Agent string.
        viewport_width : int
            Browser viewport width.
        viewport_height : int
            Browser viewport height.
        ignore_https_errors : bool
            Accept self-signed / invalid SSL certificates.
        """
        self.headless: bool = headless
        self.proxy: Optional[str] = proxy
        self.timeout: int = timeout
        self.disable_resources: bool = disable_resources
        self.user_agent: Optional[str] = user_agent
        self.viewport_width: int = viewport_width
        self.viewport_height: int = viewport_height
        self.ignore_https_errors: bool = ignore_https_errors

        # Playwright objects (initialized in start())
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None

        # State tracking
        self._network_log: List[NetworkRequest] = []
        self._discovered_endpoints: List[DiscoveredEndpoint] = []
        self._discovered_endpoint_keys: Set[str] = set()  # for dedup: "METHOD|URL"
        self._console_logs: List[str] = []
        self._is_started: bool = False
        self._current_url: str = ""

        # Pending network requests for response matching
        self._pending_requests: Dict[str, Tuple[float, PWRequest]] = {}

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "BrowserEngine":
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.stop()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Launch the Playwright browser, create incognito context and page."""
        if self._is_started:
            return

        self._playwright = await async_playwright().start()

        # Browser launch arguments
        launch_args: List[str] = [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-background-timer-throttling",
        ]

        launch_kwargs: Dict[str, Any] = {
            "headless": self.headless,
            "args": launch_args,
        }

        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}

        self._browser = await self._playwright.chromium.launch(**launch_kwargs)

        # Create incognito context
        context_kwargs: Dict[str, Any] = {
            "viewport": {"width": self.viewport_width, "height": self.viewport_height},
            "ignore_https_errors": self.ignore_https_errors,
            "java_script_enabled": True,
            "accept_downloads": False,
        }

        if self.user_agent:
            context_kwargs["user_agent"] = self.user_agent
        else:
            context_kwargs["user_agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            )

        self._context = await self._browser.new_context(**context_kwargs)

        # Set default timeouts on the context
        self._context.set_default_timeout(self.timeout)
        self._context.set_default_navigation_timeout(self.timeout)

        # Create initial page
        self._page = await self._context.new_page()

        # Attach event listeners
        self._page.on("request", self._on_request)
        self._page.on("response", self._on_response)
        self._page.on("requestfailed", self._on_request_failed)
        self._page.on("console", self._on_console)

        # Block unnecessary resources if configured
        if self.disable_resources:
            await self._page.route(
                "**/*",
                self._route_handler_block_resources,
            )

        self._is_started = True

    async def stop(self) -> None:
        """Close browser and clean up Playwright resources."""
        if not self._is_started:
            return

        try:
            if self._page and not self._page.is_closed():
                await self._page.close()
        except Exception:
            pass

        try:
            if self._context:
                await self._context.close()
        except Exception:
            pass

        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass

        try:
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass

        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None
        self._is_started = False

    async def _ensure_started(self) -> None:
        """Start the engine if it hasn't been started yet."""
        if not self._is_started:
            await self.start()

    # ------------------------------------------------------------------
    # Event handlers (Playwright callbacks)
    # ------------------------------------------------------------------

    def _on_request(self, request: PWRequest) -> None:
        """Capture outgoing network requests."""
        request_id = id(request)
        self._pending_requests[str(request_id)] = (time.time(), request)

        resource_type = request.resource_type  # xhr, fetch, document, script, etc.

        # Determine if this is an API call
        url = request.url
        is_api = self._is_api_call(url, resource_type)

        # Try to get POST body
        post_data: Optional[str] = None
        try:
            post_data = request.post_data
        except Exception:
            pass

        net_req = NetworkRequest(
            timestamp=time.time(),
            method=request.method,
            url=url,
            resource_type=resource_type,
            request_headers=dict(request.headers) if request.headers else {},
            request_body=post_data,
            is_api_call=is_api,
        )
        self._network_log.append(net_req)

        # Auto-discover API endpoints
        if is_api:
            self._add_discovered_endpoint(
                url=url,
                method=request.method,
                source="network_intercept",
                headers=dict(request.headers) if request.headers else {},
                body=post_data,
                content_type=request.headers.get("content-type", "") if request.headers else "",
            )

    def _on_response(self, response: PWResponse) -> None:
        """Match response to its request and update the network log entry."""
        request = response.request
        request_id = str(id(request))
        start_time = time.time()

        if request_id in self._pending_requests:
            start_time, _ = self._pending_requests.pop(request_id)

        elapsed = (time.time() - start_time) * 1000

        # Find the matching NetworkRequest in our log (search from the end)
        for net_req in reversed(self._network_log):
            if net_req.url == response.url and net_req.status_code is None:
                net_req.status_code = response.status
                net_req.response_headers = dict(response.headers) if response.headers else {}
                net_req.elapsed_ms = elapsed

                # Try to capture response body for API calls (async capture later)
                # We mark it for body extraction; actual body read happens in navigate()
                break

    def _on_request_failed(self, request: PWRequest) -> None:
        """Handle failed requests (timeouts, network errors, blocked)."""
        request_id = str(id(request))
        self._pending_requests.pop(request_id, None)

        failure_text = ""
        try:
            failure_text = request.failure or "Unknown failure"
        except Exception:
            failure_text = "Unknown failure"

        for net_req in reversed(self._network_log):
            if net_req.url == request.url and net_req.status_code is None:
                net_req.failed = True
                net_req.failure_reason = str(failure_text)
                net_req.status_code = 0
                break

    def _on_console(self, msg: Any) -> None:
        """Capture browser console messages."""
        try:
            text = f"[{msg.type}] {msg.text}"
            self._console_logs.append(text)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Resource blocking route handler
    # ------------------------------------------------------------------

    async def _route_handler_block_resources(self, route: Route) -> None:
        """Block images, CSS, fonts for faster page loads."""
        resource_type = route.request.resource_type
        if resource_type in ("image", "stylesheet", "font", "media"):
            await route.abort()
        else:
            await route.continue_()

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    async def navigate(self, url: str, wait_for: str = "networkidle") -> PageData:
        """
        Navigate to a URL, wait for JS to render, and extract all page data.

        Parameters
        ----------
        url : str
            The URL to navigate to.
        wait_for : str
            Playwright wait condition: ``"load"``, ``"domcontentloaded"``,
            ``"networkidle"``, or ``"commit"``.

        Returns
        -------
        PageData
            Complete data extracted from the page.
        """
        await self._ensure_started()
        assert self._page is not None

        # Clear logs for this navigation
        pre_nav_log_len = len(self._network_log)
        pre_console_len = len(self._console_logs)

        start_time = time.time()
        status_code = 0
        error_msg: Optional[str] = None
        final_url = url

        try:
            response = await self._page.goto(url, wait_until=wait_for)
            if response:
                status_code = response.status
                final_url = response.url
            else:
                # Same-page navigation (SPA route change)
                final_url = self._page.url
                status_code = 200

            # Additional wait for dynamic content
            await self._wait_for_dynamic_content()

        except PlaywrightTimeoutError:
            error_msg = f"Navigation timed out after {self.timeout}ms"
            final_url = self._page.url if self._page else url
        except PlaywrightError as e:
            error_msg = f"Navigation error: {str(e)}"
            final_url = self._page.url if self._page else url
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            final_url = self._page.url if self._page else url

        load_time = (time.time() - start_time) * 1000
        self._current_url = final_url

        # Extract all page data
        rendered_html = await self._get_page_html()
        title = await self._get_title()
        forms = await self._extract_forms_from_dom()
        links = await self._extract_links_from_dom()
        scripts = await self._extract_script_sources()
        meta_tags = await self._extract_meta_tags()
        cookies = await self.get_cookies()
        local_storage = await self.get_local_storage()
        session_storage = await self.get_session_storage()
        technologies = await self._detect_technologies()

        # Capture response bodies for API calls
        nav_network = self._network_log[pre_nav_log_len:]
        await self._capture_api_response_bodies(nav_network)

        nav_console = self._console_logs[pre_console_len:]

        return PageData(
            url=url,
            final_url=final_url,
            status_code=status_code,
            title=title,
            rendered_html=rendered_html,
            forms=forms,
            links=links,
            scripts=scripts,
            meta_tags=meta_tags,
            cookies=cookies,
            local_storage=local_storage,
            session_storage=session_storage,
            network_requests=nav_network,
            console_logs=nav_console,
            technologies=technologies,
            load_time_ms=load_time,
            error=error_msg,
        )

    async def navigate_spa_route(self, route_path: str) -> PageData:
        """
        Navigate to an SPA route by modifying the browser URL hash/path.

        For SPAs that use client-side routing, a full page reload is not needed.
        This pushes a new history entry and waits for the view to update.
        """
        await self._ensure_started()
        assert self._page is not None

        base = urlparse(self._current_url)
        new_url = f"{base.scheme}://{base.netloc}{route_path}"

        # Use History API to navigate within the SPA
        await self._page.evaluate(f"window.history.pushState({{}}, '', '{route_path}')")
        # Dispatch popstate to trigger SPA router
        await self._page.evaluate("window.dispatchEvent(new PopStateEvent('popstate'))")

        # Wait for any dynamic rendering
        await self._wait_for_dynamic_content()

        return await self._build_current_page_data(new_url)

    async def _wait_for_dynamic_content(self) -> None:
        """Wait for dynamic JavaScript content to finish rendering."""
        assert self._page is not None

        try:
            # Wait for network to be idle (no requests for 500ms)
            await self._page.wait_for_load_state("networkidle", timeout=10000)
        except PlaywrightTimeoutError:
            pass  # Acceptable — some SPAs never fully idle

        # Additional settle time for JS frameworks
        try:
            await self._page.wait_for_timeout(500)
        except Exception:
            pass

        # Wait for Angular (if present)
        try:
            await self._page.evaluate("""
                () => {
                    return new Promise((resolve) => {
                        if (window.getAllAngularTestabilities) {
                            const testabilities = window.getAllAngularTestabilities();
                            if (testabilities.length > 0) {
                                testabilities[0].whenStable(resolve);
                                return;
                            }
                        }
                        resolve();
                    });
                }
            """)
        except Exception:
            pass

    async def _build_current_page_data(self, url: str) -> PageData:
        """Build PageData from the current page state without navigation."""
        assert self._page is not None

        rendered_html = await self._get_page_html()
        title = await self._get_title()
        forms = await self._extract_forms_from_dom()
        links = await self._extract_links_from_dom()
        scripts = await self._extract_script_sources()
        meta_tags = await self._extract_meta_tags()
        cookies = await self.get_cookies()
        local_storage = await self.get_local_storage()
        session_storage = await self.get_session_storage()
        technologies = await self._detect_technologies()

        return PageData(
            url=url,
            final_url=self._page.url,
            status_code=200,
            title=title,
            rendered_html=rendered_html,
            forms=forms,
            links=links,
            scripts=scripts,
            meta_tags=meta_tags,
            cookies=cookies,
            local_storage=local_storage,
            session_storage=session_storage,
            network_requests=[],
            console_logs=[],
            technologies=technologies,
            load_time_ms=0.0,
        )

    # ------------------------------------------------------------------
    # HTML / DOM extraction
    # ------------------------------------------------------------------

    async def get_rendered_html(self, url: str) -> str:
        """
        Navigate to *url* and return the fully rendered HTML after
        JavaScript execution.
        """
        page_data = await self.navigate(url)
        return page_data.rendered_html

    async def _get_page_html(self) -> str:
        """Get the current page's full rendered HTML."""
        assert self._page is not None
        try:
            html = await self._page.content()
            return html
        except Exception:
            return ""

    async def _get_title(self) -> str:
        """Get the current page title."""
        assert self._page is not None
        try:
            return await self._page.title()
        except Exception:
            return ""

    async def _extract_meta_tags(self) -> Dict[str, str]:
        """Extract all meta tags from the current page."""
        assert self._page is not None
        try:
            meta_tags = await self._page.evaluate("""
                () => {
                    const metas = {};
                    document.querySelectorAll('meta').forEach(meta => {
                        const name = meta.getAttribute('name') ||
                                     meta.getAttribute('property') ||
                                     meta.getAttribute('http-equiv') || '';
                        const content = meta.getAttribute('content') || '';
                        if (name && content) {
                            metas[name] = content;
                        }
                    });
                    return metas;
                }
            """)
            return meta_tags if isinstance(meta_tags, dict) else {}
        except Exception:
            return {}

    async def _extract_script_sources(self) -> List[str]:
        """Extract all script src URLs from the current page."""
        assert self._page is not None
        try:
            scripts = await self._page.evaluate("""
                () => {
                    return Array.from(document.querySelectorAll('script[src]'))
                        .map(s => s.src)
                        .filter(src => src.length > 0);
                }
            """)
            return scripts if isinstance(scripts, list) else []
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Form extraction and interaction
    # ------------------------------------------------------------------

    async def _extract_forms_from_dom(self) -> List[BrowserForm]:
        """
        Extract all forms from the rendered DOM, including dynamically
        created ones (React forms, Angular template-driven forms, etc.).
        """
        assert self._page is not None

        try:
            raw_forms = await self._page.evaluate("""
                () => {
                    const forms = [];
                    document.querySelectorAll('form').forEach((form, index) => {
                        const fields = [];

                        // Input elements
                        form.querySelectorAll('input, textarea, select').forEach(el => {
                            const field = {
                                name: el.name || el.id || '',
                                type: el.type || el.tagName.toLowerCase(),
                                value: el.value || '',
                                required: el.required || false,
                                placeholder: el.placeholder || '',
                                selector: el.name
                                    ? `[name="${el.name}"]`
                                    : el.id
                                        ? `#${el.id}`
                                        : `form:nth-of-type(${index + 1}) ${el.tagName.toLowerCase()}`,
                            };

                            // For select elements, grab options
                            if (el.tagName === 'SELECT') {
                                field.options = Array.from(el.options).map(o => ({
                                    value: o.value,
                                    text: o.text,
                                }));
                            }

                            fields.push(field);
                        });

                        forms.push({
                            action: form.action || window.location.href,
                            method: (form.method || 'GET').toUpperCase(),
                            enctype: form.enctype || 'application/x-www-form-urlencoded',
                            id: form.id || '',
                            name: form.name || '',
                            selector: form.id
                                ? `#${form.id}`
                                : form.name
                                    ? `form[name="${form.name}"]`
                                    : `form:nth-of-type(${index + 1})`,
                            fields: fields,
                        });
                    });
                    return forms;
                }
            """)

            forms: List[BrowserForm] = []
            for raw in (raw_forms or []):
                fields = raw.get("fields", [])
                has_password = any(f.get("type") == "password" for f in fields)
                has_file = any(f.get("type") == "file" for f in fields)
                field_names_lower = [f.get("name", "").lower() for f in fields]

                is_login = has_password and any(
                    n in field_names_lower for n in
                    ["username", "email", "user", "login", "user_id", "userid"]
                )
                is_registration = has_password and any(
                    n in field_names_lower for n in
                    ["confirm_password", "confirmpassword", "password2",
                     "password_confirmation", "re_password", "repassword"]
                )

                forms.append(BrowserForm(
                    action=raw.get("action", ""),
                    method=raw.get("method", "GET"),
                    fields=fields,
                    enctype=raw.get("enctype", "application/x-www-form-urlencoded"),
                    form_id=raw.get("id", ""),
                    form_name=raw.get("name", ""),
                    selector=raw.get("selector", ""),
                    has_password=has_password,
                    has_file_upload=has_file,
                    is_login_form=is_login,
                    is_registration_form=is_registration,
                ))

            return forms

        except Exception:
            return []

    async def fill_form(self, selector: str, data: Dict[str, str]) -> None:
        """
        Fill a form identified by *selector* with the provided data.

        Parameters
        ----------
        selector : str
            CSS selector for the ``<form>`` element.
        data : dict
            Mapping of field name → value to fill in.
        """
        await self._ensure_started()
        assert self._page is not None

        for field_name, value in data.items():
            try:
                # Try by name attribute within the form
                field_selector = f'{selector} [name="{field_name}"]'
                element = await self._page.query_selector(field_selector)

                if not element:
                    # Try by id
                    field_selector = f'{selector} #{field_name}'
                    element = await self._page.query_selector(field_selector)

                if not element:
                    # Try by placeholder
                    field_selector = f'{selector} [placeholder*="{field_name}" i]'
                    element = await self._page.query_selector(field_selector)

                if element:
                    tag = await element.evaluate("el => el.tagName.toLowerCase()")
                    input_type = await element.evaluate("el => (el.type || '').toLowerCase()")

                    if tag == "select":
                        await element.select_option(value)
                    elif input_type in ("checkbox", "radio"):
                        if value.lower() in ("true", "1", "yes", "on"):
                            await element.check()
                        else:
                            await element.uncheck()
                    elif input_type == "file":
                        await element.set_input_files(value)
                    else:
                        # Clear existing value first
                        await element.click()
                        await element.fill("")
                        await element.fill(value)

            except Exception:
                # Field not found or not fillable — skip silently
                continue

    async def submit_form(
        self,
        selector: str,
        data: Optional[Dict[str, str]] = None,
        click_submit: bool = True,
    ) -> PageData:
        """
        Fill and submit a form.

        Parameters
        ----------
        selector : str
            CSS selector for the ``<form>`` element.
        data : dict, optional
            Field values to fill before submission.
        click_submit : bool
            If True, click the submit button. If False, trigger form submit
            via JavaScript.

        Returns
        -------
        PageData
            Page data after form submission.
        """
        await self._ensure_started()
        assert self._page is not None

        if data:
            await self.fill_form(selector, data)

        pre_nav_log_len = len(self._network_log)
        start_time = time.time()

        if click_submit:
            # Find and click the submit button
            submit_btn = await self._page.query_selector(
                f'{selector} [type="submit"], '
                f'{selector} button[type="submit"], '
                f'{selector} input[type="submit"], '
                f'{selector} button:not([type])'
            )
            if submit_btn:
                try:
                    async with self._page.expect_navigation(
                        timeout=self.timeout, wait_until="networkidle"
                    ):
                        await submit_btn.click()
                except PlaywrightTimeoutError:
                    # SPA form — may not trigger navigation
                    await self._wait_for_dynamic_content()
                except Exception:
                    await self._wait_for_dynamic_content()
            else:
                # No submit button found, submit via JS
                await self._page.evaluate(
                    f'document.querySelector(\'{selector}\').submit()'
                )
                await self._wait_for_dynamic_content()
        else:
            await self._page.evaluate(
                f'document.querySelector(\'{selector}\').submit()'
            )
            await self._wait_for_dynamic_content()

        load_time = (time.time() - start_time) * 1000

        # Build page data from current state
        page_data = await self._build_current_page_data(self._page.url)
        page_data.network_requests = self._network_log[pre_nav_log_len:]
        page_data.load_time_ms = load_time

        return page_data

    # ------------------------------------------------------------------
    # Link extraction
    # ------------------------------------------------------------------

    async def _extract_links_from_dom(self) -> List[str]:
        """Extract all link URLs from the rendered DOM."""
        assert self._page is not None

        try:
            links = await self._page.evaluate("""
                () => {
                    const links = new Set();

                    // <a href>
                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.href;
                        if (href && !href.startsWith('javascript:') &&
                            !href.startsWith('mailto:') && !href.startsWith('tel:') &&
                            !href.startsWith('#') && !href.startsWith('data:')) {
                            links.add(href);
                        }
                    });

                    // <form action>
                    document.querySelectorAll('form[action]').forEach(f => {
                        if (f.action) links.add(f.action);
                    });

                    // <iframe src>
                    document.querySelectorAll('iframe[src]').forEach(i => {
                        if (i.src) links.add(i.src);
                    });

                    // <area href> (image maps)
                    document.querySelectorAll('area[href]').forEach(a => {
                        if (a.href) links.add(a.href);
                    });

                    return Array.from(links);
                }
            """)
            return links if isinstance(links, list) else []
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Endpoint discovery
    # ------------------------------------------------------------------

    async def discover_endpoints(
        self,
        base_url: str,
        crawl_depth: int = 2,
        max_pages: int = 50,
        click_navigation: bool = True,
    ) -> List[DiscoveredEndpoint]:
        """
        Comprehensive endpoint discovery:

        1. Navigate to base_url and intercept all network requests
        2. Extract API endpoints from JavaScript source files
        3. Extract route definitions from JS frameworks
        4. Crawl internal links up to *crawl_depth*
        5. Optionally click navigation elements to trigger SPA routes

        Parameters
        ----------
        base_url : str
            The application's base URL.
        crawl_depth : int
            Maximum link-following depth.
        max_pages : int
            Maximum number of pages to visit.
        click_navigation : bool
            Whether to click nav links/buttons to discover SPA routes.

        Returns
        -------
        list[DiscoveredEndpoint]
            All discovered endpoints.
        """
        await self._ensure_started()

        visited: Set[str] = set()
        to_visit: List[Tuple[str, int]] = [(base_url, 0)]  # (url, depth)
        base_domain = urlparse(base_url).netloc

        while to_visit and len(visited) < max_pages:
            url, depth = to_visit.pop(0)

            # Normalize and dedup
            normalized = self._normalize_url(url)
            if normalized in visited:
                continue
            if urlparse(normalized).netloc != base_domain:
                continue
            if self._is_resource_url(normalized):
                continue

            visited.add(normalized)

            # Navigate and capture
            page_data = await self.navigate(url)

            # Extract endpoints from page links
            for link in page_data.links:
                link_normalized = self._normalize_url(link)
                if link_normalized not in visited and depth < crawl_depth:
                    if urlparse(link_normalized).netloc == base_domain:
                        if not self._is_resource_url(link_normalized):
                            to_visit.append((link, depth + 1))

                self._add_discovered_endpoint(
                    url=link,
                    method="GET",
                    source="html_link",
                )

            # Extract from JS files
            for script_url in page_data.scripts:
                if urlparse(script_url).netloc == base_domain or not urlparse(script_url).netloc:
                    await self._extract_endpoints_from_js_url(script_url, base_url)

            # Extract from inline scripts
            await self._extract_endpoints_from_inline_scripts(base_url)

            # Click navigation elements (for SPAs)
            if click_navigation and depth == 0:
                await self._click_navigation_elements(base_url)

        return list(self._discovered_endpoints)

    async def extract_js_routes(self, url: str) -> List[Dict[str, str]]:
        """
        Navigate to *url* and extract route definitions from JavaScript.

        Handles:
        - Angular: ``{ path: 'admin', component: ... }``
        - React Router: ``<Route path="/admin" />``
        - Vue Router: ``{ path: '/admin', component: ... }``
        - Generic route/path patterns

        Returns a list of ``{"path": ..., "source": ...}`` dicts.
        """
        await self._ensure_started()

        page_data = await self.navigate(url)
        routes: List[Dict[str, str]] = []
        seen_paths: Set[str] = set()

        base_domain = urlparse(url).netloc

        # Extract from external JS files
        for script_url in page_data.scripts:
            if urlparse(script_url).netloc == base_domain or not urlparse(script_url).netloc:
                js_routes = await self._extract_routes_from_js_url(script_url)
                for route in js_routes:
                    if route["path"] not in seen_paths:
                        seen_paths.add(route["path"])
                        routes.append(route)

        # Extract from inline scripts
        inline_routes = await self._extract_routes_from_inline_scripts()
        for route in inline_routes:
            if route["path"] not in seen_paths:
                seen_paths.add(route["path"])
                routes.append(route)

        return routes

    async def _extract_endpoints_from_js_url(self, js_url: str, base_url: str) -> None:
        """Fetch a JavaScript file and extract API endpoint references."""
        assert self._page is not None

        try:
            # Fetch the JS file content via the browser
            js_content = await self._page.evaluate("""
                async (url) => {
                    try {
                        const resp = await fetch(url);
                        return await resp.text();
                    } catch (e) {
                        return '';
                    }
                }
            """, js_url)

            if not js_content:
                return

            self._extract_endpoints_from_js_text(js_content, base_url, source_file=js_url)

        except Exception:
            pass

    async def _extract_endpoints_from_inline_scripts(self, base_url: str) -> None:
        """Extract API endpoint references from inline <script> blocks."""
        assert self._page is not None

        try:
            inline_scripts = await self._page.evaluate("""
                () => {
                    return Array.from(document.querySelectorAll('script:not([src])'))
                        .map(s => s.textContent || s.innerText || '')
                        .filter(t => t.length > 0);
                }
            """)

            for script_text in (inline_scripts or []):
                self._extract_endpoints_from_js_text(script_text, base_url, source_file="inline")

        except Exception:
            pass

    def _extract_endpoints_from_js_text(
        self, js_text: str, base_url: str, source_file: str = ""
    ) -> None:
        """Parse JavaScript text to find API endpoint references."""
        if not js_text or len(js_text) < 10:
            return

        for pattern in JS_API_ENDPOINT_PATTERNS:
            for match in pattern.finditer(js_text):
                endpoint_path = match.group(1).strip()

                # Filter junk
                if not endpoint_path or len(endpoint_path) < 2:
                    continue
                if endpoint_path.startswith(("{{", "{%", "${")):
                    continue
                if any(c in endpoint_path for c in ["*", "\\", "\n", "\t"]):
                    continue
                # Must start with / or http
                if not (endpoint_path.startswith("/") or endpoint_path.startswith("http")):
                    continue

                # Resolve relative URLs
                if endpoint_path.startswith("/"):
                    full_url = urljoin(base_url, endpoint_path)
                else:
                    full_url = endpoint_path

                # Determine method from context
                context_start = max(0, match.start() - 50)
                context = js_text[context_start:match.start()].lower()
                method = "GET"
                if "post" in context or ".post" in context:
                    method = "POST"
                elif "put" in context or ".put" in context:
                    method = "PUT"
                elif "delete" in context or ".delete" in context:
                    method = "DELETE"
                elif "patch" in context or ".patch" in context:
                    method = "PATCH"

                self._add_discovered_endpoint(
                    url=full_url,
                    method=method,
                    source=f"js_analysis:{source_file}",
                )

    async def _extract_routes_from_js_url(self, js_url: str) -> List[Dict[str, str]]:
        """Fetch a JS file and extract route definitions."""
        assert self._page is not None
        routes: List[Dict[str, str]] = []

        try:
            js_content = await self._page.evaluate("""
                async (url) => {
                    try {
                        const resp = await fetch(url);
                        return await resp.text();
                    } catch (e) {
                        return '';
                    }
                }
            """, js_url)

            if js_content:
                routes = self._extract_routes_from_js_text(js_content, source_file=js_url)

        except Exception:
            pass

        return routes

    async def _extract_routes_from_inline_scripts(self) -> List[Dict[str, str]]:
        """Extract route definitions from inline scripts."""
        assert self._page is not None
        routes: List[Dict[str, str]] = []

        try:
            inline_scripts = await self._page.evaluate("""
                () => {
                    return Array.from(document.querySelectorAll('script:not([src])'))
                        .map(s => s.textContent || s.innerText || '')
                        .filter(t => t.length > 0);
                }
            """)

            for script_text in (inline_scripts or []):
                routes.extend(
                    self._extract_routes_from_js_text(script_text, source_file="inline")
                )

        except Exception:
            pass

        return routes

    def _extract_routes_from_js_text(
        self, js_text: str, source_file: str = ""
    ) -> List[Dict[str, str]]:
        """Parse JavaScript text to find route definitions."""
        routes: List[Dict[str, str]] = []
        seen: Set[str] = set()

        for pattern in JS_ROUTE_PATTERNS:
            for match in pattern.finditer(js_text):
                path = match.group(1).strip()

                # Filter junk
                if not path or len(path) < 1:
                    continue
                if path in seen:
                    continue
                if path.startswith(("{{", "{%", "${")):
                    continue
                # Must look like a route path
                if any(c in path for c in ["\\", "\n", "\t", ";"]):
                    continue
                # Ignore very long paths (likely not routes)
                if len(path) > 200:
                    continue
                # Ensure it starts with / or is a relative path word
                if not path.startswith("/"):
                    path = "/" + path

                seen.add(path)
                routes.append({
                    "path": path,
                    "source": f"route_definition:{source_file}",
                })

        return routes

    async def _click_navigation_elements(self, base_url: str) -> None:
        """
        Click navigation links and buttons to discover SPA routes.

        Targets ``<nav>``, ``<a>`` elements in menus, sidebar links, etc.
        """
        assert self._page is not None

        selectors_to_try = [
            "nav a",
            "header a",
            ".sidebar a",
            ".menu a",
            ".nav a",
            "[role='navigation'] a",
            ".navbar a",
            "a[routerlink]",        # Angular
            "a[href^='/']",         # Internal links
        ]

        clicked_urls: Set[str] = set()

        for selector in selectors_to_try:
            try:
                elements = await self._page.query_selector_all(selector)
                for element in elements[:20]:  # Limit clicks per selector
                    try:
                        href = await element.get_attribute("href")
                        router_link = await element.get_attribute("routerlink")
                        target_url = href or router_link or ""

                        if target_url in clicked_urls:
                            continue
                        if target_url.startswith(("javascript:", "mailto:", "tel:", "#")):
                            continue

                        clicked_urls.add(target_url)

                        # Click and wait briefly
                        try:
                            await element.click(timeout=3000)
                            await self._page.wait_for_timeout(1000)
                        except Exception:
                            pass

                        # Record current URL as a discovered route
                        current = self._page.url
                        self._add_discovered_endpoint(
                            url=current,
                            method="GET",
                            source="navigation_click",
                        )

                        # Navigate back to continue clicking
                        try:
                            await self._page.go_back(timeout=5000)
                            await self._page.wait_for_timeout(500)
                        except Exception:
                            # If back fails, re-navigate
                            await self._page.goto(base_url, wait_until="networkidle")
                            await self._page.wait_for_timeout(500)

                    except Exception:
                        continue
            except Exception:
                continue

    # ------------------------------------------------------------------
    # Network interception & API call capture
    # ------------------------------------------------------------------

    def get_network_log(self) -> List[NetworkRequest]:
        """Return all intercepted network requests."""
        return list(self._network_log)

    def get_api_calls(self) -> List[NetworkRequest]:
        """Return only API calls (XHR, fetch, not static resources)."""
        return [r for r in self._network_log if r.is_api_call]

    async def intercept_api_calls(
        self,
        base_url: str,
        duration: int = 30,
        interact: bool = True,
    ) -> List[NetworkRequest]:
        """
        Navigate to *base_url* and record all API calls for *duration* seconds.

        Parameters
        ----------
        base_url : str
            The URL to navigate to.
        duration : int
            How long to monitor in seconds.
        interact : bool
            If True, attempt to click interactive elements to trigger
            additional API calls.

        Returns
        -------
        list[NetworkRequest]
            All API calls captured during the monitoring period.
        """
        await self._ensure_started()

        pre_log_len = len(self._network_log)

        # Navigate
        await self.navigate(base_url)

        if interact:
            # Click buttons and interactive elements to trigger API calls
            await self._trigger_interactions()

        # Wait for the specified duration
        end_time = time.time() + duration

        while time.time() < end_time:
            await asyncio.sleep(1)

            # Periodically interact to keep discovering API calls
            if interact and int(time.time()) % 10 == 0:
                await self._trigger_interactions()

        # Return only API calls from this monitoring session
        all_new = self._network_log[pre_log_len:]
        return [r for r in all_new if r.is_api_call]

    async def _trigger_interactions(self) -> None:
        """Click buttons and interactive elements to trigger API calls."""
        assert self._page is not None

        interactive_selectors = [
            "button:not([type='submit'])",
            "[role='button']",
            "[onclick]",
            ".btn",
            "[data-toggle]",
            "[data-action]",
        ]

        for selector in interactive_selectors:
            try:
                elements = await self._page.query_selector_all(selector)
                for element in elements[:5]:  # Limit per selector
                    try:
                        await element.click(timeout=2000)
                        await self._page.wait_for_timeout(500)
                    except Exception:
                        continue
            except Exception:
                continue

    async def _capture_api_response_bodies(
        self, requests: List[NetworkRequest]
    ) -> None:
        """
        Attempt to re-fetch API responses to capture their bodies.

        Note: Playwright's response.body() must be called during the
        response event.  For requests already completed, we do a best-effort
        re-fetch via page.evaluate for XHR/fetch calls.
        """
        assert self._page is not None

        for req in requests:
            if not req.is_api_call or req.response_body is not None:
                continue
            if req.failed or req.method != "GET":
                continue

            try:
                body = await self._page.evaluate("""
                    async (url) => {
                        try {
                            const resp = await fetch(url, { credentials: 'include' });
                            const text = await resp.text();
                            return text.substring(0, 50000);  // Cap at 50KB
                        } catch (e) {
                            return null;
                        }
                    }
                """, req.url)

                if body is not None:
                    req.response_body = body
                    req.response_size = len(body)

            except Exception:
                continue

    # ------------------------------------------------------------------
    # JavaScript execution
    # ------------------------------------------------------------------

    async def execute_js(self, script: str) -> Any:
        """
        Execute arbitrary JavaScript in the page context and return the result.

        Parameters
        ----------
        script : str
            JavaScript code to execute. Use ``return`` for a value.

        Returns
        -------
        Any
            The return value of the script, JSON-serializable.
        """
        await self._ensure_started()
        assert self._page is not None

        try:
            result = await self._page.evaluate(script)
            return result
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Storage access
    # ------------------------------------------------------------------

    async def get_local_storage(self) -> Dict[str, str]:
        """Read all key-value pairs from localStorage."""
        assert self._page is not None

        try:
            storage = await self._page.evaluate("""
                () => {
                    const items = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        items[key] = localStorage.getItem(key);
                    }
                    return items;
                }
            """)
            return storage if isinstance(storage, dict) else {}
        except Exception:
            return {}

    async def get_session_storage(self) -> Dict[str, str]:
        """Read all key-value pairs from sessionStorage."""
        assert self._page is not None

        try:
            storage = await self._page.evaluate("""
                () => {
                    const items = {};
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        items[key] = sessionStorage.getItem(key);
                    }
                    return items;
                }
            """)
            return storage if isinstance(storage, dict) else {}
        except Exception:
            return {}

    async def set_local_storage(self, data: Dict[str, str]) -> None:
        """Set key-value pairs in localStorage."""
        assert self._page is not None

        for key, value in data.items():
            try:
                await self._page.evaluate(
                    "(args) => localStorage.setItem(args.key, args.value)",
                    {"key": key, "value": value},
                )
            except Exception:
                continue

    async def set_session_storage(self, data: Dict[str, str]) -> None:
        """Set key-value pairs in sessionStorage."""
        assert self._page is not None

        for key, value in data.items():
            try:
                await self._page.evaluate(
                    "(args) => sessionStorage.setItem(args.key, args.value)",
                    {"key": key, "value": value},
                )
            except Exception:
                continue

    # ------------------------------------------------------------------
    # Cookie management
    # ------------------------------------------------------------------

    async def get_cookies(self) -> List[Dict[str, Any]]:
        """Get all cookies from the browser context."""
        assert self._context is not None

        try:
            cookies = await self._context.cookies()
            return [
                {
                    "name": c.get("name", ""),
                    "value": c.get("value", ""),
                    "domain": c.get("domain", ""),
                    "path": c.get("path", ""),
                    "expires": c.get("expires", -1),
                    "httpOnly": c.get("httpOnly", False),
                    "secure": c.get("secure", False),
                    "sameSite": c.get("sameSite", "None"),
                }
                for c in cookies
            ]
        except Exception:
            return []

    async def set_cookies(self, cookies: List[Dict[str, Any]]) -> None:
        """
        Set cookies in the browser context.

        Each cookie dict should have at minimum ``name``, ``value``, ``url``
        (or ``domain`` + ``path``).
        """
        assert self._context is not None

        try:
            await self._context.add_cookies(cookies)
        except Exception:
            pass

    async def clear_cookies(self) -> None:
        """Clear all cookies from the browser context."""
        assert self._context is not None

        try:
            await self._context.clear_cookies()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Screenshot
    # ------------------------------------------------------------------

    async def screenshot(self, path: str, full_page: bool = True) -> str:
        """
        Take a screenshot of the current page.

        Parameters
        ----------
        path : str
            File path to save the screenshot (e.g. ``evidence/vuln_001.png``).
        full_page : bool
            Capture the entire scrollable page or just the viewport.

        Returns
        -------
        str
            The file path where the screenshot was saved.
        """
        await self._ensure_started()
        assert self._page is not None

        try:
            await self._page.screenshot(path=path, full_page=full_page)
            return path
        except Exception as e:
            return f"Screenshot failed: {str(e)}"

    async def screenshot_element(self, selector: str, path: str) -> str:
        """Take a screenshot of a specific element."""
        await self._ensure_started()
        assert self._page is not None

        try:
            element = await self._page.query_selector(selector)
            if element:
                await element.screenshot(path=path)
                return path
            return f"Element not found: {selector}"
        except Exception as e:
            return f"Screenshot failed: {str(e)}"

    # ------------------------------------------------------------------
    # Element interaction
    # ------------------------------------------------------------------

    async def click(self, selector: str, timeout: int = 5000) -> bool:
        """
        Click an element identified by CSS selector.

        Returns True if the click succeeded, False otherwise.
        """
        await self._ensure_started()
        assert self._page is not None

        try:
            await self._page.click(selector, timeout=timeout)
            return True
        except Exception:
            return False

    async def type_text(self, selector: str, text: str, delay: int = 50) -> bool:
        """Type text into an input field character by character."""
        await self._ensure_started()
        assert self._page is not None

        try:
            await self._page.type(selector, text, delay=delay)
            return True
        except Exception:
            return False

    async def wait_for_selector(
        self, selector: str, timeout: int = 10000, state: str = "visible"
    ) -> bool:
        """Wait for an element to appear in the DOM."""
        await self._ensure_started()
        assert self._page is not None

        try:
            await self._page.wait_for_selector(selector, timeout=timeout, state=state)
            return True
        except PlaywrightTimeoutError:
            return False
        except Exception:
            return False

    async def get_element_text(self, selector: str) -> Optional[str]:
        """Get the text content of an element."""
        await self._ensure_started()
        assert self._page is not None

        try:
            element = await self._page.query_selector(selector)
            if element:
                return await element.text_content()
            return None
        except Exception:
            return None

    async def get_element_attribute(self, selector: str, attribute: str) -> Optional[str]:
        """Get an attribute value of an element."""
        await self._ensure_started()
        assert self._page is not None

        try:
            element = await self._page.query_selector(selector)
            if element:
                return await element.get_attribute(attribute)
            return None
        except Exception:
            return None

    async def element_exists(self, selector: str) -> bool:
        """Check if an element exists in the DOM."""
        await self._ensure_started()
        assert self._page is not None

        try:
            element = await self._page.query_selector(selector)
            return element is not None
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Technology detection
    # ------------------------------------------------------------------

    async def _detect_technologies(self) -> List[str]:
        """Detect frontend frameworks and technologies from the rendered page."""
        assert self._page is not None

        technologies: List[str] = []

        try:
            detected = await self._page.evaluate("""
                () => {
                    const techs = [];

                    // Angular
                    if (window.ng || document.querySelector('[ng-app]') ||
                        document.querySelector('[ng-controller]') ||
                        window.getAllAngularTestabilities) {
                        techs.push('Angular');
                    }

                    // React
                    if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
                        document.querySelector('[data-reactroot]') ||
                        document.querySelector('[data-reactid]')) {
                        techs.push('React');
                    }

                    // Vue.js
                    if (window.__VUE__ || window.Vue ||
                        document.querySelector('[data-v-]') ||
                        document.querySelector('#app.__vue__')) {
                        techs.push('Vue.js');
                    }

                    // Next.js
                    if (window.__NEXT_DATA__ || document.querySelector('#__next')) {
                        techs.push('Next.js');
                    }

                    // Nuxt.js
                    if (window.__NUXT__ || window.$nuxt) {
                        techs.push('Nuxt.js');
                    }

                    // jQuery
                    if (window.jQuery || window.$) {
                        techs.push('jQuery');
                    }

                    // Bootstrap
                    if (document.querySelector('.container') &&
                        document.querySelector('[class*="col-"]')) {
                        techs.push('Bootstrap (possible)');
                    }

                    // Svelte
                    if (document.querySelector('[class*="svelte-"]')) {
                        techs.push('Svelte');
                    }

                    // Ember
                    if (window.Ember || window.Em) {
                        techs.push('Ember.js');
                    }

                    // Backbone
                    if (window.Backbone) {
                        techs.push('Backbone.js');
                    }

                    // Webpack
                    if (window.webpackJsonp || window.__webpack_require__) {
                        techs.push('Webpack');
                    }

                    // Service Worker
                    if (navigator.serviceWorker &&
                        navigator.serviceWorker.controller) {
                        techs.push('Service Worker');
                    }

                    // WebSocket usage
                    if (window.WebSocket) {
                        techs.push('WebSocket capable');
                    }

                    return techs;
                }
            """)

            if isinstance(detected, list):
                technologies.extend(detected)

        except Exception:
            pass

        return technologies

    # ------------------------------------------------------------------
    # Context / state management
    # ------------------------------------------------------------------

    async def new_page(self) -> None:
        """
        Create a fresh page (tab) within the same context.

        The old page is closed. Cookies and context state persist.
        """
        assert self._context is not None

        if self._page and not self._page.is_closed():
            self._page.remove_listener("request", self._on_request)
            self._page.remove_listener("response", self._on_response)
            self._page.remove_listener("requestfailed", self._on_request_failed)
            self._page.remove_listener("console", self._on_console)
            await self._page.close()

        self._page = await self._context.new_page()
        self._page.on("request", self._on_request)
        self._page.on("response", self._on_response)
        self._page.on("requestfailed", self._on_request_failed)
        self._page.on("console", self._on_console)

        if self.disable_resources:
            await self._page.route("**/*", self._route_handler_block_resources)

    async def new_context(self) -> None:
        """
        Create a completely fresh browser context (like a new incognito window).

        Clears ALL state: cookies, localStorage, sessionStorage.
        """
        assert self._browser is not None

        # Close current page and context
        if self._page and not self._page.is_closed():
            await self._page.close()
        if self._context:
            await self._context.close()

        context_kwargs: Dict[str, Any] = {
            "viewport": {"width": self.viewport_width, "height": self.viewport_height},
            "ignore_https_errors": self.ignore_https_errors,
            "java_script_enabled": True,
            "accept_downloads": False,
        }

        if self.user_agent:
            context_kwargs["user_agent"] = self.user_agent
        else:
            context_kwargs["user_agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            )

        self._context = await self._browser.new_context(**context_kwargs)
        self._context.set_default_timeout(self.timeout)
        self._context.set_default_navigation_timeout(self.timeout)

        self._page = await self._context.new_page()
        self._page.on("request", self._on_request)
        self._page.on("response", self._on_response)
        self._page.on("requestfailed", self._on_request_failed)
        self._page.on("console", self._on_console)

        if self.disable_resources:
            await self._page.route("**/*", self._route_handler_block_resources)

    # ------------------------------------------------------------------
    # Cleanup and export
    # ------------------------------------------------------------------

    def clear_network_log(self) -> None:
        """Clear the network request log."""
        self._network_log.clear()
        self._pending_requests.clear()

    def clear_console_logs(self) -> None:
        """Clear captured console logs."""
        self._console_logs.clear()

    def clear_discovered_endpoints(self) -> None:
        """Clear all discovered endpoints."""
        self._discovered_endpoints.clear()
        self._discovered_endpoint_keys.clear()

    def get_discovered_endpoints(self) -> List[DiscoveredEndpoint]:
        """Return all discovered endpoints."""
        return list(self._discovered_endpoints)

    def get_console_logs(self) -> List[str]:
        """Return all captured console log messages."""
        return list(self._console_logs)

    def export_network_log(self, include_bodies: bool = False) -> List[Dict[str, Any]]:
        """Export the network log for reporting."""
        if include_bodies:
            return [r.to_full_dict() for r in self._network_log]
        return [r.to_dict() for r in self._network_log]

    def export_endpoints(self) -> List[Dict[str, Any]]:
        """Export discovered endpoints for reporting."""
        return [ep.to_dict() for ep in self._discovered_endpoints]

    def get_metrics(self) -> Dict[str, Any]:
        """Return aggregate browser engine metrics."""
        api_calls = self.get_api_calls()
        return {
            "total_network_requests": len(self._network_log),
            "api_calls": len(api_calls),
            "discovered_endpoints": len(self._discovered_endpoints),
            "console_logs": len(self._console_logs),
            "failed_requests": sum(1 for r in self._network_log if r.failed),
            "unique_domains": len(set(
                urlparse(r.url).netloc for r in self._network_log if r.url
            )),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_api_call(self, url: str, resource_type: str) -> bool:
        """Determine whether a network request is an API call."""
        # By resource type
        if resource_type in ("xhr", "fetch"):
            return True

        # By URL pattern
        url_lower = url.lower()
        api_patterns = ["/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/",
                        "/ajax/", "/json/", "/rpc/"]
        if any(p in url_lower for p in api_patterns):
            return True

        # By URL ending
        if url_lower.endswith((".json", ".xml")):
            return True

        return False

    def _is_resource_url(self, url: str) -> bool:
        """Check if a URL points to a static resource (image, CSS, etc.)."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in IGNORED_EXTENSIONS)

    def _normalize_url(self, url: str) -> str:
        """Normalize a URL for deduplication (strip fragment, trailing slash)."""
        parsed = urlparse(url)
        # Remove fragment
        normalized = parsed._replace(fragment="")
        result = normalized.geturl()
        # Remove trailing slash (except for root)
        if result.endswith("/") and parsed.path != "/":
            result = result[:-1]
        return result

    def _add_discovered_endpoint(
        self,
        url: str,
        method: str = "GET",
        source: str = "",
        parameters: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        content_type: str = "",
    ) -> None:
        """Add an endpoint to the discovered list (with deduplication)."""
        key = f"{method.upper()}|{self._normalize_url(url)}"
        if key in self._discovered_endpoint_keys:
            return

        # Filter out obviously non-useful URLs
        if not url or len(url) < 5:
            return
        if url.startswith(("data:", "blob:", "javascript:", "chrome:")):
            return
        if self._is_resource_url(url):
            return

        self._discovered_endpoint_keys.add(key)

        # Check if endpoint likely requires auth
        requires_auth = False
        url_lower = url.lower()
        auth_paths = ["/admin", "/dashboard", "/profile", "/account",
                      "/settings", "/user", "/manage", "/private"]
        if any(p in url_lower for p in auth_paths):
            requires_auth = True

        self._discovered_endpoints.append(DiscoveredEndpoint(
            url=url,
            method=method.upper(),
            source=source,
            parameters=parameters or {},
            headers=headers or {},
            body=body,
            requires_auth=requires_auth,
            content_type=content_type,
        ))

    # ------------------------------------------------------------------
    # repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<BrowserEngine headless={self.headless} "
            f"started={self._is_started} "
            f"requests={len(self._network_log)} "
            f"endpoints={len(self._discovered_endpoints)}>"
        )