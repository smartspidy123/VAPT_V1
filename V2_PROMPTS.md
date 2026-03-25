# VAPT-AI V2.0 - Roo Code Prompts
# =================================
# Use these prompts IN ORDER with Roo Code
# Each prompt builds one module
# Wait for each module to complete before next

# =============================================
# PHASE 0: SETUP (Do this first manually)
# =============================================

# Run these commands in terminal:
# pip install playwright httpx beautifulsoup4 lxml pyjwt
# playwright install chromium
# mkdir -p ~/vapt-ai/attacks

# =============================================
# PHASE 1: SMART HTTP CLIENT
# File: core/http_client.py
# =============================================


PROMPT 1 - Smart HTTP Client:

I am building VAPT-AI, a Python-based autonomous penetration testing tool.
I need you to create `core/http_client.py` - a smart HTTP client for security testing.

REQUIREMENTS:
1. Use httpx library (async support)
2. Session management with cookie persistence
3. Automatic token/JWT handling (store from login responses, add to subsequent requests)
4. Support all HTTP methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
5. Request/Response logging (store every request-response pair)
6. Configurable headers (User-Agent rotation, custom headers)
7. Proxy support (for Burp Suite integration)
8. Rate limiting (configurable requests per second)
9. Redirect following with control
10. Response analysis helpers:
    - Extract forms from HTML
    - Extract links from HTML
    - Extract JSON data
    - Detect error pages
    - Detect authentication state
    - Check response for common vulnerability indicators

CLASS DESIGN:
```python
class SmartHTTPClient:
    def __init__(self, base_url, proxy=None, rate_limit=10):
        # httpx.AsyncClient with cookie persistence
        # Request history storage
        # Token storage (JWT, session cookies)
    
    async def request(self, method, url, **kwargs) -> SmartResponse:
        # Make request with rate limiting
        # Auto-add authentication headers
        # Log request-response
        # Return SmartResponse object
    
    async def get(self, url, **kwargs) -> SmartResponse
    async def post(self, url, data=None, json=None, **kwargs) -> SmartResponse
    async def put(self, url, **kwargs) -> SmartResponse
    async def delete(self, url, **kwargs) -> SmartResponse
    
    def set_auth_token(self, token, token_type="Bearer"):
        # Store JWT/Bearer token for subsequent requests
    
    def set_cookies(self, cookies: dict):
        # Set session cookies
    
    def get_request_history(self) -> list:
        # Return all request-response pairs
    
    async def submit_form(self, url, form_data: dict) -> SmartResponse:
        # Submit HTML form with proper encoding

class SmartResponse:
    # Wraps httpx.Response with extra analysis
    status_code: int
    headers: dict
    body: str
    json_data: dict  # Parsed JSON if applicable
    forms: list      # Extracted HTML forms
    links: list      # Extracted links
    cookies: dict    # Response cookies
    
    def has_error_indicators(self) -> bool
    def has_sqli_indicators(self) -> bool
    def has_xss_reflection(self, payload) -> bool
    def extract_jwt_from_response(self) -> str
    def extract_csrf_token(self) -> str


IMPORTANT:

All methods must be async
Cookie jar must persist across requests (session-based)
Must handle SSL errors gracefully (verify=False option)
Must track total requests made and bytes transferred
Include a method to export all request/response history for reporting
Do NOT use curl subprocess. Use httpx library directly.
Write clean, well-documented Python code with type hints.




---

### PROMPT 2 - Browser Engine:

I am building VAPT-AI, a Python-based autonomous penetration testing tool.
I need you to create core/browser_engine.py - a headless browser engine using Playwright.

This is for testing Single Page Applications (Angular, React, Vue).

REQUIREMENTS:

Use Playwright (async API) with Chromium
Navigate to URLs and wait for JavaScript to fully render
Extract the FULL rendered DOM (after JS execution)
Discover all routes/endpoints by:
a. Extracting from JavaScript source files
b. Finding Angular/React route definitions
c. Intercepting all network requests (XHR/fetch)
d. Clicking through navigation elements
Form interaction:
a. Find all forms on a page
b. Fill forms with test data
c. Submit forms and capture responses
Network request interception:
a. Capture ALL API calls the frontend makes
b. Record request method, URL, headers, body
c. Record response status, headers, body
JavaScript execution:
a. Execute arbitrary JS in page context
b. Extract data from JavaScript variables
c. Read localStorage and sessionStorage
Screenshot capability for evidence
Cookie management (get/set cookies)

CLASS DESIGN:

class BrowserEngine:
    def __init__(self, headless=True, proxy=None):
        # Playwright browser instance
        # Network request log
        # Discovered endpoints list
    
    async def start(self):
        # Launch browser
    
    async def stop(self):
        # Close browser
    
    async def navigate(self, url: str) -> PageData:
        # Go to URL, wait for load, return page data
    
    async def get_rendered_html(self, url: str) -> str:
        # Get FULLY rendered HTML after JS execution
    
    async def discover_endpoints(self, base_url: str) -> list:
        # Navigate site, intercept requests, extract from JS
        # Return list of {url, method, headers, body} dicts
    
    async def extract_js_routes(self, url: str) -> list:
        # Find Angular/React route definitions in JS
        # Look for patterns: path: '/admin', component: ...
    
    async def get_network_log(self) -> list:
        # Return all intercepted network requests
    
    async def fill_form(self, selector, data: dict):
        # Fill form fields by name/id
    
    async def click(self, selector: str):
        # Click an element
    
    async def screenshot(self, path: str):
        # Take screenshot for evidence
    
    async def get_cookies(self) -> list:
        # Get all cookies
    
    async def get_local_storage(self) -> dict:
        # Read localStorage
    
    async def execute_js(self, script: str) -> any:
        # Execute JavaScript in page context
    
    async def intercept_api_calls(self, base_url: str, duration=30) -> list:
        # Navigate and record all API calls for duration seconds

IMPORTANT:

All Playwright operations must use async/await
Handle timeouts gracefully (default 30s per page)
Handle navigation errors (404, 500, SSL errors)
Network interception must capture POST bodies too
Route extraction must handle: Angular routes, React Router, Vue Router,
Express routes in JS, and raw API endpoint strings like '/api/...'
Extract API endpoints from JavaScript using regex patterns:
/api/, /rest/, fetch(, axios., $http., XMLHttpRequest
The browser must be in incognito/private mode
Disable images/CSS loading for speed (optional flag)
Write clean, well-documented Python code.



---

### PROMPT 3 - State Manager:

I am building VAPT-AI, a Python-based autonomous penetration testing tool.
Create core/state_manager.py - persistent state management for scan progress.

This state manager remembers EVERYTHING the tool discovers during a scan
so that agents can use previous findings to guide future attacks.

REQUIREMENTS:

Thread-safe state storage (multiple agents access simultaneously)
Persistent to disk (JSON file) - survives tool restart
Auto-save on every update
STATE CATEGORIES TO TRACK:

class ScanState:
    # Target Information
    target_url: str
    target_domain: str
    technologies: list        # Detected tech stack
    waf_detected: str
    
    # Authentication State
    registered_users: list    # [{email, password, role, token}]
    admin_token: str          # If admin access achieved
    active_session: dict      # Current session cookies/tokens
    login_endpoint: str       # Discovered login URL
    register_endpoint: str    # Discovered register URL
    
    # Discovery
    all_endpoints: list       # [{url, method, params, auth_required}]
    api_endpoints: list       # API-specific endpoints
    forms: list               # Discovered HTML forms
    js_files: list            # JavaScript file URLs
    hidden_paths: list        # Hidden directories/files found
    
    # Findings
    confirmed_vulns: list     # Confirmed vulnerabilities
    potential_vulns: list     # Need manual verification
    failed_attempts: list     # What was tested and failed
    
    # Credentials & Tokens
    discovered_tokens: list   # JWT, API keys, secrets found
    discovered_creds: list    # Username/password pairs found
    jwt_secret: str           # If JWT secret cracked
    
    # Attack Progress
    tested_endpoints: dict    # {endpoint: [tests_performed]}
    attack_chain: list        # Sequence of chained attacks
    
    # Statistics
    total_requests: int
    total_findings: int
    scan_start_time: str
    last_update_time: str

METHODS NEEDED:

add_endpoint(endpoint_data)
add_finding(vulnerability_data)
add_credential(email, password, role, token)
mark_endpoint_tested(endpoint, test_type, result)
get_untested_endpoints(test_type) -> list
get_authenticated_token() -> str
has_admin_access() -> bool
save_to_disk()
load_from_disk()
get_attack_summary() -> dict
Thread-safety: use threading.Lock for all write operations.
Auto-save: call save_to_disk() after every state modification.
State file location: ~/vapt-ai/data/scan_state_{domain}.json

Write clean Python code with dataclass or Pydantic models.




---

### PROMPT 4 - Payload Engine:
I am building VAPT-AI, a Python-based autonomous penetration testing tool.
Create core/payload_engine.py - intelligent payload generation engine.

This engine generates context-aware security testing payloads.
NOT hardcoded lists - it adapts payloads based on target technology.

REQUIREMENTS:

1. PAYLOAD CATEGORIES with 20+ payloads each:
SQL Injection:

Error-based (MySQL, PostgreSQL, SQLite, MSSQL specific)
UNION-based (column count detection, data extraction)
Boolean-based blind
Time-based blind
Stacked queries
SQLite-specific (important: OWASP Juice Shop uses SQLite)
Example: ' OR 1=1--, ' UNION SELECT sql FROM sqlite_master--
XSS:

Reflected (basic, event handlers, SVG, img)
DOM-based (document.location, innerHTML, eval)
Stored (persistent)
Angular-specific template injection: {{constructor.constructor('alert(1)')()}}
Polyglot payloads
Filter bypass variants (case change, encoding, null bytes)
iframe-based: <iframe src="javascript:alert(`xss`)">
Authentication Bypass:

SQL injection in login forms
NoSQL injection in login: {"$gt": ""}
JWT none algorithm
JWT secret brute force (common secrets list)
Default credentials list
Password reset manipulation
IDOR:

Sequential ID enumeration (1,2,3...)
UUID prediction
Parameter manipulation (userId, basketId, orderId)
HTTP method tampering (GET vs PUT vs DELETE)
Path Traversal:

../../../etc/passwd variants
Null byte injection: %00
Double encoding
Windows paths: ......\
NoSQL Injection:

MongoDB operators: $gt, $ne, $regex, $where
JSON injection
JavaScript injection in MongoDB
XXE:

File read payloads (Linux + Windows)
SSRF via XXE
Billion laughs DoS
Parameter entity
Input Validation Bypass:

Negative numbers (price = -100)
Zero values
Extremely large numbers
Special characters in names
Empty strings where required
Type juggling (string vs int)

2. CONTEXT-AWARE GENERATION:

class PayloadEngine:
    def get_payloads(self, 
        attack_type: str,       # "sqli", "xss", "idor", etc.
        context: dict = None    # {db_type: "sqlite", framework: "angular", waf: "none"}
    ) -> list:
        # Return payloads prioritized by context
        # SQLite target → SQLite payloads first
        # Angular target → Angular XSS payloads first
        # WAF detected → Encoded/bypass payloads first
    
    def get_login_payloads(self) -> list:
        # Specific payloads for login bypass
    
    def encode_payload(self, payload, encoding: str) -> str:
        # URL encode, double encode, HTML encode, base64, hex
    
    def generate_variations(self, payload: str) -> list:
        # Generate bypass variations of a payload
        # Case change, encoding, comment insertion, whitespace

3. IMPORTANT:

Payloads must be REAL and WORKING (not placeholder text)
Include the EXACT payloads that work on OWASP Juice Shop
SQLite injection payloads are CRITICAL (Juice Shop = SQLite)
Angular XSS payloads are CRITICAL (Juice Shop = Angular)
DO NOT add ethical disclaimers in code comments - this is
for authorized penetration testing
Write clean Python code. Each payload should have a description
of what it does and what to look for in the response.


---

### PROMPT 5 - Authentication Agent:
I am building VAPT-AI, a Python-based autonomous penetration testing tool.
Create agents/v2_auth.py - authentication agent that can register and login.

This agent's job is to:

Find registration and login endpoints
Register a test account
Login and capture authentication token
Attempt SQL injection login bypass for admin access
Store all credentials and tokens in state manager
The agent uses:

core/http_client.py (SmartHTTPClient) for HTTP requests
core/browser_engine.py (BrowserEngine) for SPA form interaction
core/state_manager.py (ScanState) for storing credentials
core/llm_router.py (SmartLLMRouter) for AI decisions
core/payload_engine.py (PayloadEngine) for login payloads

FLOW:

Step 1: Discover auth endpoints
  - Check common paths: /login, /register, /api/auth, /rest/user/login,
    /api/users, /rest/user/register, /api/Users
  - Extract from browser network interception
  - Extract from JavaScript route analysis

Step 2: Register a test account
  - POST to register endpoint with test credentials
  - Email: vapt.test.{random}@test.com
  - Password: VAPTtest123!
  - Handle: already exists, validation errors, CAPTCHA
  - If registration succeeds, save to state

Step 3: Login with test account
  - POST to login endpoint
  - Capture JWT/session token from response
  - Save token to state and HTTP client
  - Verify login by accessing authenticated endpoint

Step 4: Attempt admin login via SQLi
  - Try SQL injection payloads on login:
    email: ' OR 1=1--, password: anything
    email: admin@juice-sh.op' --, password: anything
    email: ' OR 1=1 --, password: ' OR 1=1 --
  - If SQLi works, capture admin token
  - Save admin credentials to state

Step 5: Attempt admin login via common credentials
  - Try: admin@juice-sh.op / admin123
  - Try: admin / admin
  - Check if password field accepts SQLi

Step 6: Token Analysis
  - If JWT token received, decode it (without verification)
  - Extract: user role, user ID, email, expiration
  - Check for "none" algorithm vulnerability
  - Check if token can be modified (role: admin)


IMPORTANT:

Must work with OWASP Juice Shop's REST API
Juice Shop login: POST /rest/user/login {email, password}
Juice Shop register: POST /api/Users {email, password,
passwordRepeat, securityQuestion: {id:1, question:...},
securityAnswer: "answer"}
Response contains: {token: "JWT...", authentication: {token, bid, umail}}
The agent must be GENERAL PURPOSE - not hardcoded for Juice Shop
but smart enough to figure out any app's auth endpoints

Output: Updated ScanState with credentials, tokens, and auth status




---

### PROMPT 6 - Enhanced Recon Agent:
I am building VAPT-AI v2.0 penetration testing tool.
Create agents/v2_recon.py - enhanced reconnaissance agent.

This replaces the old agents/recon.py with MUCH more capability.

IMPROVEMENTS OVER V1:

Uses BrowserEngine for SPA crawling (not just katana)
Deep JavaScript analysis to find hidden endpoints
Identifies ALL API endpoints with their parameters
Detects authentication requirements per endpoint
Extracts application structure (routes, components)
Identifies database type from error messages
Concurrent execution where safe

RECON TASKS (in order):

1. Basic Recon (same as V1 but better):
   - Technology detection (whatweb)
   - WAF detection (wafw00f) 
   - Port scanning (nmap - top 1000 ports)
   - Security headers analysis

2. Browser-Based Discovery (NEW):
   - Launch headless browser
   - Navigate to target
   - Intercept ALL network requests for 30 seconds
   - Click through navigation (main menu, links)
   - Extract all API endpoints from network log
   - Record: URL, method, request headers, request body, response status

3. JavaScript Deep Analysis (NEW):
   - Download all JS files
   - Extract route definitions (Angular: RouterModule, path: '...')
   - Extract API endpoint strings (/api/, /rest/, fetch calls)
   - Find hardcoded secrets (API keys, tokens, passwords)
   - Find commented-out code with sensitive info
   - Detect client-side validation rules (to bypass later)

4. API Endpoint Mapping (NEW):
   - For each discovered endpoint:
     - Determine HTTP method
     - Identify parameters (query, body, path)
     - Check if authentication required (401/403 without token)
     - Identify parameter types (int, string, email)
   - Create full API map

5. Directory/File Discovery (enhanced):
   - Standard ffuf wordlist scan
   - ALSO check: /ftp, /backup, /api-docs, /swagger, 
     /metrics, /prometheus, /actuator, /debug,
     /.git, /.env, /robots.txt, /security.txt,
     /sitemap.xml, /package.json, /webpack.config.js

6. Sensitive File Detection (NEW):
   - Check for backup files (.bak, .old, .swp, ~)
   - Check for config files exposed
   - Check for log files accessible
   - Check for database files (.db, .sqlite)

OUTPUT: Complete ScanState updated with all discovery data.
Each endpoint must include: url, method, params, auth_required,
response_code, content_type.

Use asyncio for concurrent operations where safe.
Use the existing tool_engine.py for running security tools.
Use browser_engine.py for SPA crawling.
Use http_client.py for API endpoint probing.



"Generate the COMPLETE file content. Do not skip any methods 
or write placeholder comments like '# implement here'. 
Write every single line of working code. 
The file should be ready to save and run without any modifications."

---

### PROMPT 7 - Vulnerability Scanner Agent:

I am building VAPT-AI v2.0 penetration testing tool.
Create agents/v2_scanner.py - intelligent vulnerability scanner.

This agent tests EVERY discovered endpoint for vulnerabilities.
It uses PayloadEngine for context-aware payloads and AI for response analysis.

SCANNING STRATEGY:
For each endpoint in state_manager.all_endpoints:

INJECTION TESTING:
For each parameter in the endpoint:
a. SQL Injection (PayloadEngine.get_payloads("sqli", context))

Send payload in parameter
Check response for: SQL errors, data leakage, behavior change
Try error-based, union-based, boolean-based, time-based
b. XSS Testing (PayloadEngine.get_payloads("xss", context))

Send XSS payload in parameter
Check if payload reflected unencoded in response
Try DOM, reflected, stored variants
c. NoSQL Injection (if MongoDB/NoSQL detected)

JSON-based payloads: {"$gt": ""}, {"$ne": ""}
d. Command Injection

; sleep 5, | whoami, id
ACCESS CONTROL TESTING:
a. IDOR: Change ID parameters (1→2, mine→others)

Authenticated as user A, try to access user B's data
Enumerate: /api/users/1, /api/users/2, /api/baskets/1, etc.
b. Privilege Escalation:

Access admin endpoints with regular user token
Try to modify user role in requests
c. Forced Browsing:

Access /admin, /administration, /#/administration
Access /api/users (list all users)
AUTHENTICATION TESTING:
a. Brute force (limited, with rate limiting)
b. Default credentials
c. Password reset manipulation
d. Session fixation

INPUT VALIDATION:
a. Boundary testing (negative numbers, zero, MAX_INT)
b. Type confusion (string where int expected)
c. Empty values where required
d. Special characters

FILE-RELATED:
a. File upload bypass (if upload endpoint found)
b. Path traversal (../../../etc/passwd)
c. XXE injection (if XML accepted)

CRITICAL RULES:

Use state_manager to check what's already been tested
Mark each endpoint+test combination as tested
Use AUTHENTICATED requests (from auth agent's token)
Run tests in parallel where safe (asyncio.gather)
Limit concurrent requests to avoid DoS
AI must analyze EVERY response to determine if vulnerable
Generate PoC for every confirmed finding
Feed confirmed findings back to state for chaining
RESPONSE ANALYSIS (AI-powered):
For each test, send the request+response to LLM:
"Given this request with payload X and this response,
is this endpoint vulnerable to Y? Look for: [specific indicators]"

But ALSO do fast programmatic checks first:

    Status code changes (200→500 = interesting)
    Response size changes (bigger = data leak?)
    Time differences (>5s = time-based SQLi?)
    Error strings in response
    Payload reflection in response
Output: List of confirmed and potential vulnerabilities added to ScanState.






### PROMPT 8 - V2 Orchestrator:
I am building VAPT-AI v2.0 penetration testing tool.
Create agents/v2_orchestrator.py - the main ReAct orchestrator.

This is the BRAIN of the tool. It uses LangGraph to create a
dynamic workflow that DECIDES what to do based on current state.

NOT a fixed pipeline. The orchestrator:

Checks current state
Decides next best action
Executes it
Updates state
Decides next action based on NEW state
Repeats until all tests exhausted

LANGGRAPH WORKFLOW:

from langgraph.graph import StateGraph, MessagesState

# Define the workflow graph
workflow = StateGraph(ScanState)

# Nodes (actions the agent can take):
workflow.add_node("recon", run_recon)
workflow.add_node("auth", run_auth) 
workflow.add_node("scan", run_scanner)
workflow.add_node("exploit", run_exploiter)
workflow.add_node("report", run_reporter)

# The ROUTER node - AI decides what to do next
workflow.add_node("decide", decide_next_action)

# Edges
workflow.set_entry_point("decide")
workflow.add_conditional_edges(
    "decide",
    route_decision,
    {
        "recon": "recon",
        "auth": "auth",
        "scan": "scan",
        "exploit": "exploit",
        "report": "report",
        "done": END
    }
)

# After each action, go back to decide
workflow.add_edge("recon", "decide")
workflow.add_edge("auth", "decide")
workflow.add_edge("scan", "decide")
workflow.add_edge("exploit", "decide")
workflow.add_edge("report", "decide")


DECISION LOGIC (decide_next_action):

    IF no recon done → do recon
    ELIF no auth attempted → do auth
    ELIF untested endpoints exist → do scan
    ELIF confirmed vulns exist AND not exploited → do exploit
    ELIF all tests done → do report
    ELSE → done
But also SMART decisions:

"SQLi found on login → try to extract user credentials"
"Admin token obtained → scan admin-only endpoints"
"New endpoints found via exploit → scan those too"
"JWT weak → forge admin token → access admin area"
The orchestrator must integrate with core/dashboard.py
for live progress display.

Maximum iterations: 50 (prevent infinite loops)
Each iteration must update dashboard progress.

Use LangGraph properly - this must be a REAL graph-based agent,
not just sequential function calls.


---

### PROMPT 9 - Attack Modules:
I am building VAPT-AI v2.0 penetration testing tool.
Create the attack modules in the attacks/ directory.

Each module is a focused, deep-testing module for one vulnerability type.

Create these files:

attacks/init.py - exports all modules

attacks/sqli.py - SQL Injection module

detect_sqli(http_client, url, params) -> findings
Methods: error-based, union-based, boolean-blind, time-blind
Database-specific payloads (SQLite focus)
Auto-detect column count for UNION attacks
Extract data if SQLi confirmed
attacks/xss.py - XSS module

detect_xss(http_client, url, params) -> findings
Methods: reflected, DOM, stored
Framework-specific (Angular template injection)
Filter bypass techniques
Payload: <iframe src="javascript:alert(`xss`)">
attacks/idor.py - IDOR/Access Control module

detect_idor(http_client, url, auth_tokens) -> findings
Compare responses between user A and user B tokens
Enumerate sequential IDs
Test horizontal and vertical privilege escalation
attacks/jwt_attacks.py - JWT module

analyze_jwt(token) -> analysis
try_none_algorithm(token) -> forged_token
try_common_secrets(token) -> secret_key
forge_token(claims, secret) -> new_token
attacks/auth_bypass.py - Auth bypass module

test_auth_bypass(http_client, login_url) -> findings
SQLi login bypass
Default credentials
Password reset flaws
Registration manipulation (admin role)
attacks/input_validation.py - Input validation module

test_input_validation(http_client, url, params) -> findings
Negative numbers, zero, overflow
Empty required fields
Type confusion
Special characters
Each module must:

Use PayloadEngine for payloads
Use SmartHTTPClient for requests
Return standardized Finding objects
Be independently testable
Support both authenticated and unauthenticated testing


---

### PROMPT 10 - Updated main.py:
I am building VAPT-AI v2.0 penetration testing tool.
Update main.py to use the V2 orchestrator and all new components.

The main.py should:

Parse command line arguments (same as V1: auto, recon, manual)
Initialize all V2 components:
SmartLLMRouter (existing)
SecurityToolsEngine (existing)
SmartHTTPClient (new)
BrowserEngine (new)
ScanState (new)
PayloadEngine (new)
Dashboard (existing)
Run V2Orchestrator for auto mode
Support manual mode with new commands
Handle graceful shutdown (save state on Ctrl+C)
Print final results with dashboard
Add new CLI options:
--browser / --no-browser (enable/disable headless browser)
--parallel / --sequential (concurrent vs sequential testing)
--credentials EMAIL:PASS (provide login credentials)

Keep backward compatibility with V1 commands.




