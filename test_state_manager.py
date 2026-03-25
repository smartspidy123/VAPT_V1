"""
VAPT-AI V2.0 - State Manager Verification Script
====================================================
Run: python test_state_manager.py

Tests every checkbox from the Phase 3 verification list.
No external network calls needed — all local.
"""

import json
import os
import sys
import threading
import time

# ── Import Test ──────────────────────────────────────────
print("=" * 60)
print("VAPT-AI V2.0 - State Manager Verification")
print("=" * 60)

try:
    from core.state_manager import (
        StateManager,
        ScanState,
        EndpointRecord,
        VulnerabilityRecord,
        CredentialRecord,
        TokenRecord,
        AttackChainStep,
        FailedAttempt,
    )
    print("\n[PASS] ✅ Import successful")
except ImportError as e:
    print(f"\n[FAIL] ❌ Import failed: {e}")
    sys.exit(1)

# ── Helper ───────────────────────────────────────────────
results = []
TEST_TARGET = "https://testapp.example.com"
TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "_test_state_data")


def log_result(test_name: str, passed: bool, detail: str = ""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append((test_name, passed))
    print(f"\n  [{status}] {test_name}")
    if detail:
        print(f"           {detail}")


def cleanup():
    """Remove test state files."""
    if os.path.exists(TEST_DATA_DIR):
        for f in os.listdir(TEST_DATA_DIR):
            os.remove(os.path.join(TEST_DATA_DIR, f))
        os.rmdir(TEST_DATA_DIR)


# Ensure clean start
cleanup()

# ─────────────────────────────────────────────────────────
# TEST 1: Initialization
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 1: Initialization")
print("-" * 60)

try:
    state = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)
    log_result(
        "StateManager initializes",
        state is not None,
        f"Target: {state._state.target_domain}",
    )
    log_result(
        "Target URL stored correctly",
        state._state.target_url == TEST_TARGET,
        f"URL: {state._state.target_url}",
    )
    log_result(
        "Data directory created",
        os.path.exists(TEST_DATA_DIR),
        f"Path: {TEST_DATA_DIR}",
    )
    log_result(
        "State file path generated",
        "testapp.example.com" in state.get_state_file_path(),
        f"File: {state.get_state_file_path()}",
    )
except Exception as e:
    log_result("Initialization", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 2: Add Endpoints
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 2: Endpoint Management")
print("-" * 60)

try:
    state = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)
    state.reset_state()

    # Add via EndpointRecord
    ep1 = EndpointRecord(url="https://testapp.example.com/api/users", method="GET")
    added1 = state.add_endpoint(ep1)
    log_result("Add endpoint via EndpointRecord", added1, f"Added: {added1}")

    # Add via dict
    added2 = state.add_endpoint({
        "url": "https://testapp.example.com/api/users",
        "method": "POST",
    })
    log_result("Add endpoint via dict", added2, f"Added: {added2}")

    # Duplicate check
    added3 = state.add_endpoint(ep1)
    log_result("Duplicate endpoint rejected", not added3, f"Added (should be False): {added3}")

    # Add more endpoints
    state.add_endpoint({"url": "https://testapp.example.com/login", "method": "GET"})
    state.add_endpoint({"url": "https://testapp.example.com/admin/dashboard", "method": "GET", "auth_required": True})

    # Get all endpoints
    all_eps = state.get_all_endpoints()
    log_result(
        "Get all endpoints works",
        len(all_eps) == 4,
        f"Count: {len(all_eps)}",
    )

    # API endpoint auto-classification
    api_eps = state.get_api_endpoints()
    log_result(
        "API endpoints auto-classified",
        len(api_eps) == 2,  # /api/users GET and POST
        f"API count: {len(api_eps)}",
    )

    # Bulk add
    bulk_eps = [
        {"url": "https://testapp.example.com/api/products", "method": "GET"},
        {"url": "https://testapp.example.com/api/orders", "method": "GET"},
        {"url": "https://testapp.example.com/api/users", "method": "GET"},  # duplicate
    ]
    added_count = state.add_endpoints_bulk(bulk_eps)
    log_result(
        "Bulk add works (dedup included)",
        added_count == 2,
        f"New endpoints added: {added_count}",
    )

    # Filter by method
    get_eps = state.get_endpoints_by_method("GET")
    log_result(
        "Filter by method works",
        len(get_eps) >= 4,
        f"GET endpoints: {len(get_eps)}",
    )

    # Auth-required endpoints
    auth_eps = state.get_endpoints_requiring_auth()
    log_result(
        "Auth-required filter works",
        len(auth_eps) >= 1,
        f"Auth required: {len(auth_eps)}",
    )
except Exception as e:
    log_result("Endpoint management", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 3: Vulnerability Management
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 3: Vulnerability Management")
print("-" * 60)

try:
    state = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)
    state.reset_state()

    # Add confirmed vuln
    vuln1 = VulnerabilityRecord(
        title="SQL Injection in login",
        category="sqli",
        severity="critical",
        endpoint="/api/login",
        method="POST",
        parameter="username",
        payload="' OR 1=1--",
        evidence="SQL error in response",
        description="Error-based SQL injection found",
        discovered_by="scanner_agent",
    )
    added = state.add_finding(vuln1, confirmed=True)
    log_result("Add confirmed vulnerability", added, f"Added: {added}")

    # Add potential vuln
    vuln2 = VulnerabilityRecord(
        title="Possible XSS in search",
        category="xss",
        severity="medium",
        endpoint="/search",
        parameter="q",
        payload="<script>alert(1)</script>",
    )
    added2 = state.add_finding(vuln2, confirmed=False)
    log_result("Add potential vulnerability", added2, f"Added: {added2}")

    # Duplicate check
    added3 = state.add_finding(vuln1)
    log_result("Duplicate vuln rejected", not added3, f"Added (should be False): {added3}")

    # Get confirmed
    confirmed = state.get_confirmed_vulns()
    log_result(
        "Get confirmed vulns",
        len(confirmed) >= 1,
        f"Count: {len(confirmed)}",
    )

    # Filter by category
    sqli_vulns = state.get_confirmed_vulns(category="sqli")
    log_result(
        "Filter by category works",
        len(sqli_vulns) >= 1,
        f"SQLi vulns: {len(sqli_vulns)}",
    )

    # Filter by severity
    high_plus = state.get_confirmed_vulns(severity="high")
    log_result(
        "Filter by severity works",
        len(high_plus) >= 1,
        f"High+ vulns: {len(high_plus)}",
    )

    # Get potential
    potential = state.get_potential_vulns()
    log_result(
        "Get potential vulns",
        len(potential) >= 1,
        f"Count: {len(potential)}",
    )

    # Confirm a finding
    vuln2_id = vuln2.vuln_id
    confirmed_ok = state.confirm_finding(vuln2_id)
    log_result(
        "Confirm finding moves to confirmed list",
        confirmed_ok and len(state.get_potential_vulns()) == 0,
        f"Confirmed: {confirmed_ok}, Remaining potential: {len(state.get_potential_vulns())}",
    )

    # All findings sorted
    all_findings = state.get_all_findings()
    log_result(
        "Get all findings sorted by severity",
        len(all_findings) >= 2 and all_findings[0].get("severity") == "critical",
        f"First severity: {all_findings[0].get('severity') if all_findings else 'none'}",
    )

    # has_finding_for
    has_sqli = state.has_finding_for("/api/login", "sqli")
    log_result(
        "has_finding_for works",
        has_sqli,
        f"SQLi on /api/login: {has_sqli}",
    )
except Exception as e:
    log_result("Vulnerability management", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 4: Credential Management
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 4: Credential Management")
print("-" * 60)

try:
    state = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)
    state.reset_state()

    # Register a user
    cred1 = CredentialRecord(
        email="testuser@test.com",
        password="Test123!",
        role="user",
        token="eyJhbGciOiJIUzI1NiJ9.user_token.sig",
    )
    added = state.add_credential(cred1, is_registered=True)
    log_result("Add registered user", added, f"Added: {added}")

    # Discover admin cred
    cred2 = CredentialRecord(
        email="admin@test.com",
        password="admin123",
        role="admin",
        token="eyJhbGciOiJIUzI1NiJ9.admin_token.sig",
    )
    added2 = state.add_credential(cred2, is_registered=False)
    log_result("Add discovered credential", added2, f"Added: {added2}")

    # Duplicate check
    added3 = state.add_credential(cred1, is_registered=True)
    log_result("Duplicate credential rejected", not added3, f"Added (should be False): {added3}")

    # Get registered
    registered = state.get_registered_users()
    log_result(
        "Get registered users",
        len(registered) >= 1,
        f"Count: {len(registered)}",
    )

    # Get discovered
    discovered = state.get_discovered_credentials()
    log_result(
        "Get discovered credentials",
        len(discovered) >= 1,
        f"Count: {len(discovered)}",
    )

    # All credentials
    all_creds = state.get_all_credentials()
    log_result(
        "Get all credentials",
        len(all_creds) >= 2,
        f"Count: {len(all_creds)}",
    )

    # Admin token auto-stored
    log_result(
        "Admin token auto-stored",
        state._state.admin_token == cred2.token,
        f"Admin token set: {bool(state._state.admin_token)}",
    )

    # Update token
    updated = state.update_credential_token(
        email="testuser@test.com",
        token="new_token_value",
    )
    log_result(
        "Update credential token",
        updated,
        f"Updated: {updated}",
    )
except Exception as e:
    log_result("Credential management", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 5: Authentication State
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 5: Authentication State")
print("-" * 60)

try:
    state = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)
    

    # Initially no auth
    fresh_state = StateManager("https://fresh.example.com", data_dir=TEST_DATA_DIR)
    token = fresh_state.get_authenticated_token()
    log_result(
        "No token initially",
        token is None,
        f"Token: {token}",
    )

    # Add user and check token retrieval
    fresh_state.add_credential(CredentialRecord(
        email="user@test.com", password="pass", token="user_token_123",
    ), is_registered=True)

    token = fresh_state.get_authenticated_token()
    log_result(
        "Get authenticated token (from registered user)",
        token == "user_token_123",
        f"Token: {token}",
    )

    # Admin token takes priority
    fresh_state.add_credential(CredentialRecord(
        email="admin@test.com", password="admin", role="admin", token="admin_token_456",
    ), is_registered=False)

    token2 = fresh_state.get_authenticated_token()
    log_result(
        "Admin token takes priority",
        token2 == "admin_token_456",
        f"Token: {token2}",
    )

    # has_admin_access
    log_result(
        "has_admin_access works",
        fresh_state.has_admin_access(),
        f"Has admin: {fresh_state.has_admin_access()}",
    )

    # has_any_auth
    log_result(
        "has_any_auth works",
        fresh_state.has_any_auth(),
        f"Has auth: {fresh_state.has_any_auth()}",
    )

    # Active session
    fresh_state.set_active_session(token="session_token_789", cookies={"sid": "abc123"})
    cookies = fresh_state.get_authenticated_cookies()
    log_result(
        "Set/get active session cookies",
        cookies.get("sid") == "abc123",
        f"Cookies: {cookies}",
    )

    # Auth endpoints
    fresh_state.set_login_endpoint("/api/login")
    fresh_state.set_register_endpoint("/api/register")
    log_result(
        "Login endpoint stored",
        fresh_state.get_login_endpoint() == "/api/login",
        f"Login: {fresh_state.get_login_endpoint()}",
    )
    log_result(
        "Register endpoint stored",
        fresh_state.get_register_endpoint() == "/api/register",
        f"Register: {fresh_state.get_register_endpoint()}",
    )
except Exception as e:
    log_result("Authentication state", False, str(e))
    
    
# ─────────────────────────────────────────────────────────
# TEST 6: Endpoint Testing Progress
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 6: Endpoint Testing Progress")
print("-" * 60)

try:
    # Fresh state - no leftover data
    state = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)
    state.reset_state()  # ← THIS IS THE FIX

    # Add ONLY 3 endpoints for this test
    state.add_endpoint({"url": "/api/users", "method": "GET"})
    state.add_endpoint({"url": "/api/products", "method": "GET"})
    state.add_endpoint({"url": "/api/orders", "method": "POST"})

    # Verify we have exactly 3
    all_eps = state.get_all_endpoints()
    print(f"           [DEBUG] Total endpoints: {len(all_eps)}")

    # Mark one as tested
    state.mark_endpoint_tested("/api/users", "sqli_error_based", "not_vulnerable")

    # Check tested
    is_tested = state.is_endpoint_tested("/api/users", "sqli_error_based")
    log_result(
        "mark_endpoint_tested works",
        is_tested,
        f"Tested: {is_tested}",
    )

    # Check untested
    is_untested = not state.is_endpoint_tested("/api/products", "sqli_error_based")
    log_result(
        "Untested endpoint correctly identified",
        is_untested,
        f"Untested: {is_untested}",
    )

    # Get untested endpoints for a test type
    untested = state.get_untested_endpoints("sqli_error_based")
    log_result(
        "get_untested_endpoints works",
        len(untested) == 2,  # products and orders
        f"Untested count: {len(untested)}",
    )

    # Different test type — all should be untested
    untested_xss = state.get_untested_endpoints("xss_reflected")
    log_result(
        "Different test type — all untested",
        len(untested_xss) == 3,
        f"XSS untested: {len(untested_xss)}",
    )

    # Failed attempts tracked
    failed = state._state.failed_attempts
    log_result(
        "Failed attempt recorded",
        len(failed) >= 1,
        f"Failed attempts: {len(failed)}",
    )
except Exception as e:
    log_result("Endpoint testing progress", False, str(e))
    
    
# ─────────────────────────────────────────────────────────
# TEST 7: Persistence (Save & Load)
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 7: Persistence (Save & Load)")
print("-" * 60)

try:
    # Create state with data
    state1 = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)
    state1.add_endpoint({"url": "/api/persist-test", "method": "GET"})
    state1.add_finding(VulnerabilityRecord(
        title="Persistence Test Vuln",
        category="xss",
        severity="high",
        endpoint="/persist",
    ))
    state1.add_credential(CredentialRecord(
        email="persist@test.com", password="pass123", token="persist_token",
    ), is_registered=True)

    # Verify file exists (auto-save)
    file_exists = os.path.exists(state1.get_state_file_path())
    log_result(
        "Auto-save creates file",
        file_exists,
        f"File: {state1.get_state_file_path()}",
    )

    # Verify file content is valid JSON
    with open(state1.get_state_file_path(), "r") as f:
        saved_data = json.load(f)
    log_result(
        "Saved file is valid JSON",
        isinstance(saved_data, dict) and "target_url" in saved_data,
        f"Keys: {list(saved_data.keys())[:5]}...",
    )

    # Load into new StateManager (simulates restart)
    state2 = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)

    # Verify data survived
    eps = state2.get_all_endpoints()
    has_persist_ep = any("/persist-test" in ep.get("url", "") for ep in eps)
    log_result(
        "Endpoints survive restart",
        has_persist_ep,
        f"Endpoints loaded: {len(eps)}",
    )

    vulns = state2.get_confirmed_vulns()
    has_persist_vuln = any("Persistence" in v.get("title", "") for v in vulns)
    log_result(
        "Vulnerabilities survive restart",
        has_persist_vuln,
        f"Vulns loaded: {len(vulns)}",
    )

    creds = state2.get_registered_users()
    has_persist_cred = any("persist@test.com" in c.get("email", "") for c in creds)
    log_result(
        "Credentials survive restart",
        has_persist_cred,
        f"Creds loaded: {len(creds)}",
    )

    # Reset state
    state2.reset_state()
    eps_after = state2.get_all_endpoints()
    log_result(
        "Reset state clears everything",
        len(eps_after) == 0,
        f"Endpoints after reset: {len(eps_after)}",
    )

    # Delete state file
    state2.delete_state_file()
    log_result(
        "Delete state file works",
        not os.path.exists(state2.get_state_file_path()),
        f"File exists: {os.path.exists(state2.get_state_file_path())}",
    )
except Exception as e:
    log_result("Persistence", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 8: Thread Safety
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 8: Thread Safety")
print("-" * 60)

try:
    state = StateManager("https://threadsafe.example.com", data_dir=TEST_DATA_DIR)
    errors: list = []

    def add_endpoints_thread(thread_id: int):
        """Add endpoints from a thread."""
        try:
            for i in range(20):
                state.add_endpoint({
                    "url": f"/api/thread{thread_id}/endpoint{i}",
                    "method": "GET",
                })
        except Exception as e:
            errors.append(f"Thread {thread_id}: {e}")

    def add_vulns_thread(thread_id: int):
        """Add vulnerabilities from a thread."""
        try:
            for i in range(10):
                state.add_finding(VulnerabilityRecord(
                    title=f"Thread {thread_id} Vuln {i}",
                    category="xss",
                    severity="medium",
                    endpoint=f"/thread{thread_id}/ep{i}",
                    parameter=f"param{i}",
                ))
        except Exception as e:
            errors.append(f"Thread {thread_id}: {e}")

    # Run concurrent threads
    threads = []
    for t_id in range(5):
        t1 = threading.Thread(target=add_endpoints_thread, args=(t_id,))
        t2 = threading.Thread(target=add_vulns_thread, args=(t_id,))
        threads.extend([t1, t2])

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    log_result(
        "No errors with concurrent writes",
        len(errors) == 0,
        f"Errors: {errors}" if errors else "No errors",
    )

    # Verify data integrity
    all_eps = state.get_all_endpoints()
    all_vulns = state.get_confirmed_vulns()
    log_result(
        "Correct count after concurrent writes",
        len(all_eps) == 100 and len(all_vulns) == 50,
        f"Endpoints: {len(all_eps)}/100, Vulns: {len(all_vulns)}/50",
    )

    # Cleanup
    state.delete_state_file()
except Exception as e:
    log_result("Thread safety", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 9: Attack Chain
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 9: Attack Chain Tracking")
print("-" * 60)

try:
    state = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)

    # Build an attack chain
    state.add_to_attack_chain(
        action="Found SQLi in /api/login",
        result="Extracted admin credentials",
    )
    state.add_to_attack_chain(
        action="Used admin credentials to access /admin/users",
        finding_used="sqli_finding_001",
        result="Found IDOR vulnerability",
        new_finding="idor_finding_001",
    )
    state.add_to_attack_chain(
        action="Used IDOR to access other users' data",
        finding_used="idor_finding_001",
        result="Full data breach demonstrated",
    )

    chain = state.get_attack_chain()
    log_result(
        "Attack chain tracked",
        len(chain) == 3,
        f"Steps: {len(chain)}",
    )
    log_result(
        "Chain steps numbered correctly",
        chain[0].get("step_number") == 1 and chain[2].get("step_number") == 3,
        f"Step numbers: {[s.get('step_number') for s in chain]}",
    )

    state.delete_state_file()
except Exception as e:
    log_result("Attack chain", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 10: Token Management
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 10: Token Management")
print("-" * 60)

try:
    state = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)

    token = TokenRecord(
        token_value="eyJhbGciOiJIUzI1NiJ9.test.sig",
        token_type="jwt",
        source="response_header",
        endpoint="/api/login",
    )
    added = state.add_token(token)
    log_result("Add token works", added, f"Added: {added}")

    # Duplicate
    added2 = state.add_token(token)
    log_result("Duplicate token rejected", not added2, f"Added: {added2}")

    # Get tokens
    tokens = state.get_discovered_tokens()
    log_result(
        "Get discovered tokens",
        len(tokens) >= 1,
        f"Count: {len(tokens)}",
    )

    # JWT secret
    state.set_jwt_secret("super_secret_key")
    secret = state.get_jwt_secret()
    log_result(
        "JWT secret stored and retrieved",
        secret == "super_secret_key",
        f"Secret: {secret}",
    )

    state.delete_state_file()
except Exception as e:
    log_result("Token management", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 11: Statistics and Summary
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 11: Statistics and Attack Summary")
print("-" * 60)

try:
    state = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)
    state.reset_state()

    # Populate with data
    state.add_endpoint({"url": "/api/test1", "method": "GET"})
    state.add_endpoint({"url": "/api/test2", "method": "POST"})
    state.add_finding(VulnerabilityRecord(
        title="Test", category="sqli", severity="critical", endpoint="/api/test1",
    ))
    state.add_credential(CredentialRecord(
        email="stats@test.com", password="pass", token="tok",
    ), is_registered=True)
    state.mark_endpoint_tested("/api/test1", "sqli_error_based", "vulnerable")
    state.increment_requests(42)
    state.set_scan_status("running")

    # Statistics
    stats = state.get_statistics()
    log_result(
        "Statistics generated",
        isinstance(stats, dict) and stats.get("total_requests") == 42,
        f"Requests: {stats.get('total_requests')}, "
        f"Endpoints: {stats.get('total_endpoints')}, "
        f"Coverage: {stats.get('coverage_percent')}%",
    )

    # Attack summary (for orchestrator)
    summary = state.get_attack_summary()
    log_result(
        "Attack summary generated",
        isinstance(summary, dict) and "confirmed_vulns" in summary,
        f"Keys: {list(summary.keys())}",
    )
    log_result(
        "Summary includes recommendations",
        isinstance(summary.get("recommendations"), list),
        f"Recommendations: {summary.get('recommendations')}",
    )

    # Agent context
    scanner_ctx = state.get_context_for_agent("scanner")
    log_result(
        "Agent context works (scanner)",
        "all_endpoints" in scanner_ctx and "auth_token" in scanner_ctx,
        f"Keys: {list(scanner_ctx.keys())}",
    )

    exploiter_ctx = state.get_context_for_agent("exploiter")
    log_result(
        "Agent context works (exploiter)",
        "confirmed_vulns" in exploiter_ctx and "jwt_secret" in exploiter_ctx,
        f"Keys: {list(exploiter_ctx.keys())}",
    )

    state.delete_state_file()
except Exception as e:
    log_result("Statistics and summary", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 12: Discovery Helpers
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 12: Discovery Helpers (Forms, JS, Hidden Paths)")
print("-" * 60)

try:
    state = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)
    state.reset_state()

    # Forms
    state.add_form({
        "action": "/login",
        "method": "POST",
        "is_login_form": True,
        "has_password": True,
        "fields": [{"name": "email"}, {"name": "password"}],
    })
    state.add_form({
        "action": "/search",
        "method": "GET",
        "is_login_form": False,
        "fields": [{"name": "q"}],
    })
    # Duplicate
    state.add_form({"action": "/login", "method": "POST"})

    forms = state.get_forms()
    log_result(
        "Forms stored (dedup works)",
        len(forms) == 2,
        f"Count: {len(forms)}",
    )

    login_forms = state.get_login_forms()
    log_result(
        "Login forms filtered",
        len(login_forms) == 1,
        f"Login forms: {len(login_forms)}",
    )

    # JS files
    state.add_js_file("https://testapp.example.com/static/app.js")
    state.add_js_file("https://testapp.example.com/static/vendor.js")
    state.add_js_file("https://testapp.example.com/static/app.js")  # duplicate

    js = state.get_js_files()
    log_result(
        "JS files stored (dedup works)",
        len(js) == 2,
        f"Count: {len(js)}",
    )

    # Hidden paths
    state.add_hidden_path("/.env")
    state.add_hidden_path("/admin/")
    state.add_hidden_path("/.env")  # duplicate

    paths = state.get_hidden_paths()
    log_result(
        "Hidden paths stored (dedup works)",
        len(paths) == 2,
        f"Count: {len(paths)}",
    )

    state.delete_state_file()
except Exception as e:
    log_result("Discovery helpers", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 13: Target Info
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 13: Target Information")
print("-" * 60)

try:
    state = StateManager(TEST_TARGET, data_dir=TEST_DATA_DIR)

    state.set_target_info(
        technologies=["React", "Node.js", "Express"],
        waf_detected="Cloudflare",
        server_info="nginx/1.24",
        framework_info="Express 4.18",
    )

    # Add more tech (should merge, not replace)
    state.set_target_info(technologies=["MongoDB", "React"])  # React is duplicate

    info = state.get_target_info()
    log_result(
        "Target info stored",
        info.get("waf_detected") == "Cloudflare",
        f"WAF: {info.get('waf_detected')}",
    )
    log_result(
        "Technologies merged (no duplicates)",
        len(info.get("technologies", [])) == 4,  # React, Node.js, Express, MongoDB
        f"Technologies: {info.get('technologies')}",
    )

    state.delete_state_file()
except Exception as e:
    log_result("Target information", False, str(e))

# ── Cleanup ──────────────────────────────────────────────
cleanup()

# ── Summary ──────────────────────────────────────────────
print("\n" + "=" * 60)
print("FINAL SUMMARY")
print("=" * 60)

total = len(results)
passed = sum(1 for _, p in results if p)
failed = total - passed

for test_name, test_passed in results:
    icon = "✅" if test_passed else "❌"
    print(f"  {icon} {test_name}")

print(f"\n  Total: {total} | Passed: {passed} | Failed: {failed}")

if failed == 0:
    print("\n  🎉 ALL TESTS PASSED - State Manager is ready!")
    print("  ✅ Phase 3 COMPLETE - proceed to Phase 4")
else:
    print(f"\n  ⚠️  {failed} test(s) failed - review and fix before proceeding")

print("=" * 60)