"""
VAPT-AI V2.0 - HTTP Client Verification Script
================================================
Run: python test_http_client.py

This tests every checkbox from the Phase 1 verification list.
Uses httpbin.org as a safe public test target.
"""

import asyncio
import json
import time
import sys

# ── Import Test ──────────────────────────────────────────
print("=" * 60)
print("VAPT-AI V2.0 - HTTP Client Verification")
print("=" * 60)

try:
    from core.http_client import (
        SmartHTTPClient,
        SmartResponse,
        ExtractedForm,
        FormField,
        RequestRecord,
    )
    print("\n[PASS] ✅ Import successful")
except ImportError as e:
    print(f"\n[FAIL] ❌ Import failed: {e}")
    sys.exit(1)


# ── Helper ───────────────────────────────────────────────
results = []


def log_result(test_name: str, passed: bool, detail: str = ""):
    """Track test results for final summary."""
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append((test_name, passed))
    print(f"\n  [{status}] {test_name}")
    if detail:
        print(f"           {detail}")


# ── All Tests ────────────────────────────────────────────
async def run_all_tests():
    """Run every verification test."""

    BASE_URL = "https://httpbin.org"

    # ─────────────────────────────────────────────────────
    # TEST 1: GET Request
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 1: GET Request")
    print("-" * 60)

    async with SmartHTTPClient(base_url=BASE_URL, rate_limit=5) as client:
        try:
            resp = await client.get("/get", params={"test": "vapt-ai"})
            passed = resp.status_code == 200 and resp.is_success
            log_result(
                "GET request works",
                passed,
                f"Status: {resp.status_code}, Body length: {resp.content_length}",
            )

            # Verify params were sent
            if resp.json_data:
                args = resp.json_data.get("args", {})
                passed2 = args.get("test") == "vapt-ai"
                log_result(
                    "GET params sent correctly",
                    passed2,
                    f"Args received: {args}",
                )
            else:
                log_result("GET params sent correctly", False, "No JSON in response")
        except Exception as e:
            log_result("GET request works", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 2: POST Request
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 2: POST Request (form data + JSON)")
    print("-" * 60)

    async with SmartHTTPClient(base_url=BASE_URL, rate_limit=5) as client:
        try:
            # POST with form data
            resp = await client.post("/post", data={"username": "admin", "password": "test123"})
            passed = resp.status_code == 200
            form_data = resp.json_data.get("form", {}) if resp.json_data else {}
            log_result(
                "POST with form data",
                passed and form_data.get("username") == "admin",
                f"Form data received: {form_data}",
            )

            # POST with JSON
            resp2 = await client.post("/post", json_body={"key": "value", "number": 42})
            json_sent = resp2.json_data.get("json", {}) if resp2.json_data else {}
            log_result(
                "POST with JSON body",
                json_sent.get("key") == "value",
                f"JSON received: {json_sent}",
            )
        except Exception as e:
            log_result("POST request", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 3: PUT and DELETE
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 3: PUT and DELETE Requests")
    print("-" * 60)

    async with SmartHTTPClient(base_url=BASE_URL, rate_limit=5) as client:
        try:
            resp_put = await client.put("/put", json_body={"update": "data"})
            log_result(
                "PUT request works",
                resp_put.status_code == 200,
                f"Status: {resp_put.status_code}",
            )

            resp_del = await client.delete("/delete")
            log_result(
                "DELETE request works",
                resp_del.status_code == 200,
                f"Status: {resp_del.status_code}",
            )
        except Exception as e:
            log_result("PUT/DELETE requests", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 4: Cookie Persistence
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 4: Cookie Persistence Across Requests")
    print("-" * 60)

    async with SmartHTTPClient(base_url=BASE_URL, rate_limit=5) as client:
        try:
            # Set a cookie via httpbin
            resp1 = await client.get("/cookies/set/session_id/abc123")
            
            # Now make another request - cookie should be sent automatically
            resp2 = await client.get("/cookies")
            cookies_on_server = resp2.json_data.get("cookies", {}) if resp2.json_data else {}

            passed = cookies_on_server.get("session_id") == "abc123"
            log_result(
                "Cookies persist across requests",
                passed,
                f"Cookies seen by server: {cookies_on_server}",
            )

            # Also test manual cookie setting
            client.set_cookies({"manual_cookie": "test_value"})
            resp3 = await client.get("/cookies")
            cookies2 = resp3.json_data.get("cookies", {}) if resp3.json_data else {}
            log_result(
                "Manual cookie setting works",
                "manual_cookie" in cookies2,
                f"Cookies: {cookies2}",
            )
        except Exception as e:
            log_result("Cookie persistence", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 5: JWT Token Auto-Added to Headers
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 5: JWT/Auth Token in Headers")
    print("-" * 60)

    async with SmartHTTPClient(base_url=BASE_URL, rate_limit=5) as client:
        try:
            # Simulate: after login, set a JWT token
            fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
            client.set_auth_token(fake_jwt, token_type="Bearer")

            # Make a request - check if Authorization header was sent
            resp = await client.get("/headers")
            request_headers = resp.json_data.get("headers", {}) if resp.json_data else {}
            auth_header = request_headers.get("Authorization", "")

            passed = f"Bearer {fake_jwt}" == auth_header
            log_result(
                "JWT token auto-added to Authorization header",
                passed,
                f"Authorization header: {auth_header[:60]}...",
            )

            # Test clearing token
            client.clear_auth_token()
            resp2 = await client.get("/headers")
            headers2 = resp2.json_data.get("headers", {}) if resp2.json_data else {}
            passed2 = "Authorization" not in headers2
            log_result(
                "Token cleared successfully",
                passed2,
                f"Has Authorization: {'Authorization' in headers2}",
            )
        except Exception as e:
            log_result("JWT token handling", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 6: Response Analysis Methods
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 6: Response Analysis Methods")
    print("-" * 60)

    async with SmartHTTPClient(base_url=BASE_URL, rate_limit=5) as client:
        try:
            # Get an HTML page to test form/link extraction
            resp = await client.get("/forms/post")

            # Test form extraction
            forms = resp.forms
            log_result(
                "Form extraction works",
                len(forms) > 0,
                f"Found {len(forms)} form(s). Fields: {forms[0].get_field_names() if forms else 'none'}",
            )

            # Test link extraction
            resp2 = await client.get("/")
            links = resp2.links
            log_result(
                "Link extraction works",
                len(links) > 0,
                f"Found {len(links)} link(s)",
            )

            # Test JSON parsing
            resp3 = await client.get("/get")
            log_result(
                "JSON parsing works",
                resp3.json_data is not None and isinstance(resp3.json_data, dict),
                f"JSON keys: {list(resp3.json_data.keys()) if resp3.json_data else 'none'}",
            )

            # Test content type detection
            log_result(
                "Content type detection (is_json)",
                resp3.is_json,
                f"Content-Type: {resp3.headers.get('content-type', 'unknown')}",
            )
            log_result(
                "Content type detection (is_html)",
                resp2.is_html,
                f"Content-Type: {resp2.headers.get('content-type', 'unknown')}",
            )

            # Test security header analysis
            sec_headers = resp.analyse_security_headers()
            log_result(
                "Security header analysis works",
                isinstance(sec_headers, dict) and "missing_headers" in sec_headers,
                f"Missing headers: {sec_headers.get('missing_headers', [])}",
            )

            # Test technology detection
            techs = resp2.detect_technologies()
            log_result(
                "Technology detection works",
                isinstance(techs, dict),
                f"Detected: {techs}",
            )
        except Exception as e:
            log_result("Response analysis", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 7: Error/SQLi/XSS Detection
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 7: Vulnerability Indicator Detection")
    print("-" * 60)

    async with SmartHTTPClient(base_url=BASE_URL, rate_limit=5) as client:
        try:
            # We simulate by creating SmartResponse with known content
            # Use httpbin's /html endpoint and check our detection on it
            import httpx as httpx_lib

            # Simulate a response with SQL error
            fake_sql_resp = httpx_lib.Response(
                status_code=500,
                text='<html>Error: You have an error in your SQL syntax near "admin"</html>',
                request=httpx_lib.Request("GET", "http://test.com/vuln"),
            )
            smart_sql = SmartResponse(fake_sql_resp, base_url="http://test.com")
            log_result(
                "SQL injection indicator detection",
                smart_sql.has_sqli_indicators(),
                f"Details: {smart_sql.get_sqli_details()}",
            )

            # Simulate XSS reflection
            xss_payload = '<script>alert(1)</script>'
            fake_xss_resp = httpx_lib.Response(
                status_code=200,
                text=f'<html><body>Search results for: {xss_payload}</body></html>',
                request=httpx_lib.Request("GET", "http://test.com/search"),
            )
            smart_xss = SmartResponse(fake_xss_resp, base_url="http://test.com")
            log_result(
                "XSS reflection detection",
                smart_xss.has_xss_reflection(xss_payload),
                f"Payload reflected: {smart_xss.has_xss_reflection(xss_payload)}",
            )

            # XSS context detection
            context = smart_xss.has_xss_reflection_context(xss_payload)
            log_result(
                "XSS context analysis",
                context["reflected"] and context["in_html_body"],
                f"Context: {context}",
            )

            # Error page detection
            fake_error_resp = httpx_lib.Response(
                status_code=500,
                text='<html>Internal Server Error\nTraceback (most recent call last):\n  File "app.py"</html>',
                request=httpx_lib.Request("GET", "http://test.com/error"),
            )
            smart_err = SmartResponse(fake_error_resp, base_url="http://test.com")
            log_result(
                "Error page detection",
                smart_err.has_error_indicators(),
                f"Error details: {smart_err.get_error_details()[:2]}",
            )

            # Auth state detection
            fake_login_page = httpx_lib.Response(
                status_code=200,
                text='<html><body><a href="/login">Log In</a><a href="/register">Register</a></body></html>',
                request=httpx_lib.Request("GET", "http://test.com/"),
            )
            smart_unauth = SmartResponse(fake_login_page, base_url="http://test.com")
            auth_state = smart_unauth.detect_auth_state()
            log_result(
                "Auth state detection (unauthenticated)",
                auth_state["authenticated"] is False,
                f"State: {auth_state}",
            )

            fake_dashboard = httpx_lib.Response(
                status_code=200,
                text='<html><body>Welcome back, admin! <a href="/logout">Log Out</a> | <a href="/dashboard">Dashboard</a></body></html>',
                request=httpx_lib.Request("GET", "http://test.com/home"),
            )
            smart_auth = SmartResponse(fake_dashboard, base_url="http://test.com")
            auth_state2 = smart_auth.detect_auth_state()
            log_result(
                "Auth state detection (authenticated)",
                auth_state2["authenticated"] is True,
                f"State: {auth_state2}",
            )
        except Exception as e:
            log_result("Vulnerability detection", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 8: JWT Extraction
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 8: JWT Token Extraction from Response")
    print("-" * 60)

    try:
        import httpx as httpx_lib

        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

        # JWT in JSON body
        fake_login_resp = httpx_lib.Response(
            status_code=200,
            text=json.dumps({"token": jwt_token, "user": "admin"}),
            headers={"content-type": "application/json"},
            request=httpx_lib.Request("POST", "http://test.com/login"),
        )
        smart_jwt = SmartResponse(fake_login_resp, base_url="http://test.com")
        extracted = smart_jwt.extract_jwt_from_response()
        log_result(
            "JWT extraction from JSON body",
            extracted == jwt_token,
            f"Extracted: {extracted[:40]}..." if extracted else "None",
        )
    except Exception as e:
        log_result("JWT extraction", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 9: CSRF Token Extraction
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 9: CSRF Token Extraction")
    print("-" * 60)

    try:
        import httpx as httpx_lib

        csrf_html = '''
        <html>
        <body>
            <form action="/transfer" method="POST">
                <input type="hidden" name="csrf_token" value="abc123secrettoken">
                <input type="text" name="amount">
                <button type="submit">Transfer</button>
            </form>
        </body>
        </html>
        '''
        fake_csrf_resp = httpx_lib.Response(
            status_code=200,
            text=csrf_html,
            headers={"content-type": "text/html"},
            request=httpx_lib.Request("GET", "http://test.com/transfer"),
        )
        smart_csrf = SmartResponse(fake_csrf_resp, base_url="http://test.com")
        csrf = smart_csrf.extract_csrf_token()
        log_result(
            "CSRF token extraction from hidden field",
            csrf == "abc123secrettoken",
            f"Extracted: {csrf}",
        )
    except Exception as e:
        log_result("CSRF extraction", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 10: Rate Limiting
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 10: Rate Limiting")
    print("-" * 60)

    async with SmartHTTPClient(base_url=BASE_URL, rate_limit=3) as client:
        try:
            # 3 requests/sec means minimum ~333ms between requests
            start = time.time()

            await client.get("/get")
            await client.get("/get")
            await client.get("/get")
            await client.get("/get")

            elapsed = time.time() - start
            # 4 requests at 3/sec should take at least ~1 second
            passed = elapsed >= 0.9
            log_result(
                "Rate limiting works (3 req/sec)",
                passed,
                f"4 requests took {elapsed:.2f}s (expected >= 1.0s)",
            )
        except Exception as e:
            log_result("Rate limiting", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 11: Request History Storage
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 11: Request History Storage")
    print("-" * 60)

    async with SmartHTTPClient(base_url=BASE_URL, rate_limit=5) as client:
        try:
            await client.get("/get")
            await client.post("/post", data={"test": "data"})
            await client.get("/headers")

            history = client.get_request_history()
            log_result(
                "Request history stored",
                len(history) == 3,
                f"History has {len(history)} records",
            )

            # Check record structure
            record = history[0]
            has_fields = all([
                record.method == "GET",
                record.url != "",
                record.status_code > 0,
                record.timestamp > 0,
                record.request_id != "",
            ])
            log_result(
                "History records have correct structure",
                has_fields,
                f"Method: {record.method}, URL: {record.url}, "
                f"Status: {record.status_code}, ID: {record.request_id}",
            )

            # Test metrics
            metrics = client.get_metrics()
            log_result(
                "Metrics tracking works",
                metrics["total_requests"] == 3 and metrics["total_bytes_received"] > 0,
                f"Requests: {metrics['total_requests']}, "
                f"Bytes received: {metrics['total_bytes_received']}",
            )

            # Test export
            exported = client.export_history(include_bodies=False)
            log_result(
                "History export works",
                len(exported) == 3 and all("url" in e for e in exported),
                f"Exported {len(exported)} records",
            )

            # Test search by URL
            found = client.find_requests_by_url("/headers")
            log_result(
                "Search history by URL works",
                len(found) == 1,
                f"Found {len(found)} matching record(s)",
            )

            # Test search by status
            found2 = client.find_requests_by_status(200)
            log_result(
                "Search history by status code works",
                len(found2) == 3,
                f"Found {len(found2)} records with status 200",
            )
        except Exception as e:
            log_result("Request history", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 12: Error Handling
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 12: Error Handling (timeout / bad host)")
    print("-" * 60)

    async with SmartHTTPClient(
        base_url="http://192.0.2.1",  # Non-routable IP (will timeout)
        rate_limit=0,
        timeout=3.0,
    ) as client:
        try:
            resp = await client.get("/test")
            # Should get a synthetic error response, NOT an exception
            passed = resp.status_code in (0, 408)
            log_result(
                "Timeout returns SmartResponse (no crash)",
                passed,
                f"Status: {resp.status_code}, Body: {resp.body[:80]}",
            )
        except Exception as e:
            log_result("Error handling", False, f"Raised exception: {e}")


# ── Run everything ───────────────────────────────────────
print("\n🚀 Starting tests... (this will make real HTTP requests to httpbin.org)\n")
asyncio.run(run_all_tests())

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
    print("\n  🎉 ALL TESTS PASSED - HTTP Client is ready!")
    print("  ✅ Phase 1 COMPLETE - proceed to Phase 2")
else:
    print(f"\n  ⚠️  {failed} test(s) failed - review and fix before proceeding")

print("=" * 60)