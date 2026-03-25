"""
VAPT-AI V2.0 - Browser Engine Verification Script
====================================================
Run: python test_browser_engine.py

Tests every checkbox from the Phase 2 verification list.
Uses example.com and httpbin.org as safe public targets.

Prerequisites:
    pip install playwright
    playwright install chromium
"""

import asyncio
import json
import os
import sys
import time

# ── Import Test ──────────────────────────────────────────
print("=" * 60)
print("VAPT-AI V2.0 - Browser Engine Verification")
print("=" * 60)

try:
    from core.browser_engine import (
        BrowserEngine,
        PageData,
        BrowserForm,
        NetworkRequest,
        DiscoveredEndpoint,
    )
    print("\n[PASS] ✅ Import successful")
except ImportError as e:
    print(f"\n[FAIL] ❌ Import failed: {e}")
    print("\nMake sure you have:")
    print("  pip install playwright beautifulsoup4 lxml")
    print("  playwright install chromium")
    sys.exit(1)

# ── Helper ───────────────────────────────────────────────
results = []


def log_result(test_name: str, passed: bool, detail: str = ""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append((test_name, passed))
    print(f"\n  [{status}] {test_name}")
    if detail:
        print(f"           {detail}")


# ── All Tests ────────────────────────────────────────────
async def run_all_tests():

    # ─────────────────────────────────────────────────────
    # TEST 1: Browser Start/Stop
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 1: Browser Lifecycle (Start / Stop)")
    print("-" * 60)

    try:
        engine = BrowserEngine(headless=True)
        await engine.start()
        log_result("Browser starts successfully", engine._is_started)
        await engine.stop()
        log_result("Browser stops successfully", not engine._is_started)
    except Exception as e:
        log_result("Browser lifecycle", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 2: Context Manager
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 2: Async Context Manager")
    print("-" * 60)

    try:
        async with BrowserEngine(headless=True) as engine:
            is_started = engine._is_started
            log_result("Context manager starts engine", is_started)
        log_result("Context manager stops engine", not engine._is_started)
    except Exception as e:
        log_result("Context manager", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 3: Navigation + Rendered HTML
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 3: Navigation and Rendered HTML")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            page_data = await engine.navigate("https://example.com")

            log_result(
                "Navigation returns PageData",
                isinstance(page_data, PageData),
                f"Type: {type(page_data).__name__}",
            )
            log_result(
                "Status code captured",
                page_data.status_code == 200,
                f"Status: {page_data.status_code}",
            )
            log_result(
                "Page title extracted",
                "Example" in page_data.title,
                f"Title: {page_data.title}",
            )
            log_result(
                "Rendered HTML captured",
                len(page_data.rendered_html) > 100 and "<html" in page_data.rendered_html.lower(),
                f"HTML length: {len(page_data.rendered_html)}",
            )
            log_result(
                "Load time recorded",
                page_data.load_time_ms > 0,
                f"Load time: {page_data.load_time_ms:.0f}ms",
            )
        except Exception as e:
            log_result("Navigation", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 4: get_rendered_html shortcut
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 4: get_rendered_html() Shortcut")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            html = await engine.get_rendered_html("https://example.com")
            log_result(
                "get_rendered_html returns HTML string",
                isinstance(html, str) and len(html) > 100,
                f"Length: {len(html)}",
            )
        except Exception as e:
            log_result("get_rendered_html", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 5: Link Extraction
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 5: Link Extraction from DOM")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            page_data = await engine.navigate("https://example.com")
            log_result(
                "Links extracted from page",
                isinstance(page_data.links, list),
                f"Found {len(page_data.links)} link(s): {page_data.links[:3]}",
            )
        except Exception as e:
            log_result("Link extraction", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 6: Form Extraction
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 6: Form Extraction from DOM")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            page_data = await engine.navigate("https://httpbin.org/forms/post")
            forms = page_data.forms

            log_result(
                "Forms extracted from page",
                len(forms) > 0,
                f"Found {len(forms)} form(s)",
            )

            if forms:
                form = forms[0]
                log_result(
                    "Form has correct structure",
                    hasattr(form, 'action') and hasattr(form, 'method') and hasattr(form, 'fields'),
                    f"Action: {form.action}, Method: {form.method}, Fields: {len(form.fields)}",
                )
                log_result(
                    "Form fields have names",
                    len(form.get_field_names()) > 0,
                    f"Field names: {form.get_field_names()}",
                )
        except Exception as e:
            log_result("Form extraction", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 7: Network Interception
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 7: Network Request Interception")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            await engine.navigate("https://httpbin.org")
            network_log = engine.get_network_log()

            log_result(
                "Network requests captured",
                len(network_log) > 0,
                f"Captured {len(network_log)} request(s)",
            )

            if network_log:
                req = network_log[0]
                has_fields = all([
                    hasattr(req, 'method'),
                    hasattr(req, 'url'),
                    hasattr(req, 'resource_type'),
                    hasattr(req, 'request_headers'),
                ])
                log_result(
                    "Network request has correct structure",
                    has_fields,
                    f"Method: {req.method}, URL: {req.url[:60]}, Type: {req.resource_type}",
                )
        except Exception as e:
            log_result("Network interception", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 8: Cookie Management
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 8: Cookie Management")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            await engine.navigate("https://httpbin.org")

            # Set cookies
            await engine.set_cookies([{
                "name": "test_cookie",
                "value": "vapt_ai_test",
                "url": "https://httpbin.org",
            }])

            # Get cookies
            cookies = await engine.get_cookies()
            test_cookie = next(
                (c for c in cookies if c["name"] == "test_cookie"), None
            )
            log_result(
                "Set and get cookies works",
                test_cookie is not None and test_cookie["value"] == "vapt_ai_test",
                f"Found cookie: {test_cookie}",
            )

            # Clear cookies
            await engine.clear_cookies()
            cookies_after = await engine.get_cookies()
            log_result(
                "Clear cookies works",
                len(cookies_after) == 0,
                f"Cookies after clear: {len(cookies_after)}",
            )
        except Exception as e:
            log_result("Cookie management", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 9: JavaScript Execution
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 9: JavaScript Execution")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            await engine.navigate("https://example.com")

            # Simple JS execution
            result = await engine.execute_js("() => 2 + 2")
            log_result(
                "Basic JS execution works",
                result == 4,
                f"2 + 2 = {result}",
            )

            # DOM access via JS
            title = await engine.execute_js("() => document.title")
            log_result(
                "JS can access DOM",
                isinstance(title, str) and len(title) > 0,
                f"Title via JS: {title}",
            )

            # Complex JS
            page_info = await engine.execute_js("""
                () => ({
                    url: window.location.href,
                    userAgent: navigator.userAgent,
                    screenWidth: screen.width,
                })
            """)
            log_result(
                "Complex JS returns object",
                isinstance(page_info, dict) and "url" in page_info,
                f"URL: {page_info.get('url', 'N/A')}",
            )
        except Exception as e:
            log_result("JS execution", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 10: Local/Session Storage
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 10: localStorage and sessionStorage")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            await engine.navigate("https://example.com")

            # Set localStorage
            await engine.set_local_storage({"vapt_key": "vapt_value"})
            local = await engine.get_local_storage()
            log_result(
                "localStorage set and get works",
                local.get("vapt_key") == "vapt_value",
                f"localStorage: {local}",
            )

            # Set sessionStorage
            await engine.set_session_storage({"session_key": "session_val"})
            session = await engine.get_session_storage()
            log_result(
                "sessionStorage set and get works",
                session.get("session_key") == "session_val",
                f"sessionStorage: {session}",
            )
        except Exception as e:
            log_result("Storage access", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 11: Screenshot
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 11: Screenshot Capture")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            await engine.navigate("https://example.com")

            # Create evidence directory
            os.makedirs("evidence", exist_ok=True)
            screenshot_path = "evidence/test_screenshot.png"

            result = await engine.screenshot(screenshot_path)
            file_exists = os.path.exists(screenshot_path)
            log_result(
                "Screenshot captured successfully",
                file_exists,
                f"Path: {result}, File exists: {file_exists}",
            )

            # Cleanup
            if file_exists:
                file_size = os.path.getsize(screenshot_path)
                log_result(
                    "Screenshot file has content",
                    file_size > 1000,
                    f"File size: {file_size} bytes",
                )
                os.remove(screenshot_path)
                os.rmdir("evidence")
        except Exception as e:
            log_result("Screenshot", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 12: Element Interaction
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 12: Element Interaction (click, type, wait)")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            await engine.navigate("https://example.com")

            # Check element exists
            exists = await engine.element_exists("h1")
            log_result(
                "element_exists works",
                exists is True,
                f"h1 exists: {exists}",
            )

            # Get element text
            text = await engine.get_element_text("h1")
            log_result(
                "get_element_text works",
                text is not None and len(text) > 0,
                f"h1 text: {text}",
            )

            # Wait for selector
            found = await engine.wait_for_selector("h1", timeout=3000)
            log_result(
                "wait_for_selector works",
                found is True,
                f"Found h1: {found}",
            )

            # Wait for non-existent element (should return False)
            not_found = await engine.wait_for_selector("#nonexistent123", timeout=2000)
            log_result(
                "wait_for_selector returns False for missing elements",
                not_found is False,
                f"Found #nonexistent123: {not_found}",
            )
        except Exception as e:
            log_result("Element interaction", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 13: Technology Detection
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 13: Technology Detection")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            page_data = await engine.navigate("https://example.com")
            log_result(
                "Technology detection returns list",
                isinstance(page_data.technologies, list),
                f"Detected: {page_data.technologies}",
            )
        except Exception as e:
            log_result("Technology detection", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 14: Network Log Export
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 14: Network Log Export & Metrics")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            await engine.navigate("https://httpbin.org")

            # Export network log
            exported = engine.export_network_log(include_bodies=False)
            log_result(
                "Network log export works",
                isinstance(exported, list) and len(exported) > 0,
                f"Exported {len(exported)} records",
            )

            # Metrics
            metrics = engine.get_metrics()
            log_result(
                "Metrics work",
                isinstance(metrics, dict) and "total_network_requests" in metrics,
                f"Metrics: {metrics}",
            )

            # Clear log
            engine.clear_network_log()
            log_result(
                "Clear network log works",
                len(engine.get_network_log()) == 0,
                f"Log size after clear: {len(engine.get_network_log())}",
            )
        except Exception as e:
            log_result("Export & metrics", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 15: Error Handling
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 15: Error Handling (bad URL)")
    print("-" * 60)

    async with BrowserEngine(headless=True, timeout=10000) as engine:
        try:
            page_data = await engine.navigate("https://thisdomaindoesnotexist12345.com")
            log_result(
                "Bad URL returns PageData with error (no crash)",
                isinstance(page_data, PageData) and page_data.error is not None,
                f"Error: {page_data.error}",
            )
        except Exception as e:
            log_result("Error handling", False, f"Raised exception: {e}")

    # ─────────────────────────────────────────────────────
    # TEST 16: Console Log Capture
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 16: Console Log Capture")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            await engine.navigate("https://example.com")

            # Trigger console output
            await engine.execute_js("() => console.log('VAPT-AI test message')")
            await asyncio.sleep(0.5)

            logs = engine.get_console_logs()
            has_test_msg = any("VAPT-AI test message" in log for log in logs)
            log_result(
                "Console logs captured",
                has_test_msg,
                f"Captured {len(logs)} log(s), test message found: {has_test_msg}",
            )
        except Exception as e:
            log_result("Console capture", False, str(e))

    # ─────────────────────────────────────────────────────
    # TEST 17: New Page / New Context
    # ─────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print("TEST 17: New Page and New Context")
    print("-" * 60)

    async with BrowserEngine(headless=True) as engine:
        try:
            await engine.navigate("https://example.com")

            # Set a cookie
            await engine.set_cookies([{
                "name": "persist_test",
                "value": "123",
                "url": "https://example.com",
            }])

            # New page (same context - cookies should persist)
            await engine.new_page()
            await engine.navigate("https://example.com")
            cookies = await engine.get_cookies()
            has_cookie = any(c["name"] == "persist_test" for c in cookies)
            log_result(
                "New page preserves cookies (same context)",
                has_cookie,
                f"Cookie found: {has_cookie}",
            )

            # New context (fresh - cookies should be gone)
            await engine.new_context()
            await engine.navigate("https://example.com")
            cookies2 = await engine.get_cookies()
            no_cookie = not any(c["name"] == "persist_test" for c in cookies2)
            log_result(
                "New context clears cookies",
                no_cookie,
                f"Cookie absent: {no_cookie}",
            )
        except Exception as e:
            log_result("New page/context", False, str(e))


# ── Run ──────────────────────────────────────────────────
print("\n🚀 Starting tests... (uses Playwright Chromium headless)\n")
print("⚠️  First run may take a moment while Chromium launches.\n")

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
    print("\n  🎉 ALL TESTS PASSED - Browser Engine is ready!")
    print("  ✅ Phase 2 COMPLETE - proceed to Phase 3")
else:
    print(f"\n  ⚠️  {failed} test(s) failed - review and fix before proceeding")

print("=" * 60)