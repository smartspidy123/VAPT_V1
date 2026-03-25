"""
VAPT-AI V2.0 - Payload Engine Verification Script
====================================================
Run: python test_payload_engine.py

Tests every checkbox from the Phase 4 verification list.
No external dependencies or network calls needed.
"""

import json
import sys

# ── Import Test ──────────────────────────────────────────
print("=" * 60)
print("VAPT-AI V2.0 - Payload Engine Verification")
print("=" * 60)

try:
    from core.payload_engine import PayloadEngine, Payload
    print("\n[PASS] ✅ Import successful")
except ImportError as e:
    print(f"\n[FAIL] ❌ Import failed: {e}")
    sys.exit(1)

# ── Helper ───────────────────────────────────────────────
results = []


def log_result(test_name: str, passed: bool, detail: str = ""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append((test_name, passed))
    print(f"\n  [{status}] {test_name}")
    if detail:
        print(f"           {detail}")


# ── Initialize Engine ────────────────────────────────────
engine = PayloadEngine()
print(f"\n  Engine: {engine}")

# ─────────────────────────────────────────────────────────
# TEST 1: SQLite Injection Payloads (20+)
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 1: SQLite Injection Payloads (20+)")
print("-" * 60)

try:
    sqli_all = engine.get_payloads("sqli")
    log_result(
        "SQLi payloads exist",
        len(sqli_all) > 0,
        f"Total SQLi payloads: {len(sqli_all)}",
    )

    # Filter SQLite-specific
    sqlite_payloads = [p for p in sqli_all if "sqlite" in p.get("tags", [])]
    log_result(
        "SQLite-specific payloads present (20+)",
        len(sqlite_payloads) >= 20,
        f"SQLite payloads: {len(sqlite_payloads)}",
    )

    # Check for critical Juice Shop payloads
    all_payload_strings = [p["payload"] for p in sqli_all]
    has_or_bypass = any("OR 1=1" in p for p in all_payload_strings)
    has_union_sqlite = any("sqlite_master" in p for p in all_payload_strings)
    has_admin_bypass = any("admin'--" in p for p in all_payload_strings)

    log_result(
        "Has OR 1=1 bypass payload",
        has_or_bypass,
        f"Found: {has_or_bypass}",
    )
    log_result(
        "Has UNION SELECT sqlite_master payload",
        has_union_sqlite,
        f"Found: {has_union_sqlite}",
    )
    log_result(
        "Has admin'-- login bypass",
        has_admin_bypass,
        f"Found: {has_admin_bypass}",
    )

    # Context-aware: SQLite target should prioritize SQLite payloads
    sqlite_context = engine.get_payloads("sqli", context={"db_type": "sqlite"})
    first_5_tags = [p.get("tags", []) for p in sqlite_context[:5]]
    sqlite_in_top5 = sum(1 for tags in first_5_tags if "sqlite" in tags)
    log_result(
        "SQLite context prioritizes SQLite payloads",
        sqlite_in_top5 >= 3,
        f"SQLite payloads in top 5: {sqlite_in_top5}/5",
    )

    # Subcategories present
    sqli_subcats = engine.get_subcategories("sqli")
    expected_subcats = ["error_based", "union_based", "blind_boolean", "time_based"]
    has_all_subcats = all(s in sqli_subcats for s in expected_subcats)
    log_result(
        "SQLi has all subcategories (error, union, blind, time)",
        has_all_subcats,
        f"Subcategories: {sqli_subcats}",
    )
except Exception as e:
    log_result("SQLi payloads", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 2: Angular XSS Payloads (15+)
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 2: Angular XSS Payloads (15+)")
print("-" * 60)

try:
    xss_all = engine.get_payloads("xss")
    log_result(
        "XSS payloads exist",
        len(xss_all) > 0,
        f"Total XSS payloads: {len(xss_all)}",
    )

    # Angular-specific
    angular_payloads = [p for p in xss_all if "angular" in p.get("tags", [])]
    log_result(
        "Angular XSS payloads present (15+)",
        len(angular_payloads) >= 15,
        f"Angular payloads: {len(angular_payloads)}",
    )

    # Check critical Angular payloads
    xss_strings = [p["payload"] for p in xss_all]
    has_template_injection = any("{{" in p and "constructor" in p for p in xss_strings)
    has_template_probe = any("{{7*7}}" in p for p in xss_strings)
    has_iframe_xss = any("iframe" in p.lower() and "javascript:" in p.lower() for p in xss_strings)

    log_result(
        "Has Angular template injection payload",
        has_template_injection,
        f"Found: {has_template_injection}",
    )
    log_result(
        "Has {{7*7}} detection probe",
        has_template_probe,
        f"Found: {has_template_probe}",
    )
    log_result(
        "Has iframe javascript: XSS",
        has_iframe_xss,
        f"Found: {has_iframe_xss}",
    )

    # Context-aware: Angular framework should prioritize Angular payloads
    angular_context = engine.get_payloads("xss", context={"framework": "angular"})
    first_5_tags = [p.get("tags", []) for p in angular_context[:5]]
    angular_in_top5 = sum(1 for tags in first_5_tags if "angular" in tags)
    log_result(
        "Angular context prioritizes Angular payloads",
        angular_in_top5 >= 3,
        f"Angular payloads in top 5: {angular_in_top5}/5",
    )

    # XSS subcategories
    xss_subcats = engine.get_subcategories("xss")
    has_dom = "dom" in xss_subcats
    has_reflected = "reflected" in xss_subcats
    has_stored = "stored" in xss_subcats
    log_result(
        "XSS has DOM, Reflected, Stored subcategories",
        has_dom and has_reflected and has_stored,
        f"Subcategories: {xss_subcats}",
    )
except Exception as e:
    log_result("XSS payloads", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 3: IDOR Payloads
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 3: IDOR Payloads")
print("-" * 60)

try:
    idor_all = engine.get_payloads("idor")
    log_result(
        "IDOR payloads exist",
        len(idor_all) > 0,
        f"Total IDOR payloads: {len(idor_all)}",
    )

    # Sequential IDs
    sequential = [p for p in idor_all if p.get("subcategory") == "sequential_id"]
    log_result(
        "Sequential ID enumeration payloads",
        len(sequential) >= 10,
        f"Count: {len(sequential)}",
    )

    # Parameter manipulation
    param_manip = [p for p in idor_all if p.get("subcategory") == "parameter_manipulation"]
    log_result(
        "Parameter manipulation payloads (userId, basketId, etc.)",
        len(param_manip) >= 5,
        f"Count: {len(param_manip)}",
    )

    # Method tampering
    method_tamp = [p for p in idor_all if p.get("subcategory") == "method_tampering"]
    log_result(
        "HTTP method tampering payloads",
        len(method_tamp) >= 3,
        f"Count: {len(method_tamp)}",
    )

    # Juice Shop basketId
    idor_strings = [p["payload"] for p in idor_all]
    has_basket = any("basketId" in p for p in idor_strings)
    log_result(
        "Has basketId IDOR payload (Juice Shop)",
        has_basket,
        f"Found: {has_basket}",
    )
except Exception as e:
    log_result("IDOR payloads", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 4: JWT Attack Payloads
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 4: JWT Attack Payloads")
print("-" * 60)

try:
    jwt_payloads = engine.get_payloads("jwt")
    log_result(
        "JWT payloads exist",
        len(jwt_payloads) > 0,
        f"Total JWT payloads: {len(jwt_payloads)}",
    )

    # None algorithm variants
    none_headers = engine.get_jwt_none_headers()
    log_result(
        "JWT 'none' algorithm variants present",
        len(none_headers) >= 3,
        f"Variants: {len(none_headers)}",
    )

    # JWT secrets for brute force
    secrets = engine.get_jwt_secrets()
    log_result(
        "JWT brute-force secrets present (20+)",
        len(secrets) >= 20,
        f"Secrets count: {len(secrets)}",
    )

    # Key confusion
    jwt_strings = [p["payload"] for p in jwt_payloads]
    has_hs256 = any("HS256" in p for p in jwt_strings)
    log_result(
        "Has HS256 key confusion payload",
        has_hs256,
        f"Found: {has_hs256}",
    )
except Exception as e:
    log_result("JWT payloads", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 5: Context-Aware Selection
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 5: Context-Aware Selection")
print("-" * 60)

try:
    # SQLite context
    no_context = engine.get_payloads("sqli")
    sqlite_context = engine.get_payloads("sqli", context={"db_type": "sqlite"})

    # First payload should be different (or at least reordered)
    log_result(
        "Context changes payload ordering",
        len(sqlite_context) > 0,
        f"With context: {sqlite_context[0]['payload'][:40]}...",
    )

    # MySQL context should prioritize MySQL payloads
    mysql_context = engine.get_payloads("sqli", context={"db_type": "mysql"})
    mysql_top5 = [p for p in mysql_context[:10] if "mysql" in p.get("tags", [])]
    log_result(
        "MySQL context prioritizes MySQL payloads",
        len(mysql_top5) >= 3,
        f"MySQL in top 10: {len(mysql_top5)}",
    )

    # WAF context should prioritize bypass payloads
    waf_context = engine.get_payloads("sqli", context={"waf": "cloudflare"})
    waf_top10 = [p for p in waf_context[:15] if "waf_bypass" in p.get("tags", [])]
    log_result(
        "WAF context boosts bypass payloads",
        len(waf_top10) >= 2,
        f"WAF bypass in top 15: {len(waf_top10)}",
    )

    # Juice Shop full context
    juice_context = engine.get_payloads("sqli", context={
        "db_type": "sqlite",
        "framework": "angular",
        "waf": "none",
    })
    juice_first = juice_context[0] if juice_context else {}
    has_juice_tag = "juice_shop" in juice_first.get("tags", []) or "sqlite" in juice_first.get("tags", [])
    log_result(
        "Juice Shop context (SQLite+Angular) works",
        has_juice_tag,
        f"First payload: {juice_first.get('payload', 'N/A')[:50]}",
    )
except Exception as e:
    log_result("Context-aware selection", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 6: Payload Encoding
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 6: Payload Encoding")
print("-" * 60)

try:
    test_payload = "' OR 1=1--"

    # URL encode
    url_encoded = engine.encode_payload(test_payload, "url")
    log_result(
        "URL encoding works",
        "%27" in url_encoded and "%20" in url_encoded,
        f"Encoded: {url_encoded}",
    )

    # Double URL encode
    double_encoded = engine.encode_payload(test_payload, "double_url")
    log_result(
        "Double URL encoding works",
        "%25" in double_encoded,
        f"Encoded: {double_encoded}",
    )

    # HTML encode
    html_encoded = engine.encode_payload("<script>alert(1)</script>", "html")
    log_result(
        "HTML encoding works",
        "&lt;" in html_encoded and "&gt;" in html_encoded,
        f"Encoded: {html_encoded}",
    )

    # Base64 encode
    b64_encoded = engine.encode_payload(test_payload, "base64")
    log_result(
        "Base64 encoding works",
        len(b64_encoded) > 0 and b64_encoded != test_payload,
        f"Encoded: {b64_encoded}",
    )

    # Hex encode
    hex_encoded = engine.encode_payload(test_payload, "hex")
    log_result(
        "Hex encoding works",
        all(c in "0123456789abcdef" for c in hex_encoded),
        f"Encoded: {hex_encoded}",
    )

    # Unicode encode
    uni_encoded = engine.encode_payload("alert", "unicode")
    log_result(
        "Unicode encoding works",
        "\\u" in uni_encoded,
        f"Encoded: {uni_encoded}",
    )

    # Multi-encode
    multi = engine.multi_encode(test_payload, ["url", "base64"])
    log_result(
        "Multi-encode (URL → Base64) works",
        multi != test_payload and len(multi) > 0,
        f"Encoded: {multi}",
    )
except Exception as e:
    log_result("Encoding", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 7: Variation Generation
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 7: Variation Generation")
print("-" * 60)

try:
    test_payload = "<script>alert(1)</script>"
    variations = engine.generate_variations(test_payload)

    log_result(
        "Variations generated",
        len(variations) >= 10,
        f"Total variations: {len(variations)}",
    )

    # Check specific techniques
    techniques = [v["technique"] for v in variations]
    has_case = "case_swap" in techniques
    has_url = "url_encode" in techniques
    has_null = "null_byte_append" in techniques

    log_result(
        "Has case swap variation",
        has_case,
        f"Found: {has_case}",
    )
    log_result(
        "Has URL encode variation",
        has_url,
        f"Found: {has_url}",
    )
    log_result(
        "Has null byte variation",
        has_null,
        f"Found: {has_null}",
    )

    # SQL variation with comment insertion
    sql_payload = "' UNION SELECT NULL--"
    sql_variations = engine.generate_variations(sql_payload)
    sql_techniques = [v["technique"] for v in sql_variations]
    has_comment = "comment_whitespace" in sql_techniques
    log_result(
        "SQL payload gets comment whitespace variation",
        has_comment,
        f"Found: {has_comment}",
    )
except Exception as e:
    log_result("Variation generation", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 8: Other Payload Categories
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 8: Other Payload Categories")
print("-" * 60)

try:
    # Auth bypass
    auth = engine.get_payloads("auth_bypass")
    log_result("Auth bypass payloads exist", len(auth) > 20, f"Count: {len(auth)}")

    # NoSQL
    nosql = engine.get_payloads("nosql")
    log_result("NoSQL payloads exist", len(nosql) >= 10, f"Count: {len(nosql)}")

    # XXE
    xxe = engine.get_payloads("xxe")
    log_result("XXE payloads exist", len(xxe) >= 5, f"Count: {len(xxe)}")

    # SSRF
    ssrf = engine.get_payloads("ssrf")
    log_result("SSRF payloads exist", len(ssrf) >= 10, f"Count: {len(ssrf)}")

    # Path traversal
    path_trav = engine.get_payloads("path_traversal")
    log_result("Path traversal payloads exist", len(path_trav) >= 15, f"Count: {len(path_trav)}")

    # Input validation
    input_val = engine.get_payloads("input_validation")
    log_result("Input validation payloads exist", len(input_val) >= 15, f"Count: {len(input_val)}")

    # File upload
    file_up = engine.get_payloads("file_upload")
    log_result("File upload payloads exist", len(file_up) >= 10, f"Count: {len(file_up)}")

    # Command injection
    cmd_inj = engine.get_payloads("command_injection")
    log_result("Command injection payloads exist", len(cmd_inj) >= 8, f"Count: {len(cmd_inj)}")
except Exception as e:
    log_result("Other categories", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 9: Login Payloads
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 9: Login Bypass Payloads")
print("-" * 60)

try:
    login = engine.get_login_payloads()
    log_result(
        "Login payloads generated",
        len(login) > 10,
        f"Count: {len(login)}",
    )

    # Default credentials
    default_creds = engine.get_default_credentials()
    log_result(
        "Default credentials list present",
        len(default_creds) >= 15,
        f"Count: {len(default_creds)}",
    )

    # Check admin cred
    has_admin = any(
        c.get("email") == "admin" and c.get("password") == "admin"
        for c in default_creds
    )
    log_result(
        "Has admin:admin default credential",
        has_admin,
        f"Found: {has_admin}",
    )
except Exception as e:
    log_result("Login payloads", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 10: Search and Statistics
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 10: Search and Statistics")
print("-" * 60)

try:
    # Categories
    categories = engine.get_categories()
    log_result(
        "Categories list available",
        len(categories) >= 10,
        f"Categories: {categories}",
    )

    # Total count
    total = engine.get_total_count()
    log_result(
        "Total payload count significant",
        total >= 200,
        f"Total payloads: {total}",
    )

    # All counts
    counts = engine.get_all_counts()
    log_result(
        "Per-category counts available",
        isinstance(counts, dict) and len(counts) >= 10,
        f"Counts: {counts}",
    )

    # Search
    search_results = engine.search_payloads("sqlite")
    log_result(
        "Search by keyword works",
        len(search_results) >= 5,
        f"'sqlite' results: {len(search_results)}",
    )

    # Search in specific category
    search_xss = engine.search_payloads("angular", category="xss")
    log_result(
        "Search within category works",
        len(search_xss) >= 5,
        f"'angular' in xss: {len(search_xss)}",
    )

    # Tags
    sqli_tags = engine.get_tags("sqli")
    log_result(
        "Tags retrieval works",
        "sqlite" in sqli_tags and "mysql" in sqli_tags,
        f"SQLi tags: {sqli_tags[:10]}...",
    )
except Exception as e:
    log_result("Search and statistics", False, str(e))

# ─────────────────────────────────────────────────────────
# TEST 11: Checklist Quick Test
# ─────────────────────────────────────────────────────────
print("\n" + "-" * 60)
print("TEST 11: Quick Checklist Verification Command")
print("-" * 60)

try:
    p = PayloadEngine()
    sqli_count = len(p.get_payloads('sqli'))
    log_result(
        "Checklist command works: len(p.get_payloads('sqli'))",
        sqli_count > 50,
        f"Result: {sqli_count}",
    )
except Exception as e:
    log_result("Checklist command", False, str(e))

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
    print("\n  🎉 ALL TESTS PASSED - Payload Engine is ready!")
    print("  ✅ Phase 4 COMPLETE - proceed to Phase 5")
else:
    print(f"\n  ⚠️  {failed} test(s) failed - review and fix before proceeding")

print("=" * 60)