"""
VAPT-AI Dashboard Test
=======================
Tests the CLI dashboard with simulated scan data.

Usage: python test_dashboard.py
"""

import asyncio
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.dashboard import (
    Dashboard,
    Finding,
    print_banner,
    print_scan_config,
    print_final_report_summary,
)


async def simulate_scan():
    """Simulate a scan to demonstrate the dashboard."""

    # Print startup banner
    print_banner()

    # Print config
    print_scan_config(
        target="https://juice-shop.example.com",
        mode="AUTO SCAN",
        provider="NVIDIA",
        model="deepseek-v3.2-685b",
    )

    # Create dashboard
    dashboard = Dashboard()
    dashboard.set_target("https://juice-shop.example.com")
    dashboard.set_mode("AUTO")
    dashboard.set_model_info("nvidia", "deepseek-v3.2")

    # Start live display
    with dashboard:
        # ---- PHASE 1: RECON ----
        dashboard.phase_tracker.start_phase("recon", total_tasks=6)
        dashboard.add_log("Starting reconnaissance phase", level="info", source="orchestrator")
        dashboard.refresh()
        await asyncio.sleep(1.5)

        dashboard.set_current_action("Running subdomain enumeration")
        dashboard.add_log("Running subfinder on target domain", level="action", source="recon")
        dashboard.set_ai_thought("Starting with subdomain enumeration to map the attack surface...")
        dashboard.phase_tracker.update_phase("recon", tasks_done=1)
        dashboard.update_llm_stats(tokens=450, requests=1)
        dashboard.increment_tools_run()
        dashboard.refresh()
        await asyncio.sleep(1.5)

        dashboard.add_log("Found 5 subdomains", level="success", source="subfinder")
        dashboard.add_log("Running nmap port scan", level="action", source="recon")
        dashboard.set_current_action("Port scanning target")
        dashboard.phase_tracker.update_phase("recon", tasks_done=2)
        dashboard.update_llm_stats(tokens=380, requests=1)
        dashboard.increment_tools_run()
        dashboard.refresh()
        await asyncio.sleep(1.5)

        dashboard.add_log("Ports 80, 443, 3000, 8080 open", level="success", source="nmap")
        dashboard.add_log("Running whatweb for tech detection", level="action", source="recon")
        dashboard.set_ai_thought("Port 3000 is interesting - could be Node.js. Let me check the tech stack...")
        dashboard.phase_tracker.update_phase("recon", tasks_done=3)
        dashboard.increment_tools_run()
        dashboard.refresh()
        await asyncio.sleep(1.5)

        dashboard.add_log("Tech: Node.js, Express, Angular, SQLite", level="success", source="whatweb")
        dashboard.add_log("Running WAF detection", level="action", source="recon")
        dashboard.phase_tracker.update_phase("recon", tasks_done=4)
        dashboard.increment_tools_run()
        dashboard.refresh()
        await asyncio.sleep(1)

        dashboard.add_log("No WAF detected!", level="success", source="wafw00f")
        dashboard.add_log("Crawling web application", level="action", source="recon")
        dashboard.phase_tracker.update_phase("recon", tasks_done=5)
        dashboard.increment_tools_run()
        dashboard.refresh()
        await asyncio.sleep(1.5)

        dashboard.add_log("Found 47 endpoints via crawling", level="success", source="katana")
        dashboard.add_log("Directory fuzzing with ffuf", level="action", source="recon")
        dashboard.phase_tracker.update_phase("recon", tasks_done=6)
        dashboard.increment_tools_run()
        dashboard.refresh()
        await asyncio.sleep(1)

        dashboard.add_log("Found /api, /admin, /ftp, /backup directories", level="success", source="ffuf")
        dashboard.phase_tracker.complete_phase("recon")
        dashboard.add_log("Reconnaissance phase COMPLETE", level="success", source="orchestrator")
        dashboard.update_llm_stats(tokens=2200, requests=3)
        dashboard.refresh()
        await asyncio.sleep(1)

        # ---- PHASE 2: ANALYSIS ----
        dashboard.phase_tracker.start_phase("analysis", total_tasks=4)
        dashboard.add_log("Starting vulnerability analysis", level="info", source="orchestrator")
        dashboard.set_ai_thought("Analyzing 47 endpoints. SQLite backend with no WAF = high chance of SQLi...")
        dashboard.set_model_info("nvidia", "deepseek-v3.2")
        dashboard.refresh()
        await asyncio.sleep(2)

        dashboard.phase_tracker.update_phase("analysis", tasks_done=1)
        dashboard.add_log("Identified 12 potential injection points", level="success", source="analyzer")
        dashboard.update_llm_stats(tokens=3500, requests=2)
        dashboard.refresh()
        await asyncio.sleep(1.5)

        dashboard.phase_tracker.update_phase("analysis", tasks_done=2)
        dashboard.add_log("Found 3 endpoints with reflected parameters", level="success", source="analyzer")
        dashboard.set_ai_thought("The /api/products endpoint accepts user input directly. Classic injection point...")
        dashboard.refresh()
        await asyncio.sleep(1.5)

        dashboard.phase_tracker.update_phase("analysis", tasks_done=3)
        dashboard.add_log("Authentication endpoints found: /rest/user/login", level="success", source="analyzer")
        dashboard.refresh()
        await asyncio.sleep(1)

        dashboard.phase_tracker.update_phase("analysis", tasks_done=4)
        dashboard.phase_tracker.complete_phase("analysis")
        dashboard.add_log("Analysis complete: 23 potential vulns identified", level="success", source="analyzer")
        dashboard.update_llm_stats(tokens=5000, requests=4)
        dashboard.refresh()
        await asyncio.sleep(1)

        # ---- PHASE 3: PLANNING ----
        dashboard.phase_tracker.start_phase("planning", total_tasks=2)
        dashboard.add_log("Creating attack plan", level="info", source="planner")
        dashboard.set_model_info("nvidia", "qwq-32b")
        dashboard.set_ai_thought("Prioritizing: SQLi on /api/products first, then XSS on search, then auth bypass...")
        dashboard.update_llm_stats(tokens=2800, requests=2)
        dashboard.refresh()
        await asyncio.sleep(2)

        dashboard.phase_tracker.update_phase("planning", tasks_done=1)
        dashboard.add_log("Generated 15 attack tasks", level="success", source="planner")
        dashboard.refresh()
        await asyncio.sleep(1)

        dashboard.phase_tracker.complete_phase("planning")
        dashboard.add_log("Attack plan ready", level="success", source="planner")
        dashboard.refresh()
        await asyncio.sleep(1)

        # ---- PHASE 4: EXECUTION ----
        dashboard.phase_tracker.start_phase("execution", total_tasks=8)
        dashboard.add_log("Starting attack execution", level="info", source="executor")
        dashboard.set_model_info("nvidia", "deepseek-v3.1-terminus")
        dashboard.refresh()
        await asyncio.sleep(1)

        # Finding 1: SQL Injection
        dashboard.set_current_action("Testing SQL Injection on /api/products")
        dashboard.add_log("Running sqlmap on /api/products?q=", level="action", source="executor")
        dashboard.set_ai_thought("Testing basic SQLi payloads: ' OR 1=1--, UNION SELECT...")
        dashboard.increment_tools_run()
        dashboard.refresh()
        await asyncio.sleep(2)

        dashboard.add_finding_simple(
            title="SQL Injection in Product Search",
            severity="critical",
            vuln_type="SQL Injection",
            location="/api/products?q=",
            details="UNION-based SQL injection in search parameter",
        )
        dashboard.add_log("🎯 CRITICAL: SQL Injection found in /api/products?q=", level="finding", source="sqlmap")
        dashboard.phase_tracker.update_phase("execution", tasks_done=1)
        dashboard.update_llm_stats(tokens=1500, requests=2)
        dashboard.refresh()
        await asyncio.sleep(1.5)

        # Finding 2: XSS
        dashboard.set_current_action("Testing XSS on search functionality")
        dashboard.add_log("Running dalfox on search endpoint", level="action", source="executor")
        dashboard.increment_tools_run()
        dashboard.refresh()
        await asyncio.sleep(1.5)

        dashboard.add_finding_simple(
            title="Reflected XSS in Search",
            severity="high",
            vuln_type="Cross-Site Scripting",
            location="/search?q=",
            details="Reflected XSS via script tag injection",
        )
        dashboard.add_log("🎯 HIGH: Reflected XSS in /search?q=", level="finding", source="dalfox")
        dashboard.phase_tracker.update_phase("execution", tasks_done=2)
        dashboard.refresh()
        await asyncio.sleep(1.5)

        # Finding 3: IDOR
        dashboard.set_current_action("Testing IDOR on user endpoints")
        dashboard.add_log("Testing /api/users/1 vs /api/users/2", level="action", source="executor")
        dashboard.set_ai_thought("Changing user ID in request. If I can access other user data = IDOR...")
        dashboard.increment_tools_run()
        dashboard.refresh()
        await asyncio.sleep(1.5)

        dashboard.add_finding_simple(
            title="IDOR on User Profile API",
            severity="high",
            vuln_type="IDOR",
            location="/api/users/{id}",
            details="Can access any user profile by changing ID",
        )
        dashboard.add_log("🎯 HIGH: IDOR found on /api/users/{id}", level="finding", source="curl")
        dashboard.phase_tracker.update_phase("execution", tasks_done=3)
        dashboard.refresh()
        await asyncio.sleep(1.5)

        # Finding 4: Exposed Admin Panel
        dashboard.add_finding_simple(
            title="Exposed Admin Panel",
            severity="medium",
            vuln_type="Information Disclosure",
            location="/admin",
            details="Admin panel accessible without authentication",
        )
        dashboard.add_log("🎯 MEDIUM: Admin panel exposed at /admin", level="finding", source="ffuf")
        dashboard.phase_tracker.update_phase("execution", tasks_done=4)
        dashboard.refresh()
        await asyncio.sleep(1)

        # More execution steps...
        dashboard.add_log("Testing file upload functionality", level="action", source="executor")
        dashboard.phase_tracker.update_phase("execution", tasks_done=5)
        dashboard.increment_tools_run()
        dashboard.refresh()
        await asyncio.sleep(1)

        dashboard.add_finding_simple(
            title="Missing Rate Limiting on Login",
            severity="medium",
            vuln_type="Brute Force",
            location="/rest/user/login",
            details="No rate limiting on authentication endpoint",
        )
        dashboard.add_log("🎯 MEDIUM: No rate limiting on login", level="finding", source="curl")
        dashboard.phase_tracker.update_phase("execution", tasks_done=6)
        dashboard.refresh()
        await asyncio.sleep(1)

        dashboard.add_finding_simple(
            title="CORS Misconfiguration",
            severity="low",
            vuln_type="CORS",
            location="/*",
            details="Wildcard Access-Control-Allow-Origin",
        )
        dashboard.add_log("🎯 LOW: CORS misconfiguration detected", level="finding", source="curl")
        dashboard.phase_tracker.update_phase("execution", tasks_done=7)
        dashboard.refresh()
        await asyncio.sleep(1)

        dashboard.add_finding_simple(
            title="Server Version Disclosure",
            severity="info",
            vuln_type="Information Disclosure",
            location="HTTP Headers",
            details="X-Powered-By: Express header present",
        )
        dashboard.phase_tracker.update_phase("execution", tasks_done=8)
        dashboard.phase_tracker.complete_phase("execution")
        dashboard.add_log("Execution phase COMPLETE", level="success", source="orchestrator")
        dashboard.update_llm_stats(tokens=8000, requests=10)
        dashboard.refresh()
        await asyncio.sleep(1)

        # ---- PHASE 5: REPORTING ----
        dashboard.phase_tracker.start_phase("reporting", total_tasks=2)
        dashboard.add_log("Generating vulnerability report", level="info", source="reporter")
        dashboard.set_ai_thought("Compiling 7 findings into professional report with PoC details...")
        dashboard.set_model_info("nvidia", "deepseek-v3.2")
        dashboard.refresh()
        await asyncio.sleep(2)

        dashboard.phase_tracker.update_phase("reporting", tasks_done=1)
        dashboard.add_log("Report generated: vapt_report_20250714.md", level="success", source="reporter")
        dashboard.update_llm_stats(tokens=4000, requests=3)
        dashboard.refresh()
        await asyncio.sleep(1)

        dashboard.phase_tracker.complete_phase("reporting")
        dashboard.add_log("✨ SCAN COMPLETE! All phases finished.", level="success", source="orchestrator")
        dashboard.refresh()
        await asyncio.sleep(3)

    # Print final report
    elapsed = dashboard._get_elapsed_time()
    print_final_report_summary(
        findings=dashboard.findings,
        elapsed=elapsed,
        stats={
            "requests": dashboard.total_requests,
            "tokens": dashboard.total_tokens,
            "tools": dashboard.tools_run,
        },
    )


if __name__ == "__main__":
    asyncio.run(simulate_scan())