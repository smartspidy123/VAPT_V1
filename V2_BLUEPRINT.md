# VAPT-AI V2.0 - Master Blueprint
# ================================
# This document is the COMPLETE technical specification
# for upgrading VAPT-AI from V1.0 to V2.0
#
# Give this to ANY AI coding assistant (Roo Code, Cursor, etc.)
# along with the phase-specific prompts to build each module.

## CURRENT STATE (V1.0 - Already Built):
Working files that MUST NOT be modified unless specified:
- config/settings.py (add new settings only)
- config/prompts.py (will be heavily upgraded)
- core/llm_router.py (working, keep as is)
- core/tool_engine.py (working, keep as is)
- core/dashboard.py (working, keep as is)
- tools/*.py (working, keep as is)
- utils/logger.py (working, keep as is)

## V2.0 GOAL:
Transform from "surface scanner" to "intelligent pentester" that can:
1. Browse web apps like a human (headless browser)
2. Register + Login automatically
3. Understand application structure from JavaScript
4. Perform authenticated attacks
5. Chain findings (use one vuln to find another)
6. Generate context-aware payloads
7. Run attacks in parallel  
8. Remember state across the entire scan

## V2.0 NEW FILES TO CREATE:

### Core Layer:
- core/browser_engine.py      → Playwright headless browser
- core/http_client.py         → Smart HTTP client with sessions
- core/state_manager.py       → Persistent scan state/memory
- core/payload_engine.py      → Context-aware payload generation

### Agent Layer (REPLACE old agents):
- agents/v2_orchestrator.py   → Main ReAct agent (LangGraph)
- agents/v2_recon.py          → Enhanced recon with browser
- agents/v2_auth.py           → Authentication agent
- agents/v2_scanner.py        → Vulnerability scanner agent
- agents/v2_exploiter.py      → Exploitation + chaining agent
- agents/v2_reporter.py       → Enhanced reporter

### Attack Modules:
- attacks/__init__.py
- attacks/sqli.py             → SQL Injection module
- attacks/xss.py              → XSS module (DOM, Reflected, Stored)
- attacks/idor.py             → IDOR/Access Control module
- attacks/auth_bypass.py      → Authentication bypass module
- attacks/jwt_attacks.py      → JWT attack module
- attacks/xxe.py              → XXE attack module
- attacks/ssrf.py             → SSRF module
- attacks/file_upload.py      → File upload attack module
- attacks/nosql.py            → NoSQL injection module
- attacks/input_validation.py → Input validation bypass module

### Updated:
- main.py                     → Updated entry point
- config/settings.py          → New settings added
- config/prompts.py           → Completely new prompts
- requirements.txt            → New dependencies

## TECH STACK ADDITIONS:
- playwright (headless browser)
- httpx (async HTTP client, replaces curl dependency)
- beautifulsoup4 + lxml (HTML parsing)
- pyjwt (JWT manipulation)
- asyncio (concurrent execution)

## ARCHITECTURE DIAGRAM:

┌──────────────────────────────────────────────────────────┐
│ VAPT-AI V2.0 │
│ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ V2 ORCHESTRATOR (ReAct Agent) │ │
│ │ Uses LangGraph to DECIDE what to do next │ │
│ │ Has MEMORY of everything found so far │ │
│ │ Can CHAIN: finding A → attack B → finding C │ │
│ └────────────────────┬────────────────────────────────┘ │
│ │ │
│ ┌───────────┼───────────┐ │
│ ▼ ▼ ▼ │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ RECON │ │ AUTH │ │ SCANNER │ │
│ │ Agent │ │ Agent │ │ Agent │ │
│ └────┬─────┘ └────┬─────┘ └────┬─────┘ │
│ │ │ │ │
│ ▼ ▼ ▼ │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │EXPLOITER │ │ REPORTER │ │ ATTACK │ │
│ │ Agent │ │ Agent │ │ MODULES │ │
│ └──────────┘ └──────────┘ └──────────┘ │
│ │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ CORE ENGINES │ │
│ │ Browser│HTTP Client│State│Payloads│LLM│Tools│UI │ │
│ └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘

## CRITICAL DESIGN PRINCIPLES:

1. AGENT AUTONOMY: Orchestrator decides flow, not hardcoded
2. STATE PERSISTENCE: Every finding saved, used for next decision
3. AUTHENTICATED TESTING: Most tests run after login
4. BROWSER-FIRST: Use headless browser for SPA apps
5. PARALLEL WHERE SAFE: Concurrent recon, sequential attacks
6. CONTEXT-AWARE PAYLOADS: SQLite payloads for SQLite DB, etc.
7. CHAIN ATTACKS: Use SQLi creds to test IDOR, etc.
8. SMART VERIFICATION: AI analyzes EVERY response deeply