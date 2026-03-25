```markdown
# V2.0 Quality Checklist
# Check each item after building each module

## Phase 1: HTTP Client
- [ ] Can make GET/POST/PUT/DELETE requests
- [ ] Cookies persist across requests
- [ ] JWT token auto-added to headers after login
- [ ] Response analysis methods work
- [ ] Rate limiting works
- [ ] Request history is stored
- Test: `python -c "from core.http_client import SmartHTTPClient; print('OK')"`

## Phase 2: Browser Engine  
- [ ] Playwright launches Chromium headless
- [ ] Can navigate to Juice Shop
- [ ] Network requests are intercepted
- [ ] JS routes are extracted
- [ ] Forms are discovered
- Test: `python -c "from core.browser_engine import BrowserEngine; print('OK')"`

## Phase 3: State Manager
- [ ] State saves to JSON file
- [ ] State loads from JSON file
- [ ] Thread-safe operations
- [ ] Credentials stored properly
- [ ] Tested endpoints tracked
- Test: `python -c "from core.state_manager import ScanState; print('OK')"`

## Phase 4: Payload Engine
- [ ] SQLite injection payloads present (20+)
- [ ] Angular XSS payloads present (15+)
- [ ] IDOR payloads present
- [ ] JWT attack payloads present
- [ ] Context-aware selection works
- Test: `python -c "from core.payload_engine import PayloadEngine; p=PayloadEngine(); print(len(p.get_payloads('sqli')))"`

## Phase 5: Auth Agent
- [ ] Finds login endpoint
- [ ] Registers test account
- [ ] Logs in successfully  
- [ ] Captures JWT token
- [ ] Tries SQLi login bypass
- [ ] Stores credentials in state
- Test on Juice Shop: Does it register + login?

## Phase 6: Recon Agent V2
- [ ] Browser crawling works
- [ ] JS analysis finds hidden routes
- [ ] API endpoints discovered (20+ on Juice Shop)
- [ ] Auth requirements detected per endpoint
- [ ] Concurrent execution works
- Test on Juice Shop: Does it find /api/Users, /rest/user/login, /#/administration?

## Phase 7: Scanner Agent
- [ ] Tests each endpoint for each vuln type
- [ ] SQLi detected on /rest/user/login
- [ ] XSS detected on search
- [ ] IDOR detected on /api/users
- [ ] AI response analysis works
- [ ] Findings saved to state
- Test on Juice Shop: Does it find 10+ vulnerabilities?

## Phase 8: Orchestrator
- [ ] LangGraph workflow runs
- [ ] Dynamic decision making works
- [ ] Chain attacks work (SQLi → credential dump → IDOR)
- [ ] All phases execute
- [ ] Dashboard updates in real-time

## FINAL TEST:
python main.py auto http://localhost:42000 --high
Expected: 40+ Juice Shop challenges solved