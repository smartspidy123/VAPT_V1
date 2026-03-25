"""
VAPT-AI Reconnaissance Agent
==============================
AI-powered reconnaissance agent that performs comprehensive
information gathering on the target using multiple security tools.

This agent:
1. Enumerates subdomains
2. Scans ports and services
3. Detects technologies
4. Discovers directories and files
5. Crawls for endpoints
6. Detects WAF
7. Analyzes JavaScript files
8. Compiles all findings into structured recon data
"""

import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime

from langchain_core.messages import HumanMessage, SystemMessage
from rich.console import Console

from config.prompts import RECON_AGENT_PROMPT
from core.dashboard import Dashboard

console = Console()


class ReconAgent:
    """
    Reconnaissance Agent - Phase 1 of VAPT-AI pipeline.
    
    Uses security tools + LLM to perform comprehensive recon:
    - Passive recon (subfinder, DNS)
    - Active recon (nmap, httpx, whatweb)
    - Content discovery (ffuf, katana)
    - WAF detection (wafw00f)
    - LLM-powered analysis of findings
    """

    def __init__(self, llm_router, tool_engine, dashboard: Dashboard = None):
        self.llm_router = llm_router
        self.tool_engine = tool_engine
        self.dashboard = dashboard
        self.recon_data = {}
        self.target = ""
        self.domain = ""
        self.base_url = ""

    def _log(self, message: str, level: str = "info"):
        """Log to dashboard and console."""
        if self.dashboard:
            self.dashboard.add_log(message, level=level, source="recon")
            self.dashboard.refresh()
        console.print(f"  [dim][recon][/dim] {message}")

    def _update_progress(self, tasks_done: int):
        """Update dashboard progress."""
        if self.dashboard:
            self.dashboard.phase_tracker.update_phase("recon", tasks_done=tasks_done)
            self.dashboard.refresh()

    def _set_ai_thought(self, thought: str):
        """Update AI thought on dashboard."""
        if self.dashboard:
            self.dashboard.set_ai_thought(thought)
            self.dashboard.refresh()

    def _parse_target(self, target: str):
        """Parse target URL into components."""
        self.target = target.rstrip("/")

        # Extract domain
        if "://" in target:
            self.base_url = self.target
            self.domain = target.split("://")[1].split("/")[0].split(":")[0]
        else:
            self.domain = target.split("/")[0].split(":")[0]
            self.base_url = f"http://{self.target}"

    async def run(self, target: str, intensity: str = "medium") -> Dict[str, Any]:
        """
        Run full reconnaissance on the target.
        
        Args:
            target: Target URL or domain
            intensity: Scan intensity (low, medium, high)
            
        Returns:
            Dict with all recon findings
        """
        self._parse_target(target)

        self._log(f"Starting reconnaissance on: {self.target}", "info")
        self._set_ai_thought(f"Beginning recon on {self.domain}. Will start with passive methods then move to active scanning...")

        # Initialize recon data structure
        self.recon_data = {
            "target": self.target,
            "domain": self.domain,
            "base_url": self.base_url,
            "scan_time": datetime.now().isoformat(),
            "intensity": intensity,
            "subdomains": [],
            "open_ports": [],
            "technologies": [],
            "directories": [],
            "endpoints": [],
            "waf": "unknown",
            "ssl_info": {},
            "headers": {},
            "js_files": [],
            "interesting_findings": [],
            "raw_outputs": {},
        }

        # Determine which tasks to run based on intensity
        tasks = self._get_tasks_for_intensity(intensity)
        total_tasks = len(tasks)

        if self.dashboard:
            self.dashboard.phase_tracker.start_phase("recon", total_tasks=total_tasks)

        # Execute each recon task
        task_index = 0
        for task_name, task_func in tasks:
            task_index += 1
            self._log(f"[{task_index}/{total_tasks}] {task_name}", "action")

            if self.dashboard:
                self.dashboard.set_current_action(task_name)

            try:
                await task_func()
            except Exception as e:
                self._log(f"Error in {task_name}: {e}", "error")

            self._update_progress(task_index)

        # AI-powered analysis of all collected data
        self._log("AI analyzing all recon data...", "action")
        self._set_ai_thought("Analyzing all collected data to identify attack surface and potential vulnerabilities...")
        await self._ai_analyze_recon()

        # Complete phase
        if self.dashboard:
            self.dashboard.phase_tracker.complete_phase("recon")

        self._log(f"Reconnaissance COMPLETE - collected {self._get_stats_summary()}", "success")

        return self.recon_data

    def _get_tasks_for_intensity(self, intensity: str) -> list:
        """Get recon tasks based on scan intensity."""
        # Core tasks (always run)
        core_tasks = [
            ("WAF Detection", self._detect_waf),
            ("Technology Detection", self._detect_technologies),
            ("Port Scanning", self._scan_ports),
            ("HTTP Header Analysis", self._analyze_headers),
            ("Directory Discovery", self._discover_directories),
            ("Web Crawling & Endpoint Discovery", self._crawl_endpoints),
        ]

        if intensity == "low":
            return core_tasks

        # Medium adds subdomain enum and more
        medium_tasks = core_tasks + [
            ("Subdomain Enumeration", self._enumerate_subdomains),
            ("JavaScript File Analysis", self._analyze_js_files),
        ]

        if intensity == "medium":
            return medium_tasks

        # High adds everything
        high_tasks = medium_tasks + [
            ("Deep Crawling", self._deep_crawl),
            ("Nikto Web Server Scan", self._run_nikto),
            ("Nuclei Info Scan", self._run_nuclei_info),
        ]

        return high_tasks

    # ============================================
    # RECON TASKS
    # ============================================

    async def _detect_waf(self):
        """Detect Web Application Firewall."""
        self._set_ai_thought("Checking for WAF first - this will determine our payload strategy...")

        if not self.tool_engine.is_tool_available("wafw00f"):
            self._log("wafw00f not available, skipping WAF detection", "warning")
            return

        cmd = self.tool_engine.build_wafw00f_command(self.base_url)
        result = await self.tool_engine.execute_command(cmd, timeout=60, tool_name="wafw00f")

        if self.dashboard:
            self.dashboard.increment_tools_run()

        if result.success:
            self.recon_data["raw_outputs"]["wafw00f"] = result.stdout

            if result.parsed_output:
                waf = result.parsed_output.get("waf_detected", "unknown")
                self.recon_data["waf"] = waf
                if waf and waf != "none":
                    self._log(f"WAF Detected: {waf}", "warning")
                    self._set_ai_thought(f"WAF detected: {waf}. Will need bypass techniques for payloads...")
                else:
                    self._log("No WAF detected - good for testing!", "success")
                    self._set_ai_thought("No WAF detected! Direct payloads should work...")
            else:
                # Parse manually
                output_lower = result.stdout.lower()
                if "is behind" in output_lower:
                    waf_name = result.stdout.split("is behind")[-1].strip().split("\n")[0]
                    self.recon_data["waf"] = waf_name
                    self._log(f"WAF Detected: {waf_name}", "warning")
                elif "no waf" in output_lower or "not behind" in output_lower:
                    self.recon_data["waf"] = "none"
                    self._log("No WAF detected", "success")
        else:
            self._log(f"WAF detection failed: {result.stderr[:100]}", "warning")

    async def _detect_technologies(self):
        """Detect web technologies using whatweb."""
        self._set_ai_thought("Identifying tech stack - this tells me what vulnerabilities to look for...")

        if not self.tool_engine.is_tool_available("whatweb"):
            # Fallback to curl header analysis
            self._log("whatweb not available, using curl fallback", "warning")
            await self._tech_detect_fallback()
            return

        cmd = self.tool_engine.build_whatweb_command(self.base_url, aggression=3)
        result = await self.tool_engine.execute_command(cmd, timeout=120, tool_name="whatweb")

        if self.dashboard:
            self.dashboard.increment_tools_run()

        if result.success:
            self.recon_data["raw_outputs"]["whatweb"] = result.stdout

            if result.parsed_output:
                techs = result.parsed_output.get("technologies", [])
                self.recon_data["technologies"] = techs
                self._log(f"Technologies found: {', '.join(techs[:10])}", "success")
            else:
                # Store raw output for AI analysis
                self.recon_data["technologies_raw"] = result.stdout
                self._log("Technology detection complete (raw data saved)", "success")

            self._set_ai_thought(f"Tech stack identified. Looking for known CVEs in these technologies...")

    async def _tech_detect_fallback(self):
        """Fallback tech detection using curl headers."""
        cmd = self.tool_engine.build_curl_command(
            url=self.base_url,
            method="HEAD",
            include_headers=True,
            follow_redirects=True,
        )
        result = await self.tool_engine.execute_command(cmd, timeout=30, tool_name="curl")

        if result.success:
            headers_text = result.stdout
            techs = []

            tech_indicators = {
                "x-powered-by": "Server Framework",
                "server": "Web Server",
                "x-aspnet": "ASP.NET",
                "x-drupal": "Drupal",
                "x-generator": "CMS",
                "x-wordpress": "WordPress",
            }

            for line in headers_text.split("\n"):
                line_lower = line.lower()
                for indicator, tech_type in tech_indicators.items():
                    if indicator in line_lower:
                        techs.append(f"{tech_type}: {line.strip()}")

            self.recon_data["technologies"] = techs
            if techs:
                self._log(f"Technologies (from headers): {', '.join(techs)}", "success")

    async def _scan_ports(self):
        """Scan ports using nmap."""
        self._set_ai_thought("Scanning for open ports - each port is a potential entry point...")

        if not self.tool_engine.is_tool_available("nmap"):
            self._log("nmap not available, skipping port scan", "warning")
            return

        # Use quick scan for speed, full scan for high intensity
        scan_type = "default"
        cmd = self.tool_engine.build_nmap_command(
            target=self.domain,
            scan_type=scan_type,
            ports="1-10000",
        )
        result = await self.tool_engine.execute_command(cmd, timeout=300, tool_name="nmap")

        if self.dashboard:
            self.dashboard.increment_tools_run()

        if result.success:
            self.recon_data["raw_outputs"]["nmap"] = result.stdout

            if result.parsed_output:
                ports = result.parsed_output.get("open_ports", [])
                self.recon_data["open_ports"] = ports
                services = result.parsed_output.get("services", [])

                port_summary = ", ".join(
                    [f"{p['port']}/{p['service']}" for p in ports[:10]]
                )
                self._log(f"Open ports: {port_summary}", "success")

                if len(ports) > 5:
                    self._set_ai_thought(f"Found {len(ports)} open ports. Multiple services = larger attack surface...")
            else:
                self.recon_data["nmap_raw"] = result.stdout
                self._log("Port scan complete (raw data saved)", "success")

    async def _analyze_headers(self):
        """Analyze HTTP response headers for security issues."""
        self._set_ai_thought("Checking HTTP headers for security misconfigurations...")

        cmd = self.tool_engine.build_curl_command(
            url=self.base_url,
            method="GET",
            include_headers=True,
            extra_args="-o /dev/null -D -",
        )
        result = await self.tool_engine.execute_command(cmd, timeout=30, tool_name="curl")

        if self.dashboard:
            self.dashboard.increment_tools_run()

        if result.success:
            headers = {}
            security_issues = []

            for line in result.stdout.split("\n"):
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key.strip().lower()] = value.strip()

            self.recon_data["headers"] = headers

            # Check for missing security headers
            security_headers = {
                "strict-transport-security": "HSTS",
                "content-security-policy": "CSP",
                "x-content-type-options": "X-Content-Type-Options",
                "x-frame-options": "X-Frame-Options",
                "x-xss-protection": "X-XSS-Protection",
                "referrer-policy": "Referrer-Policy",
                "permissions-policy": "Permissions-Policy",
            }

            for header, name in security_headers.items():
                if header not in headers:
                    security_issues.append(f"Missing {name} header")

            # Check for information disclosure
            info_headers = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]
            for header in info_headers:
                if header in headers:
                    security_issues.append(f"Information disclosure: {header}: {headers[header]}")

            if security_issues:
                self.recon_data["interesting_findings"].extend(security_issues)
                self._log(f"Found {len(security_issues)} header issues", "warning")
                for issue in security_issues[:3]:
                    self._log(f"  → {issue}", "info")
            else:
                self._log("Headers look secure", "success")

    async def _discover_directories(self):
        """Discover hidden directories using ffuf."""
        self._set_ai_thought("Fuzzing for hidden directories - /admin, /backup, .git, .env...")

        if not self.tool_engine.is_tool_available("ffuf"):
            self._log("ffuf not available, skipping directory discovery", "warning")
            return

        cmd = self.tool_engine.build_ffuf_command(
            target_url=self.base_url,
            wordlist="/usr/share/wordlists/dirb/common.txt",
        )
        result = await self.tool_engine.execute_command(cmd, timeout=180, tool_name="ffuf")

        if self.dashboard:
            self.dashboard.increment_tools_run()

        if result.success:
            self.recon_data["raw_outputs"]["ffuf"] = result.stdout

            # Parse found directories
            directories = []
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("["):
                    directories.append(line)

            self.recon_data["directories"] = directories
            if directories:
                self._log(f"Found {len(directories)} directories/files", "success")
                # Log first few interesting ones
                for d in directories[:5]:
                    self._log(f"  → {d}", "info")
            else:
                self._log("No hidden directories found", "info")

    async def _crawl_endpoints(self):
        """Crawl the web application to discover endpoints."""
        self._set_ai_thought("Crawling the application to map all endpoints and forms...")

        if not self.tool_engine.is_tool_available("katana"):
            # Fallback to simpler crawling
            self._log("katana not available, using basic crawling", "warning")
            await self._basic_crawl()
            return

        cmd = self.tool_engine.build_katana_command(
            target=self.base_url,
            depth=3,
            extra_args="-jc -kf -ef css,png,jpg,gif,svg,ico,woff,woff2,ttf",
        )
        result = await self.tool_engine.execute_command(cmd, timeout=180, tool_name="katana")

        if self.dashboard:
            self.dashboard.increment_tools_run()

        if result.success:
            self.recon_data["raw_outputs"]["katana"] = result.stdout

            endpoints = []
            js_files = []
            for line in result.stdout.split("\n"):
                line = line.strip()
                if not line:
                    continue
                endpoints.append(line)
                if line.endswith(".js"):
                    js_files.append(line)

            self.recon_data["endpoints"] = endpoints
            self.recon_data["js_files"] = js_files

            self._log(f"Crawled {len(endpoints)} endpoints, {len(js_files)} JS files", "success")

    async def _basic_crawl(self):
        """Basic crawling fallback using curl."""
        cmd = self.tool_engine.build_curl_command(
            url=self.base_url,
            method="GET",
            include_headers=False,
        )
        result = await self.tool_engine.execute_command(cmd, timeout=30, tool_name="curl")

        if result.success:
            # Extract links from HTML
            import re
            urls = re.findall(r'href=["\']([^"\']+)["\']', result.stdout)
            urls += re.findall(r'src=["\']([^"\']+)["\']', result.stdout)
            urls += re.findall(r'action=["\']([^"\']+)["\']', result.stdout)

            # Filter and deduplicate
            unique_urls = list(set(urls))
            self.recon_data["endpoints"] = unique_urls
            js_files = [u for u in unique_urls if u.endswith(".js")]
            self.recon_data["js_files"] = js_files

            self._log(f"Basic crawl found {len(unique_urls)} URLs", "success")

    async def _enumerate_subdomains(self):
        """Enumerate subdomains using subfinder."""
        self._set_ai_thought(f"Finding subdomains of {self.domain} to expand attack surface...")

        if not self.tool_engine.is_tool_available("subfinder"):
            self._log("subfinder not available, skipping subdomain enum", "warning")
            return

        cmd = self.tool_engine.build_subfinder_command(self.domain)
        result = await self.tool_engine.execute_command(cmd, timeout=120, tool_name="subfinder")

        if self.dashboard:
            self.dashboard.increment_tools_run()

        if result.success:
            self.recon_data["raw_outputs"]["subfinder"] = result.stdout

            subdomains = [
                line.strip()
                for line in result.stdout.split("\n")
                if line.strip() and not line.startswith("[")
            ]

            self.recon_data["subdomains"] = subdomains
            self._log(f"Found {len(subdomains)} subdomains", "success")

            if subdomains:
                for sub in subdomains[:5]:
                    self._log(f"  → {sub}", "info")

    async def _analyze_js_files(self):
        """Analyze JavaScript files for secrets and endpoints."""
        self._set_ai_thought("Analyzing JavaScript files for hardcoded secrets, API keys, endpoints...")

        js_files = self.recon_data.get("js_files", [])
        if not js_files:
            self._log("No JS files to analyze", "info")
            return

        js_findings = []

        # Analyze first 10 JS files
        for js_url in js_files[:10]:
            # Make URL absolute
            if js_url.startswith("/"):
                js_url = f"{self.base_url}{js_url}"
            elif not js_url.startswith("http"):
                js_url = f"{self.base_url}/{js_url}"

            cmd = self.tool_engine.build_curl_command(
                url=js_url,
                method="GET",
                include_headers=False,
            )
            result = await self.tool_engine.execute_command(
                cmd, timeout=30, tool_name="curl"
            )

            if result.success and result.stdout:
                # Use LLM to analyze JS content
                js_content = result.stdout[:3000]  # Limit size

                llm_response = await self.llm_router.query(
                    prompt=f"""Analyze this JavaScript code for security issues. Look for:
1. Hardcoded API keys, tokens, secrets
2. Hidden API endpoints
3. Authentication logic that can be bypassed
4. Debug/development code left in production
5. Sensitive data in comments

JavaScript from {js_url}:

{js_content}

Return ONLY a JSON list of findings. If nothing found, return [].
Format: [{{"type": "secret/endpoint/debug", "detail": "description", "value": "the actual finding"}}]""",
                    system_prompt="You are a JavaScript security analyst. Be precise and only report real findings.",
                    task_type="code_analysis",
                )

                if llm_response.success:
                    if self.dashboard:
                        self.dashboard.update_llm_stats(
                            tokens=llm_response.total_tokens,
                            requests=1,
                        )

                    try:
                        # Try to parse findings
                        content = llm_response.content.strip()
                        if content.startswith("```"):
                            content = content.split("```")[1]
                            if content.startswith("json"):
                                content = content[4:]
                        findings = json.loads(content)
                        if findings and isinstance(findings, list):
                            js_findings.extend(findings)
                            self._log(f"Found {len(findings)} issues in {js_url.split('/')[-1]}", "warning")
                    except (json.JSONDecodeError, IndexError):
                        pass

        self.recon_data["js_analysis"] = js_findings
        if js_findings:
            self._log(f"Total JS findings: {len(js_findings)}", "success")
            self.recon_data["interesting_findings"].extend(
                [f"JS: {f.get('type', 'unknown')}: {f.get('detail', 'N/A')}" for f in js_findings]
            )

    async def _deep_crawl(self):
        """Deep crawling with higher depth."""
        self._set_ai_thought("Deep crawling with higher depth for hidden pages...")

        if not self.tool_engine.is_tool_available("katana"):
            return

        cmd = self.tool_engine.build_katana_command(
            target=self.base_url,
            depth=5,
            extra_args="-jc -kf -ef css,png,jpg,gif,svg,ico,woff,woff2,ttf -fs rdn",
        )
        result = await self.tool_engine.execute_command(cmd, timeout=300, tool_name="katana")

        if self.dashboard:
            self.dashboard.increment_tools_run()

        if result.success:
            new_endpoints = []
            existing = set(self.recon_data.get("endpoints", []))

            for line in result.stdout.split("\n"):
                line = line.strip()
                if line and line not in existing:
                    new_endpoints.append(line)

            self.recon_data["endpoints"].extend(new_endpoints)
            self._log(f"Deep crawl found {len(new_endpoints)} additional endpoints", "success")

    async def _run_nikto(self):
        """Run nikto web server scan."""
        self._set_ai_thought("Running Nikto for comprehensive web server vulnerability checks...")

        if not self.tool_engine.is_tool_available("nikto"):
            return

        cmd = self.tool_engine.build_nikto_command(self.base_url, extra_args="-maxtime 120")
        result = await self.tool_engine.execute_command(cmd, timeout=180, tool_name="nikto")

        if self.dashboard:
            self.dashboard.increment_tools_run()

        if result.success:
            self.recon_data["raw_outputs"]["nikto"] = result.stdout
            self._log("Nikto scan complete", "success")

    async def _run_nuclei_info(self):
        """Run nuclei with info-level templates for basic checks."""
        self._set_ai_thought("Running Nuclei info templates for quick vulnerability fingerprinting...")

        if not self.tool_engine.is_tool_available("nuclei"):
            return

        cmd = self.tool_engine.build_nuclei_command(
            target=self.base_url,
            severity="info,low",
        )
        result = await self.tool_engine.execute_command(cmd, timeout=300, tool_name="nuclei")

        if self.dashboard:
            self.dashboard.increment_tools_run()

        if result.success:
            self.recon_data["raw_outputs"]["nuclei_info"] = result.stdout
            if result.parsed_output:
                findings_count = result.parsed_output.get("total_findings", 0)
                self._log(f"Nuclei found {findings_count} info/low findings", "success")

    # ============================================
    # AI ANALYSIS
    # ============================================

    async def _ai_analyze_recon(self):
        """Use AI to analyze all collected recon data and identify key insights."""
        # Prepare summary for AI
        summary = self._build_recon_summary()

        llm_response = await self.llm_router.query(
            prompt=f"""Analyze the following reconnaissance data and provide:
1. A summary of the target's attack surface
2. Key technologies and their known vulnerability categories
3. Most promising attack vectors based on the data
4. Any notable security issues already visible
5. Recommended next steps for vulnerability testing

RECON DATA:
{summary}

Provide your analysis in a structured format.""",
            system_prompt=RECON_AGENT_PROMPT,
            task_type="vulnerability_analysis",
        )

        if llm_response.success:
            self.recon_data["ai_analysis"] = llm_response.content

            if self.dashboard:
                self.dashboard.update_llm_stats(
                    tokens=llm_response.total_tokens,
                    requests=1,
                )

            self._log("AI analysis of recon data complete", "success")
            self._set_ai_thought("Recon analysis done. Identified key attack vectors and entry points...")
        else:
            self._log(f"AI analysis failed: {llm_response.error}", "error")

    def _build_recon_summary(self) -> str:
        """Build a text summary of recon data for AI analysis."""
        parts = []

        parts.append(f"TARGET: {self.target}")
        parts.append(f"DOMAIN: {self.domain}")

        if self.recon_data.get("waf"):
            parts.append(f"WAF: {self.recon_data['waf']}")

        if self.recon_data.get("technologies"):
            techs = self.recon_data["technologies"]
            if isinstance(techs, list):
                parts.append(f"TECHNOLOGIES: {', '.join(techs[:20])}")

        if self.recon_data.get("open_ports"):
            ports = self.recon_data["open_ports"]
            port_str = ", ".join(
                [f"{p['port']}/{p['service']}" for p in ports[:15]]
            )
            parts.append(f"OPEN PORTS: {port_str}")

        if self.recon_data.get("subdomains"):
            subs = self.recon_data["subdomains"]
            parts.append(f"SUBDOMAINS ({len(subs)}): {', '.join(subs[:10])}")

        if self.recon_data.get("directories"):
            dirs = self.recon_data["directories"]
            parts.append(f"DIRECTORIES ({len(dirs)}): {', '.join(dirs[:15])}")

        if self.recon_data.get("endpoints"):
            eps = self.recon_data["endpoints"]
            parts.append(f"ENDPOINTS ({len(eps)}): {', '.join(eps[:20])}")

        if self.recon_data.get("headers"):
            headers = self.recon_data["headers"]
            parts.append(f"RESPONSE HEADERS: {json.dumps(headers, indent=2)}")

        if self.recon_data.get("interesting_findings"):
            findings = self.recon_data["interesting_findings"]
            parts.append(f"NOTABLE FINDINGS: {chr(10).join(findings[:10])}")

        if self.recon_data.get("js_analysis"):
            js = self.recon_data["js_analysis"]
            parts.append(f"JS ANALYSIS ({len(js)} findings): {json.dumps(js[:5])}")

        return "\n\n".join(parts)

    def _get_stats_summary(self) -> str:
        """Get a brief stats summary."""
        stats = []
        if self.recon_data.get("subdomains"):
            stats.append(f"{len(self.recon_data['subdomains'])} subdomains")
        if self.recon_data.get("open_ports"):
            stats.append(f"{len(self.recon_data['open_ports'])} ports")
        if self.recon_data.get("endpoints"):
            stats.append(f"{len(self.recon_data['endpoints'])} endpoints")
        if self.recon_data.get("directories"):
            stats.append(f"{len(self.recon_data['directories'])} directories")
        return ", ".join(stats) if stats else "minimal data"

    def get_recon_data(self) -> Dict[str, Any]:
        """Get the collected recon data."""
        return self.recon_data