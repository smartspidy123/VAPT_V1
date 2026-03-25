"""
VAPT-AI Vulnerability Analyzer Agent
======================================
Analyzes recon data to identify potential vulnerabilities
and map the attack surface.
"""

import json
from typing import Dict, Any, List
from datetime import datetime

from rich.console import Console
from config.prompts import ANALYZER_AGENT_PROMPT
from core.dashboard import Dashboard

console = Console()


class AnalyzerAgent:
    """
    Vulnerability Analysis Agent - Phase 2 of VAPT-AI pipeline.
    
    Takes recon data and:
    1. Identifies potential injection points
    2. Maps OWASP Top 10 vulnerabilities
    3. Checks for known CVEs in detected technologies
    4. Prioritizes findings by likelihood and impact
    5. Generates structured vulnerability hypotheses
    """

    def __init__(self, llm_router, dashboard: Dashboard = None):
        self.llm_router = llm_router
        self.dashboard = dashboard
        self.analysis_results = {}

    def _log(self, message: str, level: str = "info"):
        if self.dashboard:
            self.dashboard.add_log(message, level=level, source="analyzer")
            self.dashboard.refresh()
        console.print(f"  [dim][analyzer][/dim] {message}")

    def _update_progress(self, tasks_done: int):
        if self.dashboard:
            self.dashboard.phase_tracker.update_phase("analysis", tasks_done=tasks_done)
            self.dashboard.refresh()

    def _set_ai_thought(self, thought: str):
        if self.dashboard:
            self.dashboard.set_ai_thought(thought)
            self.dashboard.refresh()

    async def run(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze recon data to identify potential vulnerabilities.
        
        Args:
            recon_data: Output from ReconAgent
            
        Returns:
            Dict with vulnerability analysis results
        """
        self._log("Starting vulnerability analysis", "info")

        if self.dashboard:
            self.dashboard.phase_tracker.start_phase("analysis", total_tasks=4)

        target = recon_data.get("target", "unknown")
        
        self.analysis_results = {
            "target": target,
            "analysis_time": datetime.now().isoformat(),
            "potential_vulnerabilities": [],
            "attack_surface": {},
            "technology_cves": [],
            "owasp_mapping": {},
            "priority_targets": [],
        }

        # Task 1: Map attack surface
        self._log("Mapping attack surface from recon data", "action")
        self._set_ai_thought("Analyzing all endpoints and parameters to identify input points...")
        await self._map_attack_surface(recon_data)
        self._update_progress(1)

        # Task 2: Identify potential vulnerabilities
        self._log("Identifying potential vulnerabilities", "action")
        self._set_ai_thought("Cross-referencing tech stack with known vulnerability patterns...")
        await self._identify_vulnerabilities(recon_data)
        self._update_progress(2)

        # Task 3: Check technology CVEs
        self._log("Checking for known CVEs in detected technologies", "action")
        self._set_ai_thought("Searching for CVEs in detected software versions...")
        await self._check_technology_cves(recon_data)
        self._update_progress(3)

        # Task 4: Prioritize and finalize
        self._log("Prioritizing findings and generating final analysis", "action")
        self._set_ai_thought("Ranking vulnerabilities by likelihood and impact...")
        await self._prioritize_findings()
        self._update_progress(4)

        if self.dashboard:
            self.dashboard.phase_tracker.complete_phase("analysis")

        vuln_count = len(self.analysis_results["potential_vulnerabilities"])
        self._log(f"Analysis COMPLETE - {vuln_count} potential vulnerabilities identified", "success")

        return self.analysis_results

    async def _map_attack_surface(self, recon_data: Dict[str, Any]):
        """Map the complete attack surface."""
        endpoints = recon_data.get("endpoints", [])
        directories = recon_data.get("directories", [])
        technologies = recon_data.get("technologies", [])
        headers = recon_data.get("headers", {})
        ports = recon_data.get("open_ports", [])

        # Build context for AI
        context = f"""RECON DATA FOR ATTACK SURFACE MAPPING:

Target: {recon_data.get('target', 'unknown')}
WAF: {recon_data.get('waf', 'unknown')}

Endpoints ({len(endpoints)}):
{chr(10).join(endpoints[:50])}

Directories ({len(directories)}):
{chr(10).join(directories[:30])}

Technologies: {', '.join(technologies[:20]) if isinstance(technologies, list) else str(technologies)}

Response Headers: {json.dumps(headers, indent=2) if isinstance(headers, dict) else str(headers)}

Open Ports: {json.dumps(ports[:20]) if isinstance(ports, list) else str(ports)}

Interesting Findings:
{chr(10).join(recon_data.get('interesting_findings', [])[:20])}"""

        response = await self.llm_router.query(
            prompt=f"""{context}

Based on the above recon data, map the attack surface. Return a JSON object:
{{
    "total_endpoints": <number>,
    "input_points": [
        {{
            "url": "/api/endpoint",
            "method": "GET/POST",
            "parameters": ["param1", "param2"],
            "input_type": "query/body/header/cookie",
            "description": "What this endpoint does"
        }}
    ],
    "authentication_endpoints": ["/login", "/register", "/api/auth"],
    "file_upload_endpoints": [],
    "api_endpoints": [],
    "admin_endpoints": [],
    "interesting_endpoints": [],
    "attack_surface_score": "low/medium/high/critical"
}}

Focus on endpoints that accept user input. Be thorough but realistic.""",
            system_prompt=ANALYZER_AGENT_PROMPT,
            task_type="attack_surface_mapping",
        )

        if response.success:
            if self.dashboard:
                self.dashboard.update_llm_stats(tokens=response.total_tokens, requests=1)

            try:
                content = response.content.strip()
                # Extract JSON from response
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]

                attack_surface = json.loads(content)
                self.analysis_results["attack_surface"] = attack_surface
                
                input_count = len(attack_surface.get("input_points", []))
                self._log(f"Mapped {input_count} input points", "success")
            except (json.JSONDecodeError, IndexError):
                # Store raw analysis
                self.analysis_results["attack_surface"] = {
                    "raw_analysis": response.content,
                    "endpoints_count": len(endpoints),
                }
                self._log("Attack surface mapped (raw format)", "success")

    async def _identify_vulnerabilities(self, recon_data: Dict[str, Any]):
        """Identify potential vulnerabilities using AI analysis."""
        attack_surface = self.analysis_results.get("attack_surface", {})
        
        context = f"""TARGET: {recon_data.get('target', 'unknown')}
WAF: {recon_data.get('waf', 'none')}
TECHNOLOGIES: {json.dumps(recon_data.get('technologies', [])[:20])}

ATTACK SURFACE:
{json.dumps(attack_surface, indent=2)[:3000]}

HEADERS:
{json.dumps(recon_data.get('headers', {}), indent=2)}

SECURITY ISSUES FOUND IN RECON:
{chr(10).join(recon_data.get('interesting_findings', [])[:15])}

JS ANALYSIS FINDINGS:
{json.dumps(recon_data.get('js_analysis', [])[:10])}"""

        response = await self.llm_router.query(
            prompt=f"""{context}

Based on the attack surface and recon data above, identify ALL potential vulnerabilities.
For each, provide specific details about WHERE and HOW to test.

Return a JSON array:
[
    {{
        "vuln_id": "VAPT-001",
        "type": "SQL Injection",
        "owasp_category": "A03:2021 - Injection",
        "location": "/api/products?search=",
        "parameter": "search",
        "method": "GET",
        "confidence": "high",
        "severity_estimate": "critical",
        "reasoning": "Search parameter directly reflected, no input validation observed",
        "test_payloads": ["' OR 1=1--", "1 UNION SELECT NULL--"],
        "suggested_tools": ["sqlmap", "manual curl"],
        "bypass_needed": false
    }}
]

Think about these OWASP Top 10 categories:
- A01: Broken Access Control (IDOR, privilege escalation, forced browsing)
- A02: Cryptographic Failures (weak SSL, exposed secrets)
- A03: Injection (SQLi, XSS, Command Injection, SSTI, LDAP)
- A04: Insecure Design (business logic flaws)
- A05: Security Misconfiguration (default creds, verbose errors, CORS)
- A06: Vulnerable Components (outdated libraries, known CVEs)
- A07: Authentication Failures (brute force, weak passwords, session)
- A08: Data Integrity Failures (insecure deserialization)
- A09: Logging Failures (no audit trail)
- A10: SSRF (server-side request forgery)

Also check for: Open Redirect, CORS misconfiguration, JWT issues, File Upload vulns, 
Rate Limiting issues, Information Disclosure, Directory Traversal.

Be specific with locations and parameters. Only include REALISTIC findings.""",
            system_prompt=ANALYZER_AGENT_PROMPT,
            task_type="vulnerability_analysis",
        )

        if response.success:
            if self.dashboard:
                self.dashboard.update_llm_stats(tokens=response.total_tokens, requests=1)

            try:
                content = response.content.strip()
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]

                vulns = json.loads(content)
                if isinstance(vulns, list):
                    self.analysis_results["potential_vulnerabilities"] = vulns
                    self._log(f"Identified {len(vulns)} potential vulnerabilities", "success")
                    
                    # Log top findings
                    for v in vulns[:5]:
                        sev = v.get("severity_estimate", "unknown")
                        vtype = v.get("type", "unknown")
                        loc = v.get("location", "unknown")
                        self._log(f"  → [{sev.upper()}] {vtype} at {loc}", "warning")
                elif isinstance(vulns, dict) and "vulnerabilities" in vulns:
                    vuln_list = vulns["vulnerabilities"]
                    self.analysis_results["potential_vulnerabilities"] = vuln_list
                    self._log(f"Identified {len(vuln_list)} potential vulnerabilities", "success")
            except (json.JSONDecodeError, IndexError):
                self.analysis_results["potential_vulnerabilities_raw"] = response.content
                self._log("Vulnerabilities identified (raw format)", "success")

    async def _check_technology_cves(self, recon_data: Dict[str, Any]):
        """Check detected technologies for known CVEs."""
        technologies = recon_data.get("technologies", [])
        if not technologies:
            self._log("No specific technologies to check for CVEs", "info")
            return

        tech_str = ", ".join(technologies[:15]) if isinstance(technologies, list) else str(technologies)

        response = await self.llm_router.query(
            prompt=f"""Technologies detected on target: {tech_str}

For each technology, list any known critical/high CVEs that could be exploitable.
Focus on recent CVEs (2022-2025) and commonly exploited ones.

Return a JSON array:
[
    {{
        "technology": "gunicorn/19.9.0",
        "cve_id": "CVE-XXXX-XXXXX",
        "severity": "critical/high/medium",
        "description": "Brief description",
        "exploitable": true/false,
        "exploit_available": true/false
    }}
]

If no known CVEs, return an empty array []. Be accurate - don't invent CVEs.""",
            system_prompt="You are a CVE database expert. Only list REAL, verified CVEs. Never fabricate CVE IDs.",
            task_type="vulnerability_analysis",
        )

        if response.success:
            if self.dashboard:
                self.dashboard.update_llm_stats(tokens=response.total_tokens, requests=1)

            try:
                content = response.content.strip()
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]
                
                cves = json.loads(content)
                if isinstance(cves, list):
                    self.analysis_results["technology_cves"] = cves
                    if cves:
                        self._log(f"Found {len(cves)} potential CVEs", "warning")
                    else:
                        self._log("No known CVEs found for detected technologies", "info")
            except (json.JSONDecodeError, IndexError):
                self._log("CVE check complete (raw format)", "info")

    async def _prioritize_findings(self):
        """Prioritize all findings by likelihood and impact."""
        vulns = self.analysis_results.get("potential_vulnerabilities", [])
        
        if not vulns:
            self._log("No vulnerabilities to prioritize", "info")
            return

        # Sort by severity and confidence
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        confidence_order = {"high": 0, "medium": 1, "low": 2}

        try:
            sorted_vulns = sorted(
                vulns,
                key=lambda v: (
                    severity_order.get(v.get("severity_estimate", "low"), 3),
                    confidence_order.get(v.get("confidence", "low"), 2),
                ),
            )
            self.analysis_results["potential_vulnerabilities"] = sorted_vulns

            # Create priority targets list
            priority_targets = []
            for v in sorted_vulns:
                if v.get("severity_estimate") in ["critical", "high"] or v.get("confidence") == "high":
                    priority_targets.append({
                        "vuln_id": v.get("vuln_id", ""),
                        "type": v.get("type", ""),
                        "location": v.get("location", ""),
                        "severity": v.get("severity_estimate", ""),
                    })

            self.analysis_results["priority_targets"] = priority_targets
            self._log(f"Prioritized {len(priority_targets)} high-priority targets", "success")
        except Exception as e:
            self._log(f"Prioritization warning: {e}", "warning")

    def get_analysis_results(self) -> Dict[str, Any]:
        return self.analysis_results