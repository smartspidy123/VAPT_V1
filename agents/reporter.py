"""
VAPT-AI Reporter Agent
========================
Generates professional penetration testing reports.
"""

import json
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

from rich.console import Console
from config.prompts import REPORTER_AGENT_PROMPT
from core.dashboard import Dashboard

console = Console()


class ReporterAgent:
    """
    Reporting Agent - Phase 5 of VAPT-AI pipeline.
    
    Generates professional VAPT reports including:
    1. Executive Summary
    2. Scope and Methodology
    3. Findings with PoC
    4. Risk Assessment
    5. Remediation Recommendations
    """

    def __init__(self, llm_router, dashboard: Dashboard = None):
        self.llm_router = llm_router
        self.dashboard = dashboard
        self.report = ""

    def _log(self, message: str, level: str = "info"):
        if self.dashboard:
            self.dashboard.add_log(message, level=level, source="reporter")
            self.dashboard.refresh()
        console.print(f"  [dim][reporter][/dim] {message}")

    def _update_progress(self, tasks_done: int):
        if self.dashboard:
            self.dashboard.phase_tracker.update_phase("reporting", tasks_done=tasks_done)
            self.dashboard.refresh()

    def _set_ai_thought(self, thought: str):
        if self.dashboard:
            self.dashboard.set_ai_thought(thought)
            self.dashboard.refresh()

    async def run(
        self,
        recon_data: Dict[str, Any],
        analysis_results: Dict[str, Any],
        attack_plan: Dict[str, Any],
        execution_results: Dict[str, Any],
        scan_duration: str = "",
    ) -> str:
        """Generate the full penetration testing report."""
        self._log("Starting report generation", "info")

        if self.dashboard:
            self.dashboard.phase_tracker.start_phase("reporting", total_tasks=4)

        target = recon_data.get("target", "unknown")
        confirmed_vulns = execution_results.get("confirmed_vulnerabilities", [])
        all_results = execution_results.get("all_results", [])

        # Task 1: Build report data
        self._log("Compiling scan data", "action")
        self._set_ai_thought("Gathering all findings and evidence for the report...")
        report_data = self._compile_report_data(
            recon_data, analysis_results, attack_plan, execution_results, scan_duration
        )
        self._update_progress(1)

        # Task 2: Generate executive summary and findings with AI
        self._log("AI generating detailed report content", "action")
        self._set_ai_thought("Writing executive summary and detailed vulnerability descriptions...")
        ai_report_content = await self._generate_ai_report(report_data)
        self._update_progress(2)

        # Task 3: Build final markdown report
        self._log("Building final report document", "action")
        self._set_ai_thought("Assembling the complete penetration testing report...")
        self.report = self._build_markdown_report(report_data, ai_report_content)
        self._update_progress(3)

        # Task 4: Save report
        self._log("Saving report to file", "action")
        report_path = self._save_report(target)
        self._update_progress(4)

        if self.dashboard:
            self.dashboard.phase_tracker.complete_phase("reporting")

        self._log(f"Report saved: {report_path}", "success")

        return self.report

    def _compile_report_data(
        self,
        recon_data: Dict,
        analysis_results: Dict,
        attack_plan: Dict,
        execution_results: Dict,
        scan_duration: str,
    ) -> Dict[str, Any]:
        """Compile all scan data into report-ready format."""
        confirmed = execution_results.get("confirmed_vulnerabilities", [])
        all_results = execution_results.get("all_results", [])

        # Count severities
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in confirmed:
            sev = vuln.get("severity", "medium").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Potential vulns needing manual review
        potential = [r for r in all_results if r.get("status") == "potential"]

        return {
            "target": recon_data.get("target", "unknown"),
            "domain": recon_data.get("domain", "unknown"),
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration": scan_duration,
            "waf_detected": recon_data.get("waf", "unknown"),
            "technologies": recon_data.get("technologies", []),
            "subdomains_count": len(recon_data.get("subdomains", [])),
            "ports_count": len(recon_data.get("open_ports", [])),
            "endpoints_count": len(recon_data.get("endpoints", [])),
            "directories_count": len(recon_data.get("directories", [])),
            "total_vulns_found": len(confirmed),
            "severity_counts": severity_counts,
            "confirmed_vulnerabilities": confirmed,
            "potential_vulnerabilities": potential,
            "tasks_executed": execution_results.get("tasks_executed", 0),
            "header_issues": [
                f for f in recon_data.get("interesting_findings", [])
                if "header" in f.lower() or "missing" in f.lower()
            ],
            "recon_ai_analysis": recon_data.get("ai_analysis", ""),
        }

    async def _generate_ai_report(self, report_data: Dict) -> str:
        """Use AI to generate detailed report sections."""
        confirmed = report_data.get("confirmed_vulnerabilities", [])

        # Prepare vulnerability details for AI
        vuln_details = []
        for i, vuln in enumerate(confirmed, 1):
            detail = f"""
Vulnerability #{i}:
- Type: {vuln.get('attack_type', 'Unknown')}
- Severity: {vuln.get('severity', 'medium')}
- Target URL: {vuln.get('target_url', 'unknown')}
- Evidence: {vuln.get('evidence', 'N/A')[:500]}
- Tool Used: {vuln.get('tool_used', 'N/A')}
- PoC: {json.dumps(vuln.get('poc', {}), indent=2)[:300]}
"""
            vuln_details.append(detail)

        vuln_text = "\n".join(vuln_details) if vuln_details else "No confirmed vulnerabilities."

        response = await self.llm_router.query(
            prompt=f"""Generate a professional penetration testing report content for:

TARGET: {report_data.get('target')}
SCAN DATE: {report_data.get('scan_date')}
DURATION: {report_data.get('scan_duration')}
WAF: {report_data.get('waf_detected')}
TECHNOLOGIES: {report_data.get('technologies', [])[:10]}

SEVERITY SUMMARY:
- Critical: {report_data['severity_counts']['critical']}
- High: {report_data['severity_counts']['high']}
- Medium: {report_data['severity_counts']['medium']}
- Low: {report_data['severity_counts']['low']}

CONFIRMED VULNERABILITIES:
{vuln_text}

HEADER ISSUES: {report_data.get('header_issues', [])}

Generate these sections in Markdown:
1. EXECUTIVE SUMMARY (2-3 paragraphs for management)
2. For EACH vulnerability, write:
   - Detailed description of what the vulnerability is
   - Real-world impact and risk
   - Specific remediation steps
3. OVERALL RISK ASSESSMENT (what's the overall security posture)
4. PRIORITIZED RECOMMENDATIONS (numbered list)

Be professional. This report will be submitted to clients.""",
            system_prompt=REPORTER_AGENT_PROMPT,
            task_type="report_generation",
        )

        if response.success:
            if self.dashboard:
                self.dashboard.update_llm_stats(tokens=response.total_tokens, requests=1)
            return response.content
        
        return "AI report generation failed. Manual review required."

    def _build_markdown_report(self, report_data: Dict, ai_content: str) -> str:
        """Build the final markdown report."""
        confirmed = report_data.get("confirmed_vulnerabilities", [])
        severity = report_data.get("severity_counts", {})

        report = f"""# 🔒 VAPT-AI Penetration Testing Report

---

**Target:** {report_data.get('target')}  
**Date:** {report_data.get('scan_date')}  
**Duration:** {report_data.get('scan_duration')}  
**Report Generated By:** VAPT-AI v1.0 (Autonomous VAPT Agent)

---

## 📊 Findings Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {severity.get('critical', 0)} |
| 🟠 High | {severity.get('high', 0)} |
| 🟡 Medium | {severity.get('medium', 0)} |
| 🔵 Low | {severity.get('low', 0)} |
| ⚪ Info | {severity.get('info', 0)} |
| **Total** | **{report_data.get('total_vulns_found', 0)}** |

---

## 🎯 Scope & Methodology

### Target Information
- **URL:** {report_data.get('target')}
- **WAF Detected:** {report_data.get('waf_detected', 'None')}
- **Technologies:** {', '.join(report_data.get('technologies', [])[:10]) if isinstance(report_data.get('technologies'), list) else 'N/A'}

### Reconnaissance Summary
- **Subdomains Found:** {report_data.get('subdomains_count', 0)}
- **Open Ports:** {report_data.get('ports_count', 0)}
- **Endpoints Discovered:** {report_data.get('endpoints_count', 0)}
- **Directories Found:** {report_data.get('directories_count', 0)}

### Methodology
Testing was performed using an automated AI-driven approach combining:
- Passive and active reconnaissance
- Automated vulnerability scanning (Nuclei, Nikto)
- Manual testing with AI-guided payloads
- OWASP Top 10 vulnerability assessment

### Tools Used
Nmap, Nuclei, SQLMap, ffuf, WhatWeb, wafw00f, Katana, Subfinder, curl, Dalfox

---

## 📝 AI-Generated Analysis

{ai_content}

---

## 🔍 Detailed Findings

"""
        # Add each vulnerability
        for i, vuln in enumerate(confirmed, 1):
            sev = vuln.get("severity", "medium").upper()
            sev_emoji = {
                "CRITICAL": "🔴", "HIGH": "🟠",
                "MEDIUM": "🟡", "LOW": "🔵",
            }.get(sev, "⚪")

            report += f"""### {sev_emoji} Finding #{i}: {vuln.get('attack_type', 'Unknown')}

| Field | Details |
|-------|---------|
| **Severity** | {sev} |
| **Type** | {vuln.get('attack_type', 'N/A')} |
| **URL** | `{vuln.get('target_url', 'N/A')}` |
| **Tool** | {vuln.get('tool_used', 'N/A')} |

**Evidence:**
**Proof of Concept:**

---

"""

        # Add missing security headers section
        header_issues = report_data.get("header_issues", [])
        if header_issues:
            report += """## 🛡️ Security Header Issues

The following security headers are missing or misconfigured:

"""
            for issue in header_issues:
                report += f"- {issue}\n"
            report += "\n---\n\n"

        # Add potential findings needing manual review
        potential = report_data.get("potential_vulnerabilities", [])
        if potential:
            report += """## ⚠️ Findings Requiring Manual Review

The following potential vulnerabilities were identified but need manual verification:

"""
            for p in potential:
                report += f"- **{p.get('attack_type', 'Unknown')}** at `{p.get('target_url', 'N/A')}`\n"
            report += "\n---\n\n"

        # Footer
        report += f"""
---

## 📋 Scan Statistics

| Metric | Value |
|--------|-------|
| Total Tasks Executed | {report_data.get('tasks_executed', 0)} |
| Scan Duration | {report_data.get('scan_duration', 'N/A')} |
| Confirmed Vulnerabilities | {report_data.get('total_vulns_found', 0)} |
| Manual Review Needed | {len(potential)} |

---

*This report was generated by VAPT-AI v1.0 - Autonomous VAPT & Bug Bounty Agent*  
*Report Date: {report_data.get('scan_date')}*
"""
        return report

    def _save_report(self, target: str) -> Path:
        """Save report to file."""
        from config.settings import REPORTS_DIR

        # Create filename from target
        domain = target.replace("https://", "").replace("http://", "")
        domain = domain.replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vapt_report_{domain}_{timestamp}.md"

        report_path = REPORTS_DIR / filename
        report_path.write_text(self.report, encoding="utf-8")

        # Also save as JSON
        json_path = REPORTS_DIR / filename.replace(".md", ".json")
        json_data = {
            "report_markdown": self.report,
            "generated_at": datetime.now().isoformat(),
            "target": target,
        }
        json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")

        return report_path

    def get_report(self) -> str:
        return self.report