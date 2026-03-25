"""
VAPT-AI Attack Planning Agent
===============================
Creates detailed, ordered attack plans based on vulnerability analysis.
"""

import json
from typing import Dict, Any, List
from datetime import datetime

from rich.console import Console
from config.prompts import PLANNER_AGENT_PROMPT
from core.dashboard import Dashboard

console = Console()


class PlannerAgent:
    """
    Attack Planning Agent - Phase 3 of VAPT-AI pipeline.
    
    Takes analysis results and creates:
    1. Ordered list of attack tasks
    2. Specific commands and payloads for each test
    3. Bypass techniques for WAF/filters
    4. Dependencies between attacks
    5. Estimated severity for each test
    """

    def __init__(self, llm_router, tool_engine, dashboard: Dashboard = None):
        self.llm_router = llm_router
        self.tool_engine = tool_engine
        self.dashboard = dashboard
        self.attack_plan = {}

    def _log(self, message: str, level: str = "info"):
        if self.dashboard:
            self.dashboard.add_log(message, level=level, source="planner")
            self.dashboard.refresh()
        console.print(f"  [dim][planner][/dim] {message}")

    def _update_progress(self, tasks_done: int):
        if self.dashboard:
            self.dashboard.phase_tracker.update_phase("planning", tasks_done=tasks_done)
            self.dashboard.refresh()

    def _set_ai_thought(self, thought: str):
        if self.dashboard:
            self.dashboard.set_ai_thought(thought)
            self.dashboard.refresh()

    async def run(
        self,
        analysis_results: Dict[str, Any],
        recon_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Create attack plan based on analysis results.
        """
        self._log("Starting attack planning", "info")

        if self.dashboard:
            self.dashboard.phase_tracker.start_phase("planning", total_tasks=3)

        target = recon_data.get("target", "unknown")
        waf = recon_data.get("waf", "none")
        
        self.attack_plan = {
            "target": target,
            "plan_time": datetime.now().isoformat(),
            "waf_detected": waf,
            "total_tasks": 0,
            "attack_tasks": [],
            "quick_wins": [],
            "deep_tests": [],
        }

        # Get available tools
        available_tools = self.tool_engine.get_available_tools()
        
        # Task 1: Generate attack tasks
        self._log("Generating attack tasks from vulnerability analysis", "action")
        self._set_ai_thought("Creating specific attack tasks with exact commands and payloads...")
        await self._generate_attack_tasks(analysis_results, recon_data, available_tools)
        self._update_progress(1)

        # Task 2: Add quick-win tests
        self._log("Adding quick-win security checks", "action")
        self._set_ai_thought("Adding standard security checks that are quick and often reveal issues...")
        self._add_quick_win_tasks(target, waf, available_tools)
        self._update_progress(2)

        # Task 3: Order and finalize
        self._log("Ordering tasks by priority and dependencies", "action")
        self._set_ai_thought("Prioritizing: quick wins first, then targeted attacks, then deep tests...")
        self._finalize_plan()
        self._update_progress(3)

        if self.dashboard:
            self.dashboard.phase_tracker.complete_phase("planning")

        total = self.attack_plan["total_tasks"]
        self._log(f"Attack plan COMPLETE - {total} tasks created", "success")

        return self.attack_plan

    async def _generate_attack_tasks(
        self,
        analysis_results: Dict[str, Any],
        recon_data: Dict[str, Any],
        available_tools: List[str],
    ):
        """Generate specific attack tasks from vulnerability analysis."""
        vulns = analysis_results.get("potential_vulnerabilities", [])
        attack_surface = analysis_results.get("attack_surface", {})
        target = recon_data.get("target", "")
        waf = recon_data.get("waf", "none")

        context = f"""TARGET: {target}
WAF: {waf}
AVAILABLE SECURITY TOOLS: {', '.join(available_tools)}

POTENTIAL VULNERABILITIES IDENTIFIED:
{json.dumps(vulns[:20], indent=2)}

ATTACK SURFACE:
{json.dumps(attack_surface, indent=2)[:2000]}"""

        response = await self.llm_router.query(
            prompt=f"""{context}

Create specific, executable attack tasks for each vulnerability above.
Each task must have an EXACT command or technique ready to execute.

Return a JSON array of tasks:
[
    {{
        "task_id": "ATK-001",
        "priority": 1,
        "vuln_id": "VAPT-001",
        "attack_type": "SQL Injection",
        "target_url": "{target}/api/products",
        "method": "GET",
        "parameter": "search",
        "tool": "sqlmap",
        "command": "sqlmap -u '{target}/api/products?search=test' --batch --level=3 --risk=2 --threads=5",
        "manual_test": {{
            "method": "GET",
            "url": "{target}/api/products?search=' OR 1=1--",
            "expected_if_vulnerable": "Returns all products or database error"
        }},
        "payloads": [
            "' OR '1'='1",
            "' OR 1=1--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "' AND SLEEP(5)--"
        ],
        "bypass_techniques": ["URL encoding: %27%20OR%201%3D1--", "Double encoding"],
        "severity": "critical",
        "timeout": 120,
        "depends_on": []
    }}
]

RULES:
1. Use REAL commands that will actually work
2. Include --batch flag for sqlmap (non-interactive)
3. For XSS, include curl commands with payloads
4. Include multiple payload variations
5. If WAF is detected ({waf}), include bypass techniques
6. Group related tests together
7. Put high-severity quick tests first
8. Max 20 tasks""",
            system_prompt=PLANNER_AGENT_PROMPT,
            task_type="attack_planning",
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

                tasks = json.loads(content)
                if isinstance(tasks, list):
                    self.attack_plan["attack_tasks"] = tasks
                    self._log(f"Generated {len(tasks)} attack tasks", "success")
                elif isinstance(tasks, dict):
                    task_list = tasks.get("attack_plan", tasks.get("tasks", [tasks]))
                    if isinstance(task_list, list):
                        self.attack_plan["attack_tasks"] = task_list
                        self._log(f"Generated {len(task_list)} attack tasks", "success")
            except (json.JSONDecodeError, IndexError) as e:
                self._log(f"Task generation parse issue: {e}", "warning")
                # Create basic tasks from vulnerabilities
                self._generate_basic_tasks(vulns, target, available_tools)

    def _generate_basic_tasks(
        self, vulns: List[Dict], target: str, available_tools: List[str]
    ):
        """Generate basic attack tasks when AI parsing fails."""
        tasks = []
        task_counter = 0

        for vuln in vulns[:15]:
            task_counter += 1
            vuln_type = vuln.get("type", "Unknown")
            location = vuln.get("location", target)
            parameter = vuln.get("parameter", "")
            severity = vuln.get("severity_estimate", "medium")

            # Build full URL
            test_url = location if location.startswith("http") else f"{target}{location}"

            task = {
                "task_id": f"ATK-{task_counter:03d}",
                "priority": task_counter,
                "vuln_id": vuln.get("vuln_id", f"VAPT-{task_counter:03d}"),
                "attack_type": vuln_type,
                "target_url": test_url,
                "method": vuln.get("method", "GET"),
                "parameter": parameter,
                "severity": severity,
                "timeout": 120,
                "depends_on": [],
                "payloads": vuln.get("test_payloads", []),
            }

            # Add tool-specific commands
            vuln_lower = vuln_type.lower()

            if "sql" in vuln_lower and "sqlmap" in available_tools:
                task["tool"] = "sqlmap"
                param_url = f"{test_url}?{parameter}=test" if parameter else test_url
                task["command"] = f"sqlmap -u '{param_url}' --batch --level=3 --risk=2"

            elif "xss" in vuln_lower and "dalfox" in available_tools:
                task["tool"] = "dalfox"
                task["command"] = f"dalfox url '{test_url}?{parameter}=test' --silence"

            elif "xss" in vuln_lower:
                task["tool"] = "curl"
                payload = "<script>alert(1)</script>"
                task["command"] = f"curl -s '{test_url}?{parameter}={payload}'"

            else:
                task["tool"] = "curl"
                task["command"] = f"curl -s -i '{test_url}'"

            tasks.append(task)

        self.attack_plan["attack_tasks"] = tasks
        self._log(f"Generated {len(tasks)} basic attack tasks", "success")

    def _add_quick_win_tasks(
        self, target: str, waf: str, available_tools: List[str]
    ):
        """Add standard quick-win security checks."""
        quick_wins = []
        existing_count = len(self.attack_plan.get("attack_tasks", []))

        # CORS check
        quick_wins.append({
            "task_id": f"QW-001",
            "priority": 0,
            "attack_type": "CORS Misconfiguration",
            "target_url": target,
            "tool": "curl",
            "command": f"curl -s -I -H 'Origin: https://evil.com' '{target}' | grep -i 'access-control'",
            "severity": "medium",
            "timeout": 30,
            "category": "quick_win",
        })

        # Security headers check
        quick_wins.append({
            "task_id": f"QW-002",
            "priority": 0,
            "attack_type": "Missing Security Headers",
            "target_url": target,
            "tool": "curl",
            "command": f"curl -s -I '{target}'",
            "severity": "low",
            "timeout": 30,
            "category": "quick_win",
        })

        # robots.txt check
        quick_wins.append({
            "task_id": f"QW-003",
            "priority": 0,
            "attack_type": "Information Disclosure",
            "target_url": f"{target}/robots.txt",
            "tool": "curl",
            "command": f"curl -s '{target}/robots.txt'",
            "severity": "info",
            "timeout": 30,
            "category": "quick_win",
        })

        # .env file check
        quick_wins.append({
            "task_id": f"QW-004",
            "priority": 0,
            "attack_type": "Sensitive File Exposure",
            "target_url": f"{target}/.env",
            "tool": "curl",
            "command": f"curl -s -o /dev/null -w '%{{http_code}}' '{target}/.env'",
            "severity": "critical",
            "timeout": 30,
            "category": "quick_win",
        })

        # .git exposure check
        quick_wins.append({
            "task_id": f"QW-005",
            "priority": 0,
            "attack_type": "Git Repository Exposure",
            "target_url": f"{target}/.git/HEAD",
            "tool": "curl",
            "command": f"curl -s -o /dev/null -w '%{{http_code}}' '{target}/.git/HEAD'",
            "severity": "high",
            "timeout": 30,
            "category": "quick_win",
        })

        # Open redirect check
        quick_wins.append({
            "task_id": f"QW-006",
            "priority": 0,
            "attack_type": "Open Redirect",
            "target_url": target,
            "tool": "curl",
            "command": f"curl -s -I '{target}/redirect?url=https://evil.com' -o /dev/null -w '%{{http_code}} %{{redirect_url}}'",
            "severity": "medium",
            "timeout": 30,
            "category": "quick_win",
        })

        # Nuclei scan if available
        if "nuclei" in available_tools:
            quick_wins.append({
                "task_id": f"QW-007",
                "priority": 0,
                "attack_type": "Nuclei Vulnerability Scan",
                "target_url": target,
                "tool": "nuclei",
                "command": f"nuclei -u '{target}' -severity critical,high -silent",
                "severity": "varies",
                "timeout": 300,
                "category": "quick_win",
            })

        self.attack_plan["quick_wins"] = quick_wins
        self._log(f"Added {len(quick_wins)} quick-win checks", "success")

    def _finalize_plan(self):
        """Finalize and order the attack plan."""
        quick_wins = self.attack_plan.get("quick_wins", [])
        attack_tasks = self.attack_plan.get("attack_tasks", [])

        # Combine: quick wins first, then attack tasks
        all_tasks = quick_wins + attack_tasks

        # Re-number
        for i, task in enumerate(all_tasks):
            task["execution_order"] = i + 1

        self.attack_plan["all_tasks"] = all_tasks
        self.attack_plan["total_tasks"] = len(all_tasks)

        # Categorize
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for task in all_tasks:
            sev = task.get("severity", "medium").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            elif sev == "varies":
                severity_counts["medium"] += 1

        self.attack_plan["severity_distribution"] = severity_counts
        self._log(
            f"Final plan: {severity_counts.get('critical', 0)} critical, "
            f"{severity_counts.get('high', 0)} high, "
            f"{severity_counts.get('medium', 0)} medium tests",
            "success",
        )

    def get_attack_plan(self) -> Dict[str, Any]:
        return self.attack_plan