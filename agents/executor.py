"""
VAPT-AI Attack Executor Agent
================================
Executes attack tasks and validates vulnerabilities.
"""

import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime

from rich.console import Console
from config.prompts import EXECUTOR_AGENT_PROMPT
from core.dashboard import Dashboard

console = Console()


class ExecutorAgent:
    """
    Attack Execution Agent - Phase 4 of VAPT-AI pipeline.
    
    Takes attack plan and:
    1. Executes each attack task in order
    2. Analyzes responses to confirm/deny vulnerabilities
    3. Tries alternative payloads if initial ones fail
    4. Generates proof of concept for confirmed vulns
    5. Records all attempts for reporting
    """

    def __init__(self, llm_router, tool_engine, dashboard: Dashboard = None):
        self.llm_router = llm_router
        self.tool_engine = tool_engine
        self.dashboard = dashboard
        self.execution_results = {}
        self.confirmed_vulns = []
        self.all_attempts = []

    def _log(self, message: str, level: str = "info"):
        if self.dashboard:
            self.dashboard.add_log(message, level=level, source="executor")
            self.dashboard.refresh()
        console.print(f"  [dim][executor][/dim] {message}")

    def _update_progress(self, tasks_done: int):
        if self.dashboard:
            self.dashboard.phase_tracker.update_phase("execution", tasks_done=tasks_done)
            self.dashboard.refresh()

    def _set_ai_thought(self, thought: str):
        if self.dashboard:
            self.dashboard.set_ai_thought(thought)
            self.dashboard.refresh()

    async def run(
        self,
        attack_plan: Dict[str, Any],
        recon_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute all attack tasks from the plan."""
        self._log("Starting attack execution", "info")

        all_tasks = attack_plan.get("all_tasks", [])
        total_tasks = len(all_tasks)

        if self.dashboard:
            self.dashboard.phase_tracker.start_phase("execution", total_tasks=total_tasks)

        target = recon_data.get("target", "unknown")

        self.execution_results = {
            "target": target,
            "execution_time": datetime.now().isoformat(),
            "total_tasks": total_tasks,
            "tasks_executed": 0,
            "vulnerabilities_confirmed": 0,
            "vulnerabilities_potential": 0,
            "confirmed_vulnerabilities": [],
            "all_results": [],
        }

        # Execute each task
        for i, task in enumerate(all_tasks):
            task_id = task.get("task_id", f"TASK-{i+1}")
            attack_type = task.get("attack_type", "Unknown")
            target_url = task.get("target_url", target)

            self._log(f"[{i+1}/{total_tasks}] {attack_type} → {target_url[:60]}", "action")

            if self.dashboard:
                self.dashboard.set_current_action(
                    f"[{i+1}/{total_tasks}] {attack_type}"
                )

            try:
                result = await self._execute_task(task, recon_data)
                self.execution_results["all_results"].append(result)
                self.all_attempts.append(result)

                # Check if vulnerability was confirmed
                if result.get("status") == "vulnerable":
                    self.confirmed_vulns.append(result)
                    self.execution_results["vulnerabilities_confirmed"] += 1

                    severity = result.get("severity", "medium")
                    self._log(
                        f"🎯 CONFIRMED: {attack_type} [{severity.upper()}] at {target_url[:50]}",
                        "finding",
                    )

                    # Add to dashboard findings
                    if self.dashboard:
                        self.dashboard.add_finding_simple(
                            title=f"{attack_type}",
                            severity=severity,
                            vuln_type=attack_type,
                            location=target_url[:50],
                            details=result.get("evidence", "")[:100],
                        )

                elif result.get("status") == "potential":
                    self.execution_results["vulnerabilities_potential"] += 1
                    self._log(f"⚠️ POTENTIAL: {attack_type} needs manual review", "warning")

            except Exception as e:
                self._log(f"Error executing {task_id}: {e}", "error")
                self.execution_results["all_results"].append({
                    "task_id": task_id,
                    "status": "error",
                    "error": str(e),
                })

            self.execution_results["tasks_executed"] = i + 1
            self._update_progress(i + 1)

        # Complete
        if self.dashboard:
            self.dashboard.phase_tracker.complete_phase("execution")

        confirmed = self.execution_results["vulnerabilities_confirmed"]
        potential = self.execution_results["vulnerabilities_potential"]
        self.execution_results["confirmed_vulnerabilities"] = self.confirmed_vulns

        self._log(
            f"Execution COMPLETE - {confirmed} confirmed, {potential} potential vulnerabilities",
            "success",
        )

        return self.execution_results

    async def _execute_task(
        self, task: Dict[str, Any], recon_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a single attack task."""
        task_id = task.get("task_id", "unknown")
        attack_type = task.get("attack_type", "Unknown")
        command = task.get("command", "")
        tool = task.get("tool", "curl")
        target_url = task.get("target_url", "")
        timeout = task.get("timeout", 120)
        payloads = task.get("payloads", [])

        result = {
            "task_id": task_id,
            "attack_type": attack_type,
            "target_url": target_url,
            "tool_used": tool,
            "status": "not_vulnerable",
            "severity": task.get("severity", "medium"),
            "evidence": "",
            "poc": {},
            "attempts": [],
        }

        # Step 1: Execute the main command
        if command:
            self._set_ai_thought(f"Executing: {command[:80]}...")

            tool_result = await self.tool_engine.execute_command(
                command=command,
                timeout=timeout,
                tool_name=tool,
            )

            if self.dashboard:
                self.dashboard.increment_tools_run()

            attempt = {
                "command": command,
                "output": tool_result.stdout[:2000] if tool_result.stdout else "",
                "error": tool_result.stderr[:500] if tool_result.stderr else "",
                "success": tool_result.success,
                "time": tool_result.execution_time,
            }
            result["attempts"].append(attempt)

            # Step 2: Use AI to analyze the response
            if tool_result.success and tool_result.stdout:
                analysis = await self._analyze_response(
                    task, tool_result.stdout, tool_result.stderr
                )
                
                if analysis:
                    result["status"] = analysis.get("status", "not_vulnerable")
                    result["evidence"] = analysis.get("evidence", "")
                    result["severity"] = analysis.get("severity", task.get("severity", "medium"))
                    
                    if analysis.get("poc"):
                        result["poc"] = analysis["poc"]

        # Step 3: If not confirmed, try additional payloads
        if result["status"] == "not_vulnerable" and payloads:
            self._set_ai_thought("Initial test negative. Trying alternative payloads...")

            for payload in payloads[:5]:  # Try max 5 payloads
                payload_result = await self._try_payload(
                    task, payload, recon_data
                )
                result["attempts"].append(payload_result)

                if payload_result.get("vulnerable"):
                    result["status"] = "vulnerable"
                    result["evidence"] = payload_result.get("evidence", "")
                    result["poc"] = {
                        "payload": payload,
                        "command": payload_result.get("command", ""),
                        "response_snippet": payload_result.get("response", "")[:500],
                    }
                    break

        return result

    async def _analyze_response(
        self, task: Dict[str, Any], stdout: str, stderr: str
    ) -> Optional[Dict[str, Any]]:
        """Use AI to analyze tool output and determine if vulnerability exists."""
        attack_type = task.get("attack_type", "Unknown")
        target_url = task.get("target_url", "")

        # Truncate output for context
        output_truncated = stdout[:3000]
        error_truncated = stderr[:500] if stderr else ""

        response = await self.llm_router.query(
            prompt=f"""Analyze this security tool output and determine if a vulnerability was found.

ATTACK TYPE: {attack_type}
TARGET: {target_url}
TOOL: {task.get('tool', 'unknown')}
COMMAND: {task.get('command', '')}

TOOL OUTPUT:
{output_truncated}

{f'STDERR: {error_truncated}' if error_truncated else ''}

Based on the output above, determine:
1. Is this endpoint ACTUALLY vulnerable? (not just theoretical)
2. What is the evidence?
3. What is the real severity?

Return ONLY a JSON object:
{{
    "status": "vulnerable" or "not_vulnerable" or "potential",
    "evidence": "Specific evidence from the output that proves vulnerability",
    "severity": "critical/high/medium/low",
    "poc": {{
        "description": "How to reproduce",
        "request": "The exact request that works",
        "response_indicator": "What in the response proves it"
    }},
    "reasoning": "Why you think this is/isn't vulnerable"
}}

IMPORTANT: 
- Only mark as "vulnerable" if there is CLEAR evidence in the output
- A 200 status code alone is NOT evidence of vulnerability  
- Error messages, data leakage, or unexpected behavior IS evidence
- If unsure, mark as "potential" for manual review""",
            system_prompt=EXECUTOR_AGENT_PROMPT,
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
                return json.loads(content)
            except (json.JSONDecodeError, IndexError):
                return None

        return None

    async def _try_payload(
        self,
        task: Dict[str, Any],
        payload: str,
        recon_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Try a specific payload against the target."""
        target_url = task.get("target_url", "")
        parameter = task.get("parameter", "")
        method = task.get("method", "GET")

        result = {
            "payload": payload,
            "vulnerable": False,
            "evidence": "",
            "command": "",
            "response": "",
        }

        # Build the test URL/command
        if method.upper() == "GET":
            if parameter:
                # URL encode the payload for the URL
                import urllib.parse
                encoded_payload = urllib.parse.quote(payload, safe="")
                
                if "?" in target_url:
                    test_url = f"{target_url}&{parameter}={encoded_payload}"
                else:
                    test_url = f"{target_url}?{parameter}={encoded_payload}"
            else:
                test_url = target_url

            cmd = f"curl -s -i '{test_url}'"
            result["command"] = cmd
        else:
            # POST request
            if parameter:
                data = f"{parameter}={payload}"
            else:
                data = payload
            cmd = f"curl -s -i -X POST -d '{data}' '{target_url}'"
            result["command"] = cmd

        # Execute
        tool_result = await self.tool_engine.execute_command(
            command=cmd, timeout=30, tool_name="curl"
        )

        if self.dashboard:
            self.dashboard.increment_tools_run()

        if tool_result.success:
            response_text = tool_result.stdout[:2000]
            result["response"] = response_text

            # Quick vulnerability indicators
            vuln_indicators = self._check_vuln_indicators(
                task.get("attack_type", ""), response_text, payload
            )

            if vuln_indicators["is_vulnerable"]:
                result["vulnerable"] = True
                result["evidence"] = vuln_indicators["evidence"]
            else:
                # Use AI for deeper analysis if quick check inconclusive
                analysis = await self._analyze_response(
                    task, response_text, ""
                )
                if analysis and analysis.get("status") == "vulnerable":
                    result["vulnerable"] = True
                    result["evidence"] = analysis.get("evidence", "")

        return result

    def _check_vuln_indicators(
        self, attack_type: str, response: str, payload: str
    ) -> Dict[str, Any]:
        """Quick check for common vulnerability indicators in response."""
        response_lower = response.lower()
        attack_lower = attack_type.lower()
        
        indicators = {
            "is_vulnerable": False,
            "evidence": "",
        }

        # SQL Injection indicators
        if "sql" in attack_lower:
            sqli_errors = [
                "sql syntax", "mysql", "sqlite", "postgresql", "ora-",
                "microsoft sql", "unclosed quotation", "syntax error",
                "unterminated string", "sql error", "database error",
                "warning: mysql", "you have an error in your sql",
                "sqlstate", "jdbc", "odbc",
            ]
            for error in sqli_errors:
                if error in response_lower:
                    indicators["is_vulnerable"] = True
                    indicators["evidence"] = f"SQL error detected: '{error}' found in response"
                    return indicators

        # XSS indicators
        if "xss" in attack_lower or "cross-site" in attack_lower:
            if payload in response and "<script" in payload.lower():
                indicators["is_vulnerable"] = True
                indicators["evidence"] = "Payload reflected unencoded in response"
                return indicators
            if "alert(" in response and "alert(" in payload:
                indicators["is_vulnerable"] = True
                indicators["evidence"] = "XSS payload executed/reflected"
                return indicators

        # Open Redirect indicators
        if "redirect" in attack_lower:
            if "evil.com" in response_lower or "location: https://evil" in response_lower:
                indicators["is_vulnerable"] = True
                indicators["evidence"] = "Redirect to external domain successful"
                return indicators

        # CORS indicators
        if "cors" in attack_lower:
            if "access-control-allow-origin: https://evil.com" in response_lower:
                indicators["is_vulnerable"] = True
                indicators["evidence"] = "CORS allows arbitrary origin"
                return indicators
            if "access-control-allow-origin: *" in response_lower:
                indicators["is_vulnerable"] = True
                indicators["evidence"] = "CORS wildcard (*) detected"
                return indicators

        # Sensitive file exposure
        if ".env" in attack_lower or "sensitive" in attack_lower:
            if any(
                keyword in response_lower
                for keyword in ["db_password", "api_key", "secret_key", "database_url", "aws_"]
            ):
                indicators["is_vulnerable"] = True
                indicators["evidence"] = "Sensitive configuration data exposed"
                return indicators

        # Git exposure
        if "git" in attack_lower:
            if "ref:" in response_lower and "refs/" in response_lower:
                indicators["is_vulnerable"] = True
                indicators["evidence"] = ".git/HEAD file accessible - repository exposed"
                return indicators

        # Information disclosure
        if "information" in attack_lower or "disclosure" in attack_lower:
            sensitive_patterns = [
                "stack trace", "traceback", "exception", "debug",
                "internal server error", "phpinfo", "server at",
            ]
            for pattern in sensitive_patterns:
                if pattern in response_lower:
                    indicators["is_vulnerable"] = True
                    indicators["evidence"] = f"Information disclosure: '{pattern}' found"
                    return indicators

        return indicators

    def get_execution_results(self) -> Dict[str, Any]:
        return self.execution_results

    def get_confirmed_vulns(self) -> List[Dict]:
        return self.confirmed_vulns