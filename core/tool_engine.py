"""
VAPT-AI Security Tools Engine
==============================
Central engine to manage, execute, and parse output of all security tools.
Provides unified interface for AI agents to interact with security tools.
"""

import asyncio
import subprocess
import shutil
import time
import signal
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime

from rich.console import Console

console = Console()


# ============================================
# DATA CLASSES
# ============================================

@dataclass
class ToolResult:
    """Standardized result from any security tool."""
    tool_name: str
    command: str
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    success: bool
    parsed_output: Optional[Dict[str, Any]] = None
    error_message: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def summary(self) -> str:
        """Get a brief summary of the result."""
        status = "✅ Success" if self.success else "❌ Failed"
        return (
            f"{status} | {self.tool_name} | "
            f"Time: {self.execution_time:.1f}s | "
            f"Output: {len(self.stdout)} chars"
        )


@dataclass
class ToolInfo:
    """Information about a security tool."""
    name: str
    path: str
    description: str
    is_available: bool = False
    version: str = ""
    categories: List[str] = field(default_factory=list)


# ============================================
# SECURITY TOOLS ENGINE
# ============================================

class SecurityToolsEngine:
    """
    Central engine for managing and executing security tools.
    
    Features:
    - Auto-detection of installed tools
    - Unified command execution with timeout
    - Output parsing for each tool
    - Async execution support
    - Tool result caching
    - Safety checks (scope enforcement)
    """

    def __init__(self, tool_paths: Dict[str, str], scan_config: Dict = None):
        """Initialize the tools engine."""
        self.tool_paths = tool_paths
        self.scan_config = scan_config or {}
        self.tools: Dict[str, ToolInfo] = {}
        self.execution_history: List[ToolResult] = []
        self.allowed_targets: List[str] = []
        
        # Define tool metadata
        self._tool_definitions = {
            "nmap": {
                "description": "Network scanner for port scanning and service detection",
                "categories": ["recon", "port_scan", "service_detection"],
                "version_cmd": "--version",
            },
            "nuclei": {
                "description": "Fast vulnerability scanner using templates",
                "categories": ["vuln_scan", "cve_detection", "misconfig"],
                "version_cmd": "-version",
            },
            "sqlmap": {
                "description": "Automated SQL injection detection and exploitation",
                "categories": ["injection", "sqli", "exploitation"],
                "version_cmd": "--version",
            },
            "ffuf": {
                "description": "Fast web fuzzer for directory and parameter discovery",
                "categories": ["recon", "fuzzing", "directory_bruteforce"],
                "version_cmd": "-V",
            },
            "nikto": {
                "description": "Web server scanner for dangerous files and misconfigurations",
                "categories": ["vuln_scan", "web_server", "misconfig"],
                "version_cmd": "-Version",
            },
            "subfinder": {
                "description": "Subdomain discovery tool using passive sources",
                "categories": ["recon", "subdomain_enum"],
                "version_cmd": "-version",
            },
            "httpx": {
                "description": "Fast HTTP toolkit for probing and tech detection",
                "categories": ["recon", "http_probe", "tech_detection"],
                "version_cmd": "-version",
            },
            "katana": {
                "description": "Next-gen web crawler for endpoint discovery",
                "categories": ["recon", "crawling", "endpoint_discovery"],
                "version_cmd": "-version",
            },
            "dalfox": {
                "description": "XSS scanner and parameter analyzer",
                "categories": ["xss", "injection", "parameter_analysis"],
                "version_cmd": "version",
            },
            "whatweb": {
                "description": "Web technology identifier",
                "categories": ["recon", "tech_detection", "fingerprinting"],
                "version_cmd": "--version",
            },
            "wafw00f": {
                "description": "Web Application Firewall detection tool",
                "categories": ["recon", "waf_detection"],
                "version_cmd": "--version",
            },
            "curl": {
                "description": "HTTP client for making web requests",
                "categories": ["recon", "http_request", "utility"],
                "version_cmd": "--version",
            },
        }

        # Detect available tools
        self._detect_tools()

    def _detect_tools(self):
        """Detect which security tools are installed and available."""
        console.print("\n[bold cyan]🔧 Detecting Security Tools:[/bold cyan]")
        
        available_count = 0
        total_count = len(self._tool_definitions)

        for tool_name, definition in self._tool_definitions.items():
            # Check configured path first, then system PATH
            configured_path = self.tool_paths.get(tool_name, "")
            
            # Try to find the tool
            tool_path = None
            if configured_path and os.path.isfile(configured_path):
                tool_path = configured_path
            else:
                # Search in system PATH
                tool_path = shutil.which(tool_name)

            is_available = tool_path is not None
            version = ""

            if is_available:
                # Try to get version
                try:
                    version_cmd = definition.get("version_cmd", "--version")
                    result = subprocess.run(
                        [tool_path, version_cmd],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    version_output = result.stdout + result.stderr
                    # Extract first line as version
                    version = version_output.strip().split("\n")[0][:80]
                except Exception:
                    version = "detected"
                
                available_count += 1

            self.tools[tool_name] = ToolInfo(
                name=tool_name,
                path=tool_path or configured_path,
                description=definition["description"],
                is_available=is_available,
                version=version,
                categories=definition["categories"],
            )

            status_icon = "✅" if is_available else "❌"
            status_color = "green" if is_available else "red"
            console.print(
                f"  [{status_color}]{status_icon}[/] {tool_name:12s} | "
                f"{'Available' if is_available else 'NOT FOUND':12s} | "
                f"{definition['description'][:50]}"
            )

        console.print(
            f"\n  [bold]Tools Available: {available_count}/{total_count}[/bold]\n"
        )

    def set_allowed_targets(self, targets: List[str]):
        """Set allowed targets for scope enforcement."""
        self.allowed_targets = targets
        console.print(f"[green]🎯 Scope set: {', '.join(targets)}[/green]")

    def _check_scope(self, command: str) -> bool:
        """Check if the command targets are within allowed scope."""
        if not self.allowed_targets:
            return True  # No scope restriction if not set
        
        # Check if any allowed target appears in the command
        command_lower = command.lower()
        for target in self.allowed_targets:
            if target.lower() in command_lower:
                return True
        
        return False

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a specific tool is available."""
        tool = self.tools.get(tool_name)
        return tool is not None and tool.is_available

    def get_available_tools(self) -> List[str]:
        """Get list of available tool names."""
        return [name for name, tool in self.tools.items() if tool.is_available]

    def get_tools_for_category(self, category: str) -> List[str]:
        """Get available tools for a specific category."""
        return [
            name
            for name, tool in self.tools.items()
            if tool.is_available and category in tool.categories
        ]

    def get_tools_description(self) -> str:
        """Get a formatted description of all available tools for AI context."""
        descriptions = []
        for name, tool in self.tools.items():
            if tool.is_available:
                descriptions.append(
                    f"- {name}: {tool.description} (categories: {', '.join(tool.categories)})"
                )
        return "\n".join(descriptions)

    async def execute_command(
        self,
        command: str,
        timeout: int = 300,
        tool_name: str = "custom",
        parse_output: bool = True,
    ) -> ToolResult:
        """
        Execute a shell command asynchronously with timeout and safety checks.
        
        Args:
            command: Shell command to execute
            timeout: Maximum execution time in seconds
            tool_name: Name of the tool being executed
            parse_output: Whether to parse the output
            
        Returns:
            ToolResult with execution details
        """
        # Safety: Scope check
        if not self._check_scope(command):
            return ToolResult(
                tool_name=tool_name,
                command=command,
                stdout="",
                stderr="SCOPE VIOLATION: Target not in allowed scope!",
                return_code=-1,
                execution_time=0.0,
                success=False,
                error_message="Target not in allowed scope",
            )

        # Safety: Block dangerous commands
        dangerous_patterns = [
            "rm -rf", "mkfs", "dd if=", ":(){", "fork bomb",
            "> /dev/sda", "chmod -R 777 /", "shutdown", "reboot",
            "init 0", "init 6",
        ]
        command_lower = command.lower()
        for pattern in dangerous_patterns:
            if pattern in command_lower:
                return ToolResult(
                    tool_name=tool_name,
                    command=command,
                    stdout="",
                    stderr=f"BLOCKED: Dangerous command pattern detected: {pattern}",
                    return_code=-1,
                    execution_time=0.0,
                    success=False,
                    error_message=f"Dangerous command blocked: {pattern}",
                )

        console.print(f"  [dim]🔧 Executing: {command[:100]}...[/dim]")
        start_time = time.time()

        try:
            # Execute command asynchronously
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=os.setsid if os.name != "nt" else None,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                # Kill the process group
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    await asyncio.sleep(2)
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass

                execution_time = time.time() - start_time
                result = ToolResult(
                    tool_name=tool_name,
                    command=command,
                    stdout="",
                    stderr=f"Command timed out after {timeout} seconds",
                    return_code=-1,
                    execution_time=execution_time,
                    success=False,
                    error_message=f"Timeout after {timeout}s",
                )
                self.execution_history.append(result)
                return result

            execution_time = time.time() - start_time
            
            # Decode output
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            return_code = process.returncode

            # Parse output if requested
            parsed = None
            if parse_output and stdout:
                parsed = self._parse_tool_output(tool_name, stdout)

            result = ToolResult(
                tool_name=tool_name,
                command=command,
                stdout=stdout,
                stderr=stderr,
                return_code=return_code,
                execution_time=execution_time,
                success=return_code == 0 or bool(stdout),
                parsed_output=parsed,
            )

            self.execution_history.append(result)

            # Log result
            status = "✅" if result.success else "❌"
            console.print(
                f"  {status} {tool_name} completed in {execution_time:.1f}s "
                f"(output: {len(stdout)} chars)"
            )

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            result = ToolResult(
                tool_name=tool_name,
                command=command,
                stdout="",
                stderr=str(e),
                return_code=-1,
                execution_time=execution_time,
                success=False,
                error_message=str(e),
            )
            self.execution_history.append(result)
            console.print(f"  [red]❌ {tool_name} error: {e}[/red]")
            return result

    def execute_command_sync(
        self,
        command: str,
        timeout: int = 300,
        tool_name: str = "custom",
    ) -> ToolResult:
        """Synchronous wrapper for execute_command."""
        return asyncio.run(
            self.execute_command(command, timeout, tool_name)
        )

    def _parse_tool_output(
        self, tool_name: str, output: str
    ) -> Optional[Dict[str, Any]]:
        """Parse tool output into structured format."""
        parsers = {
            "nmap": self._parse_nmap,
            "subfinder": self._parse_subfinder,
            "httpx": self._parse_httpx,
            "ffuf": self._parse_ffuf,
            "whatweb": self._parse_whatweb,
            "wafw00f": self._parse_wafw00f,
            "nuclei": self._parse_nuclei,
            "curl": self._parse_curl,
        }

        parser = parsers.get(tool_name)
        if parser:
            try:
                return parser(output)
            except Exception as e:
                console.print(f"  [yellow]⚠️ Parse error for {tool_name}: {e}[/yellow]")
                return None
        return None

    # ============================================
    # TOOL-SPECIFIC PARSERS
    # ============================================

    def _parse_nmap(self, output: str) -> Dict[str, Any]:
        """Parse nmap output."""
        result = {
            "hosts": [],
            "open_ports": [],
            "services": [],
            "os_detection": [],
            "raw_lines": [],
        }

        current_host = None
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            result["raw_lines"].append(line)

            # Host detection
            if "Nmap scan report for" in line:
                host = line.replace("Nmap scan report for", "").strip()
                current_host = host
                result["hosts"].append(host)

            # Port detection
            elif "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]  # e.g., "80/tcp"
                    state = parts[1]       # e.g., "open"
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    
                    if state == "open":
                        port_info = {
                            "port": port_proto.split("/")[0],
                            "protocol": port_proto.split("/")[1] if "/" in port_proto else "tcp",
                            "state": state,
                            "service": service,
                            "version": version,
                            "host": current_host,
                        }
                        result["open_ports"].append(port_info)
                        result["services"].append(
                            f"{service} ({version})" if version else service
                        )

            # OS detection
            elif "OS details:" in line or "Running:" in line:
                result["os_detection"].append(line)

        return result

    def _parse_subfinder(self, output: str) -> Dict[str, Any]:
        """Parse subfinder output."""
        subdomains = [
            line.strip()
            for line in output.split("\n")
            if line.strip() and not line.startswith("[")
        ]
        return {
            "subdomains": subdomains,
            "count": len(subdomains),
        }

    def _parse_httpx(self, output: str) -> Dict[str, Any]:
        """Parse httpx output."""
        results = []
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("["):
                continue
            results.append(line)
        
        return {
            "live_hosts": results,
            "count": len(results),
        }

    def _parse_ffuf(self, output: str) -> Dict[str, Any]:
        """Parse ffuf output."""
        results = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            # ffuf typically outputs: URL [Status: XXX, Size: XXX, Words: XXX]
            if "Status:" in line or "[Status" in line:
                results.append(line)
            elif line.startswith("http"):
                results.append(line)
        
        return {
            "discovered": results,
            "count": len(results),
        }

    def _parse_whatweb(self, output: str) -> Dict[str, Any]:
        """Parse whatweb output."""
        technologies = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            # WhatWeb outputs technologies in brackets
            if "[" in line:
                # Extract technology names
                import re
                techs = re.findall(r'\[([^\]]+)\]', line)
                technologies.extend(techs)
        
        return {
            "technologies": technologies,
            "raw": output,
        }

    def _parse_wafw00f(self, output: str) -> Dict[str, Any]:
        """Parse wafw00f output."""
        waf_detected = "none"
        for line in output.split("\n"):
            line_lower = line.lower().strip()
            if "is behind" in line_lower:
                # Extract WAF name
                waf_detected = line.split("is behind")[-1].strip().strip(".")
            elif "no waf" in line_lower or "not behind" in line_lower:
                waf_detected = "none"
        
        return {
            "waf_detected": waf_detected,
            "raw": output,
        }

    def _parse_nuclei(self, output: str) -> Dict[str, Any]:
        """Parse nuclei output."""
        findings = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            # Nuclei outputs: [template-id] [severity] [protocol] URL
            if line.startswith("["):
                findings.append(line)
        
        # Categorize by severity
        critical = [f for f in findings if "critical" in f.lower()]
        high = [f for f in findings if "high" in f.lower()]
        medium = [f for f in findings if "medium" in f.lower()]
        low = [f for f in findings if "low" in f.lower()]
        info = [f for f in findings if "info" in f.lower()]

        return {
            "total_findings": len(findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "all_findings": findings,
        }

    def _parse_curl(self, output: str) -> Dict[str, Any]:
        """Parse curl output."""
        headers = {}
        body = ""
        
        # Split headers and body
        if "\r\n\r\n" in output:
            header_section, body = output.split("\r\n\r\n", 1)
            for line in header_section.split("\r\n"):
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key.lower()] = value
        else:
            body = output

        return {
            "headers": headers,
            "body": body[:5000],  # Limit body size
            "body_length": len(body),
        }

    # ============================================
    # PRE-BUILT COMMAND GENERATORS
    # ============================================

    def build_nmap_command(
        self,
        target: str,
        scan_type: str = "default",
        ports: str = None,
        extra_args: str = "",
    ) -> str:
        """Build nmap command based on scan type."""
        tool_path = self.tools["nmap"].path or "nmap"
        
        commands = {
            "quick": f"{tool_path} -T4 -F {target}",
            "default": f"{tool_path} -sV -sC -T4 {target}",
            "full": f"{tool_path} -sV -sC -T4 -p- {target}",
            "udp": f"{tool_path} -sU -T4 --top-ports 100 {target}",
            "vuln": f"{tool_path} --script=vuln -T4 {target}",
            "stealth": f"{tool_path} -sS -T2 -f {target}",
            "aggressive": f"{tool_path} -A -T4 -p- {target}",
        }
        
        cmd = commands.get(scan_type, commands["default"])
        
        if ports:
            cmd += f" -p {ports}"
        if extra_args:
            cmd += f" {extra_args}"
        
        return cmd

    def build_nuclei_command(
        self,
        target: str,
        severity: str = None,
        templates: str = None,
        extra_args: str = "",
    ) -> str:
        """Build nuclei command."""
        tool_path = self.tools["nuclei"].path or "nuclei"
        cmd = f"{tool_path} -u {target} -silent"
        
        if severity:
            cmd += f" -severity {severity}"
        if templates:
            cmd += f" -t {templates}"
        if extra_args:
            cmd += f" {extra_args}"
        
        return cmd

    def build_ffuf_command(
        self,
        target_url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        extra_args: str = "",
    ) -> str:
        """Build ffuf command for directory fuzzing."""
        tool_path = self.tools["ffuf"].path or "ffuf"
        cmd = (
            f"{tool_path} -u {target_url}/FUZZ "
            f"-w {wordlist} -mc 200,301,302,403 -t 50 -s"
        )
        if extra_args:
            cmd += f" {extra_args}"
        return cmd

    def build_sqlmap_command(
        self,
        target_url: str,
        data: str = None,
        extra_args: str = "",
    ) -> str:
        """Build sqlmap command."""
        tool_path = self.tools["sqlmap"].path or "sqlmap"
        cmd = f"{tool_path} -u \"{target_url}\" --batch --level=3 --risk=2"
        
        if data:
            cmd += f" --data=\"{data}\""
        if extra_args:
            cmd += f" {extra_args}"
        
        return cmd

    def build_katana_command(
        self,
        target: str,
        depth: int = 3,
        extra_args: str = "",
    ) -> str:
        """Build katana crawler command."""
        tool_path = self.tools["katana"].path or "katana"
        cmd = f"{tool_path} -u {target} -d {depth} -silent -jc"
        if extra_args:
            cmd += f" {extra_args}"
        return cmd

    def build_dalfox_command(
        self,
        target_url: str,
        extra_args: str = "",
    ) -> str:
        """Build dalfox XSS scanner command."""
        tool_path = self.tools["dalfox"].path or "dalfox"
        cmd = f"{tool_path} url \"{target_url}\" --silence"
        if extra_args:
            cmd += f" {extra_args}"
        return cmd

    def build_subfinder_command(
        self,
        domain: str,
        extra_args: str = "",
    ) -> str:
        """Build subfinder command."""
        tool_path = self.tools["subfinder"].path or "subfinder"
        cmd = f"{tool_path} -d {domain} -silent"
        if extra_args:
            cmd += f" {extra_args}"
        return cmd

    def build_whatweb_command(
        self,
        target: str,
        aggression: int = 3,
    ) -> str:
        """Build whatweb command."""
        tool_path = self.tools["whatweb"].path or "whatweb"
        return f"{tool_path} {target} -a {aggression} --color=never"

    def build_wafw00f_command(self, target: str) -> str:
        """Build wafw00f command."""
        tool_path = self.tools["wafw00f"].path or "wafw00f"
        return f"{tool_path} {target}"

    def build_nikto_command(
        self,
        target: str,
        extra_args: str = "",
    ) -> str:
        """Build nikto command."""
        tool_path = self.tools["nikto"].path or "nikto"
        cmd = f"{tool_path} -h {target} -nointeractive"
        if extra_args:
            cmd += f" {extra_args}"
        return cmd

    def build_curl_command(
        self,
        url: str,
        method: str = "GET",
        headers: Dict[str, str] = None,
        data: str = None,
        include_headers: bool = True,
        follow_redirects: bool = True,
        extra_args: str = "",
    ) -> str:
        """Build curl command."""
        tool_path = self.tools["curl"].path or "curl"
        cmd = f"{tool_path} -s"
        
        if include_headers:
            cmd += " -i"
        if follow_redirects:
            cmd += " -L"
        
        cmd += f" -X {method}"
        
        if headers:
            for key, value in headers.items():
                cmd += f" -H \"{key}: {value}\""
        
        if data:
            cmd += f" -d '{data}'"
        
        if extra_args:
            cmd += f" {extra_args}"
        
        cmd += f" \"{url}\""
        
        return cmd

    # ============================================
    # UTILITY METHODS
    # ============================================

    def get_execution_summary(self) -> Dict[str, Any]:
        """Get summary of all tool executions in this session."""
        total = len(self.execution_history)
        successful = sum(1 for r in self.execution_history if r.success)
        failed = total - successful
        total_time = sum(r.execution_time for r in self.execution_history)

        tools_used = {}
        for r in self.execution_history:
            if r.tool_name not in tools_used:
                tools_used[r.tool_name] = {"count": 0, "success": 0, "failed": 0}
            tools_used[r.tool_name]["count"] += 1
            if r.success:
                tools_used[r.tool_name]["success"] += 1
            else:
                tools_used[r.tool_name]["failed"] += 1

        return {
            "total_executions": total,
            "successful": successful,
            "failed": failed,
            "total_time": f"{total_time:.1f}s",
            "tools_used": tools_used,
        }

    def print_execution_summary(self):
        """Pretty print execution summary."""
        summary = self.get_execution_summary()
        console.print("\n[bold cyan]🔧 Tool Execution Summary:[/bold cyan]")
        console.print(f"  Total Executions: {summary['total_executions']}")
        console.print(f"  Successful:       {summary['successful']}")
        console.print(f"  Failed:           {summary['failed']}")
        console.print(f"  Total Time:       {summary['total_time']}")
        
        if summary["tools_used"]:
            console.print("  Tools Used:")
            for tool, stats in summary["tools_used"].items():
                console.print(
                    f"    {tool:12s} | "
                    f"Runs: {stats['count']} | "
                    f"✅ {stats['success']} | "
                    f"❌ {stats['failed']}"
                )