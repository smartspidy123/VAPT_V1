"""
VAPT-AI Nmap Tool
=================
LangChain-compatible tool wrapper for nmap.
"""

import asyncio
from typing import Optional, Type
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool


class NmapInput(BaseModel):
    """Input schema for Nmap tool."""
    target: str = Field(description="Target IP address, hostname, or CIDR range to scan")
    scan_type: str = Field(
        default="default",
        description="Scan type: quick, default, full, udp, vuln, stealth, aggressive"
    )
    ports: Optional[str] = Field(
        default=None,
        description="Specific ports to scan (e.g., '80,443,8080' or '1-1000')"
    )
    extra_args: str = Field(
        default="",
        description="Additional nmap arguments"
    )


class NmapTool(BaseTool):
    """LangChain tool for running nmap scans."""
    
    name: str = "nmap_scanner"
    description: str = (
        "Network scanner for port scanning, service detection, and vulnerability scanning. "
        "Use this to discover open ports, identify running services and their versions, "
        "and detect the operating system of the target. "
        "Scan types: quick (fast, top ports), default (service versions + scripts), "
        "full (all 65535 ports), vuln (vulnerability scripts), aggressive (all features)."
    )
    args_schema: Type[BaseModel] = NmapInput
    tool_engine: object = None  # Will be set during initialization

    class Config:
        arbitrary_types_allowed = True

    def _run(self, target: str, scan_type: str = "default", 
             ports: str = None, extra_args: str = "") -> str:
        """Execute nmap scan synchronously."""
        if not self.tool_engine:
            return "Error: Tool engine not initialized"
        
        if not self.tool_engine.is_tool_available("nmap"):
            return "Error: nmap is not installed"
        
        cmd = self.tool_engine.build_nmap_command(
            target=target,
            scan_type=scan_type,
            ports=ports,
            extra_args=extra_args,
        )
        
        result = self.tool_engine.execute_command_sync(
            command=cmd,
            timeout=300,
            tool_name="nmap",
        )
        
        if result.success:
            response = f"Nmap Scan Results:\n{result.stdout}"
            if result.parsed_output:
                ports_info = result.parsed_output.get("open_ports", [])
                if ports_info:
                    response += f"\n\nParsed Open Ports ({len(ports_info)}):\n"
                    for p in ports_info:
                        response += f"  - Port {p['port']}/{p['protocol']}: {p['service']} {p.get('version', '')}\n"
            return response
        else:
            return f"Nmap scan failed: {result.error_message or result.stderr}"

    async def _arun(self, target: str, scan_type: str = "default",
                    ports: str = None, extra_args: str = "") -> str:
        """Execute nmap scan asynchronously."""
        if not self.tool_engine:
            return "Error: Tool engine not initialized"
        
        cmd = self.tool_engine.build_nmap_command(
            target=target,
            scan_type=scan_type,
            ports=ports,
            extra_args=extra_args,
        )
        
        result = await self.tool_engine.execute_command(
            command=cmd,
            timeout=300,
            tool_name="nmap",
        )
        
        if result.success:
            return f"Nmap Scan Results:\n{result.stdout}"
        return f"Nmap scan failed: {result.error_message or result.stderr}"