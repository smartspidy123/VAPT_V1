"""
VAPT-AI Nuclei Tool
====================
LangChain-compatible tool wrapper for nuclei vulnerability scanner.
"""

import asyncio
from typing import Optional, Type
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool


class NucleiInput(BaseModel):
    """Input schema for Nuclei tool."""
    target: str = Field(description="Target URL to scan for vulnerabilities")
    severity: Optional[str] = Field(
        default=None,
        description="Filter by severity: critical, high, medium, low, info (comma-separated)"
    )
    templates: Optional[str] = Field(
        default=None,
        description="Specific template path or category to use"
    )
    extra_args: str = Field(default="", description="Additional nuclei arguments")


class NucleiTool(BaseTool):
    """LangChain tool for running nuclei vulnerability scans."""
    
    name: str = "nuclei_scanner"
    description: str = (
        "Fast template-based vulnerability scanner. Scans for known CVEs, "
        "misconfigurations, exposed panels, default credentials, and more. "
        "Use severity filter to focus on critical/high issues first. "
        "This is excellent for finding known vulnerability patterns quickly."
    )
    args_schema: Type[BaseModel] = NucleiInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, target: str, severity: str = None,
             templates: str = None, extra_args: str = "") -> str:
        if not self.tool_engine:
            return "Error: Tool engine not initialized"
        
        if not self.tool_engine.is_tool_available("nuclei"):
            return "Error: nuclei is not installed"
        
        cmd = self.tool_engine.build_nuclei_command(
            target=target, severity=severity,
            templates=templates, extra_args=extra_args,
        )
        
        result = self.tool_engine.execute_command_sync(
            command=cmd, timeout=600, tool_name="nuclei",
        )
        
        if result.success:
            response = f"Nuclei Scan Results:\n{result.stdout}"
            if result.parsed_output:
                parsed = result.parsed_output
                response += (
                    f"\n\nSummary: {parsed.get('total_findings', 0)} findings "
                    f"(Critical: {len(parsed.get('critical', []))}, "
                    f"High: {len(parsed.get('high', []))}, "
                    f"Medium: {len(parsed.get('medium', []))}, "
                    f"Low: {len(parsed.get('low', []))})"
                )
            return response
        return f"Nuclei scan failed: {result.error_message or result.stderr}"

    async def _arun(self, target: str, severity: str = None,
                    templates: str = None, extra_args: str = "") -> str:
        if not self.tool_engine:
            return "Error: Tool engine not initialized"
        
        cmd = self.tool_engine.build_nuclei_command(
            target=target, severity=severity,
            templates=templates, extra_args=extra_args,
        )
        
        result = await self.tool_engine.execute_command(
            command=cmd, timeout=600, tool_name="nuclei",
        )
        
        if result.success:
            return f"Nuclei Scan Results:\n{result.stdout}"
        return f"Nuclei scan failed: {result.error_message or result.stderr}"