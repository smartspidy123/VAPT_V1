"""
VAPT-AI Tools Engine Test
=========================
Tests security tool detection and basic command execution.

Usage: python test_tools.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from config import settings
from core.tool_engine import SecurityToolsEngine
from tools.web_tools import create_all_tools

console = Console()


async def main():
    console.print(
        Panel(
            "[bold red]🔧 VAPT-AI Tools Engine Test 🔧[/bold red]\n"
            "Testing security tool detection and execution...",
            border_style="red",
        )
    )

    # Initialize tool engine
    engine = SecurityToolsEngine(
        tool_paths=settings.TOOL_PATHS,
        scan_config=settings.SCAN_CONFIG,
    )

    # Print available tools
    available = engine.get_available_tools()
    console.print(f"\n[bold]Available tools: {len(available)}[/bold]")
    console.print(f"Tools: {', '.join(available)}")

    # Test tool categories
    console.print("\n[bold]Tools by category:[/bold]")
    for category in ["recon", "vuln_scan", "injection", "fuzzing"]:
        tools = engine.get_tools_for_category(category)
        console.print(f"  {category}: {', '.join(tools) if tools else 'none'}")

    # Test basic curl command (safe test)
    console.print("\n[bold]Testing curl against httpbin.org...[/bold]")
    result = await engine.execute_command(
        command='curl -s -o /dev/null -w "%{http_code}" https://httpbin.org/get',
        timeout=30,
        tool_name="curl",
    )
    console.print(f"  Status Code: {result.stdout}")
    console.print(f"  Success: {result.success}")
    console.print(f"  Time: {result.execution_time:.2f}s")

    # Test nmap version (no scan, just version check)
    if engine.is_tool_available("nmap"):
        console.print("\n[bold]Testing nmap (version only)...[/bold]")
        result = await engine.execute_command(
            command="nmap --version",
            timeout=10,
            tool_name="nmap",
        )
        console.print(f"  {result.stdout.split(chr(10))[0]}")

    # Create LangChain tools
    console.print("\n[bold]Creating LangChain tool wrappers...[/bold]")
    tools = create_all_tools(engine)
    console.print(f"  Created {len(tools)} tool wrappers:")
    for tool in tools:
        console.print(f"    🔧 {tool.name}: {tool.description[:60]}...")

    # Test scope enforcement
    console.print("\n[bold]Testing scope enforcement...[/bold]")
    engine.set_allowed_targets(["httpbin.org", "localhost"])
    
    # This should pass (in scope)
    result = await engine.execute_command(
        command="curl -s https://httpbin.org/headers",
        timeout=10,
        tool_name="curl",
    )
    console.print(f"  In-scope test: {'✅ Allowed' if result.success else '❌ Blocked'}")

    # This should fail (out of scope)
    result = await engine.execute_command(
        command="curl -s https://evil.com/hack",
        timeout=10,
        tool_name="curl",
    )
    console.print(
        f"  Out-of-scope test: {'✅ Correctly Blocked' if not result.success else '❌ Should have blocked!'}"
    )

    # Test dangerous command blocking
    console.print("\n[bold]Testing dangerous command blocking...[/bold]")
    result = await engine.execute_command(
        command="rm -rf /",
        timeout=10,
        tool_name="custom",
    )
    console.print(
        f"  Dangerous cmd test: {'✅ Correctly Blocked' if not result.success else '❌ DANGER!'}"
    )

    # Print execution summary
    engine.print_execution_summary()

    # Print AI-friendly tool descriptions
    console.print("\n[bold]AI-Friendly Tool Descriptions:[/bold]")
    console.print(engine.get_tools_description())

    console.print("\n[bold green]🎉 Tools Engine Test Complete![/bold green]")


if __name__ == "__main__":
    asyncio.run(main())
