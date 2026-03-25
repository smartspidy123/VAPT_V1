"""
VAPT-AI Recon Agent Test
=========================
Tests the recon agent against a safe target.

Usage: python test_recon.py [target_url]

Default target: http://localhost:3000 (OWASP Juice Shop)
Safe test: https://httpbin.org
"""

import asyncio
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from config import settings
from core.llm_router import SmartLLMRouter
from core.tool_engine import SecurityToolsEngine
from core.dashboard import Dashboard, print_banner, print_final_report_summary
from agents.recon import ReconAgent

console = Console()


async def main():
    # Get target from command line or use default
    target = sys.argv[1] if len(sys.argv) > 1 else "https://httpbin.org"

    print_banner()

    console.print(
        Panel(
            f"[bold]🔍 VAPT-AI Recon Agent Test[/bold]\n"
            f"Target: [cyan]{target}[/cyan]\n"
            f"Intensity: medium",
            border_style="cyan",
        )
    )

    # Initialize components
    console.print("\n[bold]Initializing components...[/bold]")

    llm_router = SmartLLMRouter(settings)
    tool_engine = SecurityToolsEngine(
        tool_paths=settings.TOOL_PATHS,
        scan_config=settings.SCAN_CONFIG,
    )
    tool_engine.set_allowed_targets([target])

    # Create dashboard
    dashboard = Dashboard()
    dashboard.set_target(target)
    dashboard.set_mode("RECON ONLY")
    dashboard.set_model_info("nvidia", "auto-routed")

    # Create recon agent
    recon_agent = ReconAgent(
        llm_router=llm_router,
        tool_engine=tool_engine,
        dashboard=dashboard,
    )

    # Run with live dashboard
    console.print("\n[bold yellow]Starting recon in 3 seconds...[/bold yellow]")
    await asyncio.sleep(3)

    with dashboard:
        recon_data = await recon_agent.run(target=target, intensity="medium")

    # Save results
    output_file = settings.DATA_DIR / "recon_results.json"
    with open(output_file, "w") as f:
        # Filter out non-serializable data
        serializable_data = {}
        for key, value in recon_data.items():
            try:
                json.dumps(value)
                serializable_data[key] = value
            except (TypeError, ValueError):
                serializable_data[key] = str(value)
        json.dump(serializable_data, f, indent=2)

    console.print(f"\n[green]✅ Recon data saved to: {output_file}[/green]")

    # Print summary
    console.print("\n[bold]📊 Recon Summary:[/bold]")
    summary_keys = [
        "subdomains", "open_ports", "technologies",
        "directories", "endpoints", "waf",
        "interesting_findings",
    ]

    for key in summary_keys:
        value = recon_data.get(key)
        if isinstance(value, list):
            console.print(f"  {key}: {len(value)} items")
            for item in value[:3]:
                console.print(f"    → {item}")
        elif value:
            console.print(f"  {key}: {value}")

    # Print AI analysis if available
    if recon_data.get("ai_analysis"):
        console.print("\n[bold magenta]🤖 AI Analysis:[/bold magenta]")
        console.print(recon_data["ai_analysis"][:1000])

    # Print tool execution summary
    tool_engine.print_execution_summary()
    llm_router.print_usage_stats()

    console.print("\n[bold green]🎉 Recon test complete![/bold green]")


if __name__ == "__main__":
    asyncio.run(main())