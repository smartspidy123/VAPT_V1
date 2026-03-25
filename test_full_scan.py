"""
VAPT-AI Full Scan Test
=======================
Tests the complete pipeline: Recon → Analysis → Planning → Execution

Usage: python test_full_scan.py [target_url]
Default: http://localhost:3000 (Juice Shop)
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
from agents.analyzer import AnalyzerAgent
from agents.planner import PlannerAgent
from agents.executor import ExecutorAgent

console = Console()


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "https://httpbin.org"

    print_banner()

    console.print(
        Panel(
            f"[bold]⚔️ VAPT-AI Full Scan Test[/bold]\n"
            f"Target: [cyan]{target}[/cyan]\n"
            f"Mode: AUTO SCAN\n"
            f"Pipeline: Recon → Analysis → Planning → Execution",
            border_style="red",
        )
    )

    # Initialize components
    console.print("\n[bold]Initializing...[/bold]")
    llm_router = SmartLLMRouter(settings)
    tool_engine = SecurityToolsEngine(
        tool_paths=settings.TOOL_PATHS,
        scan_config=settings.SCAN_CONFIG,
    )
    tool_engine.set_allowed_targets([target])

    # Dashboard
    dashboard = Dashboard()
    dashboard.set_target(target)
    dashboard.set_mode("AUTO SCAN")
    dashboard.set_model_info("auto", "multi-model")

    # Create agents
    recon_agent = ReconAgent(llm_router, tool_engine, dashboard)
    analyzer_agent = AnalyzerAgent(llm_router, dashboard)
    planner_agent = PlannerAgent(llm_router, tool_engine, dashboard)
    executor_agent = ExecutorAgent(llm_router, tool_engine, dashboard)

    console.print("[bold yellow]Starting full scan in 3 seconds...[/bold yellow]")
    await asyncio.sleep(3)

    with dashboard:
        # Phase 1: Recon
        dashboard.add_log("═══ PHASE 1: RECONNAISSANCE ═══", "info")
        recon_data = await recon_agent.run(target=target, intensity="medium")

        await asyncio.sleep(1)

        # Phase 2: Analysis
        dashboard.add_log("═══ PHASE 2: VULNERABILITY ANALYSIS ═══", "info")
        analysis_results = await analyzer_agent.run(recon_data)

        await asyncio.sleep(1)

        # Phase 3: Planning
        dashboard.add_log("═══ PHASE 3: ATTACK PLANNING ═══", "info")
        attack_plan = await planner_agent.run(analysis_results, recon_data)

        await asyncio.sleep(1)

        # Phase 4: Execution
        dashboard.add_log("═══ PHASE 4: ATTACK EXECUTION ═══", "info")
        execution_results = await executor_agent.run(attack_plan, recon_data)

        await asyncio.sleep(2)

    # Save all results
    all_results = {
        "target": target,
        "scan_time": dashboard._get_elapsed_time(),
        "recon_summary": {
            "subdomains": len(recon_data.get("subdomains", [])),
            "ports": len(recon_data.get("open_ports", [])),
            "endpoints": len(recon_data.get("endpoints", [])),
            "directories": len(recon_data.get("directories", [])),
            "waf": recon_data.get("waf", "unknown"),
        },
        "analysis_summary": {
            "potential_vulns": len(analysis_results.get("potential_vulnerabilities", [])),
            "priority_targets": len(analysis_results.get("priority_targets", [])),
        },
        "plan_summary": {
            "total_tasks": attack_plan.get("total_tasks", 0),
        },
        "execution_summary": {
            "tasks_executed": execution_results.get("tasks_executed", 0),
            "confirmed": execution_results.get("vulnerabilities_confirmed", 0),
            "potential": execution_results.get("vulnerabilities_potential", 0),
        },
        "confirmed_vulnerabilities": execution_results.get("confirmed_vulnerabilities", []),
    }

    output_file = settings.DATA_DIR / "full_scan_results.json"
    with open(output_file, "w") as f:
        serializable = {}
        for k, v in all_results.items():
            try:
                json.dumps(v)
                serializable[k] = v
            except (TypeError, ValueError):
                serializable[k] = str(v)
        json.dump(serializable, f, indent=2)

    console.print(f"\n[green]✅ Full results saved: {output_file}[/green]")

    # Print final report
    print_final_report_summary(
        findings=dashboard.findings,
        elapsed=dashboard._get_elapsed_time(),
        stats={
            "requests": dashboard.total_requests,
            "tokens": dashboard.total_tokens,
            "tools": dashboard.tools_run,
        },
    )

    # Print LLM usage
    llm_router.print_usage_stats()
    tool_engine.print_execution_summary()

    console.print("\n[bold green]🎉 Full scan complete![/bold green]")


if __name__ == "__main__":
    asyncio.run(main())