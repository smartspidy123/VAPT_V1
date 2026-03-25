"""
VAPT-AI - Autonomous VAPT & Bug Bounty Agent
=============================================
Main orchestrator that connects all agents and runs scans.

Usage:
    python main.py auto <target_url>          # Full automated scan
    python main.py recon <target_url>         # Recon only
    python main.py manual <target_url>        # Interactive manual mode
    python main.py --help                     # Show help
"""

import asyncio
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

from config import settings
from core.llm_router import SmartLLMRouter
from core.tool_engine import SecurityToolsEngine
from core.dashboard import (
    Dashboard,
    print_banner,
    print_scan_config,
    print_final_report_summary,
)
from agents.recon import ReconAgent
from agents.analyzer import AnalyzerAgent
from agents.planner import PlannerAgent
from agents.executor import ExecutorAgent
from agents.reporter import ReporterAgent

console = Console()


class VAPTAIOrchestrator:
    """Main orchestrator for VAPT-AI scans."""

    def __init__(self):
        self.llm_router = None
        self.tool_engine = None
        self.dashboard = None
        self.target = ""
        self.mode = "auto"
        self.intensity = "medium"

    def initialize(self):
        """Initialize all components."""
        console.print("\n[bold]⚙️ Initializing VAPT-AI...[/bold]\n")

        # LLM Router
        self.llm_router = SmartLLMRouter(settings)

        # Tool Engine
        self.tool_engine = SecurityToolsEngine(
            tool_paths=settings.TOOL_PATHS,
            scan_config=settings.SCAN_CONFIG,
        )

        console.print("[green]✅ All components initialized[/green]\n")

    async def run_auto_scan(self, target: str, intensity: str = "medium"):
        """Run full automated scan pipeline."""
        self.target = target
        self.mode = "auto"
        self.intensity = intensity

        # Set scope
        self.tool_engine.set_allowed_targets([target])

        # Dashboard
        self.dashboard = Dashboard()
        self.dashboard.set_target(target)
        self.dashboard.set_mode("AUTO SCAN")
        self.dashboard.set_model_info("auto", "multi-model")

        # Create agents
        recon = ReconAgent(self.llm_router, self.tool_engine, self.dashboard)
        analyzer = AnalyzerAgent(self.llm_router, self.dashboard)
        planner = PlannerAgent(self.llm_router, self.tool_engine, self.dashboard)
        executor = ExecutorAgent(self.llm_router, self.tool_engine, self.dashboard)
        reporter = ReporterAgent(self.llm_router, self.dashboard)

        print_scan_config(target, "AUTO SCAN", "Multi-Provider", "Auto-Routed")

        console.print("[bold yellow]🚀 Starting scan in 3 seconds...[/bold yellow]")
        await asyncio.sleep(3)

        recon_data = {}
        analysis_results = {}
        attack_plan = {}
        execution_results = {}

        with self.dashboard:
            # Phase 1: Recon
            self.dashboard.add_log("═══ PHASE 1: RECONNAISSANCE ═══", "info")
            recon_data = await recon.run(target=target, intensity=intensity)
            await asyncio.sleep(1)

            # Phase 2: Analysis
            self.dashboard.add_log("═══ PHASE 2: VULNERABILITY ANALYSIS ═══", "info")
            analysis_results = await analyzer.run(recon_data)
            await asyncio.sleep(1)

            # Phase 3: Planning
            self.dashboard.add_log("═══ PHASE 3: ATTACK PLANNING ═══", "info")
            attack_plan = await planner.run(analysis_results, recon_data)
            await asyncio.sleep(1)

            # Phase 4: Execution
            self.dashboard.add_log("═══ PHASE 4: ATTACK EXECUTION ═══", "info")
            execution_results = await executor.run(attack_plan, recon_data)
            await asyncio.sleep(1)

            # Phase 5: Reporting
            self.dashboard.add_log("═══ PHASE 5: REPORT GENERATION ═══", "info")
            report = await reporter.run(
                recon_data=recon_data,
                analysis_results=analysis_results,
                attack_plan=attack_plan,
                execution_results=execution_results,
                scan_duration=self.dashboard._get_elapsed_time(),
            )
            await asyncio.sleep(2)

        # Final output
        self._print_final_results(execution_results)

    async def run_recon_only(self, target: str, intensity: str = "medium"):
        """Run reconnaissance only."""
        self.target = target
        self.tool_engine.set_allowed_targets([target])

        self.dashboard = Dashboard()
        self.dashboard.set_target(target)
        self.dashboard.set_mode("RECON ONLY")
        self.dashboard.set_model_info("auto", "multi-model")

        recon = ReconAgent(self.llm_router, self.tool_engine, self.dashboard)

        print_scan_config(target, "RECON ONLY", "Multi-Provider", "Auto-Routed")

        with self.dashboard:
            recon_data = await recon.run(target=target, intensity=intensity)

        console.print("\n[green]✅ Recon complete![/green]")
        self.llm_router.print_usage_stats()
        self.tool_engine.print_execution_summary()

    async def run_manual_mode(self, target: str):
        """Run interactive manual mode."""
        self.target = target
        self.tool_engine.set_allowed_targets([target])

        console.print(
            Panel(
                f"[bold]🎮 VAPT-AI Manual Mode[/bold]\n"
                f"Target: [cyan]{target}[/cyan]\n"
                f"Type 'help' for commands, 'exit' to quit",
                border_style="cyan",
            )
        )

        # Create agents (without dashboard for cleaner output)
        recon = ReconAgent(self.llm_router, self.tool_engine)
        analyzer = AnalyzerAgent(self.llm_router)
        planner = PlannerAgent(self.llm_router, self.tool_engine)
        executor = ExecutorAgent(self.llm_router, self.tool_engine)
        reporter = ReporterAgent(self.llm_router)

        recon_data = {}
        analysis_results = {}
        attack_plan = {}
        execution_results = {}

        while True:
            try:
                command = Prompt.ask("\n[bold cyan]vapt-ai>[/bold cyan]").strip().lower()

                if command == "exit" or command == "quit":
                    console.print("[yellow]Exiting...[/yellow]")
                    break

                elif command == "help":
                    self._print_manual_help()

                elif command == "recon" or command == "1":
                    intensity = Prompt.ask(
                        "Intensity", choices=["low", "medium", "high"], default="medium"
                    )
                    recon_data = await recon.run(target=target, intensity=intensity)
                    console.print("[green]✅ Recon complete![/green]")

                elif command == "analyze" or command == "2":
                    if not recon_data:
                        console.print("[red]Run recon first![/red]")
                        continue
                    analysis_results = await analyzer.run(recon_data)
                    console.print("[green]✅ Analysis complete![/green]")

                elif command == "plan" or command == "3":
                    if not analysis_results:
                        console.print("[red]Run analysis first![/red]")
                        continue
                    attack_plan = await planner.run(analysis_results, recon_data)
                    console.print("[green]✅ Plan created![/green]")

                elif command == "attack" or command == "4":
                    if not attack_plan:
                        console.print("[red]Create plan first![/red]")
                        continue
                    if not Confirm.ask("⚠️ Start attack execution?"):
                        continue
                    execution_results = await executor.run(attack_plan, recon_data)
                    console.print("[green]✅ Execution complete![/green]")

                elif command == "report" or command == "5":
                    if not execution_results:
                        console.print("[red]Run attack first![/red]")
                        continue
                    report = await reporter.run(
                        recon_data, analysis_results, attack_plan, execution_results
                    )
                    console.print("[green]✅ Report generated![/green]")

                elif command == "auto" or command == "6":
                    if Confirm.ask("Run full auto scan?"):
                        await self.run_auto_scan(target)

                elif command == "stats":
                    self.llm_router.print_usage_stats()
                    self.tool_engine.print_execution_summary()

                elif command == "findings":
                    if execution_results:
                        confirmed = execution_results.get("confirmed_vulnerabilities", [])
                        console.print(f"\n[bold]Confirmed: {len(confirmed)}[/bold]")
                        for v in confirmed:
                            console.print(
                                f"  [{v.get('severity', 'medium').upper()}] "
                                f"{v.get('attack_type')} → {v.get('target_url')}"
                            )
                    else:
                        console.print("[dim]No findings yet. Run a scan first.[/dim]")

                else:
                    console.print(f"[yellow]Unknown command: {command}. Type 'help'.[/yellow]")

            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'exit' to quit[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

    def _print_manual_help(self):
        """Print manual mode help."""
        help_text = """
[bold]Available Commands:[/bold]

  [cyan]1 / recon[/cyan]     - Run reconnaissance
  [cyan]2 / analyze[/cyan]   - Analyze recon data for vulnerabilities
  [cyan]3 / plan[/cyan]      - Create attack plan
  [cyan]4 / attack[/cyan]    - Execute attacks
  [cyan]5 / report[/cyan]    - Generate report
  [cyan]6 / auto[/cyan]      - Run full auto scan

  [cyan]stats[/cyan]         - Show LLM and tool usage stats
  [cyan]findings[/cyan]      - Show current findings
  [cyan]help[/cyan]          - Show this help
  [cyan]exit[/cyan]          - Exit VAPT-AI
"""
        console.print(help_text)

    def _print_final_results(self, execution_results: Dict):
        """Print final scan results."""
        if self.dashboard:
            print_final_report_summary(
                findings=self.dashboard.findings,
                elapsed=self.dashboard._get_elapsed_time(),
                stats={
                    "requests": self.dashboard.total_requests,
                    "tokens": self.dashboard.total_tokens,
                    "tools": self.dashboard.tools_run,
                },
            )

        self.llm_router.print_usage_stats()
        self.tool_engine.print_execution_summary()


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="VAPT-AI - Autonomous VAPT & Bug Bounty Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py auto https://target.com           Full auto scan
  python main.py auto https://target.com --high     Aggressive scan
  python main.py recon https://target.com           Recon only
  python main.py manual https://target.com          Interactive mode
        """,
    )

    parser.add_argument(
        "mode",
        choices=["auto", "recon", "manual"],
        help="Scan mode: auto (full scan), recon (recon only), manual (interactive)",
    )
    parser.add_argument(
        "target",
        help="Target URL (e.g., https://example.com)",
    )
    parser.add_argument(
        "--intensity", "-i",
        choices=["low", "medium", "high"],
        default="medium",
        help="Scan intensity (default: medium)",
    )
    parser.add_argument(
        "--high",
        action="store_const",
        const="high",
        dest="intensity",
        help="Shortcut for --intensity high",
    )

    return parser.parse_args()


async def main():
    """Main entry point."""
    print_banner()

    args = parse_args()

    # Create and initialize orchestrator
    orchestrator = VAPTAIOrchestrator()
    orchestrator.initialize()

    # Run based on mode
    if args.mode == "auto":
        await orchestrator.run_auto_scan(args.target, args.intensity)
    elif args.mode == "recon":
        await orchestrator.run_recon_only(args.target, args.intensity)
    elif args.mode == "manual":
        await orchestrator.run_manual_mode(args.target)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        raise