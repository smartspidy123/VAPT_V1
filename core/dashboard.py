"""
VAPT-AI CLI Dashboard
======================
Rich + Live display based hacker-style CLI dashboard.
Shows real-time progress, findings, logs, and stats.
"""

import time
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import deque

from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    SpinnerColumn,
)
from rich.align import Align
from rich import box


console = Console()


# ============================================
# DATA CLASSES
# ============================================

@dataclass
class Finding:
    """Represents a discovered vulnerability."""
    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    vuln_type: str
    location: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    details: str = ""
    confirmed: bool = False


@dataclass
class LogEntry:
    """Represents a log entry."""
    timestamp: str
    level: str  # info, success, warning, error, action
    message: str
    source: str = ""


# ============================================
# PHASE TRACKER
# ============================================

class PhaseTracker:
    """Track progress of each scan phase."""

    def __init__(self):
        self.phases = {
            "recon": {"name": "RECON", "emoji": "📡", "progress": 0, "status": "pending", "tasks_total": 0, "tasks_done": 0},
            "analysis": {"name": "ANALYSIS", "emoji": "🔍", "progress": 0, "status": "pending", "tasks_total": 0, "tasks_done": 0},
            "planning": {"name": "PLANNING", "emoji": "📋", "progress": 0, "status": "pending", "tasks_total": 0, "tasks_done": 0},
            "execution": {"name": "EXECUTION", "emoji": "⚔️", "progress": 0, "status": "pending", "tasks_total": 0, "tasks_done": 0},
            "reporting": {"name": "REPORTING", "emoji": "📄", "progress": 0, "status": "pending", "tasks_total": 0, "tasks_done": 0},
        }
        self.current_phase = None

    def start_phase(self, phase: str, total_tasks: int = 100):
        self.current_phase = phase
        if phase in self.phases:
            self.phases[phase]["status"] = "running"
            self.phases[phase]["progress"] = 0
            self.phases[phase]["tasks_total"] = total_tasks
            self.phases[phase]["tasks_done"] = 0

    def update_phase(self, phase: str, progress: int = None, tasks_done: int = None):
        if phase in self.phases:
            if progress is not None:
                self.phases[phase]["progress"] = min(progress, 100)
            if tasks_done is not None:
                self.phases[phase]["tasks_done"] = tasks_done
                total = self.phases[phase]["tasks_total"]
                if total > 0:
                    self.phases[phase]["progress"] = int((tasks_done / total) * 100)

    def complete_phase(self, phase: str):
        if phase in self.phases:
            self.phases[phase]["status"] = "complete"
            self.phases[phase]["progress"] = 100

    def fail_phase(self, phase: str):
        if phase in self.phases:
            self.phases[phase]["status"] = "failed"

    def get_overall_progress(self) -> int:
        total = sum(p["progress"] for p in self.phases.values())
        return total // len(self.phases)


# ============================================
# DASHBOARD
# ============================================

class Dashboard:
    """
    Real-time CLI dashboard for VAPT-AI.
    
    Features:
    - Live progress bars for each phase
    - Real-time log display
    - Findings counter by severity
    - LLM usage stats
    - Current action display
    - Timer
    """

    def __init__(self):
        self.target: str = ""
        self.mode: str = "AUTO"
        self.model_info: str = ""
        self.start_time: datetime = datetime.now()

        # Tracking
        self.phase_tracker = PhaseTracker()
        self.findings: List[Finding] = []
        self.log_entries: deque = deque(maxlen=50)  # Keep last 50 logs
        self.current_action: str = "Initializing..."
        self.ai_thought: str = ""

        # Stats
        self.total_tokens: int = 0
        self.total_requests: int = 0
        self.total_cost: float = 0.0
        self.active_provider: str = ""
        self.active_model: str = ""
        self.tools_run: int = 0

        # Display control
        self._live: Optional[Live] = None
        self._running: bool = False
        self._lock = threading.Lock()

    def set_target(self, target: str):
        self.target = target

    def set_mode(self, mode: str):
        self.mode = mode.upper()

    def set_model_info(self, provider: str, model: str):
        self.active_provider = provider
        self.active_model = model
        self.model_info = f"{provider}/{model}"

    def update_llm_stats(self, tokens: int = 0, requests: int = 0, cost: float = 0.0):
        with self._lock:
            self.total_tokens += tokens
            self.total_requests += requests
            self.total_cost += cost

    def set_current_action(self, action: str):
        with self._lock:
            self.current_action = action

    def set_ai_thought(self, thought: str):
        with self._lock:
            self.ai_thought = thought[:200]  # Limit length

    def add_log(self, message: str, level: str = "info", source: str = ""):
        with self._lock:
            entry = LogEntry(
                timestamp=datetime.now().strftime("%H:%M:%S"),
                level=level,
                message=message,
                source=source,
            )
            self.log_entries.append(entry)

    def add_finding(self, finding: Finding):
        with self._lock:
            self.findings.append(finding)

    def add_finding_simple(
        self, title: str, severity: str, vuln_type: str, location: str, details: str = ""
    ):
        finding = Finding(
            id=f"VAPT-{len(self.findings) + 1:03d}",
            title=title,
            severity=severity.lower(),
            vuln_type=vuln_type,
            location=location,
            details=details,
        )
        self.add_finding(finding)

    def increment_tools_run(self):
        with self._lock:
            self.tools_run += 1

    # ============================================
    # RENDERING
    # ============================================

    def _get_elapsed_time(self) -> str:
        elapsed = datetime.now() - self.start_time
        hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _get_severity_counts(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _build_header(self) -> Panel:
        header_text = Text()
        header_text.append("🔥 VAPT-AI v1.0 🔥\n", style="bold red")
        header_text.append("Autonomous VAPT & Bug Bounty Agent", style="dim white")

        return Panel(
            Align.center(header_text),
            border_style="bright_red",
            box=box.DOUBLE,
        )

    def _build_target_info(self) -> Panel:
        info = Text()
        info.append(f"  Target:  ", style="dim")
        info.append(f"{self.target}\n", style="bold cyan")
        info.append(f"  Mode:    ", style="dim")
        info.append(f"{self.mode}", style="bold yellow")
        info.append(f"    Model: ", style="dim")
        info.append(f"{self.model_info}\n", style="bold green")
        info.append(f"  Started: ", style="dim")
        info.append(f"{self.start_time.strftime('%H:%M:%S')}", style="white")
        info.append(f"    Elapsed: ", style="dim")
        info.append(f"{self._get_elapsed_time()}", style="bold white")

        return Panel(info, border_style="cyan", box=box.ROUNDED, title="[bold]Target Info[/bold]")

    def _build_progress(self) -> Panel:
        lines = Text()

        for phase_key, phase in self.phase_tracker.phases.items():
            emoji = phase["emoji"]
            name = phase["name"]
            progress = phase["progress"]
            status = phase["status"]

            # Status indicator
            if status == "complete":
                status_str = "✅ Complete"
                bar_style = "green"
            elif status == "running":
                status_str = "⏳ Running"
                bar_style = "yellow"
            elif status == "failed":
                status_str = "❌ Failed"
                bar_style = "red"
            else:
                status_str = "⏸  Pending"
                bar_style = "dim"

            # Progress bar
            bar_width = 30
            filled = int(bar_width * progress / 100)
            empty = bar_width - filled

            lines.append(f"  {emoji} {name:12s} [", style="white")
            lines.append("█" * filled, style=bar_style)
            lines.append("░" * empty, style="dim")
            lines.append(f"] {progress:3d}% ", style="white")
            lines.append(f"{status_str}\n", style=bar_style)

        return Panel(lines, border_style="yellow", box=box.ROUNDED, title="[bold]Scan Progress[/bold]")

    def _build_findings_summary(self) -> Panel:
        counts = self._get_severity_counts()
        total = sum(counts.values())

        findings_text = Text()
        findings_text.append(f"  🔴 CRITICAL: {counts['critical']}  ", style="bold red")
        findings_text.append(f"  🟠 HIGH: {counts['high']}  ", style="bold bright_red")
        findings_text.append(f"  🟡 MEDIUM: {counts['medium']}  ", style="bold yellow")
        findings_text.append(f"  🔵 LOW: {counts['low']}  ", style="bold blue")
        findings_text.append(f"  ⚪ INFO: {counts['info']}", style="dim")
        findings_text.append(f"\n  Total Findings: {total}", style="bold white")

        return Panel(
            findings_text,
            border_style="red" if counts["critical"] > 0 else "green",
            box=box.ROUNDED,
            title="[bold]Findings[/bold]",
        )

    def _build_log_panel(self) -> Panel:
        log_text = Text()
        
        # Show last 12 log entries
        recent_logs = list(self.log_entries)[-12:]
        
        if not recent_logs:
            log_text.append("  Waiting for actions...", style="dim")
        else:
            for entry in recent_logs:
                # Level-based styling
                level_styles = {
                    "info": ("ℹ️", "dim white"),
                    "success": ("✅", "green"),
                    "warning": ("⚠️", "yellow"),
                    "error": ("❌", "red"),
                    "action": ("🔧", "cyan"),
                    "finding": ("🎯", "bold red"),
                    "ai": ("🤖", "bright_magenta"),
                }
                
                icon, style = level_styles.get(entry.level, ("•", "white"))
                
                log_text.append(f"  [{entry.timestamp}] ", style="dim")
                log_text.append(f"{icon} ", style=style)
                
                # Truncate long messages
                msg = entry.message[:90]
                log_text.append(f"{msg}\n", style=style)

        return Panel(
            log_text,
            border_style="blue",
            box=box.ROUNDED,
            title="[bold]Live Action Log[/bold]",
        )

    def _build_ai_panel(self) -> Panel:
        ai_text = Text()

        if self.ai_thought:
            ai_text.append(f'  "{self.ai_thought}"', style="italic bright_magenta")
        else:
            ai_text.append("  Waiting for AI reasoning...", style="dim")

        return Panel(
            ai_text,
            border_style="magenta",
            box=box.ROUNDED,
            title="[bold]🤖 AI Thinking[/bold]",
        )

    def _build_stats_bar(self) -> Panel:
        stats = Text()
        
        # Provider status
        provider_display = self.active_provider.upper() if self.active_provider else "N/A"
        stats.append(f"  LLM: ", style="dim")
        stats.append(f"{provider_display} ✅", style="bold green")
        stats.append(f"  │  ", style="dim")

        # Tokens
        stats.append(f"Tokens: ", style="dim")
        stats.append(f"{self.total_tokens:,}", style="bold white")
        stats.append(f"  │  ", style="dim")

        # Requests
        stats.append(f"Requests: ", style="dim")
        stats.append(f"{self.total_requests}", style="bold white")
        stats.append(f"  │  ", style="dim")

        # Tools run
        stats.append(f"Tools: ", style="dim")
        stats.append(f"{self.tools_run}", style="bold cyan")
        stats.append(f"  │  ", style="dim")

        # Cost
        stats.append(f"Cost: ", style="dim")
        stats.append(f"${self.total_cost:.4f}", style="bold green")

        return Panel(stats, border_style="dim", box=box.ROUNDED)

    def _build_findings_table(self) -> Optional[Panel]:
        """Build detailed findings table if there are findings."""
        if not self.findings:
            return None

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("ID", style="dim", width=10)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=18)
        table.add_column("Title", width=35)
        table.add_column("Location", width=30)

        severity_styles = {
            "critical": "[bold red]🔴 CRITICAL[/]",
            "high": "[bold bright_red]🟠 HIGH[/]",
            "medium": "[bold yellow]🟡 MEDIUM[/]",
            "low": "[bold blue]🔵 LOW[/]",
            "info": "[dim]⚪ INFO[/]",
        }

        # Show last 8 findings
        for finding in self.findings[-8:]:
            sev_display = severity_styles.get(finding.severity, finding.severity)
            table.add_row(
                finding.id,
                sev_display,
                finding.vuln_type[:18],
                finding.title[:35],
                finding.location[:30],
            )

        return Panel(table, border_style="red", title="[bold]🎯 Vulnerability Details[/bold]")

    def build_display(self) -> Group:
        """Build the complete dashboard display."""
        components = [
            self._build_header(),
            self._build_target_info(),
            self._build_progress(),
            self._build_findings_summary(),
            self._build_log_panel(),
            self._build_ai_panel(),
        ]

        # Add findings table if there are findings
        findings_table = self._build_findings_table()
        if findings_table:
            components.append(findings_table)

        components.append(self._build_stats_bar())

        return Group(*components)

    # ============================================
    # LIVE DISPLAY CONTROL
    # ============================================

    def start_live(self, refresh_rate: int = 4):
        """Start the live dashboard display."""
        self._running = True
        self._live = Live(
            self.build_display(),
            console=console,
            refresh_per_second=refresh_rate,
            screen=False,
        )
        self._live.start()
        self.add_log("Dashboard started", level="info", source="dashboard")

    def stop_live(self):
        """Stop the live dashboard display."""
        self._running = False
        if self._live:
            self._live.stop()

    def refresh(self):
        """Manually refresh the dashboard."""
        if self._live and self._running:
            try:
                self._live.update(self.build_display())
            except Exception:
                pass  # Ignore display errors

    def __enter__(self):
        self.start_live()
        return self

    def __exit__(self, *args):
        self.stop_live()


# ============================================
# STATIC DISPLAY FUNCTIONS (Non-live)
# ============================================

def print_banner():
    """Print the VAPT-AI startup banner."""
    banner = """
[bold red]
 ██╗   ██╗ █████╗ ██████╗ ████████╗     █████╗ ██╗
 ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝    ██╔══██╗██║
 ██║   ██║███████║██████╔╝   ██║       ███████║██║
 ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║       ██╔══██║██║
  ╚████╔╝ ██║  ██║██║        ██║       ██║  ██║██║
   ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝       ╚═╝  ╚═╝╚═╝
[/bold red]
[bold white]  Autonomous VAPT & Bug Bounty AI Agent[/bold white]
[dim]  Version 1.0 | Multi-LLM | Multi-Tool[/dim]
[dim]  ─────────────────────────────────────[/dim]
"""
    console.print(banner)


def print_scan_config(target: str, mode: str, provider: str, model: str):
    """Print scan configuration before starting."""
    table = Table(
        title="📋 Scan Configuration",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=False,
    )
    table.add_column("Key", style="bold cyan", width=20)
    table.add_column("Value", style="white")

    table.add_row("Target", target)
    table.add_row("Mode", mode)
    table.add_row("LLM Provider", provider)
    table.add_row("Model", model)
    table.add_row("Started", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    console.print(table)
    console.print()


def print_final_report_summary(findings: List[Finding], elapsed: str, stats: Dict):
    """Print final summary after scan completes."""
    console.print("\n")

    # Severity counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1

    # Summary panel
    summary = Text()
    summary.append("═" * 50 + "\n", style="bold red")
    summary.append("  SCAN COMPLETE\n\n", style="bold white")
    summary.append(f"  Duration:     {elapsed}\n", style="white")
    summary.append(f"  Total Findings: {len(findings)}\n\n", style="bold white")
    summary.append(f"  🔴 Critical:  {counts['critical']}\n", style="bold red")
    summary.append(f"  🟠 High:      {counts['high']}\n", style="bold bright_red")
    summary.append(f"  🟡 Medium:    {counts['medium']}\n", style="bold yellow")
    summary.append(f"  🔵 Low:       {counts['low']}\n", style="bold blue")
    summary.append(f"  ⚪ Info:      {counts['info']}\n\n", style="dim")

    if stats:
        summary.append(f"  LLM Requests: {stats.get('requests', 0)}\n", style="dim")
        summary.append(f"  Total Tokens: {stats.get('tokens', 0):,}\n", style="dim")
        summary.append(f"  Tools Run:    {stats.get('tools', 0)}\n", style="dim")

    summary.append("═" * 50, style="bold red")

    console.print(
        Panel(
            summary,
            title="[bold]🏆 VAPT-AI Scan Results[/bold]",
            border_style="red",
            box=box.DOUBLE,
        )
    )

    # Findings table
    if findings:
        table = Table(
            title="🎯 All Findings",
            box=box.ROUNDED,
            border_style="red",
        )
        table.add_column("ID", style="dim")
        table.add_column("Severity")
        table.add_column("Type")
        table.add_column("Title")
        table.add_column("Location")

        severity_styles = {
            "critical": "[bold red]🔴 CRITICAL[/]",
            "high": "[bold bright_red]🟠 HIGH[/]",
            "medium": "[bold yellow]🟡 MEDIUM[/]",
            "low": "[bold blue]🔵 LOW[/]",
            "info": "[dim]⚪ INFO[/]",
        }

        for f in findings:
            sev = severity_styles.get(f.severity, f.severity)
            table.add_row(f.id, sev, f.vuln_type, f.title, f.location)

        console.print(table)