"""
VAPT-AI Router Test
===================
Run this to verify all LLM providers are working.

Usage: python test_router.py
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from config import settings
from core.llm_router import SmartLLMRouter

console = Console()


async def test_provider(router: SmartLLMRouter, provider: str, task_type: str):
    """Test a specific provider."""
    console.print(f"\n[bold]Testing {provider.upper()} ({task_type})...[/bold]")

    response = await router.query(
        prompt="You are a cybersecurity expert. In one short paragraph, explain what SQL Injection is and give one example payload.",
        system_prompt="You are a helpful cybersecurity assistant.",
        task_type=task_type,
        preferred_provider=provider,
    )

    if response.success:
        console.print(f"  [green]✅ SUCCESS[/green]")
        console.print(f"  Provider: {response.provider}")
        console.print(f"  Model:    {response.model}")
        console.print(f"  Tokens:   {response.total_tokens}")
        console.print(f"  Latency:  {response.latency:.2f}s")
        console.print(f"  Response: {response.content[:200]}...")
        return True
    else:
        console.print(f"  [red]❌ FAILED: {response.error}[/red]")
        return False


async def main():
    console.print(
        Panel(
            "[bold red]🔥 VAPT-AI Router Test 🔥[/bold red]\n"
            "Testing all LLM providers...",
            border_style="red",
        )
    )

    # Initialize router
    router = SmartLLMRouter(settings)

    results = {}

    # Test each provider
    providers_to_test = [
        ("nvidia", "reasoning"),
        ("nvidia", "coding"),
        ("groq", "general"),
        ("gemini", "general"),
        ("openrouter", "reasoning"),
        ("ollama", "general"),
    ]

    for provider, task_type in providers_to_test:
        try:
            success = await test_provider(router, provider, task_type)
            results[f"{provider}/{task_type}"] = "✅" if success else "❌"
        except Exception as e:
            console.print(f"  [red]❌ ERROR: {e}[/red]")
            results[f"{provider}/{task_type}"] = "❌"

    # Print summary
    console.print("\n")
    table = Table(title="🏆 Provider Test Results")
    table.add_column("Provider/Task", style="cyan")
    table.add_column("Status", justify="center")

    for name, status in results.items():
        table.add_row(name, status)

    console.print(table)

    # Print usage stats
    router.print_usage_stats()

    # Test auto-routing (let router choose best)
    console.print("\n[bold]Testing Auto-Routing (router chooses best)...[/bold]")
    response = await router.query(
        prompt="Generate 3 XSS payloads that bypass common WAF filters. Format as a numbered list.",
        system_prompt="You are an offensive security expert specializing in web application testing.",
        task_type="payload_generation",
    )

    if response.success:
        console.print(f"[green]✅ Auto-routed to: {response.provider}/{response.model}[/green]")
        console.print(f"[bold]Response:[/bold]\n{response.content}")
    else:
        console.print(f"[red]❌ Auto-routing failed: {response.error}[/red]")

    console.print("\n[bold green]🎉 Test complete![/bold green]")


if __name__ == "__main__":
    asyncio.run(main())
