"""
VAPT-AI Smart LLM Router
=========================
Ye module automatically best available LLM select karta hai,
API keys rotate karta hai, rate limits handle karta hai,
aur failover manage karta hai.

Multi-model strategy:
- Different tasks → Different specialist models
- Auto key rotation when rate limited
- Auto provider fallback when provider fails
- Usage tracking for cost management
"""

import time
import asyncio
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from rich.console import Console

console = Console()


# ============================================
# DATA CLASSES
# ============================================

@dataclass
class APIKeyState:
    """Track state of each API key."""
    key: str
    provider: str
    request_count: int = 0
    token_count: int = 0
    last_request_time: float = 0.0
    last_reset_time: float = field(default_factory=time.time)
    is_rate_limited: bool = False
    rate_limit_until: float = 0.0
    consecutive_errors: int = 0
    is_disabled: bool = False
    total_requests: int = 0
    total_tokens: int = 0

    def reset_window(self):
        """Reset the rate limit window (every 60 seconds)."""
        self.request_count = 0
        self.token_count = 0
        self.last_reset_time = time.time()

    def is_available(self) -> bool:
        """Check if this key is available for use."""
        if self.is_disabled:
            return False
        if self.is_rate_limited and time.time() < self.rate_limit_until:
            return False
        # Reset window if 60 seconds passed
        if time.time() - self.last_reset_time > 60:
            self.reset_window()
            self.is_rate_limited = False
        return True


@dataclass
class ProviderState:
    """Track state of each provider."""
    name: str
    is_healthy: bool = True
    last_error_time: float = 0.0
    consecutive_errors: int = 0
    cooldown_until: float = 0.0
    total_requests: int = 0
    total_tokens: int = 0
    total_cost: float = 0.0

    def is_available(self) -> bool:
        """Check if provider is available."""
        if not self.is_healthy and time.time() < self.cooldown_until:
            return False
        if not self.is_healthy and time.time() >= self.cooldown_until:
            self.is_healthy = True
            self.consecutive_errors = 0
        return self.is_healthy


@dataclass
class LLMResponse:
    """Standardized response from any LLM."""
    content: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    latency: float = 0.0
    cost: float = 0.0
    success: bool = True
    error: str = ""


# ============================================
# SMART LLM ROUTER
# ============================================

class SmartLLMRouter:
    """
    Intelligent LLM routing with:
    - Multi-provider support (NVIDIA, Groq, Gemini, OpenRouter, Ollama)
    - Multi-model support (different models for different tasks)
    - Automatic API key rotation
    - Rate limit handling
    - Automatic failover
    - Usage tracking
    """

    def __init__(self, settings):
        """Initialize the router with settings."""
        self.settings = settings
        self.providers_config = settings.LLM_PROVIDERS
        self.task_model_mapping = settings.TASK_MODEL_MAPPING

        # Initialize states
        self.key_states: Dict[str, List[APIKeyState]] = {}
        self.provider_states: Dict[str, ProviderState] = {}
        self.llm_cache: Dict[str, BaseChatModel] = {}

        # Usage tracking
        self.usage_log: List[Dict] = []
        self.session_start = datetime.now()

        # Initialize all providers and keys
        self._initialize_providers()

        console.print("[green]✅ Smart LLM Router initialized[/green]")
        self._print_provider_status()

    def _initialize_providers(self):
        """Initialize all providers and their API keys."""
        for provider_name, config in self.providers_config.items():
            # Filter out empty keys
            valid_keys = [k for k in config["api_keys"] if k and k != ""]

            if not valid_keys and provider_name != "ollama":
                console.print(
                    f"[yellow]⚠️  {provider_name}: No valid API keys found, skipping[/yellow]"
                )
                self.provider_states[provider_name] = ProviderState(
                    name=provider_name, is_healthy=False
                )
                continue

            # Initialize key states
            self.key_states[provider_name] = [
                APIKeyState(key=key, provider=provider_name)
                for key in valid_keys
            ]

            # Initialize provider state
            self.provider_states[provider_name] = ProviderState(
                name=provider_name
            )

    def _print_provider_status(self):
        """Print status of all providers."""
        console.print("\n[bold cyan]📡 LLM Provider Status:[/bold cyan]")
        for name, state in self.provider_states.items():
            num_keys = len(self.key_states.get(name, []))
            status = "✅ Ready" if state.is_available() else "❌ Unavailable"
            priority = self.providers_config.get(name, {}).get("priority", 99)
            console.print(
                f"  [{('green' if state.is_available() else 'red')}]"
                f"{status}[/] {name.upper():12s} | "
                f"Keys: {num_keys} | Priority: {priority}"
            )
        console.print()

    def _get_available_key(self, provider_name: str) -> Optional[APIKeyState]:
        """Get the next available API key for a provider (round-robin with health check)."""
        keys = self.key_states.get(provider_name, [])
        if not keys:
            return None

        # Sort by request count (least used first) among available keys
        available_keys = [k for k in keys if k.is_available()]
        if not available_keys:
            return None

        # Return the least recently used key
        return min(available_keys, key=lambda k: k.last_request_time)

    def _create_llm_instance(
        self, provider_name: str, model: str, api_key: str, temperature: float = 0.1
    ) -> Optional[BaseChatModel]:
        """Create a LangChain LLM instance for the given provider."""
        config = self.providers_config[provider_name]
        cache_key = f"{provider_name}:{model}:{api_key[:10]}:{temperature}"

        if cache_key in self.llm_cache:
            return self.llm_cache[cache_key]

        try:
            llm = None

            if provider_name == "nvidia":
                from langchain_nvidia_ai_endpoints import ChatNVIDIA
                llm = ChatNVIDIA(
                    model=model,
                    api_key=api_key,
                    temperature=temperature,
                    max_tokens=4096,
                    timeout=config["timeout"],
                )

            elif provider_name == "groq":
                from langchain_groq import ChatGroq
                llm = ChatGroq(
                    model=model,
                    api_key=api_key,
                    temperature=temperature,
                    max_tokens=4096,
                    timeout=config["timeout"],
                )

            elif provider_name == "gemini":
                from langchain_google_genai import ChatGoogleGenerativeAI
                llm = ChatGoogleGenerativeAI(
                    model=model,
                    google_api_key=api_key,
                    temperature=temperature,
                    max_output_tokens=4096,
                    timeout=config["timeout"],
                )

            elif provider_name == "openrouter":
                from langchain_openai import ChatOpenAI
                llm = ChatOpenAI(
                    model=model,
                    api_key=api_key,
                    base_url=config["base_url"],
                    temperature=temperature,
                    max_tokens=4096,
                    timeout=config["timeout"],
                )

            elif provider_name == "ollama":
                from langchain_ollama import ChatOllama
                llm = ChatOllama(
                    model=model,
                    temperature=temperature,
                    num_predict=4096,
                    timeout=config["timeout"],
                )

            if llm:
                self.llm_cache[cache_key] = llm
            return llm

        except Exception as e:
            console.print(
                f"[red]❌ Failed to create LLM instance for {provider_name}/{model}: {e}[/red]"
            )
            return None

    def _get_sorted_providers(self) -> List[str]:
        """Get providers sorted by priority, only available ones."""
        available = [
            name
            for name, state in self.provider_states.items()
            if state.is_available() and self.key_states.get(name)
        ]
        return sorted(
            available,
            key=lambda x: self.providers_config[x].get("priority", 99),
        )

    def _mark_key_rate_limited(self, key_state: APIKeyState, cooldown: int = 60):
        """Mark an API key as rate limited."""
        key_state.is_rate_limited = True
        key_state.rate_limit_until = time.time() + cooldown
        console.print(
            f"[yellow]⏳ Rate limited: {key_state.provider} key "
            f"...{key_state.key[-6:]} for {cooldown}s[/yellow]"
        )

    def _mark_provider_error(self, provider_name: str):
        """Mark a provider as having an error."""
        state = self.provider_states[provider_name]
        state.consecutive_errors += 1
        state.last_error_time = time.time()

        if state.consecutive_errors >= 3:
            # Cooldown for 5 minutes after 3 consecutive errors
            state.is_healthy = False
            state.cooldown_until = time.time() + 300
            console.print(
                f"[red]🚫 Provider {provider_name} disabled for 5 minutes "
                f"(3 consecutive errors)[/red]"
            )

    def _mark_provider_success(self, provider_name: str):
        """Mark a provider as healthy after successful request."""
        state = self.provider_states[provider_name]
        state.consecutive_errors = 0
        state.is_healthy = True

    def _update_usage(
        self,
        provider_name: str,
        key_state: APIKeyState,
        response: LLMResponse,
    ):
        """Update usage tracking after a request."""
        key_state.request_count += 1
        key_state.total_requests += 1
        key_state.token_count += response.total_tokens
        key_state.total_tokens += response.total_tokens
        key_state.last_request_time = time.time()

        provider_state = self.provider_states[provider_name]
        provider_state.total_requests += 1
        provider_state.total_tokens += response.total_tokens

        # Check if approaching rate limit
        config = self.providers_config[provider_name]
        if key_state.request_count >= config["rpm_limit"] - 2:
            self._mark_key_rate_limited(key_state)

        # Log usage
        self.usage_log.append(
            {
                "timestamp": datetime.now().isoformat(),
                "provider": provider_name,
                "model": response.model,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "total_tokens": response.total_tokens,
                "latency": response.latency,
                "cost": response.cost,
            }
        )

    async def query(
        self,
        prompt: str,
        system_prompt: str = "",
        task_type: str = "general",
        temperature: Optional[float] = None,
        max_retries: int = 3,
        preferred_provider: Optional[str] = None,
    ) -> LLMResponse:
        """
        Send a query to the best available LLM.

        Args:
            prompt: The user prompt
            system_prompt: System prompt for context
            task_type: Type of task (determines which model role to use)
            temperature: Override temperature
            max_retries: Number of retries across providers
            preferred_provider: Force a specific provider

        Returns:
            LLMResponse with the result
        """
        # Determine model role based on task type
        model_role = self.task_model_mapping.get(task_type, "general")

        # Get temperature from config if not specified
        if temperature is None:
            temp_category = task_type.split("_")[0] if "_" in task_type else task_type
            temperature = self.settings.AGENT_CONFIG["temperature"].get(
                temp_category, 0.1
            )

        # Get sorted list of providers to try
        if preferred_provider and preferred_provider in self.provider_states:
            providers_to_try = [preferred_provider] + [
                p
                for p in self._get_sorted_providers()
                if p != preferred_provider
            ]
        else:
            providers_to_try = self._get_sorted_providers()

        if not providers_to_try:
            return LLMResponse(
                content="",
                provider="none",
                model="none",
                success=False,
                error="No LLM providers available!",
            )

        last_error = ""

        for attempt in range(max_retries):
            for provider_name in providers_to_try:
                # Get model for this task type and provider
                config = self.providers_config[provider_name]
                model = config["models"].get(model_role, config["models"]["general"])

                # Get available key
                key_state = self._get_available_key(provider_name)
                if not key_state:
                    continue

                # Create LLM instance
                api_key = key_state.key
                llm = self._create_llm_instance(
                    provider_name, model, api_key, temperature
                )
                if not llm:
                    continue

                try:
                    # Build messages
                    messages = []
                    if system_prompt:
                        messages.append(SystemMessage(content=system_prompt))
                    messages.append(HumanMessage(content=prompt))

                    # Execute query with timing
                    start_time = time.time()
                    response = await asyncio.to_thread(llm.invoke, messages)
                    latency = time.time() - start_time

                    # Parse response
                    content = (
                        response.content
                        if hasattr(response, "content")
                        else str(response)
                    )

                    # Get token usage
                    usage = getattr(response, "usage_metadata", {}) or {}
                    input_tokens = (
                        usage.get("input_tokens", 0)
                        if isinstance(usage, dict)
                        else 0
                    )
                    output_tokens = (
                        usage.get("output_tokens", 0)
                        if isinstance(usage, dict)
                        else 0
                    )
                    total_tokens = input_tokens + output_tokens
                    if total_tokens == 0:
                        # Estimate if not provided
                        total_tokens = len(prompt.split()) + len(content.split())
                        input_tokens = len(prompt.split())
                        output_tokens = len(content.split())

                    result = LLMResponse(
                        content=content,
                        provider=provider_name,
                        model=model,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        total_tokens=total_tokens,
                        latency=latency,
                        success=True,
                    )

                    # Update tracking
                    self._update_usage(provider_name, key_state, result)
                    self._mark_provider_success(provider_name)

                    return result

                except Exception as e:
                    error_msg = str(e).lower()
                    last_error = str(e)

                    # Handle rate limiting
                    if any(
                        phrase in error_msg
                        for phrase in ["rate limit", "429", "too many requests", "quota"]
                    ):
                        self._mark_key_rate_limited(key_state, cooldown=60)
                        console.print(
                            f"[yellow]⚠️  Rate limited on {provider_name}, trying next...[/yellow]"
                        )
                    else:
                        key_state.consecutive_errors += 1
                        self._mark_provider_error(provider_name)
                        console.print(
                            f"[red]❌ Error on {provider_name}/{model}: {e}[/red]"
                        )

                    continue

            # Wait before retry
            if attempt < max_retries - 1:
                wait_time = (attempt + 1) * 5
                console.print(
                    f"[yellow]⏳ All providers failed, retrying in {wait_time}s... "
                    f"(attempt {attempt + 2}/{max_retries})[/yellow]"
                )
                await asyncio.sleep(wait_time)

        return LLMResponse(
            content="",
            provider="none",
            model="none",
            success=False,
            error=f"All providers failed after {max_retries} retries. Last error: {last_error}",
        )

    def query_sync(
        self,
        prompt: str,
        system_prompt: str = "",
        task_type: str = "general",
        temperature: Optional[float] = None,
        preferred_provider: Optional[str] = None,
    ) -> LLMResponse:
        """Synchronous wrapper for query()."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(
                        asyncio.run,
                        self.query(
                            prompt, system_prompt, task_type,
                            temperature, preferred_provider=preferred_provider,
                        ),
                    ).result()
                return result
        except RuntimeError:
            pass

        return asyncio.run(
            self.query(
                prompt, system_prompt, task_type,
                temperature, preferred_provider=preferred_provider,
            )
        )

    def get_llm_for_task(
        self, task_type: str = "general", temperature: Optional[float] = None
    ) -> Optional[BaseChatModel]:
        """
        Get a raw LangChain LLM instance for a specific task.
        Useful for LangGraph agents that need a direct LLM object.
        """
        model_role = self.task_model_mapping.get(task_type, "general")

        if temperature is None:
            temp_category = task_type.split("_")[0] if "_" in task_type else task_type
            temperature = self.settings.AGENT_CONFIG["temperature"].get(
                temp_category, 0.1
            )

        for provider_name in self._get_sorted_providers():
            config = self.providers_config[provider_name]
            model = config["models"].get(model_role, config["models"]["general"])

            key_state = self._get_available_key(provider_name)
            if not key_state:
                continue

            llm = self._create_llm_instance(
                provider_name, model, key_state.key, temperature
            )
            if llm:
                console.print(
                    f"[dim]🤖 Using {provider_name}/{model} for {task_type}[/dim]"
                )
                return llm

        console.print("[red]❌ No LLM available for task: {task_type}[/red]")
        return None

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get current session usage statistics."""
        stats = {
            "session_duration": str(datetime.now() - self.session_start),
            "total_requests": sum(
                s.total_requests for s in self.provider_states.values()
            ),
            "total_tokens": sum(
                s.total_tokens for s in self.provider_states.values()
            ),
            "providers": {},
        }

        for name, state in self.provider_states.items():
            stats["providers"][name] = {
                "requests": state.total_requests,
                "tokens": state.total_tokens,
                "healthy": state.is_healthy,
                "keys_available": sum(
                    1 for k in self.key_states.get(name, []) if k.is_available()
                ),
                "keys_total": len(self.key_states.get(name, [])),
            }

        return stats

    def print_usage_stats(self):
        """Pretty print usage statistics."""
        stats = self.get_usage_stats()
        console.print("\n[bold cyan]📊 Usage Statistics:[/bold cyan]")
        console.print(f"  Session Duration: {stats['session_duration']}")
        console.print(f"  Total Requests:   {stats['total_requests']}")
        console.print(f"  Total Tokens:     {stats['total_tokens']:,}")
        console.print()

        for name, pstats in stats["providers"].items():
            if pstats["requests"] > 0:
                console.print(
                    f"  {name.upper():12s} | "
                    f"Requests: {pstats['requests']:4d} | "
                    f"Tokens: {pstats['tokens']:>8,} | "
                    f"Keys: {pstats['keys_available']}/{pstats['keys_total']}"
                )