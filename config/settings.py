"""
VAPT-AI Global Settings
=======================
Saari configurations yahan centralized hain.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv(Path(__file__).parent.parent / ".env")


# ============================================
# PROJECT PATHS
# ============================================
PROJECT_ROOT = Path(__file__).parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
LOGS_DIR = PROJECT_ROOT / "logs"
DATA_DIR = PROJECT_ROOT / "data"

# Create directories if they don't exist
REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)


# ============================================
# LLM PROVIDER CONFIGURATIONS
# ============================================

# Har provider ki config with rate limits, models, keys
LLM_PROVIDERS = {
    "nvidia": {
        "api_keys": [
            os.getenv("NVIDIA_API_KEY_1", ""),
            os.getenv("NVIDIA_API_KEY_2", ""),
            os.getenv("NVIDIA_API_KEY_3", ""),
        ],
        "base_url": "https://integrate.api.nvidia.com/v1",
        "models": {
            # Primary - Main Brain (Complex reasoning, attack planning)
            "reasoning": "deepseek-ai/deepseek-v3-2",
            # Code/Payload specialist
            "coding": "qwen/qwen3-coder-480b-a35b-instruct",
            # Tool execution specialist  
            "execution": "deepseek-ai/deepseek-v3-1-terminus",
            # Deep thinking for complex vulns
            "thinking": "qwen/qwq-32b",
            # Fast general purpose
            "general": "mistralai/mistral-nemotron",
        },
        "rpm_limit": 20,  # requests per minute per key
        "tpm_limit": 100000,  # tokens per minute per key
        "timeout": 120,
        "priority": 1,  # Lower = higher priority
    },
    "groq": {
        "api_keys": [
            os.getenv("GROQ_API_KEY", ""),
        ],
        "base_url": "https://api.groq.com/openai/v1",
        "models": {
            "reasoning": "llama-3.3-70b-versatile",
            "coding": "llama-3.3-70b-versatile",
            "execution": "llama-3.3-70b-versatile",
            "thinking": "llama-3.3-70b-versatile",
            "general": "llama-3.1-8b-instant",
        },
        "rpm_limit": 30,
        "tpm_limit": 131072,
        "timeout": 60,
        "priority": 2,
    },
    "gemini": {
        "api_keys": [
            os.getenv("GEMINI_API_KEY", ""),
        ],
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "models": {
            "reasoning": "gemini-2.5-flash",
            "coding": "gemini-2.5-flash",
            "execution": "gemini-2.5-flash",
            "thinking": "gemini-2.5-flash",
            "general": "gemini-2.5-flash",
        },
        "rpm_limit": 15,
        "tpm_limit": 1000000,
        "timeout": 90,
        "priority": 3,
    },
    "openrouter": {
        "api_keys": [
            os.getenv("OPENROUTER_API_KEY", ""),
        ],
        "base_url": "https://openrouter.ai/api/v1",
        "models": {
            "reasoning": "deepseek/deepseek-r1",
            "coding": "deepseek/deepseek-r1",
            "execution": "deepseek/deepseek-r1",
            "thinking": "deepseek/deepseek-r1",
            "general": "meta-llama/llama-3.3-70b-instruct",
        },
        "rpm_limit": 20,
        "tpm_limit": 200000,
        "timeout": 120,
        "priority": 4,
    },
    "ollama": {
        "api_keys": ["local"],
        "base_url": "http://localhost:11434",
        "models": {
            "reasoning": "llama3.1:8b",
            "coding": "llama3.1:8b",
            "execution": "llama3.1:8b",
            "thinking": "llama3.1:8b",
            "general": "llama3.1:8b",
        },
        "rpm_limit": 999,  # Local = no limit
        "tpm_limit": 999999,
        "timeout": 300,  # Local models are slow
        "priority": 99,  # Last resort
    },
}


# ============================================
# TASK TYPE TO MODEL ROLE MAPPING
# ============================================

# Konse task ke liye konsa model role use hoga
TASK_MODEL_MAPPING = {
    # Recon phase - fast model chahiye
    "recon": "general",
    "subdomain_enum": "general",
    "port_scan": "general",
    "tech_detect": "general",

    # Analysis phase - reasoning chahiye
    "vulnerability_analysis": "reasoning",
    "attack_surface_mapping": "reasoning",
    "risk_assessment": "reasoning",

    # Planning phase - deep thinking chahiye
    "attack_planning": "thinking",
    "exploit_strategy": "thinking",
    "bypass_technique": "thinking",

    # Execution phase - tool calling chahiye
    "tool_execution": "execution",
    "command_generation": "execution",
    "payload_delivery": "execution",

    # Code/Payload - coding specialist chahiye
    "payload_generation": "coding",
    "code_analysis": "coding",
    "exploit_writing": "coding",
    "js_analysis": "coding",

    # Reporting - general enough
    "report_generation": "reasoning",
    "finding_summary": "general",
}


# ============================================
# SECURITY TOOL PATHS
# ============================================

TOOL_PATHS = {
    "nmap": os.getenv("NMAP_PATH", "/usr/bin/nmap"),
    "nuclei": os.getenv("NUCLEI_PATH", "/usr/bin/nuclei"),
    "sqlmap": os.getenv("SQLMAP_PATH", "/usr/bin/sqlmap"),
    "ffuf": os.getenv("FFUF_PATH", "/usr/bin/ffuf"),
    "nikto": os.getenv("NIKTO_PATH", "/usr/bin/nikto"),
    "subfinder": os.getenv("SUBFINDER_PATH", "/usr/bin/subfinder"),
    "httpx": os.getenv("HTTPX_PATH", "/usr/bin/httpx"),
    "katana": os.getenv("KATANA_PATH", "/usr/bin/katana"),
    "dalfox": os.getenv("DALFOX_PATH", "/usr/bin/dalfox"),
    "whatweb": os.getenv("WHATWEB_PATH", "/usr/bin/whatweb"),
    "wafw00f": os.getenv("WAFW00F_PATH", "/usr/bin/wafw00f"),
    "curl": os.getenv("CURL_PATH", "/usr/bin/curl"),
}


# ============================================
# AGENT CONFIGURATIONS
# ============================================

AGENT_CONFIG = {
    # Maximum iterations for each agent
    "max_iterations": {
        "recon": 50,
        "analyzer": 30,
        "planner": 20,
        "executor": 100,
        "reporter": 15,
    },

    # Timeout per agent (seconds)
    "agent_timeout": {
        "recon": 600,       # 10 min
        "analyzer": 300,    # 5 min
        "planner": 180,     # 3 min
        "executor": 1800,   # 30 min
        "reporter": 300,    # 5 min
    },

    # Temperature settings per task type
    "temperature": {
        "recon": 0.1,         # Low creativity, factual
        "analysis": 0.2,      # Slightly creative for finding patterns
        "planning": 0.3,      # Need some creativity for attack vectors
        "execution": 0.0,     # ZERO creativity, precise commands
        "payload_gen": 0.4,   # Creative for bypass payloads
        "reporting": 0.1,     # Factual reporting
    },
}


# ============================================
# SCAN CONFIGURATIONS
# ============================================

SCAN_CONFIG = {
    # Scan modes
    "modes": ["auto", "manual", "recon_only", "vuln_only"],

    # Default scan intensity
    "default_intensity": "medium",  # low, medium, high, aggressive

    # Rate limiting for target (requests per second)
    "target_rps": {
        "low": 5,
        "medium": 15,
        "high": 30,
        "aggressive": 50,
    },

    # Maximum concurrent tool executions
    "max_concurrent_tools": 3,

    # Save intermediate results
    "save_intermediate": True,

    # Auto-screenshot on finding
    "auto_screenshot": False,
}


# ============================================
# VULNERABILITY SEVERITY MAPPING
# ============================================

SEVERITY_LEVELS = {
    "critical": {"color": "red", "emoji": "🔴", "score_range": (9.0, 10.0)},
    "high": {"color": "orange", "emoji": "🟠", "score_range": (7.0, 8.9)},
    "medium": {"color": "yellow", "emoji": "🟡", "score_range": (4.0, 6.9)},
    "low": {"color": "blue", "emoji": "🔵", "score_range": (1.0, 3.9)},
    "info": {"color": "gray", "emoji": "⚪", "score_range": (0.0, 0.9)},
}


# ============================================
# OUTPUT SETTINGS
# ============================================

OUTPUT_CONFIG = {
    "report_formats": ["markdown", "html", "json"],
    "default_format": "markdown",
    "verbose": True,
    "debug": False,
    "log_level": "INFO",
    "log_file": LOGS_DIR / "vapt-ai.log",
}