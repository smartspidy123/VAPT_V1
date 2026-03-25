"""
VAPT-AI Logger
==============
Centralized logging with both file and console output.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from rich.logging import RichHandler
from rich.console import Console

console = Console()


def setup_logger(
    name: str = "vapt-ai",
    log_dir: Path = None,
    level: str = "INFO",
    log_to_file: bool = True,
) -> logging.Logger:
    """Setup and return a configured logger."""

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Rich console handler (pretty output)
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
    )
    rich_handler.setLevel(logging.INFO)
    rich_format = logging.Formatter("%(message)s")
    rich_handler.setFormatter(rich_format)
    logger.addHandler(rich_handler)

    # File handler
    if log_to_file and log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"vapt-ai_{timestamp}.log"

        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

        console.print(f"[dim]📝 Log file: {log_file}[/dim]")

    return logger