"""
core/logger.py — Rich console accessor for SentinelX NetLab V1

Display goes through Rich. Modules must not call print().

This file does not contain business logic. It only exposes a Console
for CLI and future modules to write to the terminal.
"""

from rich.console import Console

_console = Console()


def get_console() -> Console:
    """Return the shared Rich Console used for all terminal output.

    Returns:
        Console: Process-wide Rich console instance.
    """
    return _console


def display(message: object) -> None:
    """Write a message or Rich renderable to the terminal.

    Args:
        message: Text or Rich renderable (e.g. a Table).
    """
    _console.print(message)
