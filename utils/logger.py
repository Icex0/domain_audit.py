"""Logging utilities with color support."""

import logging
import sys
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text

console = Console()


class AuditLogger:
    """Color-coded logger matching PowerShell output style."""
    
    # Color mappings from PowerShell
    COLORS = {
        "info": "white",
        "success": "green",
        "warning": "yellow",
        "error": "red",
        "verbose": "dim white"
    }
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure rich logging."""
        logging.basicConfig(
            level=logging.DEBUG if self.verbose else logging.INFO,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(console=console, rich_tracebacks=True, show_time=False)]
        )
        self.logger = logging.getLogger("domain_audit")
    
    def info(self, message: str):
        """White informational text."""
        console.print(f"[white]{message}[/white]")
    
    def success(self, message: str):
        """Dark green success message."""
        console.print(f"[green]{message}[/green]")
    
    def warning(self, message: str):
        """Yellow warning message."""
        console.print(f"[yellow]{message}[/yellow]")
    
    def error(self, message: str):
        """Red error message."""
        console.print(f"[red]{message}[/red]")
    
    def log_verbose(self, message: str):
        """Verbose output only shown with -v flag."""
        if self.verbose:
            console.print(f"[dim white][+] {message}[/dim white]")
    
    def section(self, title: str):
        """Print section header."""
        console.print(f"\n[bold cyan]---------- {title.upper()} ----------[/bold cyan]")
    
    def finding(self, message: str):
        """Red finding message."""
        console.print(f"[red][-] {message}[/red]")
    
    def debug(self, message: str):
        """Debug output only shown with -v flag."""
        if self.verbose:
            console.print(f"[dim white][D] {message}[/dim white]")
    
    def check_pass(self, message: str):
        """Green check passed message."""
        console.print(f"[green][+] {message}[/green]")
    
    def check_manual(self, message: str):
        """Yellow manual check message."""
        console.print(f"[yellow][?] {message}[/yellow]")
    
    def write(self, message: str):
        """White write-to-file message."""
        console.print(f"[white][W] {message}[/white]")


# Global logger instance
_logger: Optional[AuditLogger] = None


def get_logger(verbose: bool = False) -> AuditLogger:
    """Get or create the global logger instance."""
    global _logger
    if _logger is None:
        _logger = AuditLogger(verbose=verbose)
    return _logger


def set_verbose(verbose: bool):
    """Update verbose mode on existing logger."""
    global _logger
    if _logger:
        _logger.verbose = verbose
