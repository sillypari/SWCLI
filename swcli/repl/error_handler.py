from enum import Enum
from typing import Optional, Callable

class ErrorLevel(Enum):
    INFO = "info"           # Just informational
    WARNING = "warning"     # Something unexpected but recoverable
    ERROR = "error"         # Command failed
    CRITICAL = "critical"   # Can't continue

class CLIError:
    """Structured CLI error with user-friendly message."""
    
    def __init__(
        self,
        level: ErrorLevel,
        message: str,
        suggestion: str = "",
        raw_error: Optional[Exception] = None,
    ):
        self.level = level
        self.message = message
        self.suggestion = suggestion
        self.raw_error = raw_error
    
    def display(self):
        """Print formatted error."""
        from swcli.repl.renderer import console
        
        if self.level == ErrorLevel.CRITICAL:
            console.print(f"\n  [bold red]CRITICAL:[/bold red] {self.message}")
        elif self.level == ErrorLevel.ERROR:
            console.print(f"\n  [red]ERROR:[/red] {self.message}")
        elif self.level == ErrorLevel.WARNING:
            console.print(f"\n  [yellow]WARNING:[/yellow] {self.message}")
        else:
            console.print(f"\n  [blue]INFO:[/blue] {self.message}")
        
        if self.suggestion:
            console.print(f"  [dim]{self.suggestion}[/dim]")

async def safe_execute(repl, handler: Callable, *args, **kwargs):
    """Wrap command execution with error handling."""
    from sidewinder.core.errors import SidewinderError
    
    try:
        return await handler(repl, *args, **kwargs)
    
    except KeyboardInterrupt:
        repl.print("\n[yellow]Cancelled.[/yellow]")
        return None
    
    except SidewinderError as e:
        repl.print(f"\n[red]ERROR:[/red] {e.what}")
        repl.print(f"[dim]Why: {e.why}[/dim]")
        for step in getattr(e, 'how_to_fix', []):
            repl.print(f"  [dim]• {step}[/dim]")
        return None
    
    except FileNotFoundError as e:
        repl.print(f"\n[red]ERROR:[/red] File not found: {e.filename}")
        repl.print("[dim]Check the path and try again.[/dim]")
        return None
    
    except PermissionError:
        repl.print("\n[red]ERROR:[/red] Permission denied")
        repl.print("[dim]Run with sudo: sudo swcli[/dim]")
        return None
    
    except RuntimeError as e:
        # Subprocess failures
        if "exit" in str(e).lower() or "failed" in str(e).lower():
            repl.print(f"\n[red]ERROR:[/red] Command failed")
            repl.print(f"[dim]{str(e)[:200]}[/dim]")
        else:
            repl.print(f"\n[red]ERROR:[/red] {e}")
        return None
    
    except Exception as e:
        # Unexpected error
        repl.print(f"\n[red]UNEXPECTED ERROR:[/red] {type(e).__name__}: {e}")
        repl.print("[dim]This is a bug. Please report it.[/dim]")
        return None
