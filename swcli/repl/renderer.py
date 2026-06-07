from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

# Color constants
COLORS = {
    "primary":    "green",        # Success, active, selected
    "secondary":  "cyan",         # Info, headers
    "accent":     "magenta",      # Special actions
    "error":      "red",          # Errors, danger
    "warning":    "yellow",       # Warnings
    "success":    "bright_green", # Passwords found
    "info":       "blue",         # Informational
    "muted":      "dim",          # Secondary text
    "dim":        "dark_gray",    # Dimmed text
    "text":       "white",        # Primary text
}

def print_banner():
    """Print the swcli ASCII banner."""
    console.print("""
[green] ____            _ ___   ____[/green]
[green]/ ___|_      __/_/ ___| / ___|[/green]
[dim]\\___ \\ \\ \\/ / / \\___ \\| |[/dim]
[dim] ___) \\ V  V /  |___) | |___[/dim]
[dim]|____/ \\_\\_/   |____/ \\____|[/dim]

[bold]WiFi Audit Toolkit v0.1.0[/bold]
[dim]Type / for commands, ? for help, quit to exit[/dim]
""")

def print_table(headers: list[str], rows: list[list[str]], title: str = ""):
    """Print a formatted table."""
    if not rows:
        console.print(f"  [dim]No data available.[/dim]")
        return
    
    table = Table(title=title, show_header=True, header_style="bold cyan")
    
    for header in headers:
        table.add_column(header)
    
    for row in rows:
        table.add_row(*[str(item) for item in row])
    
    console.print(table)

def print_success(msg: str):
    """Print success message."""
    console.print(f"  [green][+][/green] {msg}")

def print_error(msg: str):
    """Print error message."""
    console.print(f"  [red][!][/red] {msg}")

def print_warning(msg: str):
    """Print warning message."""
    console.print(f"  [yellow][~][/yellow] {msg}")

def print_info(msg: str):
    """Print info message."""
    console.print(f"  [blue][i][/blue] {msg}")

def print_progress(line: str):
    """Print progress line (overwrites previous)."""
    console.print(f"\r  {line}", end="", highlight=False)
