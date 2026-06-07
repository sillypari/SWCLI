from swcli.repl.palette import Command, CommandPalette
from swcli.repl.renderer import print_table

async def cmd_help(repl):
    """Show help for commands."""
    repl.print("\n  [bold cyan]Available Commands[/bold cyan]")
    
    # We can group them by category
    categories = {}
    for cmd in repl.palette.commands:
        if cmd.category not in categories:
            categories[cmd.category] = []
        categories[cmd.category].append(cmd)
        
    for cat, cmds in categories.items():
        repl.print(f"\n  [bold]{cat}[/bold]")
        for c in cmds:
            repl.print(f"    {c.name.ljust(20)} {c.description}")
            
    repl.print("\n  Type / to open the interactive command palette.")

def register_commands(palette: CommandPalette):
    palette.register(Command("/help", "List all commands", "System", cmd_help, requires_root=False))
