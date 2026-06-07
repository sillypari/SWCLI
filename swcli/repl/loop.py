import sys
import os
import asyncio
from swcli.repl.session_ui import UISession
from swcli.repl.prompts import read_key
from swcli.repl.palette import CommandPalette
from swcli.repl.renderer import print_banner
from rich.console import Console

console = Console()

class SwcliREPL:
    def __init__(self):
        self.session = UISession()
        self.running = True
        self.context = "main"
        self.palette = CommandPalette()
        self.print = console.print
        
    def setup_commands(self):
        try:
            from swcli.repl.commands import setup_all_commands
            setup_all_commands(self.palette)
        except ImportError as e:
            self.print(f"[red]Error loading commands: {e}[/red]")

    def run(self):
        self.setup_commands()
        print_banner()
        while self.running:
            try:
                user_input = self.get_input()
                if user_input is not None:
                    asyncio.run(self.process_input(user_input))
            except KeyboardInterrupt:
                if self.context == "prompt":
                    self.context = "main"
                    self.print("\n[yellow]Cancelled.[/yellow]")
                elif self.context == "palette":
                    self.context = "main"
                    self.palette.close()
                else:
                    self.print("\nType /quit to exit.")
            except EOFError:
                self.running = False
                break

    def get_input(self) -> str:
        if self.context == "palette":
            return read_key()
        elif self.context == "main":
            sys.stdout.write("\nswcli> ")
            sys.stdout.flush()
            return input().strip()
        return ""

    async def process_input(self, user_input: str):
        if self.context == "main":
            if user_input == "/":
                self.context = "palette"
                self.palette.open()
            elif user_input in ("quit", "exit", "/quit"):
                self.running = False
            elif user_input == "?":
                self.show_help()
            elif user_input.startswith("!"):
                os.system(user_input[1:])
        elif self.context == "palette":
            if user_input in ('up', 'k'):
                self.palette.navigate_up()
            elif user_input in ('down', 'j'):
                self.palette.navigate_down()
            elif user_input == '\n':
                cmd = self.palette.select()
                if cmd:
                    self.context = "main"
                    self.palette.close()
                    # Check root
                    if cmd.requires_root and os.name != 'nt' and os.geteuid() != 0:
                        self.print("[red]This command requires root. Run: sudo swcli[/red]")
                        return
                    
                    # Execute
                    from swcli.repl.error_handler import safe_execute
                    await safe_execute(self, cmd.handler)
            elif user_input == 'esc':
                if not self.palette.go_back():
                    self.context = "main"
                    self.palette.close()
            elif user_input == '\x08' or user_input == '\x7f': # Backspace
                self.palette.filter(self.palette.filter_text[:-1])
            elif len(user_input) == 1 and user_input.isprintable():
                self.palette.filter(self.palette.filter_text + user_input)

    def show_help(self):
        self.print("""
  [bold]swcli — WiFi Audit Toolkit[/bold]
  
  Type [cyan]/[/cyan] to open command palette.
  Type [cyan]?[/cyan] for this help.
  Type [cyan]quit[/cyan] or [cyan]exit[/cyan] to leave.
  Type [cyan]![cmd][/cyan] to run a shell command.
  
  Navigate: j/k   Select: Enter   Back: Esc   Filter: type to search
""")
        if self.palette.commands:
            self.print("  [bold]Available commands:[/bold]")
            cats = {}
            for cmd in self.palette.commands:
                cats.setdefault(cmd.category, []).append(cmd)
            for cat in sorted(cats):
                self.print(f"\n  [cyan]{cat}[/cyan]")
                for c in cats[cat]:
                    self.print(f"    {c.name:<25} {c.description}")
        self.print("")
