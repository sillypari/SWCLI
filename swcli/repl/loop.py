import os
import asyncio
from swcli.repl.session_ui import UISession, autosave_session
from swcli.repl.prompts import read_key, read_command_line
from swcli.repl.palette import CommandPalette
from swcli.repl.renderer import print_banner, print_splash
from rich.console import Console

console = Console()

class SwcliREPL:
    def __init__(self):
        self.session = UISession()
        self.running = True
        self.context = "main"
        self.palette = CommandPalette()
        self.print = console.print
        self.command_history = []
        
    def setup_commands(self):
        try:
            from swcli.repl.commands import setup_all_commands
            setup_all_commands(self.palette)
        except ImportError as e:
            self.print(f"[red]Error loading commands: {e}[/red]")

    def run(self):
        self.setup_commands()
        print_splash()
        self.context = "palette"
        self.palette.open()
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
                    print_banner()
                else:
                    self.print("\nType /quit to exit.")
            except EOFError:
                self.running = False
                break

    def get_input(self) -> str:
        if self.context == "palette":
            return read_key()
        elif self.context == "main":
            known = {cmd.name for cmd in self.palette.commands}
            known.update({"/quit", "/exit", "quit", "exit", "?", "!"})
            return read_command_line("\nswcli> ", self.command_history, known)
        return ""


    async def execute_command(self, cmd):
        if cmd.requires_root and os.name != 'nt' and os.geteuid() != 0:
            self.print("[red]This command requires root. Run: sudo swcli[/red]")
            return
        from swcli.repl.error_handler import safe_execute
        previous_context = self.context
        self.context = "prompt"
        try:
            await safe_execute(self, cmd.handler)
        finally:
            self.context = "main" if self.running else previous_context

    def find_command(self, name: str):
        name = name.strip()
        if name.startswith("/"):
            name = "/" + name[1:].strip()
        aliases = {
            "/deauth": "/capture deauth",
            "/passive": "/capture passive",
            "/crack": "/crack aircrack",
            "/crash": "/crack aircrack",
            "/targets": "/target",
            "/handsake": "/handshake",
            "/hanskae": "/handshake",
            "/scan handsake": "/scan handshakes",
            "/scan hanskaes": "/scan handshakes",
            "/scan hansakes": "/scan handshakes",
        }
        name = aliases.get(name, name)
        for cmd in self.palette.commands:
            if cmd.name == name:
                return cmd
        return None

    async def process_input(self, user_input: str):
        if self.context == "main":
            if user_input.startswith("/"):
                user_input = "/" + user_input[1:].strip()
            if user_input == "/":
                self.context = "palette"
                self.palette.open()
            elif user_input in ("quit", "exit", "/quit"):
                try:
                    path = autosave_session(self.session, "quit")
                    self.print(f"[dim]Autosaved session: {path}[/dim]")
                except Exception as e:
                    self.print(f"[yellow]Autosave failed:[/yellow] {e}")
                self.running = False
            elif user_input == "?":
                self.show_help()
            elif user_input.startswith("!"):
                os.system(user_input[1:])
            elif user_input.startswith("/"):
                cmd = self.find_command(user_input)
                if cmd:
                    await self.execute_command(cmd)
                else:
                    self.print(f"[yellow]Unknown command:[/yellow] {user_input}. Type [cyan]/[/cyan] for palette or [cyan]?[/cyan] for help.")
        elif self.context == "palette":
            if user_input == 'up':
                self.palette.navigate_up()
            elif user_input == 'down':
                self.palette.navigate_down()
            elif user_input == 'page_up':
                self.palette.page_up()
            elif user_input == 'page_down':
                self.palette.page_down()
            elif user_input == '\n':
                cmd = self.palette.select()
                if cmd:
                    self.context = "main"
                    self.palette.close()
                    await self.execute_command(cmd)
            elif user_input == 'esc':
                if not self.palette.go_back():
                    self.context = "main"
                    self.palette.close()
                    print_banner()
            elif user_input == '\x08' or user_input == '\x7f': # Backspace
                self.palette.filter(self.palette.filter_text[:-1])
            elif len(user_input) == 1 and user_input.isprintable():
                self.palette.filter(self.palette.filter_text + user_input)

    def show_help(self):
        self.print("""
  [bold]SWCLI — Wireless Audit Console[/bold]
  
  Type [cyan]/[/cyan] to open command palette.
  Type [cyan]?[/cyan] for this help.
  Type [cyan]quit[/cyan] or [cyan]exit[/cyan] to leave.
  Type [cyan]![cmd][/cyan] to run a shell command.
  
  Main prompt: Up/Down history, live command coloring.
  Palette: Up/Down move, Enter select, Esc back, type to search.
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
