from dataclasses import dataclass
from typing import Callable, Optional
import os
import shutil

@dataclass
class Command:
    name: str
    description: str
    category: str
    handler: Callable
    subcommands: list["Command"] = None
    requires_iface: bool = False
    requires_root: bool = True
    enabled: bool = True

class CommandPalette:
    def __init__(self):
        self.commands: list[Command] = []
        self.filtered: list[Command] = []
        self.selected_index: int = 0
        self.filter_text: str = ""
        self.is_open: bool = False
        self.navigation_stack: list[list[Command]] = []
    
    def register(self, cmd: Command):
        self.commands.append(cmd)
        self.filtered = self.commands
    
    def open(self):
        self.is_open = True
        self.selected_index = 0
        self.filter_text = ""
        self.filtered = self.commands
        self.render()
    
    def close(self):
        self.is_open = False
        self.navigation_stack.clear()
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def navigate_up(self):
        if self.selected_index > 0:
            self.selected_index -= 1
            self.render()
    
    def navigate_down(self):
        if self.selected_index < len(self.filtered) - 1:
            self.selected_index += 1
            self.render()
            
    def filter(self, text: str):
        self.filter_text = text
        text_lower = text.lower()
        if not text:
            self.filtered = self.commands
        else:
            self.filtered = [
                cmd for cmd in self.commands
                if text_lower in cmd.name.lower() or text_lower in cmd.description.lower()
            ]
        self.selected_index = 0
        self.render()
    
    def select(self) -> Optional[Command]:
        if not self.filtered: return None
        cmd = self.filtered[self.selected_index]
        if cmd.subcommands:
            self.navigation_stack.append(self.commands)
            self.commands = cmd.subcommands
            self.filter_text = ""
            self.filtered = self.commands
            self.selected_index = 0
            self.render()
            return None
        return cmd
    
    def go_back(self) -> bool:
        if self.navigation_stack:
            self.commands = self.navigation_stack.pop()
            self.filtered = self.commands
            self.filter_text = ""
            self.selected_index = 0
            self.render()
            return True
        return False
    
    def render(self):
        terminal_width = shutil.get_terminal_size().columns
        os.system('cls' if os.name == 'nt' else 'clear')
        
        lines = []
        lines.append("  Commands:" + (f" (Filter: {self.filter_text})" if self.filter_text else ""))
        lines.append("  " + "─" * max(10, terminal_width - 4))
        
        max_name_len = 20
        max_desc_len = max(10, terminal_width - max_name_len - 10)
        
        for i, cmd in enumerate(self.filtered):
            name = cmd.name[:max_name_len].ljust(max_name_len)
            desc = cmd.description[:max_desc_len]
            
            if i == self.selected_index:
                lines.append(f"  \033[44m\033[37m▶ {name} {desc}\033[0m")
            else:
                arrow = "→" if cmd.subcommands else " "
                lines.append(f"  {arrow} {name} {desc}")
                
        lines.append("  " + "─" * max(10, terminal_width - 4))
        lines.append("  j/k/up/down: navigate  Enter: select  Esc: back  (Type to filter)")
        
        print("\n".join(lines))
