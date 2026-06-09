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

@dataclass
class PaletteItem:
    label: str
    description: str
    kind: str
    command: Optional[Command] = None
    category: str = ""
    count: int = 0

class CommandPalette:
    PAGE_SIZE = 12
    PINNED = ("/status", "/next", "/doctor", "/target")
    CATEGORY_ORDER = ("Control", "Setup", "Scan", "Capture", "Crack", "Attack", "Session", "Hardware", "System", "Config")
    CATEGORY_COLORS = {
        "Control": "\033[96m",
        "Setup": "\033[94m",
        "Scan": "\033[92m",
        "Capture": "\033[95m",
        "Crack": "\033[93m",
        "Attack": "\033[91m",
        "Session": "\033[36m",
        "Hardware": "\033[34m",
        "System": "\033[33m",
        "Config": "\033[90m",
    }
    RESET = "\033[0m"
    SELECTED = "\033[48;5;24m\033[97m"
    TITLE = "\033[96m"
    BOLD = "\033[1m"
    MUTED = "\033[90m"
    GOOD = "\033[92m"
    WARN = "\033[93m"
    BAD = "\033[91m"

    def __init__(self):
        self.commands: list[Command] = []
        self.filtered: list[PaletteItem] = []
        self.selected_index: int = 0
        self.filter_text: str = ""
        self.is_open: bool = False
        self.mode: str = "categories"
        self.current_category: str = ""

    def register(self, cmd: Command):
        self.commands.append(cmd)
        self.filtered = self._category_items()

    def open(self):
        self.is_open = True
        self.mode = "categories"
        self.current_category = ""
        self.selected_index = 0
        self.filter_text = ""
        self.filtered = self._category_items()
        self.render()

    def close(self):
        self.is_open = False
        self.mode = "categories"
        self.current_category = ""
        os.system('cls' if os.name == 'nt' else 'clear')

    def _category_items(self) -> list[PaletteItem]:
        counts = {}
        for cmd in self.commands:
            counts[cmd.category] = counts.get(cmd.category, 0) + 1
        ordered = [c for c in self.CATEGORY_ORDER if c in counts]
        ordered += sorted(c for c in counts if c not in ordered)
        return [PaletteItem(c, self._category_description(c), "category", category=c, count=counts[c]) for c in ordered]

    def _category_description(self, category: str) -> str:
        descriptions = {
            "Control": "Status, readiness, target, next actions",
            "Setup": "Monitor mode and service preparation",
            "Scan": "Discover APs, clients, EAPOL context",
            "Capture": "Passive/deauth capture and validation",
            "Crack": "Wordlists and offline cracking",
            "Attack": "Explicit attack modules",
            "Session": "Save, load, autosaves",
            "Hardware": "Adapter discovery and details",
            "System": "Cleanup and help",
            "Config": "Configuration view and edits",
        }
        return descriptions.get(category, "Command group")

    def _color(self, category: str) -> str:
        return self.CATEGORY_COLORS.get(category, "\033[96m")

    def _visible_len(self, value: str) -> int:
        import re
        return len(re.sub(r"\033\[[0-9;]*m", "", value))

    def _pad_ansi(self, value: str, width: int) -> str:
        return value + " " * max(0, width - self._visible_len(value))

    def _command_item(self, cmd: Command) -> PaletteItem:
        return PaletteItem(cmd.name, cmd.description, "command", command=cmd, category=cmd.category)

    def _back_item(self) -> PaletteItem:
        return PaletteItem("Back", "Return to command categories", "back")

    def _commands_for_category(self, category: str) -> list[PaletteItem]:
        cmds = [cmd for cmd in self.commands if cmd.category == category]
        pinned = [cmd for name in self.PINNED for cmd in cmds if cmd.name == name]
        rest = [cmd for cmd in cmds if cmd.name not in self.PINNED]
        return [self._back_item()] + [self._command_item(cmd) for cmd in pinned + rest]

    def _search_items(self, text: str) -> list[PaletteItem]:
        text_lower = text.lower()
        matches = []
        for cmd in self.commands:
            haystack = f"{cmd.name} {cmd.description} {cmd.category}".lower()
            if text_lower in haystack:
                matches.append(cmd)
        pinned = [cmd for name in self.PINNED for cmd in matches if cmd.name == name]
        rest = [cmd for cmd in matches if cmd.name not in self.PINNED]
        return [self._command_item(cmd) for cmd in pinned + rest]

    def navigate_up(self):
        if self.selected_index > 0:
            self.selected_index -= 1
            self.render()

    def navigate_down(self):
        if self.selected_index < len(self.filtered) - 1:
            self.selected_index += 1
            self.render()

    def page_up(self):
        self.selected_index = max(0, self.selected_index - self.PAGE_SIZE)
        self.render()

    def page_down(self):
        self.selected_index = min(max(0, len(self.filtered) - 1), self.selected_index + self.PAGE_SIZE)
        self.render()

    def filter(self, text: str):
        self.filter_text = text
        if text:
            self.mode = "search"
            self.current_category = ""
            self.filtered = self._search_items(text)
        elif self.current_category:
            self.mode = "commands"
            self.filtered = self._commands_for_category(self.current_category)
        else:
            self.mode = "categories"
            self.filtered = self._category_items()
        self.selected_index = 0
        self.render()

    def select(self) -> Optional[Command]:
        if not self.filtered:
            return None
        item = self.filtered[self.selected_index]
        if item.kind == "category":
            self.mode = "commands"
            self.current_category = item.category
            self.filter_text = ""
            self.filtered = self._commands_for_category(item.category)
            self.selected_index = 1 if len(self.filtered) > 1 else 0
            self.render()
            return None
        if item.kind == "back":
            self.go_back()
            return None
        return item.command

    def go_back(self) -> bool:
        if self.filter_text:
            self.filter("")
            return True
        if self.mode == "commands":
            self.mode = "categories"
            self.current_category = ""
            self.filtered = self._category_items()
            self.selected_index = 0
            self.render()
            return True
        return False

    def _visible_window(self):
        if not self.filtered:
            return 0, 0, []
        page = self.selected_index // self.PAGE_SIZE
        start = page * self.PAGE_SIZE
        end = min(len(self.filtered), start + self.PAGE_SIZE)
        return page, (len(self.filtered) - 1) // self.PAGE_SIZE, self.filtered[start:end]

    def _detail_lines(self, item: Optional[PaletteItem], width: int) -> list[str]:
        if not item:
            return ["No commands match the filter."]
        if item.kind == "back":
            return [
                "Back",
                "Return to command categories.",
                "Shortcut: Esc",
            ]
        if item.kind == "category":
            return [
                f"Category: {item.label}",
                item.description,
                f"Commands: {item.count}",
                "Enter opens this category. Type to search all commands.",
            ]
        cmd = item.command
        changes = "yes" if cmd.requires_root else "no/read-only"
        root = f"{self.WARN}yes{self.RESET}" if cmd.requires_root else f"{self.GOOD}no{self.RESET}"
        iface = f"{self.WARN}yes{self.RESET}" if cmd.requires_iface else f"{self.GOOD}no{self.RESET}"
        state = f"{self.WARN}{changes}{self.RESET}" if cmd.requires_root else f"{self.GOOD}{changes}{self.RESET}"
        color = self._color(cmd.category)
        return [
            f"Command: {color}{cmd.name}{self.RESET}",
            cmd.description,
            f"Category: {color}{cmd.category}{self.RESET}",
            f"Requires root: {root}",
            f"Requires interface: {iface}",
            f"May change system state: {state}",
        ]

    def render(self):
        size = shutil.get_terminal_size((100, 30))
        width = size.columns
        os.system('cls' if os.name == 'nt' else 'clear')

        title = "SWCLI Commands"
        if self.mode == "commands":
            title += f" / {self.current_category}"
        elif self.mode == "search":
            title += f" / Search: {self.filter_text}"

        try:
            from sidewinder.core.adapter import list_interfaces, get_interface_mode
            ifaces = list_interfaces()
            iface_status = []
            for i in ifaces:
                mode = get_interface_mode(i)
                color = self.GOOD if mode == "monitor" else self.BAD
                iface_status.append(f"{self.RESET}{i}: {color}Mon{self.TITLE}")
            
            if iface_status:
                title += f"  {self.MUTED}|{self.TITLE}  " + f"  {self.MUTED}|{self.TITLE}  ".join(iface_status)
        except Exception:
            pass

        left_width = min(56, max(36, width // 2))
        detail_width = max(30, width - left_width - 7)
        page, max_page, visible = self._visible_window()
        start = page * self.PAGE_SIZE
        selected_item = self.filtered[self.selected_index] if self.filtered else None

        lines = []
        lines.append(f"  {self.TITLE}{title}{self.RESET}")
        lines.append("  " + "─" * max(20, width - 4))
        lines.append(f"  {self.BOLD}{'Commands'.ljust(left_width)}{self.RESET} │ {self.BOLD}Details{self.RESET}")
        lines.append(f"  {self.MUTED}{'-' * left_width}{self.RESET} │ {self.MUTED}{'-' * detail_width}{self.RESET}")

        detail = self._detail_lines(selected_item, detail_width)
        rows = max(self.PAGE_SIZE, len(detail))
        for row in range(rows):
            idx = start + row
            if row < len(visible):
                item = visible[row]
                marker = "▶" if idx == self.selected_index else " "
                icon = "<" if item.kind == "back" else ">" if item.kind == "category" else " "
                color = self.MUTED if item.kind == "back" else self._color(item.category)
                if item.kind == "back":
                    raw = f"{marker} {icon} {item.label}"
                    text = f"{marker} {icon} {self.MUTED}{item.label}{self.RESET}"
                elif item.kind == "category":
                    raw = f"{marker} {icon} {item.label} ({item.count})"
                    text = f"{marker} {icon} {color}{item.label}{self.RESET} {self.MUTED}({item.count}){self.RESET}"
                else:
                    raw = f"{marker} {icon} {item.label}"
                    text = f"{marker} {icon} {color}{item.label}{self.RESET}"
                if idx == self.selected_index:
                    left = f"{self.SELECTED}{raw[:left_width].ljust(left_width)}{self.RESET}"
                else:
                    left = self._pad_ansi(text, left_width)
            else:
                left = " " * left_width
            right = detail[row] if row < len(detail) else ""
            lines.append(f"  {left} │ {right[:detail_width]}")

        lines.append("  " + "─" * max(20, width - 4))
        total = len(self.filtered)
        lines.append(f"  {self.MUTED}Page{self.RESET} {page + 1}/{max_page + 1 if total else 1}  {self.MUTED}Items{self.RESET} {total}  {self.MUTED}Mode{self.RESET}: {self.mode}")
        lines.append(f"  {self.MUTED}Up/Down{self.RESET}: move  {self.MUTED}PgUp/PgDn{self.RESET}: page  {self.GOOD}Enter{self.RESET}: select  {self.WARN}Esc{self.RESET}: back  Type: search")
        print("\n".join(lines))
