# SWCLI Interactive REPL — Implementation Specification

> **Goal:** Build an interactive command palette REPL for swcli.
> User types `/` → sees commands → navigates with j/k → selects with Enter → fills prompts → confirms.
> Also supports direct command mode for scripts: `sudo swcli scan wlx5c628b765de2mon`

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [REPL Main Loop](#2-repl-main-loop)
3. [Command Palette System](#3-command-palette-system)
4. [Navigation System](#4-navigation-system)
5. [Interactive Prompts](#5-interactive-prompts)
6. [Session State & Memory](#6-session-state--memory)
7. [Direct Command Mode](#7-direct-command-mode)
8. [Color & Formatting](#8-color--formatting)
9. [Error Handling](#9-error-handling)
10. [Edge Cases & Gotchas](#10-edge-cases--gotchas)
11. [Command Implementations](#11-command-implementations)
12. [Help System](#12-help-system)

---

## 1. Architecture Overview

### Entry Point

```
swcli (no args)           → interactive REPL mode
swcli <command> [args]    → direct command mode (execute and exit)
```

### Module Structure

```
swcli/
├── __main__.py           # Entry: detect mode, launch
├── repl/
│   ├── __init__.py
│   ├── loop.py           # Main REPL loop (readline alternative)
│   ├── palette.py        # Command palette (/, j/k, Enter, Esc)
│   ├── prompts.py        # Interactive prompt system
│   ├── renderer.py       # Color output, tables, live updates
│   ├── session_ui.py     # UI session state (last BSSID, channel, etc.)
│   └── commands/
│       ├── __init__.py
│       ├── hardware.py   # /adapters, /rfkill
│       ├── monitor.py    # /monitor, /monitor stop
│       ├── scan.py       # /scan, /scan results
│       ├── capture.py    # /capture passive/deauth/pmid, /validate
│       ├── attack.py     # /attack evil-twin, /attack wps
│       ├── crack.py      # /crack aircrack/hashcat, /wordlists
│       ├── cleanup.py    # /cleanup, /cleanup procs, /cleanup files
│       ├── session.py    # /session save/load/list
│       ├── config.py     # /config show/set
│       └── help.py       # /help, ?
├── cli.py                # Direct command mode (argparse)
└── core/                 # Existing Sidewinder core modules
```

---

## 2. REPL Main Loop

### 2.1 Loop Design

```python
# repl/loop.py

class SwcliREPL:
    """Main REPL loop. Reads user input, dispatches to commands."""
    
    def __init__(self):
        self.session = UISession()           # UI state (last values, etc.)
        self.running = True
        self.history = []                    # Command history
        self.history_index = -1              # For up/down arrow navigation
        self.palette_open = False            # Is command palette visible?
        self.palette_selected = 0            # Currently highlighted command
        self.context = "main"                # "main", "palette", "prompt"
    
    def run(self):
        """Main loop."""
        self.print_banner()
        while self.running:
            try:
                user_input = self.get_input()    # Blocking input
                self.process_input(user_input)
            except KeyboardInterrupt:
                # Ctrl+C: cancel current operation, don't exit
                self.print("\n[yellow]Cancelled.[/yellow]")
                self.context = "main"
                continue
            except EOFError:
                # Ctrl+D: exit
                self.running = False
                break
    
    def get_input(self) -> str:
        """Read input based on current context."""
        if self.context == "palette":
            return self.read_palette_input()     # j/k/Enter/Esc
        elif self.context == "prompt":
            return self.read_prompt_input()      # Value entry with default
        else:
            return self.read_main_input()        # Normal text input
    
    def process_input(self, user_input: str):
        """Route input to appropriate handler."""
        if self.context == "palette":
            self.handle_palette_input(user_input)
        elif self.context == "prompt":
            self.handle_prompt_input(user_input)
        else:
            self.handle_main_input(user_input)
```

### 2.2 Input Reading

```python
import sys
import tty
import termios

def read_key() -> str:
    """Read a single keypress without requiring Enter.
    
    Returns:
        Single character: 'j', 'k', '\n' (Enter), '\x1b' (Esc), etc.
    
    Gotcha: Must restore terminal settings after reading.
    """
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        
        # Handle escape sequences (arrow keys, etc.)
        if ch == '\x1b':
            ch2 = sys.stdin.read(1)
            if ch2 == '[':
                ch3 = sys.stdin.read(1)
                if ch3 == 'A': return 'up'
                if ch3 == 'B': return 'down'
                if ch3 == 'C': return 'right'
                if ch3 == 'D': return 'left'
            return 'esc'
        
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def read_line(prompt: str, default: str = "") -> str:
    """Read a full line of input with optional default value.
    
    Shows: "prompt [default]: "
    If user presses Enter without typing: returns default.
    
    Gotcha: Must handle empty input gracefully.
    """
    if default:
        display = f"{prompt} [{default}]: "
    else:
        display = f"{prompt}: "
    
    sys.stdout.write(display)
    sys.stdout.flush()
    
    user_input = input().strip()
    
    if not user_input and default:
        return default
    return user_input
```

### 2.3 Signal Handling

```python
import signal

def setup_signal_handlers(repl: SwcliREPL):
    """Handle Ctrl+C and Ctrl+D gracefully.
    
    Gotcha: signal handlers run in main thread, but REPL may be
    in subprocess. Need to handle both cases.
    """
    def handle_sigint(sig, frame):
        # If in a prompt: cancel prompt, go back to main
        # If in main: set running = False
        if repl.context == "prompt":
            repl.context = "main"
            repl.print("\n[yellow]Cancelled.[/yellow]")
        elif repl.context == "palette":
            repl.context = "main"
        else:
            repl.print("\n[yellow]Type /quit to exit.[/yellow]")
    
    signal.signal(signal.SIGINT, handle_sigint)
```

---

## 3. Command Palette System

### 3.1 Command Registry

```python
# repl/palette.py

from dataclasses import dataclass
from typing import Callable, Optional

@dataclass
class Command:
    """A single command in the palette."""
    name: str                    # "/scan", "/capture passive"
    description: str             # "Start WiFi scan"
    category: str                # "Scan", "Capture", "Attack"
    handler: Callable            # Function to call when selected
    subcommands: list["Command"] = None  # Nested commands (e.g., /capture → passive/deauth/pmid)
    requires_iface: bool = False # Does this command need an interface argument?
    requires_root: bool = True   # Does this need root?
    enabled: bool = True         # Can be disabled (e.g., if deps missing)

class CommandPalette:
    """Manages the command palette and navigation."""
    
    def __init__(self):
        self.commands: list[Command] = []
        self.filtered: list[Command] = []
        self.selected_index: int = 0
        self.filter_text: str = ""
        self.is_open: bool = False
        self.navigation_stack: list[list[Command]] = []  # For nested menus
    
    def register(self, cmd: Command):
        """Register a command."""
        self.commands.append(cmd)
        self.filtered = self.commands
    
    def open(self):
        """Open the palette."""
        self.is_open = True
        self.selected_index = 0
        self.filter_text = ""
        self.filtered = self.commands
        self.render()
    
    def close(self):
        """Close the palette."""
        self.is_open = False
        self.navigation_stack.clear()
    
    def navigate_up(self):
        """Move selection up (j key or up arrow)."""
        if self.selected_index > 0:
            self.selected_index -= 1
            self.render()
    
    def navigate_down(self):
        """Move selection down (k key or down arrow)."""
        if self.selected_index < len(self.filtered) - 1:
            self.selected_index += 1
            self.render()
    
    def select(self) -> Optional[Command]:
        """Select current command (Enter).
        
        If command has subcommands: push to navigation stack, show submenu.
        If command is leaf: return the command for execution.
        """
        cmd = self.filtered[self.selected_index]
        
        if cmd.subcommands:
            # Push current list, show submenu
            self.navigation_stack.append(self.filtered)
            self.filtered = cmd.subcommands
            self.selected_index = 0
            self.render()
            return None  # Don't execute yet
        
        return cmd  # Execute this command
    
    def go_back(self) -> bool:
        """Go back to parent menu (Esc).
        
        Returns:
            True if went back, False if was at top level (should close palette).
        """
        if self.navigation_stack:
            self.filtered = self.navigation_stack.pop()
            self.selected_index = 0
            self.render()
            return True
        return False  # At top level
    
    def filter(self, text: str):
        """Filter commands by text."""
        self.filter_text = text
        text_lower = text.lower()
        self.filtered = [
            cmd for cmd in self.commands
            if text_lower in cmd.name.lower() or text_lower in cmd.description.lower()
        ]
        self.selected_index = 0
        self.render()
    
    def render(self):
        """Render the palette to screen.
        
        Gotcha: Must clear previous render before drawing new one.
        Use ANSI escape codes for cursor movement.
        """
        # Move cursor to palette position
        # Draw box with commands
        # Highlight selected item
        # Show navigation hints at bottom
        pass
```

### 3.2 Command List

```python
def build_command_list() -> list[Command]:
    """Build the complete command list for the palette."""
    return [
        # ── Hardware ──
        Command(
            name="/adapters",
            description="List wireless adapters",
            category="Hardware",
            handler=cmd_adapters,
            requires_root=False,
        ),
        Command(
            name="/adapters info",
            description="Show adapter details",
            category="Hardware",
            handler=cmd_adapters_info,
            requires_root=False,
        ),
        Command(
            name="/rfkill",
            description="Check rfkill status",
            category="Hardware",
            handler=cmd_rfkill,
            requires_root=False,
        ),
        Command(
            name="/rfkill unblock",
            description="Unblock wifi",
            category="Hardware",
            handler=cmd_rfkill_unblock,
            requires_root=True,
        ),
        
        # ── Setup ──
        Command(
            name="/services",
            description="Kill conflicting services",
            category="Setup",
            handler=cmd_services_kill,
            requires_root=True,
        ),
        Command(
            name="/services restore",
            description="Restore services",
            category="Setup",
            handler=cmd_services_restore,
            requires_root=True,
        ),
        Command(
            name="/monitor",
            description="Enter monitor mode",
            category="Setup",
            handler=cmd_monitor_start,
            requires_root=True,
        ),
        Command(
            name="/monitor stop",
            description="Exit monitor mode",
            category="Setup",
            handler=cmd_monitor_stop,
            requires_root=True,
        ),
        
        # ── Scan ──
        Command(
            name="/scan",
            description="Start WiFi scan",
            category="Scan",
            handler=cmd_scan,
            requires_iface=True,
            requires_root=True,
        ),
        Command(
            name="/scan results",
            description="Show last scan",
            category="Scan",
            handler=cmd_scan_results,
            requires_root=False,
        ),
        
        # ── Capture ──
        Command(
            name="/capture passive",
            description="Passive handshake capture",
            category="Capture",
            handler=cmd_capture_passive,
            requires_iface=True,
            requires_root=True,
        ),
        Command(
            name="/capture deauth",
            description="Deauth + capture",
            category="Capture",
            handler=cmd_capture_deauth,
            requires_iface=True,
            requires_root=True,
        ),
        Command(
            name="/capture pmkid",
            description="PMKID capture",
            category="Capture",
            handler=cmd_capture_pmkid,
            requires_iface=True,
            requires_root=True,
        ),
        Command(
            name="/validate",
            description="Validate .cap file",
            category="Capture",
            handler=cmd_validate,
            requires_root=False,
        ),
        
        # ── Attack ──
        Command(
            name="/attack evil-twin",
            description="Evil Twin AP",
            category="Attack",
            handler=cmd_evil_twin,
            requires_iface=True,
            requires_root=True,
        ),
        Command(
            name="/attack wps",
            description="WPS Pixie-Dust",
            category="Attack",
            handler=cmd_wps,
            requires_iface=True,
            requires_root=True,
        ),
        
        # ── Crack ──
        Command(
            name="/crack aircrack",
            description="Crack with aircrack-ng (CPU)",
            category="Crack",
            handler=cmd_crack_aircrack,
            requires_root=False,
        ),
        Command(
            name="/crack hashcat",
            description="Crack with hashcat (GPU)",
            category="Crack",
            handler=cmd_crack_hashcat,
            requires_root=False,
        ),
        Command(
            name="/wordlists",
            description="List available wordlists",
            category="Crack",
            handler=cmd_wordlists,
            requires_root=False,
        ),
        
        # ── System ──
        Command(
            name="/cleanup",
            description="Full cleanup",
            category="System",
            handler=cmd_cleanup_full,
            requires_root=True,
        ),
        Command(
            name="/cleanup procs",
            description="Kill attack processes only",
            category="System",
            handler=cmd_cleanup_procs,
            requires_root=True,
        ),
        Command(
            name="/cleanup files",
            description="Clean temp files only",
            category="System",
            handler=cmd_cleanup_files,
            requires_root=True,
        ),
        
        # ── Session ──
        Command(
            name="/session save",
            description="Save current state",
            category="Session",
            handler=cmd_session_save,
            requires_root=False,
        ),
        Command(
            name="/session load",
            description="Load saved session",
            category="Session",
            handler=cmd_session_load,
            requires_root=False,
        ),
        Command(
            name="/session list",
            description="List saved sessions",
            category="Session",
            handler=cmd_session_list,
            requires_root=False,
        ),
        
        # ── Config ──
        Command(
            name="/config show",
            description="Show configuration",
            category="Config",
            handler=cmd_config_show,
            requires_root=False,
        ),
        Command(
            name="/config set",
            description="Update config value",
            category="Config",
            handler=cmd_config_set,
            requires_root=False,
        ),
        
        # ── Other ──
        Command(
            name="/help",
            description="Show help",
            category="Other",
            handler=cmd_help,
            requires_root=False,
        ),
        Command(
            name="/quit",
            description="Exit swcli",
            category="Other",
            handler=cmd_quit,
            requires_root=False,
        ),
    ]
```

### 3.3 Palette Rendering

```python
def render_palette(palette: CommandPalette, terminal_width: int):
    """Render the command palette.
    
    Layout:
    ┌─────────────────────────────────────────┐
    │  Commands:                              │  ← header
    ├─────────────────────────────────────────┤
    │  /adapters        List wireless adap... │  ← command list
    │  /monitor         Enter monitor mode    │
    │  /scan      →     Start WiFi scan       │  ← has submenu (→)
    │  /capture        ▶ Capture handshake    │  ← SELECTED (highlight)
    │  /crack           Crack password        │
    │  /cleanup         Restore system        │
    ├─────────────────────────────────────────┤
    │  j/k: navigate  Enter: select  Esc: back│  ← hints
    └─────────────────────────────────────────┘
    
    Gotcha: Must handle terminal width gracefully.
    - Truncate long command names with "..."
    - Truncate long descriptions with "..."
    - Ensure box doesn't exceed terminal width
    """
    lines = []
    
    # Header
    lines.append("  Commands:")
    lines.append("  " + "─" * (terminal_width - 4))
    
    # Commands
    max_name_len = 20
    max_desc_len = terminal_width - max_name_len - 10
    
    for i, cmd in enumerate(palette.filtered):
        name = cmd.name[:max_name_len].ljust(max_name_len)
        desc = cmd.description[:max_desc_len]
        
        # Highlight selected
        if i == palette.selected_index:
            lines.append(f"  [bold white on blue]▶ {name} {desc}[/bold white on blue]")
        else:
            # Show → for commands with submenus
            arrow = "→" if cmd.subcommands else " "
            lines.append(f"  {arrow} {name} {desc}")
    
    # Hints
    lines.append("  " + "─" * (terminal_width - 4))
    lines.append("  j/k: navigate  Enter: select  Esc: back")
    
    return "\n".join(lines)
```

---

## 4. Navigation System

### 4.1 Key Bindings

| Context | Key | Action |
|---------|-----|--------|
| Main | `/` | Open command palette |
| Main | `?` | Show help |
| Main | `!` | Run shell command (e.g., `! ls /tmp`) |
| Main | `quit` / `exit` | Exit swcli |
| Main | `Ctrl+C` | Cancel (no-op at top level) |
| Palette | `j` or `↓` | Navigate down |
| Palette | `k` or `↑` | Navigate up |
| Palette | `Enter` | Select command (or open submenu) |
| Palette | `Esc` | Go back (or close palette) |
| Palette | `/` | Filter commands (type to search) |
| Palette | `Ctrl+C` | Close palette |
| Prompt | `Enter` | Accept default or typed value |
| Prompt | `Ctrl+C` | Cancel prompt, go back |
| Prompt | `Tab` | Auto-complete (if applicable) |

### 4.2 Navigation Stack

```
User opens palette:
  Stack: [] 
  Showing: [adapters, monitor, scan, capture, crack, cleanup, ...]

User selects /capture (has submenu):
  Stack: [[adapters, monitor, scan, capture, crack, cleanup, ...]]
  Showing: [passive, deauth, pmkid]

User presses Esc:
  Stack: []
  Showing: [adapters, monitor, scan, capture, crack, cleanup, ...]

User presses Esc again:
  Stack: []
  Palette closed
```

### 4.3 Nested Menu Example

```
/                    → top level commands
  capture        →   → submenu: passive, deauth, pmkid
    passive      →   → execute command
    deauth       →   → execute command  
    pmkid        →   → execute command

Esc at any point → go back one level
Esc at top level → close palette
```

---

## 5. Interactive Prompts

### 5.1 Prompt Types

```python
# repl/prompts.py

from typing import Any, Callable, Optional

class PromptResult:
    """Result of a prompt interaction."""
    def __init__(self, value: Any, cancelled: bool = False):
        self.value = value
        self.cancelled = cancelled

def prompt_text(
    message: str,
    default: str = "",
    validator: Optional[Callable[[str], bool]] = None,
    error_msg: str = "Invalid input",
) -> PromptResult:
    """Prompt for text input.
    
    Args:
        message: Prompt message
        default: Default value (shown in brackets, used if user presses Enter)
        validator: Optional validation function
        error_msg: Message to show if validation fails
    
    Returns:
        PromptResult with value or cancelled=True
    
    Gotcha: Must handle:
        - Empty input → use default
        - Invalid input → re-prompt with error
        - Ctrl+C → cancel
        - EOF → cancel
    """
    while True:
        try:
            user_input = read_line(message, default)
            
            if not user_input and not default:
                continue  # No input, no default → ask again
            
            if validator and not validator(user_input):
                print(f"  [red]{error_msg}[/red]")
                continue
            
            return PromptResult(user_input)
        
        except KeyboardInterrupt:
            return PromptResult(None, cancelled=True)
        except EOFError:
            return PromptResult(None, cancelled=True)

def prompt_choice(
    message: str,
    choices: list[str],
    default: int = 0,
) -> PromptResult:
    """Prompt user to choose from a list.
    
    Display:
        Message:
          1. option_a    ← highlighted if default
          2. option_b
          3. option_c
    
        Select [1]:
    
    Gotcha: Must handle:
        - Number input (1, 2, 3)
        - Name input ("option_a")
        - Enter with no input → use default
        - Invalid choice → re-prompt
        - Ctrl+C → cancel
    """
    while True:
        print(f"\n  {message}")
        for i, choice in enumerate(choices, 1):
            marker = "→" if i - 1 == default else " "
            print(f"    {marker} {i}. {choice}")
        
        try:
            user_input = read_line(f"\n  Select", str(default + 1))
            
            # Parse input
            try:
                index = int(user_input) - 1
            except ValueError:
                # Try name match
                index = -1
                for i, c in enumerate(choices):
                    if user_input.lower() in c.lower():
                        index = i
                        break
            
            if 0 <= index < len(choices):
                return PromptResult(choices[index])
            
            print(f"  [red]Invalid choice. Enter 1-{len(choices)}.[/red]")
        
        except KeyboardInterrupt:
            return PromptResult(None, cancelled=True)
        except EOFError:
            return PromptResult(None, cancelled=True)

def prompt_confirm(
    message: str,
    default: bool = False,
) -> PromptResult:
    """Prompt for yes/no confirmation.
    
    Display:
        Are you sure? [y/N]:
    
    Gotcha: Must handle:
        - y/yes → True
        - n/no → False
        - Enter with no input → default
        - Ctrl+C → cancel (treated as "no")
    """
    default_str = "y/N" if not default else "Y/n"
    
    while True:
        try:
            user_input = read_line(f"{message} [{default_str}]")
            
            if not user_input:
                return PromptResult(default)
            
            if user_input.lower() in ("y", "yes"):
                return PromptResult(True)
            if user_input.lower() in ("n", "no"):
                return PromptResult(False)
            
            print(f"  [red]Enter y or n.[/red]")
        
        except KeyboardInterrupt:
            return PromptResult(False, cancelled=True)
        except EOFError:
            return PromptResult(False, cancelled=True)

def prompt_mac(
    message: str,
    default: str = "",
    allow_broadcast: bool = True,
) -> PromptResult:
    """Prompt for MAC address with validation.
    
    Validates format: XX:XX:XX:XX:XX:XX
    Optionally accepts FF:FF:FF:FF:FF:FF (broadcast).
    
    Gotcha: Must handle:
        - Lowercase input → auto-upgrade to uppercase
        - Missing colons → re-prompt
        - Invalid hex → re-prompt
        - Broadcast when not allowed → re-prompt
    """
    import re
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
    
    def validate(mac: str) -> bool:
        if not mac_pattern.match(mac):
            return False
        if mac.upper() == "FF:FF:FF:FF:FF:FF" and not allow_broadcast:
            return False
        return True
    
    while True:
        result = prompt_text(message, default, validate, "Invalid MAC format (use XX:XX:XX:XX:XX:XX)")
        if result.cancelled:
            return result
        return PromptResult(result.value.upper())

def prompt_channel(
    message: str,
    default: int = 6,
) -> PromptResult:
    """Prompt for WiFi channel with validation.
    
    Valid channels: 1-14 (2.4GHz), 36-165 (5GHz)
    
    Gotcha: Must handle:
        - Channel out of range → re-prompt
        - Non-numeric input → re-prompt
        - Empty input → use default
    """
    valid_channels = set(range(1, 15)) | set(range(36, 166))
    
    def validate(ch: str) -> bool:
        try:
            return int(ch) in valid_channels
        except ValueError:
            return False
    
    while True:
        result = prompt_text(message, str(default), validate, "Invalid channel (1-14 or 36-165)")
        if result.cancelled:
            return result
        return PromptResult(int(result.value))
```

### 5.2 Prompt Flow Example (Capture Deauth)

```python
async def cmd_capture_deauth(repl: SwcliREPL):
    """Interactive deauth capture command."""
    
    # Step 1: Get interface
    adapters = await discover_all_adapters()
    monitor_adapters = [a for a in adapters if a.monitor_capable]
    
    if not monitor_adapters:
        repl.print("[red]No monitor-capable adapters found.[/red]")
        repl.print("Run /monitor to enter monitor mode first.")
        return
    
    if len(monitor_adapters) == 1:
        iface = monitor_adapters[0]
        repl.print(f"  Using: {iface.iface} ({iface.chipset})")
    else:
        # Show adapter list, let user choose
        choices = [f"{a.iface} ({a.chipset})" for a in monitor_adapters]
        result = prompt_choice("Select adapter:", choices)
        if result.cancelled:
            return
        index = choices.index(result.value)
        iface = monitor_adapters[index]
    
    # Step 2: Get target BSSID
    bssid_result = prompt_mac("Target BSSID")
    if bssid_result.cancelled:
        return
    bssid = bssid_result.value
    
    # Step 3: Get channel
    # Try to auto-detect from last scan
    last_channel = repl.session.get_channel_for_bssid(bssid)
    ch_result = prompt_channel("Channel", default=last_channel or 6)
    if ch_result.cancelled:
        return
    channel = ch_result.value
    
    # Step 4: Get client MAC
    client_result = prompt_mac(
        "Client MAC",
        default="FF:FF:FF:FF:FF:FF",
        allow_broadcast=True,
    )
    if client_result.cancelled:
        return
    client = client_result.value
    
    # Step 5: Get deauth count
    count_result = prompt_text("Deauth count", default="10")
    if count_result.cancelled:
        return
    count = int(count_result.value)
    
    # Step 6: Get burst count
    bursts_result = prompt_text("Bursts", default="3")
    if bursts_result.cancelled:
        return
    bursts = int(bursts_result.value)
    
    # Step 7: Confirm
    repl.print(f"""
  [bold]Deauth + Capture:[/bold]
    Interface:  {iface.iface}mon
    Target:     {bssid}
    Channel:    {channel}
    Client:     {client}
    Deauths:    {count} × {bursts} = {count * bursts} total
    Timeout:    300s

  [yellow]WARNING: Will disconnect all clients on this AP.[/yellow]""")
    
    confirm = prompt_confirm("Start deauth attack?")
    if confirm.cancelled or not confirm.value:
        repl.print("[yellow]Cancelled.[/yellow]")
        return
    
    # Step 8: Execute
    # ... run the actual attack ...
```

### 5.3 Auto-Fill from Session

```python
class UISession:
    """Stores UI state for auto-filling prompts.
    
    Gotcha: Values may become stale (adapter disconnected, etc.).
    Must validate before using stored values.
    """
    
    def __init__(self):
        self.last_iface: str = ""
        self.last_bssid: str = ""
        self.last_channel: int = 0
        self.last_wordlist: str = ""
        self.last_cap_file: str = ""
        self.scan_results: list[Network] = []
        self.clients: list[Client] = []
        self.monitor_mode: bool = False
        self.monitor_iface: str = ""
    
    def get_channel_for_bssid(self, bssid: str) -> Optional[int]:
        """Look up channel from last scan results.
        
        Gotcha: BSSID must be uppercase for comparison.
        """
        bssid_upper = bssid.upper()
        for net in self.scan_results:
            if net.bssid.upper() == bssid_upper:
                return net.channel
        return None
    
    def get_default_iface(self) -> str:
        """Get the last used interface.
        
        Gotcha: Must verify interface still exists before returning.
        """
        if self.last_iface:
            from pathlib import Path
            if Path(f"/sys/class/net/{self.last_iface}").exists():
                return self.last_iface
        return ""
    
    def get_default_cap_file(self) -> str:
        """Get the last capture file.
        
        Gotcha: Must verify file still exists before returning.
        """
        if self.last_cap_file:
            import os
            if os.path.exists(self.last_cap_file):
                return self.last_cap_file
        return ""
```

---

## 6. Session State & Memory

### 6.1 What Gets Remembered

| Value | Stored Where | Lifetime |
|-------|-------------|----------|
| Last interface used | UISession | Current REPL session |
| Last BSSID targeted | UISession | Current REPL session |
| Last channel | UISession | Current REPL session |
| Last wordlist | UISession | Current REPL session |
| Last capture file | UISession | Current REPL session |
| Scan results | UISession + ~/.sidewinder/session.json | Until new scan |
| Discovered clients | UISession + ~/.sidewinder/session.json | Until new scan |
| Monitor mode status | UISession | Current REPL session |
| Killed services | ServiceManager | Until restore |

### 6.2 Auto-Populate Prompts

```python
def auto_fill_prompt(
    repl: SwcliREPL,
    prompt_type: str,
    message: str,
) -> str:
    """Auto-fill a prompt with the last known value.
    
    Shows the default in brackets so user can just press Enter.
    
    Gotcha: Must verify the stored value is still valid:
        - Interface still exists in sysfs
        - File still exists on disk
        - BSSID still in scan results
    """
    if prompt_type == "iface":
        default = repl.session.get_default_iface()
        if default:
            message = f"{message} [{default}]"
    
    elif prompt_type == "bssid":
        default = repl.session.last_bssid
        if default:
            message = f"{message} [{default}]"
    
    elif prompt_type == "channel":
        default = str(repl.session.last_channel) if repl.session.last_channel else ""
        if default:
            message = f"{message} [{default}]"
    
    elif prompt_type == "wordlist":
        default = repl.session.last_wordlist
        if default:
            message = f"{message} [{default}]"
    
    elif prompt_type == "cap_file":
        default = repl.session.get_default_cap_file()
        if default:
            message = f"{message} [{default}]"
    
    return message
```

---

## 7. Direct Command Mode

### 7.1 Argparse Setup

```python
# cli.py

import argparse
import sys

def build_direct_parser() -> argparse.ArgumentParser:
    """Build argument parser for direct command mode.
    
    Usage:
        sudo swcli adapters
        sudo swcli monitor wlx5c628b765de2 --channel 6
        sudo swcli scan wlx5c628b765de2mon
    """
    parser = argparse.ArgumentParser(
        prog="swcli",
        description="WiFi Audit Toolkit",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # adapters
    subparsers.add_parser("adapters", help="List wireless adapters")
    
    # monitor
    mon_parser = subparsers.add_parser("monitor", help="Enter monitor mode")
    mon_parser.add_argument("interface", help="Wireless interface")
    mon_parser.add_argument("--channel", type=int, default=6, help="Channel")
    mon_parser.add_argument("--stop", action="store_true", help="Exit monitor mode")
    
    # scan
    scan_parser = subparsers.add_parser("scan", help="Start WiFi scan")
    scan_parser.add_argument("interface", help="Monitor interface")
    scan_parser.add_argument("--band", choices=["a", "bg"], help="Band")
    scan_parser.add_argument("--channels", help="Comma-separated channels")
    
    # capture
    cap_parser = subparsers.add_parser("capture", help="Capture handshake")
    cap_sub = cap_parser.add_subparsers(dest="method", required=True)
    
    passive = cap_sub.add_parser("passive", help="Passive capture")
    passive.add_argument("interface", help="Monitor interface")
    passive.add_argument("bssid", help="Target BSSID")
    passive.add_argument("channel", type=int, help="Channel")
    
    deauth = cap_sub.add_parser("deauth", help="Deauth + capture")
    deauth.add_argument("interface", help="Monitor interface")
    deauth.add_argument("bssid", help="Target BSSID")
    deauth.add_argument("channel", type=int, help="Channel")
    deauth.add_argument("--client", default="FF:FF:FF:FF:FF:FF", help="Client MAC")
    deauth.add_argument("--count", type=int, default=10, help="Deauth count")
    deauth.add_argument("--bursts", type=int, default=3, help="Burst count")
    
    # crack
    crack_parser = subparsers.add_parser("crack", help="Crack password")
    crack_sub = crack_parser.add_subparsers(dest="method", required=True)
    
    ac = crack_sub.add_parser("aircrack", help="Crack with aircrack-ng")
    ac.add_argument("cap_file", help="Capture file")
    ac.add_argument("--bssid", required=True, help="Target BSSID")
    ac.add_argument("--wordlist", required=True, help="Wordlist path")
    
    hc = crack_sub.add_parser("hashcat", help="Crack with hashcat")
    hc.add_argument("cap_file", help="Capture file")
    hc.add_argument("--wordlist", required=True, help="Wordlist path")
    
    # validate
    val_parser = subparsers.add_parser("validate", help="Validate capture file")
    val_parser.add_argument("cap_file", help="Capture file path")
    
    # cleanup
    subparsers.add_parser("cleanup", help="Full cleanup")
    
    return parser
```

### 7.2 Mode Detection

```python
# __main__.py

def main():
    """Entry point. Detect mode and dispatch."""
    if len(sys.argv) == 1:
        # No args → interactive REPL
        from repl.loop import SwcliREPL
        repl = SwcliREPL()
        repl.run()
    else:
        # Has args → direct command mode
        parser = build_direct_parser()
        args = parser.parse_args()
        
        # Check root if needed
        if requires_root(args.command):
            check_root()
        
        # Execute command
        execute_direct_command(args)
```

---

## 8. Color & Formatting

### 8.1 Color Scheme

```python
# repl/renderer.py

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
    """Print a formatted table.
    
    Gotcha: Must handle:
        - Empty rows → show "No data" message
        - Long values → truncate with "..."
        - Terminal width → wrap or truncate columns
    """
    if not rows:
        console.print(f"  [dim]No data available.[/dim]")
        return
    
    table = Table(title=title, show_header=True, header_style="bold cyan")
    
    for header in headers:
        table.add_column(header)
    
    for row in rows:
        table.add_row(*row)
    
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
```

---

## 9. Error Handling

### 9.1 Error Categories

```python
# repl/error_handler.py

from enum import Enum
from typing import Optional

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
        if self.level == ErrorLevel.CRITICAL:
            print(f"\n  [bold red]CRITICAL:[/bold red] {self.message}")
        elif self.level == ErrorLevel.ERROR:
            print(f"\n  [red]ERROR:[/red] {self.message}")
        elif self.level == ErrorLevel.WARNING:
            print(f"\n  [yellow]WARNING:[/yellow] {self.message}")
        else:
            print(f"\n  [blue]INFO:[/blue] {self.message}")
        
        if self.suggestion:
            print(f"  [dim]{self.suggestion}[/dim]")
```

### 9.2 Error Scenarios

```python
# For each command, document expected errors and how to handle them

ERROR_SCENARIOS = {
    "monitor_start": [
        {
            "condition": "Interface doesn't exist",
            "error": CLIError(
                level=ErrorLevel.ERROR,
                message="Interface not found: wlx5c628b765de2",
                suggestion="Run /adapters to see available interfaces.",
            ),
        },
        {
            "condition": "Not root",
            "error": CLIError(
                level=ErrorLevel.ERROR,
                message="Root privileges required",
                suggestion="Run: sudo swcli",
            ),
        },
        {
            "condition": "rfkill blocked",
            "error": CLIError(
                level=ErrorLevel.WARNING,
                message="Adapter blocked by rfkill",
                suggestion="Run: sudo swcli rfkill unblock",
            ),
        },
        {
            "condition": "Driver doesn't support monitor",
            "error": CLIError(
                level=ErrorLevel.ERROR,
                message="Adapter doesn't support monitor mode",
                suggestion="Try a different adapter or install correct drivers.",
            ),
        },
        {
            "condition": "Interface busy (NetworkManager running)",
            "error": CLIError(
                level=ErrorLevel.ERROR,
                message="Interface is busy — NetworkManager is using it",
                suggestion="Run: sudo swcli services (kill NetworkManager first)",
            ),
        },
    ],
    
    "capture_deauth": [
        {
            "condition": "Adapter doesn't support injection",
            "error": CLIError(
                level=ErrorLevel.ERROR,
                message="Adapter doesn't support packet injection",
                suggestion="Use an RTL8821AU or RT5370 adapter.",
            ),
        },
        {
            "condition": "Channel mismatch",
            "error": CLIError(
                level=ErrorLevel.WARNING,
                message="Capture may fail — channel doesn't match target",
                suggestion="Verify the channel is correct for this BSSID.",
            ),
        },
        {
            "condition": "No EAPOL after timeout",
            "error": CLIError(
                level=ErrorLevel.WARNING,
                message="No handshake captured after 300s",
                suggestion="Try: wait longer, move closer, or use deauth.",
            ),
        },
    ],
    
    "crack_aircrack": [
        {
            "condition": "aircrack-ng not installed",
            "error": CLIError(
                level=ErrorLevel.ERROR,
                message="aircrack-ng not found",
                suggestion="Install: sudo apt install aircrack-ng",
            ),
        },
        {
            "condition": "Wordlist not found",
            "error": CLIError(
                level=ErrorLevel.ERROR,
                message="Wordlist not found: /path/to/wordlist.txt",
                suggestion="Run /wordlists to see available wordlists.",
            ),
        },
        {
            "condition": "Invalid capture file",
            "error": CLIError(
                level=ErrorLevel.ERROR,
                message="Cannot read capture file",
                suggestion="Run /validate to check the file.",
            ),
        },
    ],
}
```

### 9.3 Exception Wrapping

```python
async def safe_execute(repl: SwcliREPL, handler: Callable, *args, **kwargs):
    """Wrap command execution with error handling.
    
    Catches exceptions and converts to user-friendly messages.
    
    Gotcha: Must NOT swallow critical exceptions (SystemExit, etc.)
    """
    try:
        return await handler(repl, *args, **kwargs)
    
    except KeyboardInterrupt:
        repl.print("\n[yellow]Cancelled.[/yellow]")
        return None
    
    except SidewinderError as e:
        # Structured error from core modules
        repl.print(f"\n[red]{e.severity.value.upper()}:[/red] {e.what}")
        repl.print(f"[dim]Why: {e.why}[/dim]")
        for step in e.how_to_fix:
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
        # Unexpected error — log it, show generic message
        repl.print(f"\n[red]UNEXPECTED ERROR:[/red] {type(e).__name__}: {e}")
        repl.print("[dim]This is a bug. Please report it.[/dim]")
        # Log full traceback to file
        import traceback
        with open("~/.sidewinder/error.log", "a") as f:
            traceback.print_exc(file=f)
        return None
```

---

## 10. Edge Cases & Gotchas

### 10.1 Terminal Edge Cases

| Edge Case | Problem | Solution |
|-----------|---------|----------|
| Terminal resized mid-render | Garbled output | Catch `SIGWINCH`, re-render on resize |
| Pipe output (`swcli \| less`) | Raw ANSI codes | Detect non-TTY, disable colors |
| SSH session | Different terminal capabilities | Use `rich` auto-detection |
| UTF-8 not supported | Box drawing fails | Fallback to ASCII chars |
| Very narrow terminal (< 40 cols) | Table overflow | Truncate columns, show `...` |
| Very wide terminal (> 200 cols) | Wasted space | Cap table width at 120 cols |
| Background process output | Interleaved with prompts | Redirect subprocess stdout/stderr to log file |

### 10.2 Input Edge Cases

| Edge Case | Problem | Solution |
|-----------|---------|----------|
| Empty input at prompt | No value provided | Use default, or re-prompt if no default |
| Ctrl+C during prompt | Interrupt | Cancel command, go back to main |
| Ctrl+D during prompt | EOF | Exit REPL cleanly |
| Ctrl+Z | Suspend process | Let OS handle (SIGTSTP) |
| Very long input | Buffer overflow | Truncate to 256 chars |
| Unicode input | Encoding errors | Use `errors="replace"` on decode |
| Paste multi-line input | Only first line read | Read line-by-line, ignore rest |
| Arrow keys in main mode | Raw escape chars | Only interpret in palette context |
| `j`/`k` typed in main mode | Treated as command | Only interpret in palette context |

### 10.3 State Edge Cases

| Edge Case | Problem | Solution |
|-----------|---------|----------|
| Adapter disconnected during scan | Process dies, error | Catch error, show "Adapter lost" message |
| Adapter disconnected during capture | Capture fails | Return partial handshake if available |
| Monitor mode lost mid-operation | All operations fail | MonitorWatcher detects, warns user |
| Service restore fails | Network down | Log warning, suggest manual fix |
| Session file corrupted | Load fails | Create fresh session, warn user |
| Config file corrupted | Load fails | Use defaults, warn user |
| /tmp filled up | Write fails | Check disk space before capture, warn |
| Multiple swcli instances | Conflicting processes | Use PID file, warn if another instance running |

### 10.4 Concurrency Edge Cases

| Edge Case | Problem | Solution |
|-----------|---------|----------|
| Ctrl+C during subprocess | Zombie process | `start_new_session=True` + `os.killpg` |
| Multiple Ctrl+C | Aggressive kill | After 3 Ctrl+C, force kill everything |
| Signal during prompt | State corruption | Block signals during prompt input |
| Background task + user input | Race condition | Use asyncio locks for shared state |
| Scan running + user types command | Conflicting actions | Disable commands during scan |

### 10.5 The Big Gotchas

```
GOTCHA 1: Terminal cleanup on crash
─────────────────────────────────────
If swcli crashes with raw terminal settings (from read_key()),
the terminal will be broken (no echo, no line buffering).

SOLUTION: Always restore terminal settings in a finally block:
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        # ... do stuff ...
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

Or use atexit:
    import atexit
    atexit.register(lambda: termios.tcsetattr(fd, termios.TCSADRAIN, old_settings))


GOTCHA 2: Root check in interactive mode
─────────────────────────────────────────
User starts `swcli` (no sudo), then tries `/monitor`.
Command fails with "Permission denied".

SOLUTION: Check root at startup, warn if not root:
    if os.geteuid() != 0:
        print("[yellow]WARNING: Not running as root. Some commands will fail.[/yellow]")
        print("Run: sudo swcli\n")
    
    Then when they try a root command:
        if requires_root and os.geteuid() != 0:
            print("[red]This command requires root. Run: sudo swcli[/red]")
            return


GOTCHA 3: Stale session values
───────────────────────────────
User selects BSSID AA:BB:CC:DD:EE:01 from scan.
User unplugs adapter, plugs in different one.
User tries /capture — BSSID still stored, but wrong adapter.

SOLUTION: Validate stored values before using:
    def get_default_iface(self) -> str:
        if self.last_iface:
            if not Path(f"/sys/class/net/{self.last_iface}").exists():
                self.last_iface = ""  # Clear stale value
                return ""
            return self.last_iface
        return ""


GOTCHA 4: airodump-ng CSV parsing race condition
──────────────────────────────────────────────────
airodump-ng writes CSV while we read it.
File may be partially written → parse error.

SOLUTION: Read file into memory first, then parse:
    with open(csv_file, errors="replace") as f:
        content = f.read()  # Read entire file at once
    # Now parse content (no race condition)


GOTCHA 5: Ctrl+C during subprocess wait
─────────────────────────────────────────
User presses Ctrl+C while waiting for airodump-ng.
Python raises KeyboardInterrupt, but subprocess keeps running.

SOLUTION: Catch KeyboardInterrupt, explicitly kill subprocess:
    try:
        await proc.wait()
    except KeyboardInterrupt:
        proc.kill()
        await proc.wait()
        raise  # Re-raise after cleanup


GOTCHA 6: Palette renders over command output
──────────────────────────────────────────────
User types a command that produces output.
Output appears, then palette renders on top of it.

SOLUTION: Clear screen before palette, or render palette
in a fixed region of the terminal:
    # Option A: Clear and redraw
    os.system('clear' if os.name == 'posix' else 'cls')
    render_palette()
    
    # Option B: Use alternate screen buffer
    print("\033[?1049h")  # Enter alternate buffer
    render_palette()
    print("\033[?1049l")  # Exit alternate buffer


GOTCHA 7: Multiple monitor interfaces
──────────────────────────────────────
User has two USB adapters, both in monitor mode.
Which one to use for scan/capture?

SOLUTION: Always ask user to select:
    monitor_ifaces = [a for a in adapters if a.current_mode == "monitor"]
    if len(monitor_ifaces) > 1:
        result = prompt_choice("Select monitor interface:", monitor_ifaces)


GOTCHA 8: Session persistence across REPL restarts
───────────────────────────────────────────────────
User scans, finds networks.
User exits swcli.
User starts swcli again — scan results are gone.

SOLUTION: Auto-save session on exit, auto-load on start:
    def run(self):
        # Load previous session
        self.session = UISession.load() or UISession()
        
        try:
            # ... REPL loop ...
        finally:
            # Save session on exit
            self.session.save()
```

---

## 11. Command Implementations

### 11.1 /adapters

```python
async def cmd_adapters(repl: SwcliREPL):
    """List all wireless adapters."""
    adapters = await discover_all_adapters()
    
    if not adapters:
        repl.print("[yellow]No wireless adapters found.[/yellow]")
        return
    
    headers = ["#", "Interface", "Chipset", "Driver", "Bands", "Mode", "Monitor", "Inject", "Status"]
    rows = []
    
    for i, a in enumerate(adapters, 1):
        rows.append([
            str(i),
            a.iface,
            a.chipset,
            a.driver[:12],
            ",".join(a.bands),
            a.current_mode,
            "[green]YES[/green]" if a.monitor_capable else "[red]NO[/red]",
            "[green]YES[/green]" if a.injection_capable else "[red]NO[/red]",
            a.status,
        ])
    
    print_table(headers, rows)
    repl.print(f"\n  Total: {len(adapters)} adapters")
    repl.print("  Use: /monitor <interface> to enter monitor mode")
```

### 11.2 /monitor

```python
async def cmd_monitor_start(repl: SwcliREPL):
    """Enter monitor mode interactively."""
    adapters = await discover_all_adapters()
    monitor_capable = [a for a in adapters if a.monitor_capable]
    
    if not monitor_capable:
        repl.print("[red]No monitor-capable adapters found.[/red]")
        return
    
    # Step 1: Select adapter
    if len(monitor_capable) == 1:
        iface = monitor_capable[0]
        repl.print(f"  Adapter: {iface.iface} ({iface.chipset})")
    else:
        choices = [f"{a.iface} ({a.chipset})" for a in monitor_capable]
        result = prompt_choice("Select adapter:", choices)
        if result.cancelled:
            return
        iface = monitor_capable[choices.index(result.value)]
    
    # Step 2: Select channel
    ch_result = prompt_channel("Channel", default=6)
    if ch_result.cancelled:
        return
    channel = ch_result.value
    
    # Step 3: Confirm
    repl.print(f"""
  [bold]Enter Monitor Mode:[/bold]
    Adapter:  {iface.iface} ({iface.chipset})
    PHY:      {iface.phy}
    Channel:  {channel}
  
  This will:
    - Bring {iface.iface} down
    - Create: {iface.iface}mon
    - Set channel {channel}
    - Set TX power 30 dBm""")
    
    confirm = prompt_confirm("Continue?")
    if confirm.cancelled or not confirm.value:
        repl.print("[yellow]Cancelled.[/yellow]")
        return
    
    # Step 4: Execute
    try:
        mon_iface = await enter_monitor_mode(iface.iface, iface.phy, channel)
        repl.print(f"[green][+][/green] Monitor mode active: {mon_iface}")
        repl.session.monitor_mode = True
        repl.session.monitor_iface = mon_iface
        repl.session.last_iface = iface.iface
    except Exception as e:
        repl.print(f"[red][!][/red] Failed: {e}")
```

---

## 12. Help System

### 12.1 Contextual Help

```python
def show_help(repl: SwcliREPL, context: str = "main"):
    """Show contextual help based on current context."""
    
    help_text = {
        "main": """
  [bold]swcli — WiFi Audit Toolkit[/bold]
  
  Type [cyan]/[/cyan] to open command palette.
  Type [cyan]?[/cyan] for this help.
  Type [cyan]quit[/cyan] or [cyan]exit[/cyan] to leave.
  
  Quick commands:
    /adapters              List wireless adapters
    /monitor <iface>       Enter monitor mode
    /scan <mon_iface>      Start WiFi scan
    /capture deauth ...    Capture handshake
    /crack aircrack ...    Crack password
    /cleanup               Restore system
  
  Navigate: j/k   Select: Enter   Back: Esc
""",
        
        "palette": """
  [bold]Command Palette[/bold]
  
  Navigate with [cyan]j[/cyan]/[cyan]k[/cyan] or [cyan]↑[/cyan]/[cyan]↓[/cyan]
  Select with [cyan]Enter[/cyan]
  Go back with [cyan]Esc[/cyan]
  Type to filter commands
""",
        
        "capture": """
  [bold]Capture Commands[/bold]
  
  /capture passive <iface> <bssid> <ch>
    Listen for handshake without sending packets.
    Safe but slow (may take minutes).
  
  /capture deauth <iface> <bssid> <ch>
    Send deauth frames to force handshake.
    Fast but noisy (clients get disconnected).
  
  /capture pmkid <iface> <bssid> <ch>
    Capture PMKID directly from AP.
    No clients required. Needs hcxdumptool.
  
  /validate <cap_file>
    Check if capture file has valid handshake.
""",
    }
    
    repl.print(help_text.get(context, help_text["main"]))
```

---

## 13. Testing Strategy

### 13.1 Unit Tests

```python
# tests/test_prompts.py

def test_prompt_text_with_default():
    """User presses Enter → returns default."""
    # Mock stdin
    # Verify default is returned

def test_prompt_text_no_default_empty_input():
    """No default, empty input → re-prompt."""
    # Mock stdin returning empty, then "value"
    # Verify "value" is returned

def test_prompt_choice_valid_number():
    """User types '2' → returns second choice."""
    # Mock stdin returning "2"
    # Verify second choice returned

def test_prompt_choice_valid_name():
    """User types 'option_b' → returns matching choice."""
    # Mock stdin returning "option_b"
    # Verify matching choice returned

def test_prompt_confirm_y():
    """User types 'y' → returns True."""
    # Mock stdin returning "y"
    # Verify True returned

def test_prompt_confirm_enter_default_true():
    """Empty input, default=True → returns True."""
    # Mock stdin returning ""
    # Verify True returned

def test_prompt_mac_validation():
    """Invalid MAC → re-prompt."""
    # Mock stdin returning "invalid", then "AA:BB:CC:DD:EE:FF"
    # Verify second value returned

def test_prompt_channel_validation():
    """Invalid channel → re-prompt."""
    # Mock stdin returning "200", then "6"
    # Verify 6 returned
```

### 13.2 Integration Tests

```python
# tests/test_repl.py

def test_repl_opens_palette():
    """Type '/' → palette opens."""
    # Simulate input: "/"
    # Verify palette is visible

def test_repl_palette_navigation():
    """Type 'j' → selection moves down."""
    # Simulate input: "/", "j"
    # Verify selected_index incremented

def test_repl_palette_select_command():
    """Type Enter → command executes."""
    # Simulate input: "/", Enter on "/adapters"
    # Verify cmd_adapters was called

def test_repl_palette_esc_closes():
    """Type Esc at top level → palette closes."""
    # Simulate input: "/", Esc
    # Verify palette.is_open == False

def test_repl_direct_command():
    """Run 'swcli adapters' → executes directly."""
    # Simulate sys.argv = ["swcli", "adapters"]
    # Verify output produced
```

---

## Summary

**What to build:**

1. `SwcliREPL` — main loop with context switching (main/palette/prompt)
2. `CommandPalette` — `/` opens, j/k navigates, Enter selects, Esc goes back
3. `Prompt system` — text, choice, confirm, MAC, channel — all with defaults
4. `UISession` — remembers last values, auto-fills prompts
5. `Direct mode` — argparse for script-friendly one-liners
6. `Error handling` — structured errors, graceful recovery, terminal cleanup
7. `Help system` — contextual `?` help

**Key gotchas to handle:**
- Terminal cleanup on crash (restore settings)
- Root check at startup (warn, don't block)
- Stale session values (validate before use)
- airodump-ng CSV race condition (read-then-parse)
- Ctrl+C during subprocess (explicit kill)
- Multiple monitor interfaces (ask user to pick)
- Signal handling during prompts (don't corrupt state)
