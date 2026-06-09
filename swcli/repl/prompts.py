import sys
import os
import re
from typing import Any, Callable, Optional
from swcli.repl.renderer import console

if os.name == 'nt':
    import msvcrt
else:
    import tty
    import termios

def _ensure_cooked_stdin() -> None:
    """Put stdin back into normal line-input mode before using input()."""
    if os.name == 'nt' or not sys.stdin.isatty():
        return
    fd = sys.stdin.fileno()
    try:
        settings = termios.tcgetattr(fd)
    except termios.error:
        return

    settings[0] |= getattr(termios, "ICRNL", 0)
    settings[1] |= getattr(termios, "OPOST", 0)
    settings[3] |= (
        getattr(termios, "ECHO", 0)
        | getattr(termios, "ICANON", 0)
        | getattr(termios, "ISIG", 0)
        | getattr(termios, "IEXTEN", 0)
    )
    try:
        settings[6][termios.VMIN] = 1
        settings[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSAFLUSH, settings)
    except termios.error:
        return

def read_key() -> str:
    if os.name == 'nt':
        ch = msvcrt.getch()
        if ch in (b'\x00', b'\xe0'):
            ch2 = msvcrt.getch()
            if ch2 == b'H': return 'up'
            if ch2 == b'P': return 'down'
            if ch2 == b'M': return 'right'
            if ch2 == b'K': return 'left'
            if ch2 == b'I': return 'page_up'
            if ch2 == b'Q': return 'page_down'
        if ch == b'\x1b': return 'esc'
        if ch == b'\r': return '\n'
        return ch.decode('utf-8', errors='ignore')
    else:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == '\x1b':
                ch2 = sys.stdin.read(1)
                if ch2 == '[':
                    ch3 = sys.stdin.read(1)
                    if ch3 == 'A': return 'up'
                    if ch3 == 'B': return 'down'
                    if ch3 == 'C': return 'right'
                    if ch3 == 'D': return 'left'
                    if ch3 == '5':
                        sys.stdin.read(1)
                        return 'page_up'
                    if ch3 == '6':
                        sys.stdin.read(1)
                        return 'page_down'
                return 'esc'
            if ch == '\r': return '\n'
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def read_line(prompt: str, default: str = "") -> str:
    _ensure_cooked_stdin()
    if default:
        display = f"  {prompt} [{default}]: "
    else:
        display = f"  {prompt}: "
    
    sys.stdout.write(display)
    sys.stdout.flush()
    
    user_input = input().strip()
    
    if not user_input and default:
        return default
    return user_input


def _ansi_style(text: str, style: str) -> str:
    styles = {
        "cyan": "\033[96m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "dim": "\033[90m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }
    return f"{styles.get(style, '')}{text}{styles['reset']}"


def _highlight_command(text: str, known_commands: set[str]) -> str:
    if not text:
        return ""

    lowered = text.strip().lower()
    if lowered in ("quit", "exit", "/quit", "/ quit"):
        return _ansi_style(text, "yellow")
    if text.startswith("!"):
        return _ansi_style(text, "red")
    if text.startswith("?"):
        return _ansi_style(text, "green")
    if text.startswith("/"):
        normalized = "/" + text[1:].strip()
        for cmd in sorted(known_commands, key=len, reverse=True):
            if normalized == cmd or normalized.startswith(cmd + " "):
                suffix = text[len(cmd):] if text.startswith(cmd) else ""
                return _ansi_style(text[:len(text) - len(suffix)], "cyan") + suffix
        return _ansi_style(text, "cyan")
    return text


def read_command_line(prompt: str, history: list[str], known_commands: set[str]) -> str:
    """Read a command with lightweight syntax highlighting and history."""
    buffer = ""
    history_index = len(history)
    line_prompt = prompt.lstrip("\n")
    leading_newlines = prompt[:len(prompt) - len(line_prompt)]
    if leading_newlines:
        sys.stdout.write(leading_newlines)
        sys.stdout.flush()

    def render() -> None:
        highlighted = _highlight_command(buffer, known_commands)
        sys.stdout.write(f"\r\033[K{line_prompt}{highlighted}")
        sys.stdout.flush()

    render()
    while True:
        key = read_key()
        if key == "\n":
            sys.stdout.write("\n")
            sys.stdout.flush()
            value = buffer.strip()
            if value and (not history or history[-1] != value):
                history.append(value)
                del history[:-200]
            return value
        if key == "\x03":
            raise KeyboardInterrupt
        if key == "\x04":
            raise EOFError
        if key in ("\x08", "\x7f"):
            buffer = buffer[:-1]
        elif key == "up":
            if history and history_index > 0:
                history_index -= 1
                buffer = history[history_index]
        elif key == "down":
            if history and history_index < len(history) - 1:
                history_index += 1
                buffer = history[history_index]
            else:
                history_index = len(history)
                buffer = ""
        elif key == "esc":
            buffer = ""
        elif len(key) == 1 and key.isprintable():
            buffer += key
            history_index = len(history)
        render()

class PromptResult:
    def __init__(self, value: Any, cancelled: bool = False):
        self.value = value
        self.cancelled = cancelled

def prompt_text(
    message: str,
    default: str = "",
    validator: Optional[Callable[[str], bool]] = None,
    error_msg: str = "Invalid input",
) -> PromptResult:
    while True:
        try:
            user_input = read_line(message, default)
            
            if not user_input and not default:
                continue
            
            if validator and not validator(user_input):
                console.print(f"  [red]{error_msg}[/red]")
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
    allow_back: bool = True,
) -> PromptResult:
    while True:
        console.print(f"\n  [bold]{message}[/bold]")
        if allow_back:
            console.print("      0. Back")
        for i, choice in enumerate(choices, 1):
            marker = "→" if i - 1 == default else " "
            console.print(f"    {marker} {i}. {choice}")
        
        try:
            user_input = read_line(f"\n  Select", str(default + 1))
            if allow_back and user_input.lower() in ("0", "b", "back", "esc", "q", "quit", "cancel"):
                return PromptResult(None, cancelled=True)
            
            try:
                index = int(user_input) - 1
            except ValueError:
                index = -1
                for i, c in enumerate(choices):
                    if user_input.lower() in c.lower():
                        index = i
                        break
            
            if 0 <= index < len(choices):
                return PromptResult(choices[index])
            
            low = 0 if allow_back else 1
            console.print(f"  [red]Invalid choice. Enter {low}-{len(choices)}.[/red]")
        
        except KeyboardInterrupt:
            return PromptResult(None, cancelled=True)
        except EOFError:
            return PromptResult(None, cancelled=True)

def prompt_confirm(message: str, default: bool = False) -> PromptResult:
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
            
            console.print(f"  [red]Enter y or n.[/red]")
        except (KeyboardInterrupt, EOFError):
            return PromptResult(False, cancelled=True)

def prompt_mac(message: str, default: str = "", allow_broadcast: bool = True) -> PromptResult:
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

def prompt_channel(message: str, default: int = 6) -> PromptResult:
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
