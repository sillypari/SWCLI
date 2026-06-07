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

def read_key() -> str:
    if os.name == 'nt':
        ch = msvcrt.getch()
        if ch in (b'\x00', b'\xe0'):
            ch2 = msvcrt.getch()
            if ch2 == b'H': return 'up'
            if ch2 == b'P': return 'down'
            if ch2 == b'M': return 'right'
            if ch2 == b'K': return 'left'
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
                return 'esc'
            if ch == '\r': return '\n'
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def read_line(prompt: str, default: str = "") -> str:
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
) -> PromptResult:
    while True:
        console.print(f"\n  [bold]{message}[/bold]")
        for i, choice in enumerate(choices, 1):
            marker = "→" if i - 1 == default else " "
            console.print(f"    {marker} {i}. {choice}")
        
        try:
            user_input = read_line(f"\n  Select", str(default + 1))
            
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
            
            console.print(f"  [red]Invalid choice. Enter 1-{len(choices)}.[/red]")
        
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
