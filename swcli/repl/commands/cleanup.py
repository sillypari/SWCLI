from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_confirm
from sidewinder.core.cleanup import get_cleanup_manager
from sidewinder.core.paths import output_root
from swcli.repl.renderer import print_success
import subprocess
import shutil
import os

async def cmd_cleanup_full(repl):
    repl.print("  [bold]Full cleanup will:[/bold]")
    repl.print("    1. Kill attack processes")
    repl.print("    2. Exit monitor mode")
    repl.print("    3. Restore NetworkManager")
    repl.print(f"    4. Delete generated files under {output_root()}")
    
    conf = prompt_confirm("\n  Run full cleanup?")
    if conf.cancelled or not conf.value: return
    
    mgr = get_cleanup_manager()
    await mgr.full_cleanup("", "", "")
    print_success("Cleanup complete.")

async def cmd_cleanup_procs(repl):
    repl.print("  [blue]Killing attack processes...[/blue]")
    for p in ["airodump-ng", "aireplay-ng", "hashcat", "aircrack-ng"]:
        subprocess.run(["pkill", "-9", "-f", p], stderr=subprocess.DEVNULL)
        repl.print(f"    [+] Sent SIGKILL to {p}")

async def cmd_cleanup_files(repl):
    root = output_root()
    conf = prompt_confirm(f"Delete generated files under {root}?")
    if conf.cancelled or not conf.value: return
    if os.path.isdir(root):
        shutil.rmtree(root)
    os.makedirs(root, exist_ok=True)
    print_success("Generated files deleted.")

def register_commands(palette: CommandPalette):
    palette.register(Command("/cleanup", "Full cleanup", "System", cmd_cleanup_full))
    palette.register(Command("/cleanup procs", "Kill attack procs only", "System", cmd_cleanup_procs))
    palette.register(Command("/cleanup files", "Clean temp files only", "System", cmd_cleanup_files))
