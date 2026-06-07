from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_mac, prompt_confirm
from swcli.repl.session_ui import auto_fill_prompt
from sidewinder.core.cracker import crack_aircrack, crack_hashcat, find_wordlists
from swcli.repl.renderer import print_success, print_error, print_table
import os

async def cmd_wordlists(repl):
    wls = find_wordlists()
    if not wls:
        repl.print("[yellow]No wordlists found.[/yellow]")
        return
        
    rows = []
    for i, w in enumerate(wls, 1):
        size = os.path.getsize(w) if os.path.exists(w) else 0
        rows.append([str(i), w, f"{size:,} bytes"])
        
    print_table(["#", "Path", "Size"], rows, "Available Wordlists")
    repl.session.last_wordlist = wls[0]

async def cmd_crack_aircrack(repl):
    cap_res = prompt_text(*auto_fill_prompt(repl.session, "cap_file", "Capture File"))
    if cap_res.cancelled: return
    
    bssid_res = prompt_mac(*auto_fill_prompt(repl.session, "bssid", "Target BSSID"))
    if bssid_res.cancelled: return
    
    wl_res = prompt_text(*auto_fill_prompt(repl.session, "wordlist", "Wordlist"))
    if wl_res.cancelled: return
    
    conf = prompt_confirm("Start Aircrack-ng?")
    if conf.cancelled or not conf.value: return
    
    res = await crack_aircrack(cap_res.value, bssid_res.value, wl_res.value)
    if res.found:
        print_success(f"KEY FOUND! [ {res.password} ]")
    else:
        print_error("Password not found in wordlist.")

async def cmd_crack_hashcat(repl):
    cap_res = prompt_text(*auto_fill_prompt(repl.session, "cap_file", "Capture File"))
    if cap_res.cancelled: return
    
    wl_res = prompt_text(*auto_fill_prompt(repl.session, "wordlist", "Wordlist"))
    if wl_res.cancelled: return
    
    conf = prompt_confirm("Start Hashcat (Requires hcxpcapngtool)?")
    if conf.cancelled or not conf.value: return
    
    res = await crack_hashcat(cap_res.value, wl_res.value)
    if res.found:
        print_success(f"KEY FOUND! [ {res.password} ]")
    else:
        print_error("Password not found in wordlist.")

def register_commands(palette: CommandPalette):
    palette.register(Command("/wordlists", "List available wordlists", "Crack", cmd_wordlists, requires_root=False))
    palette.register(Command("/crack aircrack", "Crack with aircrack-ng", "Crack", cmd_crack_aircrack, requires_root=False))
    palette.register(Command("/crack hashcat", "Crack with hashcat", "Crack", cmd_crack_hashcat, requires_root=False))
