import asyncio
import os
import glob
import time
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_mac, prompt_confirm, prompt_choice
from swcli.repl.session_ui import auto_fill_prompt
from sidewinder.core.cracker import crack_aircrack, crack_hashcat, find_wordlists, CrackProgress
from rich.live import Live
from swcli.repl.renderer import (
    build_aircrack_status_panel,
    console,
    print_success,
    print_error,
    print_table,
)

def _get_cap_file(repl) -> str:
    files = glob.glob("/tmp/swcli_cap_*-01.cap") + glob.glob("/tmp/swcli_cap-*.cap")
    files.sort(key=os.path.getmtime, reverse=True)
    
    if files:
        choices = []
        for f in files[:5]: # Top 5 recent
            size = os.path.getsize(f) / 1024
            choices.append(f"{f} ({size:.1f} KB)")
        choices.append("Enter path manually")
        
        res = prompt_choice("Select Capture File", choices)
        if res.cancelled: return None
        if "Enter path manually" not in res.value:
            return res.value.split(" ")[0]
            
    res = prompt_text(*auto_fill_prompt(repl.session, "cap_file", "Capture File"))
    return res.value if not res.cancelled else None

MAX_WORDLIST_DIR_CHOICES = 10


def _format_wordlist_choice(path: str) -> str:
    size = os.path.getsize(path) / (1024 * 1024) if os.path.exists(path) else 0
    return f"{path} ({size:.1f} MB)"


def _select_txt_from_directory(directory: str) -> str | None:
    txt_files = []
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if not entry.is_file():
                    continue
                if not entry.name.lower().endswith(".txt"):
                    continue
                txt_files.append(entry.path)
                if len(txt_files) >= MAX_WORDLIST_DIR_CHOICES + 1:
                    break
    except OSError as e:
        print_error(f"Cannot read wordlist directory: {e}")
        return None

    if not txt_files:
        print_error(f"No .txt wordlists found in directory: {directory}")
        return None

    txt_files = sorted(txt_files, key=lambda path: os.path.basename(path).lower())
    shown = txt_files[:MAX_WORDLIST_DIR_CHOICES]
    choice_map = {_format_wordlist_choice(path): path for path in shown}
    choices = list(choice_map)
    if len(txt_files) > MAX_WORDLIST_DIR_CHOICES:
        print_error(f"Directory has more than {MAX_WORDLIST_DIR_CHOICES} .txt files; showing first {MAX_WORDLIST_DIR_CHOICES} only.")

    res = prompt_choice("Select .txt wordlist", choices)
    if res.cancelled:
        return None
    return choice_map[res.value]


def _resolve_wordlist_path(path: str) -> str | None:
    path = os.path.expanduser(path.strip())
    if os.path.isdir(path):
        return _select_txt_from_directory(path)
    return path


def _get_wordlist(repl) -> str:
    wls = find_wordlists()
    if wls:
        choice_map = {_format_wordlist_choice(w): w for w in wls[:5]}
        choices = list(choice_map)
        choices.append("Enter path manually")
        
        res = prompt_choice("Select Wordlist", choices)
        if res.cancelled: return None
        if "Enter path manually" not in res.value:
            return choice_map[res.value]
            
    res = prompt_text(*auto_fill_prompt(repl.session, "wordlist", "Wordlist or directory"))
    if res.cancelled:
        return None
    return _resolve_wordlist_path(res.value)

def _create_crack_render(method: str, cap_file: str, bssid: str, wordlist: str, state: dict, start_time: float):
    def render():
        elapsed = time.monotonic() - start_time
        return build_aircrack_status_panel(
            method=method,
            cap_file=cap_file,
            bssid=bssid,
            wordlist=wordlist,
            tested=state["tested"],
            total=state["total"],
            keys_per_second=state["speed"],
            elapsed=elapsed,
            eta_seconds=state["eta"],
            current_key=state["current_key"],
            found_password=state["found_password"],
            status=state["status"],
            activity=state["activity"],
        )
    return render

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
    cap_file = _get_cap_file(repl)
    if not cap_file: return
    if not os.path.isfile(cap_file):
        print_error(f"Capture file not found or is a directory: {cap_file}")
        return
    
    bssid_res = prompt_mac(*auto_fill_prompt(repl.session, "bssid", "Target BSSID"))
    if bssid_res.cancelled: return
    
    wordlist = _get_wordlist(repl)
    if not wordlist: return
    if not os.path.isfile(wordlist):
        print_error(f"Wordlist not found or is a directory: {wordlist}")
        return
    
    repl.session.last_wordlist = wordlist
    conf = prompt_confirm("Start Aircrack-ng?")
    if conf.cancelled or not conf.value: return
    
    repl.print("\n [dim]Initializing Aircrack-ng...[/dim]")
    start_time = time.monotonic()
    state = {"tested": 0, "total": 0, "speed": 0.0, "eta": 0.0, "current_key": "", "found_password": "", "status": "running", "activity": "|"}
    activity_frames = ("|", "/", "-", "\\")
    done = False
    render = _create_crack_render("Aircrack-ng", cap_file, bssid_res.value, wordlist, state, start_time)

    async def animate(live):
        idx = 0
        while not done:
            state["activity"] = activity_frames[idx % len(activity_frames)]
            live.update(render(), refresh=True)
            idx += 1
            await asyncio.sleep(0.2)

    try:
        with Live(render(), console=console, refresh_per_second=8, transient=False) as live:
            anim_task = asyncio.create_task(animate(live))
            def on_progress(p: CrackProgress) -> None:
                state.update({
                    "tested": p.keys_tested or state["tested"],
                    "total": p.total_keys or state["total"],
                    "speed": p.keys_per_second or state["speed"],
                    "eta": p.eta_seconds,
                    "current_key": p.current_key or state["current_key"],
                })
                live.update(render(), refresh=True)

            try:
                res = await crack_aircrack(cap_file, bssid_res.value, wordlist, on_progress=on_progress)
            finally:
                done = True
                anim_task.cancel()
                try:
                    await anim_task
                except asyncio.CancelledError:
                    pass
            state["tested"] = res.keys_tested or state["tested"]
            state["status"] = "found" if res.found else "exhausted"
            if res.found:
                state["found_password"] = res.password
            live.update(render(), refresh=True)
        if res.found:
            print_success(f"KEY FOUND! [ [bold bright_green]{res.password}[/bold bright_green] ]")
            repl.session.add_password(bssid_res.value, res.password) if hasattr(repl.session, "add_password") else None
            repl.session.cracked_passwords.append(res)
        else:
            repl.session.cracked_passwords.append(res)
            print_error("Password not found in wordlist.")
    except Exception as e:
        print_error(str(e))

async def cmd_crack_hashcat(repl):
    cap_file = _get_cap_file(repl)
    if not cap_file: return
    if not os.path.isfile(cap_file):
        print_error(f"Capture file not found or is a directory: {cap_file}")
        return
    
    wordlist = _get_wordlist(repl)
    if not wordlist: return
    if not os.path.isfile(wordlist):
        print_error(f"Wordlist not found or is a directory: {wordlist}")
        return
    
    repl.session.last_wordlist = wordlist
    conf = prompt_confirm("Start Hashcat (Requires hcxpcapngtool)?")
    if conf.cancelled or not conf.value: return
    
    repl.print("\n [dim]Converting to hashcat format and initializing...[/dim]")
    start_time = time.monotonic()
    state = {"tested": 0, "total": 0, "speed": 0.0, "eta": 0.0, "current_key": "", "found_password": "", "status": "running", "activity": "|"}
    activity_frames = ("|", "/", "-", "\\")
    done = False
    render = _create_crack_render("Hashcat", cap_file, "auto", wordlist, state, start_time)

    async def animate(live):
        idx = 0
        while not done:
            state["activity"] = activity_frames[idx % len(activity_frames)]
            live.update(render(), refresh=True)
            idx += 1
            await asyncio.sleep(0.2)

    try:
        with Live(render(), console=console, refresh_per_second=8, transient=False) as live:
            anim_task = asyncio.create_task(animate(live))
            def on_progress(p: CrackProgress) -> None:
                state.update({
                    "tested": p.keys_tested or state["tested"],
                    "total": p.total_keys or state["total"],
                    "speed": p.keys_per_second or state["speed"],
                    "eta": p.eta_seconds,
                    "current_key": p.current_key or state["current_key"],
                })
                live.update(render(), refresh=True)

            try:
                res = await crack_hashcat(cap_file, wordlist, on_progress=on_progress)
            finally:
                done = True
                anim_task.cancel()
                try:
                    await anim_task
                except asyncio.CancelledError:
                    pass
            state["tested"] = res.keys_tested or state["tested"]
            state["status"] = "found" if res.found else "exhausted"
            if res.found:
                state["found_password"] = res.password
            live.update(render(), refresh=True)
        repl.session.cracked_passwords.append(res)
        if res.found:
            print_success(f"KEY FOUND! [ [bold bright_green]{res.password}[/bold bright_green] ]")
        else:
            print_error("Password not found in wordlist.")
    except Exception as e:
        print_error(str(e))

def register_commands(palette: CommandPalette):
    palette.register(Command("/wordlists", "List available wordlists", "Crack", cmd_wordlists, requires_root=False))
    palette.register(Command("/crack aircrack", "Crack with aircrack-ng", "Crack", cmd_crack_aircrack, requires_root=False))
    palette.register(Command("/crack hashcat", "Crack with hashcat", "Crack", cmd_crack_hashcat, requires_root=False))
