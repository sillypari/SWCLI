import os
import json
from pathlib import Path
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_confirm
from sidewinder.core.session import Session, Network, Client
from swcli.repl.renderer import print_success, print_error, print_table
from swcli.repl.session_ui import list_autosaves

SESSION_DIR = os.path.expanduser("~/.sidewinder/sessions")

def _apply_session(repl, session: Session):
    repl.session.scan_results = session.scan_results
    repl.session.clients = session.clients
    repl.session.selected_target = session.selected_target
    repl.session.last_iface = session.adapter
    repl.session.last_cap_file = session.last_capture
    repl.session.captures = session.captures
    repl.session.handshake = session.handshake
    repl.session.cracked_passwords = session.cracked_passwords
    if session.selected_target:
        repl.session.last_bssid = session.selected_target.bssid
        repl.session.last_channel = session.selected_target.channel
    if session.captures:
        repl.session.last_cap_file = session.captures[-1]

async def cmd_session_save(repl):
    path = prompt_text("Save path", default=os.path.expanduser("~/.sidewinder/session.json"))
    if path.cancelled: return

    session = repl.session.to_core_session()

    try:
        saved_path = session.save(path.value)
        print_success(f"Session saved to {saved_path}")
    except Exception as e:
        print_error(f"Failed to save: {e}")

async def cmd_session_load(repl):
    if not os.path.isdir(SESSION_DIR):
        repl.print("[yellow]No saved sessions found.[/yellow]")
        return

    files = [f for f in os.listdir(SESSION_DIR) if f.endswith(".json")]
    if not files:
        repl.print("[yellow]No saved sessions found.[/yellow]")
        return

    choices = files[:20]
    from swcli.repl.prompts import prompt_choice
    res = prompt_choice("Select session to load:", choices)
    if res.cancelled: return

    path = os.path.join(SESSION_DIR, res.value)
    try:
        session = Session.load(path)
        if not session:
            print_error("Failed to load session — file may be corrupt.")
            return

        _apply_session(repl, session)
        print_success(f"Session loaded: {session.id[:8]}... ({len(session.scan_results)} networks)")
    except Exception as e:
        print_error(f"Failed to load: {e}")

async def cmd_session_list(repl):
    if not os.path.isdir(SESSION_DIR):
        repl.print("[yellow]No saved sessions found.[/yellow]")
        return

    files = sorted(
        [f for f in os.listdir(SESSION_DIR) if f.endswith(".json")],
        key=lambda f: os.path.getmtime(os.path.join(SESSION_DIR, f)),
        reverse=True,
    )

    if not files:
        repl.print("[yellow]No saved sessions found.[/yellow]")
        return

    rows = []
    for i, f in enumerate(files[:20], 1):
        path = os.path.join(SESSION_DIR, f)
        size = os.path.getsize(path)
        mtime = os.path.getmtime(path)
        from datetime import datetime
        ts = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
        rows.append([str(i), f[:12] + "...", f"{size:,} bytes", ts])

    print_table(["#", "ID", "Size", "Saved"], rows, "Saved Sessions")


async def cmd_session_autosaves(repl):
    autosaves = list_autosaves()
    if not autosaves:
        repl.print("[yellow]No autosaved sessions found.[/yellow]")
        return

    rows = []
    for i, path in enumerate(autosaves, 1):
        stat = path.stat()
        from datetime import datetime
        ts = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        rows.append([str(i), path.name, f"{stat.st_size:,} bytes", ts])
    print_table(["#", "Autosave", "Size", "Saved"], rows, "Last 5 Autosaves")


async def cmd_session_load_autosave(repl):
    autosaves = list_autosaves()
    if not autosaves:
        repl.print("[yellow]No autosaved sessions found.[/yellow]")
        return

    from swcli.repl.prompts import prompt_choice
    choices = [f"{path.name} ({path.stat().st_size:,} bytes)" for path in autosaves]
    choice_map = {label: path for label, path in zip(choices, autosaves)}
    res = prompt_choice("Load autosave", choices)
    if res.cancelled:
        return

    session = Session.load(str(choice_map[res.value]))
    if not session:
        print_error("Failed to load autosave — file may be corrupt.")
        return
    _apply_session(repl, session)
    print_success(f"Autosave loaded: {choice_map[res.value].name} ({len(session.scan_results)} networks)")

def register_commands(palette: CommandPalette):
    palette.register(Command("/session save", "Save current state", "Session", cmd_session_save, requires_root=False))
    palette.register(Command("/session load", "Load saved session", "Session", cmd_session_load, requires_root=False))
    palette.register(Command("/session list", "List saved sessions", "Session", cmd_session_list, requires_root=False))
    palette.register(Command("/session autosaves", "List last 5 autosaves", "Session", cmd_session_autosaves, requires_root=False))
    palette.register(Command("/session load autosave", "Load an autosaved session", "Session", cmd_session_load_autosave, requires_root=False))
