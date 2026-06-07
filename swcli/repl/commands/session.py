import os
import json
from pathlib import Path
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_confirm
from sidewinder.core.session import Session, Network, Client
from swcli.repl.renderer import print_success, print_error, print_table

SESSION_DIR = os.path.expanduser("~/.sidewinder/sessions")

async def cmd_session_save(repl):
    path = prompt_text("Save path", default=os.path.expanduser("~/.sidewinder/session.json"))
    if path.cancelled: return

    session = Session(
        adapter=repl.session.last_iface,
        scan_results=repl.session.scan_results,
        clients=repl.session.clients,
        last_capture=repl.session.last_cap_file,
        captures=repl.session.captures,
    )

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

        repl.session.scan_results = session.scan_results
        repl.session.clients = session.clients
        repl.session.last_iface = session.adapter
        repl.session.last_cap_file = session.last_capture
        repl.session.captures = session.captures
        if session.selected_target:
            repl.session.last_bssid = session.selected_target.bssid
            repl.session.last_channel = session.selected_target.channel
        if session.captures:
            repl.session.last_cap_file = session.captures[-1]

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

def register_commands(palette: CommandPalette):
    palette.register(Command("/session save", "Save current state", "Session", cmd_session_save, requires_root=False))
    palette.register(Command("/session load", "Load saved session", "Session", cmd_session_load, requires_root=False))
    palette.register(Command("/session list", "List saved sessions", "Session", cmd_session_list, requires_root=False))
