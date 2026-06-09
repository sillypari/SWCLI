import json
import os
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from sidewinder.core.session import Session

AUTOSAVE_DIR = os.path.expanduser("~/.sidewinder/autosaves")
MAX_AUTOSAVES = 5


class UISession:
    """Stores UI state for auto-filling prompts."""
    
    def __init__(self):
        self.last_iface: str = ""
        self.last_bssid: str = ""
        self.last_channel: int = 0
        self.last_wordlist: str = ""
        self.last_cap_file: str = ""
        self.last_scan_show_rxq: bool = False
        self.last_scan_advanced_info: bool = False
        self.scan_results = []
        self.clients = []
        self.selected_target = None
        self.selected_client: str = ""
        self.captures: list[str] = []
        self.monitor_mode: bool = False
        self.monitor_iface: str = ""
        self.handshake = None
        self.cracked_passwords = []
    
    def get_channel_for_bssid(self, bssid: str) -> Optional[int]:
        bssid_upper = bssid.upper()
        for net in self.scan_results:
            if net.bssid.upper() == bssid_upper:
                return net.channel
        return None
    
    def get_default_iface(self) -> str:
        if self.last_iface:
            # Note: /sys/class/net is Linux specific. We fallback gracefully.
            if os.name == 'nt' or Path(f"/sys/class/net/{self.last_iface}").exists():
                return self.last_iface
        return ""
    
    def get_default_cap_file(self) -> str:
        if self.last_cap_file:
            if os.path.exists(self.last_cap_file):
                return self.last_cap_file
        return ""

    def to_core_session(self) -> Session:
        return Session(
            adapter=self.last_iface,
            scan_results=self.scan_results,
            clients=self.clients,
            selected_target=self.selected_target,
            last_capture=self.last_cap_file,
            captures=self.captures,
            handshake=self.handshake,
            cracked_passwords=self.cracked_passwords,
        )


def autosave_session(session: UISession, reason: str = "state_changed") -> str:
    """Write a rotating autosave. Keeps only the newest MAX_AUTOSAVES files."""
    os.makedirs(AUTOSAVE_DIR, exist_ok=True)
    core = session.to_core_session()
    core.log("autosave", reason=reason)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    path = os.path.join(AUTOSAVE_DIR, f"autosave-{stamp}.json")
    with open(path, "w") as f:
        json.dump(asdict(core), f, indent=2, default=str)

    autosaves = sorted(
        Path(AUTOSAVE_DIR).glob("autosave-*.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for old in autosaves[MAX_AUTOSAVES:]:
        try:
            old.unlink()
        except OSError:
            pass
    return path


def list_autosaves() -> list[Path]:
    if not os.path.isdir(AUTOSAVE_DIR):
        return []
    return sorted(
        Path(AUTOSAVE_DIR).glob("autosave-*.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )[:MAX_AUTOSAVES]


def auto_fill_prompt(session: UISession, prompt_type: str, message: str) -> tuple[str, str]:
    """Auto-fill a prompt with the last known value. Returns (message, default)."""
    default = ""
    if prompt_type == "iface":
        default = session.get_default_iface()
    elif prompt_type == "bssid":
        default = session.last_bssid
    elif prompt_type == "channel":
        default = str(session.last_channel) if session.last_channel else ""
    elif prompt_type == "wordlist":
        default = session.last_wordlist
    elif prompt_type == "cap_file":
        default = session.get_default_cap_file()
    
    return (message, default)
