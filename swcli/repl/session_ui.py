import os
from pathlib import Path
from typing import Optional

class UISession:
    """Stores UI state for auto-filling prompts."""
    
    def __init__(self):
        self.last_iface: str = ""
        self.last_bssid: str = ""
        self.last_channel: int = 0
        self.last_wordlist: str = ""
        self.last_cap_file: str = ""
        self.scan_results = []
        self.clients = []
        self.captures: list[str] = []
        self.monitor_mode: bool = False
        self.monitor_iface: str = ""
    
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
