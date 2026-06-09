"""Sidewinder Configuration Management.

Handles loading, saving, and querying user configuration.
Configuration is stored in ~/.sidewinder/config.json
"""
import json
import logging
import os
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class SidewinderConfig:
    """Application configuration."""
    
    # Paths
    capture_dir: str = "./swcli-output/captures"
    wordlist_dir: str = "./swcli-output/wordlists"
    results_dir: str = "./swcli-output"
    
    # Defaults
    default_wordlist: str = "/usr/share/wordlists/rockyou.txt"
    default_channel: int = 1
    default_deauth_count: int = 10
    advanced_scan_info: bool = False
    keep_scan_captures: bool = False
    save_captures_without_eapol: bool = False
    
    # Timeouts
    capture_timeout_seconds: float = 300.0
    deauth_cooldown_seconds: float = 10.0
    
    # Hardware/Network
    regulatory_domain: str = "00"  # "00" means global/world. Set to "US", "GB", etc.
    mac_randomization: bool = False

    # Themes
    theme: str = "midnight"
    scan_color_mode: str = "airodump"
    theme_directory: str = "~/.sidewinder/themes"
    load_user_themes: bool = True
    load_builtin_themes: bool = True
    theme_preview: bool = True


    def save(self, path: str = "~/.sidewinder/config.json") -> None:
        """Save configuration to disk."""
        expanded_path = expand_user_path(path)
        os.makedirs(os.path.dirname(expanded_path), exist_ok=True)
        try:
            with open(expanded_path, "w") as f:
                json.dump(asdict(self), f, indent=4)
        except Exception as e:
            logger.error("Failed to save config: %s", e)

    @classmethod
    def load(cls, path: str = "~/.sidewinder/config.json") -> "SidewinderConfig":
        """Load configuration from disk, creating defaults if missing."""
        expanded_path = expand_user_path(path)
        if not os.path.exists(expanded_path):
            config = cls()
            config.save(path)
            return config

        try:
            with open(expanded_path, "r") as f:
                data = json.load(f)
            # Filter unknown kwargs to be forward-compatible
            import dataclasses
            valid_keys = {f.name for f in dataclasses.fields(cls)}
            filtered_data = {k: v for k, v in data.items() if k in valid_keys}
            config = cls(**filtered_data)
            if config.capture_dir == "~/.sidewinder/captures":
                config.capture_dir = "./swcli-output/captures"
            if config.results_dir == "~/.sidewinder/results":
                config.results_dir = "./swcli-output"
            return config
        except Exception as e:
            logger.error("Failed to load config (using defaults): %s", e)
            return cls()

    def get_capture_path(self, bssid: str) -> str:
        """Generate a capture file path for a given BSSID."""
        expanded_dir = expand_user_path(self.capture_dir)
        os.makedirs(expanded_dir, exist_ok=True)
        import re
        sanitized = re.sub(r'[^a-zA-Z0-9]', '', bssid)
        return os.path.join(expanded_dir, f"capture_{sanitized}")


def get_home_dir() -> str:
    """Get the home directory of the invoking user, even under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return pwd.getpwnam(sudo_user).pw_dir
        except (ImportError, KeyError):
            pass
    return os.path.expanduser("~")


def expand_user_path(path: str) -> str:
    """Expand user path using invoking user's home directory under sudo if available."""
    if path.startswith("~"):
        home = get_home_dir()
        # Remove leading ~ and any separator directly following it
        rel_path = path[2:] if path.startswith("~/") else path[1:]
        return os.path.join(home, rel_path)
    return os.path.expanduser(path)

