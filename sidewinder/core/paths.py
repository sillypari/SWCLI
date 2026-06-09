"""Output path helpers for SWCLI-generated files."""
from __future__ import annotations

import os
from datetime import datetime

from .config import SidewinderConfig, expand_user_path

CONFIG_PATH = "~/.sidewinder/config.json"


def output_root() -> str:
    cfg = SidewinderConfig.load(CONFIG_PATH)
    root = expand_user_path(cfg.results_dir)
    os.makedirs(root, exist_ok=True)
    return root


def output_dir(name: str) -> str:
    path = os.path.join(output_root(), name)
    os.makedirs(path, exist_ok=True)
    return path


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def output_prefix(kind: str, stem: str | None = None) -> str:
    base = stem or kind
    return os.path.join(output_dir(kind), f"{base}_{timestamp()}")


def scan_prefix() -> str:
    return output_prefix("scans", "scan")


def capture_prefix(kind: str) -> str:
    return output_prefix("captures", kind)


def attack_prefix(kind: str) -> str:
    return output_prefix("attacks", kind)


def hash_path(filename: str) -> str:
    return os.path.join(output_dir("hashes"), filename)


def passwords_dir() -> str:
    """Return the passwords output directory, creating it if needed."""
    return output_dir("passwords")


def password_file_path(bssid: str = "", method: str = "") -> str:
    """Generate a password file path for saving cracked credentials.

    Creates a timestamped file in ./swcli-output/passwords/ with format:
      passwords_<BSSID>_<method>_<timestamp>.txt

    Args:
        bssid:   Target AP BSSID (optional, sanitized for filename).
        method:  Cracking method used (aircrack/hashcat).

    Returns:
        Absolute path to the password file.
    """
    import re
    sanitized_bssid = re.sub(r'[^a-zA-Z0-9]', '', bssid) if bssid else "unknown"
    method_tag = method if method else "crack"
    ts = timestamp()
    filename = f"passwords_{sanitized_bssid}_{method_tag}_{ts}.txt"
    return os.path.join(passwords_dir(), filename)


def save_password(
    password: str,
    bssid: str = "",
    essid: str = "",
    method: str = "",
    wordlist: str = "",
    extra_info: str = "",
) -> str:
    """Save a cracked password to the output folder.

    Writes to a human-readable .txt file and appends to a master
    passwords.txt log for easy reference.

    Args:
        password:    The cracked password string.
        bssid:       Target AP BSSID.
        essid:       Target AP ESSID/network name.
        method:      Cracking method (aircrack/hashcat).
        wordlist:    Wordlist used for cracking.
        extra_info:  Any additional info to include.

    Returns:
        Path to the individual password file that was written.
    """
    from ..core.session import CrackResult

    # Write individual password file
    individual_path = password_file_path(bssid, method)
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "=" * 60,
        "SWCLI - Cracked Password",
        "=" * 60,
        f"Password:    {password}",
        f"BSSID:       {bssid or 'N/A'}",
        f"ESSID:       {essid or 'N/A'}",
        f"Method:      {method or 'N/A'}",
        f"Wordlist:    {wordlist or 'N/A'}",
        f"Timestamp:   {timestamp_str}",
    ]
    if extra_info:
        lines.append(f"Extra:       {extra_info}")
    lines.append("=" * 60)
    lines.append("")

    os.makedirs(os.path.dirname(individual_path), exist_ok=True)
    with open(individual_path, "w") as f:
        f.write("\n".join(lines))

    # Append to master passwords.txt log
    master_path = os.path.join(passwords_dir(), "passwords.txt")
    with open(master_path, "a") as f:
        f.write(f"[{timestamp_str}] {essid or 'N/A'} ({bssid or 'N/A'}) | Password: {password} | Method: {method} | Wordlist: {wordlist}\n")

    return individual_path
