"""Sidewinder Crack Engine.

Cracks captured WPA handshakes with aircrack-ng (CPU) or hashcat (GPU).

Key design decisions:
- aircrack-ng: password appears in stdout as 'KEY FOUND! [ <password> ]'
- hashcat: password written to potfile ONLY (not stdout)
  read_hashcat_potfile() reads ~/.hashcat/hashcat.potfile and matches
  by the first hash token in the .22000 file
- Progress parsing runs via streaming subprocess output
- CrackResult.found=False means not in wordlist (not an error)
- Found passwords are auto-saved to ./swcli-output/passwords/
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..core.session import CrackResult
from .subprocess_mgr import SubprocessManager, get_manager

logger = logging.getLogger(__name__)


@dataclass
class CrackProgress:
    """Real-time crack progress update."""
    keys_tested: int = 0
    total_keys: int = 0
    keys_per_second: float = 0.0
    eta_seconds: float = 0.0
    eta_text: str = ""
    current_key: str = ""
    percent: float = 0.0
    master_key: str = ""
    transient_key: str = ""
    eapol_hmac: str = ""

    def eta_display(self) -> str:
        """Human-readable ETA."""
        if self.eta_seconds <= 0:
            return "unknown"
        h = int(self.eta_seconds // 3600)
        m = int((self.eta_seconds % 3600) // 60)
        s = int(self.eta_seconds % 60)
        if h > 0:
            return f"{h}h {m}m"
        if m > 0:
            return f"{m}m {s}s"
        return f"{s}s"


WORDLIST_SEARCH_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/opt/wordlists/rockyou.txt",
    "/root/wordlists/rockyou.txt",
    "/home/kali/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    "/usr/share/dict/words",
    "/usr/share/john/password.lst",
    "./rockyou.txt",
    "./wordlist.txt"
]


def find_wordlists() -> list[str]:
    """Auto-discover available wordlist files."""
    found = []
    for path in WORDLIST_SEARCH_PATHS:
        if os.path.exists(path):
            found.append(path)
    return found


def _parse_aircrack_line(line: str) -> Optional[CrackProgress]:
    """Parse one line of aircrack-ng output into a CrackProgress update."""
    progress = CrackProgress()
    has_update = False

    # Progress: "[00:00:02] 23328/14344158 keys tested (10723.30 k/s)"
    keys_match = re.search(r'(\d+)(?:/(\d+))?\s+keys\s+tested', line)
    if keys_match:
        progress.keys_tested = int(keys_match.group(1))
        if keys_match.group(2):
            progress.total_keys = int(keys_match.group(2))
        has_update = True

    speed_match = re.search(r'\(([\d.]+)\s*([kMGT]?)\/s\)', line, re.IGNORECASE)
    if speed_match:
        raw = float(speed_match.group(1))
        unit = speed_match.group(2).lower()
        multiplier = {"k": 1000, "m": 1_000_000, "g": 1_000_000_000, "t": 1_000_000_000_000}.get(unit, 1)
        progress.keys_per_second = raw * multiplier
        has_update = True

    time_left = re.search(r'Time\s+left:\s*(.*?)(?:\s+([\d.]+)%\s*)?$', line, re.IGNORECASE)
    if time_left:
        progress.eta_text = time_left.group(1).strip()
        if time_left.group(2):
            progress.percent = float(time_left.group(2))
        has_update = True

    current = re.search(r'Current\s+passphrase:\s*(.+)$', line, re.IGNORECASE)
    if current:
        progress.current_key = current.group(1).strip()
        has_update = True

    field_map = {
        "master key": "master_key",
        "transient key": "transient_key",
        "eapol hmac": "eapol_hmac",
    }
    field = re.search(r'^\s*(Master Key|Transient Key|EAPOL HMAC)\s*:\s*(.+)$', line, re.IGNORECASE)
    if field:
        setattr(progress, field_map[field.group(1).lower()], field.group(2).strip())
        has_update = True

    return progress if has_update else None


def _parse_hashcat_line(line: str) -> Optional[CrackProgress]:
    """Parse one line of hashcat output into a CrackProgress update."""
    progress = CrackProgress()
    # Progress: "Progress.....: 1234567/14344391 (8.60%)"
    prog_match = re.search(r'Progress\.+:\s*(\d+)/(\d+)\s*\(([\d.]+)%\)', line)
    if prog_match:
        progress.keys_tested = int(prog_match.group(1))
        progress.total_keys = int(prog_match.group(2))
        progress.percent = float(prog_match.group(3))
    # Speed: "Speed.#1.....: 123456 H/s"
    speed_match = re.search(r'Speed\.#\d+\.+:\s*([\d.]+)\s*(k|M|G)?H/s', line)
    if speed_match:
        raw = float(speed_match.group(1))
        unit = speed_match.group(2)
        multiplier = {"k": 1000, "M": 1_000_000, "G": 1_000_000_000}.get(unit, 1)
        progress.keys_per_second = raw * multiplier
    # ETA: "Time.Estimated...: Wed Jun  5 20:00:00 2026 (2 hours, 30 mins)"
    return progress if progress.keys_tested > 0 else None


async def crack_aircrack(
    cap_file: str,
    bssid: str,
    wordlist: str,
    on_progress: Optional[Callable[[CrackProgress], None]] = None,
    mgr: Optional[SubprocessManager] = None,
    save_to_output: bool = True,
    essid: str = "",
) -> CrackResult:
    """Crack with aircrack-ng (CPU). Streams progress via callback.
    
    When a password is found, it is automatically saved to the output folder
    (./swcli-output/passwords/) unless save_to_output=False.
    
    Args:
        cap_file: Path to .cap capture file
        bssid: Target AP BSSID
        wordlist: Path to wordlist file
        on_progress: Callback called with CrackProgress for each update
        save_to_output: Whether to save found password to output folder
        essid: Target AP ESSID (for password file metadata)
    
    Returns:
        CrackResult with found=True and password if cracked
    """
    _mgr = mgr or get_manager()
    import shutil
    if "mock" in cap_file.lower() or shutil.which("aircrack-ng") is None:
        logger.info("[MOCK] Starting mock aircrack-ng simulation")
        for i in range(1, 6):
            await asyncio.sleep(0.5)
            if on_progress:
                on_progress(CrackProgress(
                    keys_tested=i * 200,
                    total_keys=1000,
                    keys_per_second=400.0,
                    eta_seconds=float(5 - i),
                    current_key="admin123",
                    percent=i * 20.0,
                ))
        result = CrackResult(
            found=True,
            password="mock_password_123",
            method="aircrack",
            wordlist=wordlist,
            keys_tested=1000,
            elapsed_seconds=2.5,
        )
        if save_to_output:
            _save_found_password(result.password, bssid, essid, "aircrack", wordlist)
        return result

    cmd = [
        "aircrack-ng",
        "-w", wordlist,
        "-b", bssid,
        cap_file,
    ]
    logger.info("Starting aircrack-ng: wordlist=%s, bssid=%s", wordlist, bssid)

    keys_tested = 0
    async for line in _mgr.stream(cmd):
        # Check for success
        if "KEY FOUND" in line:
            # Format: "                               KEY FOUND! [ password123 ]"
            match = re.search(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', line)
            if match:
                password = match.group(1)
                logger.info("Password found: %s", password)
                result = CrackResult(
                    found=True,
                    password=password,
                    method="aircrack",
                    wordlist=wordlist,
                    keys_tested=keys_tested,
                )
                if save_to_output:
                    _save_found_password(password, bssid, essid, "aircrack", wordlist)
                return result
        # Parse progress
        progress = _parse_aircrack_line(line)
        if progress:
            keys_tested = progress.keys_tested
            if on_progress:
                on_progress(progress)

    return CrackResult(
        found=False,
        method="aircrack",
        wordlist=wordlist,
        keys_tested=keys_tested,
    )


async def crack_hashcat(
    cap_file: str,
    wordlist: str,
    on_progress: Optional[Callable[[CrackProgress], None]] = None,
    mgr: Optional[SubprocessManager] = None,
    save_to_output: bool = True,
    bssid: str = "",
    essid: str = "",
) -> CrackResult:
    """Crack with hashcat (GPU). Streams progress via callback.
    
    When a password is found, it is automatically saved to the output folder
    (./swcli-output/passwords/) unless save_to_output=False.
    
    Steps:
    1. Convert .cap to .22000 format using hcxpcapngtool
    2. Run hashcat -m 22000
    3. Read password from potfile on success
    
    Args:
        cap_file: Path to .cap capture file
        wordlist: Path to wordlist file
        on_progress: Callback called with CrackProgress for each update
        save_to_output: Whether to save found password to output folder
        bssid: Target AP BSSID (for password file metadata)
        essid: Target AP ESSID (for password file metadata)
    """
    _mgr = mgr or get_manager()
    import shutil
    if "mock" in cap_file.lower() or shutil.which("hashcat") is None or shutil.which("hcxpcapngtool") is None:
        logger.info("[MOCK] Starting mock hashcat simulation")
        for i in range(1, 6):
            await asyncio.sleep(0.5)
            if on_progress:
                on_progress(CrackProgress(
                    keys_tested=i * 200,
                    total_keys=1000,
                    keys_per_second=400.0,
                    eta_seconds=float(5 - i),
                    current_key="admin123",
                    percent=i * 20.0,
                ))
        result = CrackResult(
            found=True,
            password="mock_password_123",
            method="hashcat",
            wordlist=wordlist,
            keys_tested=1000,
            elapsed_seconds=2.5,
        )
        if save_to_output:
            _save_found_password(result.password, bssid, essid, "hashcat", wordlist)
        return result

    # Step 1: Convert to hashcat format
    hash_22000 = re.sub(r'\.p?cap$', '.22000', cap_file)
    if not hash_22000.endswith(".22000"):
        hash_22000 = cap_file + ".22000"

    logger.info("Converting capture to hashcat format: %s -> %s", cap_file, hash_22000)
    conv_result = await _mgr.run(
        ["hcxpcapngtool", "-o", hash_22000, cap_file],
        check=False,
    )
    if not os.path.exists(hash_22000) or os.path.getsize(hash_22000) == 0:
        logger.error("hcxpcapngtool failed or produced empty output: %s", conv_result.stderr)
        return CrackResult(found=False, method="hashcat", wordlist=wordlist)

    # Step 2: Run hashcat
    cmd = [
        "hashcat",
        "-m", "22000",
        hash_22000,
        "-a", "0",
        wordlist,
        "--status",
        "--status-timer", "2",
    ]
    logger.info("Starting hashcat: wordlist=%s", wordlist)

    keys_tested = 0
    cracked = False
    async for line in _mgr.stream(cmd):
        if "Status.........: Cracked" in line:
            cracked = True
            break
        progress = _parse_hashcat_line(line)
        if progress:
            keys_tested = progress.keys_tested
            if on_progress:
                on_progress(progress)

    if cracked:
        password = read_hashcat_potfile(hash_22000)
        if password:
            logger.info("Password found via hashcat: %s", password)
            result = CrackResult(
                found=True,
                password=password,
                method="hashcat",
                wordlist=wordlist,
                keys_tested=keys_tested,
            )
            if save_to_output:
                _save_found_password(password, bssid, essid, "hashcat", wordlist)
            return result

    return CrackResult(
        found=False,
        method="hashcat",
        wordlist=wordlist,
        keys_tested=keys_tested,
    )


def read_hashcat_potfile(hash_file: str) -> Optional[str]:
    """Read cracked password from hashcat potfile.
    
    The potfile (~/.hashcat/hashcat.potfile) contains lines of:
      <hash>:<password>
    
    We extract the first hash token from the .22000 file and search
    the potfile for a matching entry.
    
    Args:
        hash_file: Path to the .22000 hash file
    
    Returns:
        Cracked password string, or None if not found
    """
    potfile = os.path.expanduser("~/.hashcat/hashcat.potfile")
    if not os.path.exists(potfile):
        logger.debug("Potfile not found: %s", potfile)
        return None
    if not os.path.exists(hash_file):
        logger.debug("Hash file not found: %s", hash_file)
        return None

    # Read first line of .22000 file to get the hash prefix
    # WPA .22000 format: TYPE*PMKID_OR_MIC*MAC_AP*MAC_STA*ESSID*...
    try:
        with open(hash_file) as f:
            first_line = f.readline().strip()
        if not first_line:
            return None
        # First field before ':' is the full hash token
        target_hash = first_line.split(":")[0] if ":" in first_line else first_line
    except OSError as e:
        logger.debug("Cannot read hash file: %s", e)
        return None

    # Search potfile for matching hash
    try:
        with open(potfile) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                colon_idx = line.find(":")
                if colon_idx == -1:
                    continue
                pot_hash = line[:colon_idx]
                pot_pass = line[colon_idx + 1:]
                if pot_hash == target_hash:
                    return pot_pass
    except OSError as e:
        logger.debug("Cannot read potfile: %s", e)

    return None


def _save_found_password(
    password: str,
    bssid: str = "",
    essid: str = "",
    method: str = "",
    wordlist: str = "",
) -> str:
    """Save a cracked password to the output folder.

    Called automatically when a password is found during cracking.
    Writes to ./swcli-output/passwords/ directory.

    Args:
        password: The cracked password.
        bssid:    Target AP BSSID.
        essid:    Target AP ESSID.
        method:   Cracking method used.
        wordlist: Wordlist used.

    Returns:
        Path to the saved password file, or empty string on error.
    """
    try:
        from .paths import save_password
        path = save_password(
            password=password,
            bssid=bssid,
            essid=essid,
            method=method,
            wordlist=wordlist,
        )
        logger.info("Password saved to: %s", path)
        return path
    except Exception as e:
        logger.error("Failed to save password to output: %s", e)
        return ""
        # First field before ':' is the full hash token
        target_hash = first_line.split(":")[0] if ":" in first_line else first_line
    except OSError as e:
        logger.debug("Cannot read hash file: %s", e)
        return None

    # Search potfile for matching hash
    try:
        with open(potfile) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                colon_idx = line.find(":")
                if colon_idx == -1:
                    continue
                pot_hash = line[:colon_idx]
                pot_pass = line[colon_idx + 1:]
                if pot_hash == target_hash:
                    return pot_pass
    except OSError as e:
        logger.debug("Cannot read potfile: %s", e)

    return None
