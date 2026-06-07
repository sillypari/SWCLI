"""Sidewinder Session Management.

Save and resume audit sessions across restarts.
Handles nested dataclass deserialization correctly.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class Network:
    """Scanned WiFi network.

    Attributes:
        bssid:          Access point MAC address.
        channel:        Operating channel number.
        signal:         RSSI signal strength in dBm.
        privacy:        Encryption type string (e.g. 'WPA2').
        cipher:         Cipher suite (e.g. 'CCMP').
        auth:           Authentication method (e.g. 'PSK').
        essid:          Network name (may be empty for hidden networks).
        wps:            Whether WPS is advertised.
        beacons:        Beacon frame count seen.
        data_packets:   Data packet count seen.
        first_seen:     ISO timestamp of first observation.
        last_seen:      ISO timestamp of most recent observation.
    """

    bssid: str
    channel: int
    signal: int
    privacy: str
    cipher: str
    auth: str
    essid: str
    speed: int = 0
    wps: bool = False
    beacons: int = 0
    data_packets: int = 0
    data_per_sec: int = 0
    manuf: str = ""
    he: bool = False
    first_seen: int = 0
    last_seen: int = 0

    def display_name(self) -> str:
        """Return ESSID or [HIDDEN] if empty."""
        return self.essid if self.essid.strip() else "[HIDDEN]"


@dataclass
class Client:
    """WiFi client connected to an AP.

    Attributes:
        mac:        Client MAC address.
        bssid:      Associated AP BSSID.
        signal:     RSSI signal strength in dBm.
        packets:    Number of data packets observed.
        probe:      Probe request SSID (if any).
        first_seen: ISO timestamp of first observation.
        last_seen:  ISO timestamp of most recent observation.
    """

    mac: str
    bssid: str
    signal: int = 0
    packets: int = 0
    probe: str = ""
    manuf: str = ""
    eapol: bool = False
    assoc_req: int = 0
    probe_req: int = 0
    deauth: int = 0
    first_seen: int = 0
    last_seen: int = 0


@dataclass
class HandshakeResult:
    """Result of EAPOL handshake validation.

    Attributes:
        status:      Overall status: 'full', 'partial', or 'invalid'.
        m1:          Whether EAPOL message 1 was captured.
        m2:          Whether EAPOL message 2 was captured.
        m3:          Whether EAPOL message 3 was captured.
        m4:          Whether EAPOL message 4 was captured.
        sha256:      SHA-256 hash of the captured capture file.
        eapol_count: Total number of EAPOL frames captured.
    """

    status: str          # "full", "partial", "invalid"
    m1: bool = False
    m2: bool = False
    m3: bool = False
    m4: bool = False
    sha256: str = ""
    eapol_count: int = 0


@dataclass
class CrackResult:
    """Result of a password crack attempt.

    Attributes:
        found:           Whether the password was successfully recovered.
        password:        Recovered plaintext password (empty if not found).
        method:          Cracking tool used: 'aircrack' or 'hashcat'.
        wordlist:        Path to the wordlist used.
        keys_tested:     Number of candidate passwords tested.
        elapsed_seconds: Wall-clock time taken for the crack attempt.
    """

    found: bool
    password: str = ""
    method: str = ""      # "aircrack" or "hashcat"
    wordlist: str = ""
    keys_tested: int = 0
    elapsed_seconds: float = 0.0


@dataclass
class Session:
    """Full audit session — saveable and resumable.

    A Session aggregates every piece of state produced during a Sidewinder
    audit: the adapter used, discovered networks, captured clients, handshake
    validation results, crack results, and a structured event log.

    Attributes:
        id:                Unique session UUID (auto-generated).
        start_time:        ISO timestamp when the session was created.
        adapter:           Interface name of the WiFi adapter in use.
        scan_results:      List of networks discovered during scanning.
        clients:           List of clients observed during scanning.
        selected_target:   The network chosen for capture/crack.
        captures:          List of file paths to captured .cap files.
        handshake:         Result of the most recent handshake validation.
        cracked_passwords: All crack attempts and their results.
        logs:              Timestamped event log entries.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    adapter: str = ""
    scan_results: list[Network] = field(default_factory=list)
    clients: list[Client] = field(default_factory=list)
    selected_target: Optional[Network] = None
    captures: list[str] = field(default_factory=list)
    handshake: Optional[HandshakeResult] = None
    cracked_passwords: list[CrackResult] = field(default_factory=list)
    logs: list[dict[str, Any]] = field(default_factory=list)

    DEFAULT_PATH: str = "~/.sidewinder/session.json"

    def save(self, path: str = "") -> str:
        """Save session to a JSON file and return the path written.

        Creates parent directories if they do not already exist.

        Args:
            path: Optional override path.  Defaults to DEFAULT_PATH.

        Returns:
            Absolute path of the file that was written.
        """
        from .config import expand_user_path
        save_path = expand_user_path(path or self.DEFAULT_PATH)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "w") as f:
            json.dump(asdict(self), f, indent=2, default=str)
        
        try:
            archive_dir = expand_user_path("~/.sidewinder/sessions")
            os.makedirs(archive_dir, exist_ok=True)
            archive_path = os.path.join(archive_dir, f"{self.id}.json")
            with open(archive_path, "w") as f:
                json.dump(asdict(self), f, indent=2, default=str)
        except Exception:
            pass

        return save_path

    @classmethod
    def load(cls, path: str = "") -> Optional["Session"]:
        """Load a session from a JSON file with proper nested deserialization.

        ``json.load()`` returns plain ``dict`` objects for nested dataclasses.
        This method manually reconstructs each nested type so callers always
        receive properly typed objects.

        Note:
            An alternative to manual reconstruction is the ``dacite`` library
            (``pip install dacite``), which handles nested type resolution
            automatically.

        Args:
            path: Optional override path.  Defaults to DEFAULT_PATH.

        Returns:
            A fully populated Session, or None if the file does not exist.
        """
        from .config import expand_user_path
        load_path = expand_user_path(path or cls.DEFAULT_PATH)
        if not os.path.exists(load_path):
            return None

        with open(load_path) as f:
            data = json.load(f)

        # Deserialize nested dataclasses manually
        data["scan_results"] = [
            Network(**n) for n in data.get("scan_results", [])
        ]
        data["clients"] = [
            Client(**c) for c in data.get("clients", [])
        ]
        if data.get("selected_target"):
            data["selected_target"] = Network(**data["selected_target"])
        else:
            data["selected_target"] = None
        if data.get("handshake"):
            data["handshake"] = HandshakeResult(**data["handshake"])
        else:
            data["handshake"] = None
        data["cracked_passwords"] = [
            CrackResult(**c) for c in data.get("cracked_passwords", [])
        ]

        # DEFAULT_PATH is a class variable, not an instance field — remove it
        # from the dict so we do not accidentally pass it to __init__.
        data.pop("DEFAULT_PATH", None)

        return cls(**data)

    def log(self, event: str, **kwargs: Any) -> None:
        """Append a timestamped log entry to this session.

        Args:
            event:   Short description of the event (e.g. 'scan_started').
            **kwargs: Additional key-value metadata to include in the entry.
        """
        entry: dict[str, Any] = {
            "time": datetime.now().isoformat(),
            "event": event,
        }
        entry.update(kwargs)
        self.logs.append(entry)

    def elapsed_seconds(self) -> float:
        """Return total elapsed seconds since the session started.

        Returns:
            Floating-point number of seconds since ``start_time``.
        """
        start = datetime.fromisoformat(self.start_time)
        return (datetime.now() - start).total_seconds()
