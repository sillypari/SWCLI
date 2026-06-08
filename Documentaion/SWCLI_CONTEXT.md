# SWCLI — Comprehensive Architecture & Core Systems Context

> **Purpose:** This document provides complete context for building a CLI-based interface (`swcli`) that replaces Sidewinder's TUI. Every core module, data flow, subprocess call, and edge case is documented here.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Core Data Models](#3-core-data-models)
4. [Module-by-Module Reference](#4-module-by-module-reference)
5. [Subprocess Calls Reference](#5-subprocess-calls-reference)
6. [CLI Command Mapping](#6-cli-command-mapping)
7. [State Machine & Flows](#7-state-machine--flows)
8. [Error Handling System](#8-error-handling-system)
9. [Adapter Detection & Management](#9-adapter-detection--management)
10. [Attack Modules](#10-attack-modules)
11. [Session Persistence](#11-session-persistence)
12. [Configuration](#12-configuration)
13. [Edge Cases & Known Issues](#13-edge-cases--known-issues)

---

## 1. Project Overview

**Sidewinder** is a WiFi auditing tool that wraps the aircrack-ng suite. It bypasses `airmon-ng` entirely, using direct `iw`/`ip`/sysfs calls for monitor mode management.

**SWCLI** replaces the Textual TUI with a simple command-line interface — similar to how `airmon-ng`, `airodump-ng`, and `aireplay-ng` themselves work, but orchestrated from Python.

**Python version:** >=3.11  
**Dependencies:** `scapy>=2.5` (EAPOL validation), optionally `rich` for pretty CLI output  
**System tools required:** `airodump-ng`, `aireplay-ng`, `aircrack-ng`, `iw`, `ip`, `systemctl`

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        SWCLI (new CLI)                          │
│  argparse commands → calls core modules → prints to stdout      │
├─────────────────────────────────────────────────────────────────┤
│                         CORE LAYER                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ adapter  │  │ monitor  │  │ services │  │  subprocess  │   │
│  │ .py      │  │ .py      │  │ .py      │  │  _mgr.py     │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘   │
│       │              │              │                │           │
│  ┌────┴─────┐  ┌────┴─────┐  ┌────┴─────┐  ┌──────┴───────┐   │
│  │ scanner  │  │ capture  │  │ cracker  │  │   cleanup    │   │
│  │ .py      │  │ .py      │  │ .py      │  │   .py        │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘   │
│       │              │              │                │           │
│  ┌────┴──────────────┴──────────────┴────────────────┴───────┐  │
│  │                    session.py + config.py                  │  │
│  └───────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                      ATTACK LAYER                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ deauth   │  │ pmkid    │  │ evil_    │  │  wps         │   │
│  │ .py      │  │ .py      │  │ twin.py  │  │  .py         │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                     SYSTEM CALLS                                │
│  iw, ip, airodump-ng, aireplay-ng, aircrack-ng, hashcat,       │
│  hcxpcapngtool, systemctl, rfkill, ps, pkill                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Data Models

All dataclasses live in `sidewinder/core/session.py`.

### 3.1 Network

```python
@dataclass
class Network:
    bssid: str              # "AA:BB:CC:DD:EE:FF"
    channel: int            # 1-196
    signal: int             # dBm (-30 excellent, -90 terrible)
    privacy: str            # "WPA2", "WPA3", "WEP", "OPN"
    cipher: str             # "CCMP", "TKIP", "WEP"
    auth: str               # "PSK", "SAE", "OWE", "OPEN"
    essid: str              # Network name (empty = hidden)
    wps: bool = False
    beacons: int = 0
    data_packets: int = 0
    first_seen: str = ""    # ISO timestamp
    last_seen: str = ""     # ISO timestamp
```

**Key method:** `display_name()` → returns ESSID or `"[HIDDEN]"`

### 3.2 Client

```python
@dataclass
class Client:
    mac: str                # "AA:BB:CC:DD:EE:FF"
    bssid: str              # Associated AP BSSID
    signal: int = 0         # dBm
    packets: int = 0
    probe: str = ""         # Probe request SSID
    first_seen: str = ""
    last_seen: str = ""
```

### 3.3 HandshakeResult

```python
@dataclass
class HandshakeResult:
    status: str             # "full", "partial", "invalid"
    m1: bool = False        # EAPOL Message 1
    m2: bool = False        # EAPOL Message 2
    m3: bool = False        # EAPOL Message 3
    m4: bool = False        # EAPOL Message 4
    sha256: str = ""        # SHA-256 of capture file
    eapol_count: int = 0    # Total EAPOL frames
```

**Status values:**
- `"full"` — M1+M2+M3+M4 all captured (best)
- `"partial"` — M1+M2 captured (usable for offline crack)
- `"invalid"` — No usable handshake

### 3.4 CrackResult

```python
@dataclass
class CrackResult:
    found: bool
    password: str = ""
    method: str = ""         # "aircrack" or "hashcat"
    wordlist: str = ""
    keys_tested: int = 0
    elapsed_seconds: float = 0.0
```

### 3.5 Session

```python
@dataclass
class Session:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    adapter: str = ""
    scan_results: list[Network] = field(default_factory=list)
    clients: list[Client] = field(default_factory=list)
    selected_target: Optional[Network] = None
    captures: list[str] = field(default_factory=list)      # File paths
    handshake: Optional[HandshakeResult] = None
    cracked_passwords: list[CrackResult] = field(default_factory=list)
    logs: list[dict[str, Any]] = field(default_factory=list)
```

**Persistence:** `~/.sidewinder/session.json` (current), `~/.sidewinder/sessions/<id>.json` (archives)

### 3.6 AdapterInfo

```python
@dataclass
class AdapterInfo:
    iface: str              # "wlx5c628b765de2"
    phy: str = ""           # "phy0"
    driver: str = ""        # "rtw88_8821au"
    chipset: str = ""       # "RTL8821AU"
    name: str = ""          # "RTL8821AU"
    bus: str = ""           # "usb", "pci", "sdio"
    vid: int = 0
    pid: int = 0
    mac: str = ""
    bands: list[str]        # ["2.4G", "5G"]
    monitor_capable: bool = False
    injection_capable: bool = False
    is_up: bool = False
    current_mode: str = ""  # "managed", "monitor"
    status: str = "UNKNOWN" # "OPTIMIZED", "WORKING", "LIMITED", "EMERGENCY"
```

### 3.7 CrackProgress (runtime only)

```python
@dataclass
class CrackProgress:
    keys_tested: int = 0
    total_keys: int = 0
    keys_per_second: float = 0.0
    eta_seconds: float = 0.0
    current_key: str = ""
    percent: float = 0.0
```

---

## 4. Module-by-Module Reference

### 4.1 `subprocess_mgr.py` — Subprocess Management

**Purpose:** Robust async subprocess handling with process group isolation, streaming, and zombie prevention.

**Key class:** `SubprocessManager`

| Method | Purpose | Returns |
|--------|---------|---------|
| `run(cmd, timeout, check, env)` | Run command, wait, return result | `ProcessResult` |
| `stream(cmd, timeout, env)` | Stream stdout line-by-line | `AsyncIterator[str]` |
| `start_background(cmd, env)` | Start process in background | `Process` |
| `kill_background(proc)` | Kill a background process | `None` |
| `cleanup_all()` | Kill all tracked processes | `None` |

**ProcessResult:**
```python
@dataclass
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str
    @property
    def success(self) -> bool:  # returncode == 0
```

**Critical design:**
- All processes started with `start_new_session=True` (process group isolation)
- Kill chain: `SIGTERM` → 0.5s → `SIGKILL` (via `os.killpg`)
- Convenience wrappers: `run()` and `stream()` at module level

**Singleton:** `get_manager()` returns module-level `SubprocessManager`

---

### 4.2 `adapter.py` — Adapter Detection

**Purpose:** Detect wireless adapters via sysfs, identify chipset/driver/bands, classify capabilities.

**Key functions:**

| Function | What it does | sysfs path |
|----------|-------------|------------|
| `list_interfaces()` | List all wireless interfaces | `/sys/class/net/*/phy80211` |
| `iface_exists(iface)` | Check if interface exists | `/sys/class/net/{iface}` |
| `iface_is_up(iface)` | Check if interface is UP | `/sys/class/net/{iface}/operstate` |
| `get_phy(iface)` | Read PHY name | `/sys/class/net/{iface}/phy80211/name` |
| `get_driver(iface)` | Read driver name | `/sys/class/net/{iface}/device/driver` (symlink resolve) |
| `get_bus(iface)` | Read bus type | `/sys/class/net/{iface}/device/modalias` |
| `get_vid_pid(iface)` | Read USB VID:PID | `/sys/class/net/{iface}/device/idVendor` + `idProduct` |
| `get_mac(iface)` | Read MAC address | `/sys/class/net/{iface}/address` |
| `get_interface_mode(iface)` | Read mode | `/sys/class/net/{iface}/type` (1=managed, 803=monitor) |
| `detect_adapter(iface)` | Full detection | Combines all above + known devices registry |
| `discover_all_adapters()` | Detect all | Iterates `list_interfaces()` |
| `get_best_adapter(adapters, op)` | Select best for operation | Priority: RTL8821AU(10) > RTL8812AU(9) > RT5370(5) > MT7902(1) |

**Known devices registry:**
```python
KNOWN_DEVICES = {
    (0x148F, 0x5370): {"name": "RT5370",   "bands": ["2.4G"],        "monitor": True,  "injection": True},
    (0x148F, 0x5372): {"name": "RT5372",   "bands": ["2.4G"],        "monitor": True,  "injection": True},
    (0x148F, 0x7601): {"name": "MT7601U",  "bands": ["2.4G"],        "monitor": True,  "injection": False},
    (0x2357, 0x0120): {"name": "RTL8821AU","bands": ["2.4G", "5G"],  "monitor": True,  "injection": True},
    (0x2357, 0x011E): {"name": "RTL8821AU","bands": ["2.4G", "5G"],  "monitor": True,  "injection": True},
    (0x0BDA, 0x8812): {"name": "RTL8812AU","bands": ["2.4G", "5G"],  "monitor": True,  "injection": True},
    (0x14C3, 0x7902): {"name": "MT7902",   "bands": ["2.4G","5G","6G"],"monitor": True,"injection": False},
}
```

**Status classification:**
- `OPTIMIZED` — injection + monitor capable
- `WORKING` — monitor capable only
- `LIMITED` — unknown, checked via `iw list`
- `EMERGENCY` — MT7902/wlo1 fallback; SWCLI permits all operations, runtime success depends on driver support

---

### 4.3 `monitor.py` — Monitor Mode Management

**Purpose:** Enter/exit monitor mode using direct `iw`/`ip` calls (bypasses airmon-ng).

**Two paths:**

1. **Standard mac80211** — Creates a new monitor VIF:
   ```
   iw phy {phy} interface add {iface}mon type monitor
   ```
   Used for: RT5370, most adapters

2. **Bad driver fallback** — Changes existing interface type in-place:
   ```
   iw dev {iface} set type monitor
   iw dev {iface} set monitor otherbss
   ```
   Used for: RTL8821AU with morrownr driver

**Functions:**

| Function | System calls | Notes |
|----------|-------------|-------|
| `set_link(iface, state)` | `ip link set {iface} {up/down}` | |
| `enter_monitor_mode(iface, phy, channel)` | `ip link down` → `iw phy ... add` → `ip link up` → `iw dev set channel` → `iw dev set txpower` | Returns `{iface}mon` |
| `enter_monitor_mode_bad_driver(iface)` | `ip link down` → `iw dev set type monitor` → `iw dev set monitor otherbss` → `ip link up` | Returns same iface |
| `exit_monitor_mode(mon_iface, iface, phy)` | `iw dev {mon} del` → `iw phy ... add {iface} type station` → `ip link up` | Restores managed |
| `set_channel(iface, channel, bw)` | `iw dev {iface} set channel {ch} [HT20/HT40+/80MHz]` | |
| `lock_channel(mon_iface, channel)` | `iw dev set channel` → `iw dev info` verify | Returns bool |
| `set_power_save(iface, enable)` | `iw dev {iface} set power_save on/off` | |
| `get_interface_mode_sync(iface)` | Reads `/sys/class/net/{iface}/type` | Returns "monitor"/"managed"/"unknown" |

**MonitorWatcher:** Background async task that polls sysfs every 2s to detect if monitor mode is lost. Yields events but never auto-fixes.

---

### 4.4 `services.py` — Service Management

**Purpose:** Kill conflicting WiFi services (NetworkManager, wpa_supplicant, etc.) and restore them after audit.

**Conflicting services:**
```python
CONFLICTING_SERVICES = [
    "NetworkManager", "wpa_supplicant", "wpa_cli",
    "dhclient", "dhcpcd", "avahi-daemon", "avahi-autoipd", "iwd",
]
```

**KillResult:**
```python
@dataclass
class KillResult:
    killed: list[KilledProcess]    # Successfully killed
    skipped: list[str]             # Duplicates
    errors: list[str]              # Failures
```

**KillProcess record:**
```python
@dataclass
class KilledProcess:
    name: str
    pid: int
    was_systemd: bool = False
```

**ServiceManager methods:**

| Method | What it does |
|--------|-------------|
| `find_conflicting()` | Runs `ps -A -o pid=,args=`, matches against CONFLICTING_SERVICES |
| `kill_conflicting()` | `systemctl stop` → `os.killpg(SIGKILL)` → track for restore |
| `restore()` | Reverse order, `systemctl start` → poll `is-active` every 0.5s (15s max) |
| `kill_process_by_name(name)` | `pkill -9 -f {name}` |

**Singleton:** `get_service_manager()`

---

### 4.5 `scanner.py` — WiFi Scanner

**Purpose:** Run airodump-ng, parse CSV output, emit discovered networks/clients in real-time.

**Parser state machine:**
```
IDLE → detect "BSSID" line → AP_HEADER
AP_HEADER → blank line → AP_DATA
AP_DATA → parse each line → Network
AP_DATA → detect "BSSID STATION" → CLIENT_HEADER
CLIENT_HEADER → blank line → CLIENT_DATA
CLIENT_DATA → parse each line → Client
```

**AirodumpParser:**
- `feed(line)` → returns `Network`, `Client`, or `None`
- `reset()` → resets parser state for reuse across cycles (no alloc per cycle)
- Stateful: tracks `ParseState` but does NOT store data (stores in ScanEngine)

**AP line format (CSV):**
```
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
```

**Client line format (CSV):**
```
Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
```

**ScanEngine:**

| Method | Purpose |
|--------|---------|
| `scan(mon_iface, prefix, band, channels, update_secs, hop_ms, write_interval_secs, poll_ms, on_network, on_client)` | Start scanning with configurable timing |
| `stop()` | Set `_running = False` |
| `stop_and_wait()` | Stop + kill background process |
| `get_networks()` | Return sorted by signal (strongest first) |
| `get_clients(bssid=None)` | Return clients, optionally filtered by AP |
| `get_stats()` | Return memory management stats |

**Configurable timing (passed to airodump-ng):**

| Param | Default | airodump-ng flag |
|-------|---------|-----------------|
| `update_secs` | 0.1 | `--update` |
| `hop_ms` | 250 | `-f` |
| `write_interval_secs` | 0 | `--write-interval` |
| `poll_ms` | 100 | — (Python CSV poll) |

**Memory management:**
- Max 500 networks (evicts weakest signal when full)
- Max 1000 clients (evicts oldest last_seen when full)
- Stale eviction: removes entries not seen for >120s (every ~10 cycles)
- Dedup callbacks: only fires on first seen or changed data (signal/channel/beacons/essid)
- Reuses `AirodumpParser` across cycles (no new dict per poll)
- Line-by-line CSV read (no full file load)

**Mock mode:** If `mon_iface` contains "MOCK", returns simulated data without running airodump-ng.

---

### 4.6 `capture.py` — Handshake Capture

**Purpose:** Capture WPA handshakes via passive listening or active deauth.

**IEEE 802.11-2020 EAPOL key_info bitmasks:**
```python
KEY_INFO_PAIRWISE = 0x0008   # Bit 3
KEY_INFO_INSTALL  = 0x0040   # Bit 6
KEY_INFO_ACK      = 0x0080   # Bit 7
KEY_INFO_MIC      = 0x0100   # Bit 8
KEY_INFO_SECURE   = 0x0200   # Bit 9
```

**Message classification:**
```
M1: Pairwise=1, Install=0, ACK=1, MIC=0, Secure=0
M2: Pairwise=1, Install=0, ACK=0, MIC=1, Secure=0
M3: Pairwise=1, Install=1, ACK=1, MIC=1, Secure=1
M4: Pairwise=1, Install=0, ACK=0, MIC=1, Secure=1
```

**Functions:**

| Function | Purpose |
|----------|---------|
| `validate_handshake(cap_file)` | Read .cap with scapy, classify M1-M4, return `HandshakeResult` |
| `poll_eapol(pcap_file, bssid, timeout, poll_interval, on_progress)` | Separate async task polling PCAP for EAPOL frames |
| `capture_passive(mon_iface, bssid, channel, output_prefix, timeout)` | Start airodump-ng + EAPOL poll task |
| `capture_deauth(mon_iface, bssid, client, channel, output_prefix, count, timeout)` | Passive capture + send deauth frames via aireplay-ng |

**Critical design decisions:**
1. EAPOL detection does NOT happen via airodump-ng stdout — must poll PCAP file with scapy
2. `poll_eapol()` runs as SEPARATE asyncio task from capture loop
3. `capture_deauth()` takes channel as explicit parameter (never looked up dynamically)

**Passive capture command:**
```
airodump-ng {iface} --bssid {bssid} --channel {ch} --write {prefix} --output-format pcap --write-interval 1
```

**Deauth capture command:**
```
aireplay-ng --deauth {count} -a {bssid} -c {client} {iface}
```

---

### 4.7 `cracker.py` — Password Cracking

**Purpose:** Crack captured WPA handshakes with aircrack-ng (CPU) or hashcat (GPU).

**Aircrack-ng:**
- Password in stdout: `KEY FOUND! [ password123 ]`
- Progress: `1234 keys tested (5678.90 k/s)`
- Command: `aircrack-ng -w {wordlist} -b {bssid} {cap_file}`

**Hashcat:**
- Password in potfile ONLY (not stdout)
- Steps: `.cap` → `hcxpcapngtool -o {hash_file} {cap_file}` → `hashcat -m 22000 {hash_file} -a 0 {wordlist} --status --status-timer 2`
- Potfile: `~/.hashcat/hashcat.potfile` (format: `<hash>:<password>`)

**Wordlist auto-discovery:**
```python
WORDLIST_SEARCH_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/opt/wordlists/rockyou.txt",
    "/root/wordlists/rockyou.txt",
    "/home/kali/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
]
```

**crack_aircrack():** Streams aircrack-ng output, parses progress, detects "KEY FOUND"
**crack_hashcat():** Converts to .22000, runs hashcat, reads potfile on success

---

### 4.8 `cleanup.py` — System Cleanup

**Purpose:** Restore system to pre-attack state after audit.

**Cleanup steps:**
1. Kill attack processes (`airodump-ng`, `aireplay-ng`, `hashcat`, `aircrack-ng`)
2. Exit monitor mode (delete VIF, restore managed)
3. Restore killed services (NetworkManager, etc.)
4. Verify connectivity (`ip addr show {iface}` has `inet `)

**CleanupManager methods:**

| Method | Purpose |
|--------|---------|
| `register(mon_iface, iface, phy)` | Store for cleanup on signal |
| `full_cleanup(mon_iface, iface, phy)` | Execute all cleanup steps, return connectivity bool |
| `cleanup_files(extra_patterns, dry_run)` | Delete `/tmp/sidewinder_*` files |
| `install_signal_handlers(loop)` | SIGINT/SIGTERM → auto cleanup |

**Singleton:** `get_cleanup_manager()`

---

### 4.9 `errors.py` — Error Classification

**Purpose:** Structured error handling with What/Why/HowToFix.

**Severity levels:** `INFO`, `WARNING`, `ERROR`, `CRITICAL`
**Categories:** `HARDWARE`, `PROCESS`, `NETWORK`, `PERMISSION`, `RESOURCE`, `USER`

**SidewinderError:**
```python
@dataclass
class SidewinderError(Exception):
    severity: Severity
    category: Category
    what: str
    why: str
    how_to_fix: list[str]
    raw_error: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
```

**Error database (ERROR_DB):** 16+ predefined errors:
- `ADAPTER_NOT_FOUND`, `MONITOR_MODE_FAILED`, `ROOT_REQUIRED`, `DISK_FULL`
- `NO_HANDSHAKE`, `AIRODUMP_FAILED`, `AIRODUMP_STUCK`, `AIREPLAY_FAILED`
- `RFKILL_BLOCKED`, `ADAPTER_DISCONNECTED`, `WRONG_DRIVER`, `MT7902_INJECTION_RUNTIME_RISK`
- `WORDLIST_NOT_FOUND`, `CRACK_NO_RESULT`, `WPS_LOCKED`, `PMKID_TIMEOUT`
- `VM_DETECTED`, `PCAP_CORRUPTED`, `EVIL_TWIN_DHCP_FAILED`

**Per-chipset errors (ADAPTER_ERRORS):** RT5370, RTL8821AU, MT7902 specific errors

---

### 4.10 `config.py` — Configuration

**Path:** `~/.sidewinder/config.json`

```python
@dataclass
class SidewinderConfig:
    capture_dir: str = "~/.sidewinder/captures"
    wordlist_dir: str = "~/.sidewinder/wordlists"
    results_dir: str = "~/.sidewinder/results"
    default_wordlist: str = "/usr/share/wordlists/rockyou.txt"
    default_channel: int = 1
    default_deauth_count: int = 10
    capture_timeout_seconds: float = 300.0
    deauth_cooldown_seconds: float = 10.0
    regulatory_domain: str = "00"    # "00" = global
    mac_randomization: bool = False
    theme: str = "midnight"
```

**Key functions:**
- `SidewinderConfig.load(path)` → loads from JSON, creates defaults if missing
- `SidewinderConfig.save(path)` → writes to JSON
- `expand_user_path(path)` → expands `~` using SUDO_USER if available
- `get_home_dir()` → respects `SUDO_USER` env var

---

### 4.11 `intelligence.py` — Attack Recommendations

**Purpose:** Evaluates targets and recommends attacks (does NOT auto-execute).

**IntelligenceEngine.evaluate_target(target, clients):**
- Returns `list[Recommendation]` sorted by confidence (highest first)
- Checks: active clients → WPS → signal strength

**Recommendation:**
```python
@dataclass
class Recommendation:
    method: str        # "deauth_active", "deauth_broadcast", "pmkid", "wps_pixiedust"
    confidence: int    # 0-100
    reason: str
    warnings: list[str]
```

---

### 4.12 `fingerprint.py` — Client Fingerprinting

**Purpose:** MAC OUI lookup + basic OS detection.

**Fingerprinter:**
- Looks up OUI from `~/.sidewinder/oui.db` (SQLite)
- Heuristic OS detection based on vendor name:
  - Apple → iOS/macOS
  - Samsung/Huawei/Xiaomi → Android
  - Intel/Realtek/Qualcomm → Windows/Linux
  - Espressif/Tuya → IoT

---

### 4.13 `attack.py` — Attack Base Classes

```python
class AttackState(Enum):
    PENDING = "pending"
    INITIALIZING = "initializing"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class AttackConfig:
    target_bssid: str
    channel: int
    timeout: float = 300.0

@dataclass
class AttackResult:
    success: bool
    errors: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

class BaseAttackEngine:
    state: AttackState
    set_progress_callback(callback)
    async start(config, **kwargs) -> AttackResult
    async stop()
    is_running() -> bool
```

---

### 4.14 `adapters/__init__.py` — AdapterManager

**AdapterManager:**
- `discover()` → find all adapters, store in dict
- `get_best_for_operation(operation)` → select best for "scan"/"capture"/"deauth"/"inject"/"internet"
- `get_internet_adapter()` → MT7902 preferred
- `get_all()` → sorted by priority
- `refresh(iface)` → re-detect single interface

**FailoverManager:**
- `setup(operation)` → set primary + backup adapter
- `execute_with_failover(func, *args)` → try primary, fallback to backup on failure

---

### 4.15 Adapter Implementations

**RT5370 (`rt5370.py`):** Standard mac80211 path, creates `{iface}mon` VIF
**RTL8821AU (`rtl8821au.py`):** May need morrownr driver, uses bad driver fallback
**MT7902 (`mt7902.py`):** EMERGENCY — SWCLI permits all operations; injection/deauth/evil-twin may still fail at runtime if the driver refuses them

---

## 5. Subprocess Calls Reference

Every system call Sidewinder makes:

| Operation | Command | When |
|-----------|---------|------|
| List interfaces | Read `/sys/class/net/*/phy80211` | Adapter detection |
| Check interface mode | Read `/sys/class/net/{iface}/type` | Mode check |
| Bring interface up/down | `ip link set {iface} up/down` | Monitor enter/exit |
| Create monitor VIF | `iw phy {phy} interface add {iface}mon type monitor` | Enter monitor |
| Delete monitor VIF | `iw dev {mon_iface} del` | Exit monitor |
| Set channel | `iw dev {iface} set channel {ch} [bw]` | Capture/scan |
| Set TX power | `iw dev {iface} set txpower fixed 3000` | Enter monitor |
| Set power save | `iw dev {iface} set power_save on/off` | Optional |
| Check monitor via iw | `iw list` | Unknown adapter |
| Set monitor type | `iw dev {iface} set type monitor` | Bad driver path |
| Set monitor flags | `iw dev {iface} set monitor otherbss` | Bad driver path |
| Recreate managed | `iw phy {phy} interface add {iface} type station` | Exit monitor |
| Verify channel | `iw dev {iface} info` | Channel lock |
| Find conflicting | `ps -A -o pid=,args=` | Service check |
| Kill service (graceful) | `systemctl stop {name}` | Service kill |
| Check service active | `systemctl is-active {name}` | Service restore |
| Kill service (force) | `os.killpg(pgid, SIGKILL)` | Service kill |
| Kill by name | `pkill -9 -f {name}` | Cleanup |
| Scan WiFi | `airodump-ng {iface} --write {prefix} --output-format csv -a --wps [--band {band}] [--channel {ch}]` | Scan |
| Capture handshake | `airodump-ng {iface} --bssid {bssid} --channel {ch} --write {prefix} --output-format pcap --write-interval 1` | Capture |
| Send deauth | `aireplay-ng --deauth {count} -a {bssid} -c {client} {iface}` | Deauth attack |
| Crack (CPU) | `aircrack-ng -w {wordlist} -b {bssid} {cap_file}` | Crack |
| Convert for hashcat | `hcxpcapngtool -o {hash_file} {cap_file}` | Crack |
| Crack (GPU) | `hashcat -m 22000 {hash_file} -a 0 {wordlist} --status --status-timer 2` | Crack |
| Check disk space | `df -h` | Error diagnostics |
| Kill attack procs | `pkill -9 -f airodump-ng` + `pkill -9 -f aireplay-ng` + etc. | Cleanup |
| Check connectivity | `ip addr show {iface}` | Cleanup verify |
| Detect MT7902 | `lspci -nn` | Adapter detection |

---

## 6. CLI Command Mapping

Suggested SWCLI commands mapping to core functions:

```
swcli adapters                           → discover_all_adapters()
swcli monitor start <iface>              → enter_monitor_mode(iface, phy, channel)
swcli monitor stop <mon> <iface> <phy>   → exit_monitor_mode(mon, iface, phy)
swcli monitor status <iface>             → get_interface_mode_sync(iface)
swcli scan [options]                     → ScanEngine.scan()
swcli scan stop                          → ScanEngine.stop()
swcli scan results                       → ScanEngine.get_networks() + get_clients()
swcli services kill                      → ServiceManager.kill_conflicting()
swcli services restore                   → ServiceManager.restore()
swcli capture passive <iface> <bssid> <ch> → capture_passive()
swcli capture deauth <iface> <bssid> <client> <ch> → capture_deauth()
swcli capture validate <cap_file>        → validate_handshake()
swcli crack aircrack <cap> <bssid> <wl>  → crack_aircrack()
swcli crack hashcat <cap> <wl>           → crack_hashcat()
swcli crack wordlists                    → find_wordlists()
swcli analyze <target> <clients>         → IntelligenceEngine.evaluate_target()
swcli cleanup [--full]                   → CleanupManager.full_cleanup()
swcli session save/load/list             → Session operations
swcli config show/set                    → SidewinderConfig operations
```

---

## 7. State Machine & Flows

### 7.1 Full Audit Flow

```
1. Root check
2. Detect adapters → pick best
3. Kill conflicting services
4. Enter monitor mode
5. Scan for networks
6. User selects target
7. Choose capture method (passive/deauth)
8. Capture handshake (polls EAPOL via scapy)
9. Validate handshake (M1-M4)
10. Pick wordlist
11. Crack with aircrack-ng or hashcat
12. Display result
13. Cleanup (restore services, exit monitor, delete temp files)
```

### 7.2 Monitor Mode Entry

```
ip link set {iface} down
iw phy {phy} interface add {iface}mon type monitor
ip link set {iface}mon up
iw dev {iface}mon set channel {ch}
iw dev {iface}mon set txpower fixed 3000
verify: read /sys/class/net/{iface}mon/type == 803
```

### 7.3 Monitor Mode Exit

```
iw dev {mon_iface} del
iw phy {phy} interface add {iface} type station
ip link set {iface} up
```

### 7.4 Capture Flow

```
airodump-ng --bssid {bssid} --channel {ch} --write {prefix} --output-format pcap --write-interval 1 {mon_iface}
    ↓ (separate task)
poll_eapol({prefix}-01.cap, bssid, timeout=300)
    ↓ (every 2s)
scapy PcapReader → check EAPOL key_info bits → classify M1-M4
    ↓
if M1+M2+M3+M4 → status="full" → return
if M1+M2 → status="partial" → return (usable)
timeout → return None
```

---

## 8. Error Handling System

Every `SidewinderError` has:
- `severity` — INFO/WARNING/ERROR/CRITICAL
- `category` — HARDWARE/PROCESS/NETWORK/PERMISSION/RESOURCE/USER
- `what` — One-line description
- `why` — Root cause
- `how_to_fix` — Ordered steps
- `raw_error` — Optional debug string

**Usage pattern:**
```python
from sidewinder.core.errors import ERROR_DB, SidewinderError

# Raise predefined error
raise ERROR_DB["NO_HANDSHAKE"]

# Raise with custom raw error
err = ERROR_DB["AIRODUMP_FAILED"]
err.raw_error = stderr_output
raise err
```

---

## 9. Adapter Detection & Management

### 9.1 Detection Priority

```
RTL8821AU (10) > RTL8812AU (9) > RT5370 (5) > MT7601U (3) > MT7902 (1)
```

### 9.2 Operation Support Matrix

| Adapter | Scan | Capture | Deauth | Inject | Evil Twin |
|---------|------|---------|--------|--------|-----------|
| RT5370 | ✓ | ✓ | ✓ | ✓ | ✗ |
| RTL8821AU | ✓ | ✓ | ✓ | ✓ | ✓ |
| MT7902 | ✓ | ✗ | ✗ | ✗ | ✗ |

### 9.3 Card Settings Matrix

```python
CARD_SETTINGS = {
    "RT5370": {
        "scan":    {"mode": "managed",  "power_save": "auto"},
        "capture": {"mode": "monitor",  "power_save": "off", "htmcs": "0",  "rate": "OFDM"},
        "deauth":  {"mode": "monitor",  "power_save": "off", "rate": "CCK", "count": 10},
        "inject":  {"mode": "monitor",  "power_save": "off", "rate": "OFDM", "mcs": "0"},
    },
    "RTL8821AU": {
        "scan":       {"mode": "managed", "power_save": "auto"},
        "capture":    {"mode": "monitor", "flags": "fcsfail otherbss", "band": "auto"},
        "deauth":     {"mode": "monitor", "flags": "fcsfail otherbss", "count": 10},
        "inject":     {"mode": "monitor", "flags": "fcsfail otherbss", "rate": "auto"},
        "evil_twin":  {"mode": "monitor+AP", "channel": "target"},
    },
    "MT7902": {
        "scan":    {"mode": "managed"},
        "capture": None,  # Not supported
        "deauth":  None,
        "inject":  None,
    },
}
```

---

## 10. Attack Modules

### 10.1 Deauth Attack (`deauth.py`)

**Flow:**
1. Validate adapter supports injection via `check_adapter_allowed()`
2. Start passive capture task
3. Wait 1s for capture to initialize
4. Send deauth bursts via `aireplay-ng --deauth`
5. Cooldown between bursts
6. Wait for EAPOL capture
7. Return `DeauthResult` with handshake + stats

**DeauthConfig:**
```python
bssid, client="FF:FF:FF:FF:FF:FF", channel=6, count=10, bursts=3, cooldown=10.0, timeout=300.0
```

**DeauthResult:**
```python
handshake: Optional[HandshakeResult], deauths_sent: int, bursts_sent: int, errors: list[str]
```

### 10.2 PMKID Attack (`pmkid.py`)
- Uses `hcxdumptool` to capture PMKID directly from AP
- No clients required
- Only works on APs with 802.11r roaming enabled

### 10.3 Evil Twin (`evil_twin.py`)
- Creates rogue AP mimicking target SSID
- Requires secondary adapter for internet passthrough
- Uses `dnsmasq` for DHCP

### 10.4 WPS Attack (`wps.py`)
- Pixie-Dust or PIN bruteforce via `reaver`/`bully`
- WPS may lock after failed attempts

---

## 11. Session Persistence

**Save path:** `~/.sidewinder/session.json`
**Archive path:** `~/.sidewinder/sessions/{uuid}.json`

**Session.save():**
1. Converts to dict via `dataclasses.asdict()`
2. Writes to `session.json`
3. Archives to `sessions/{id}.json`

**Session.load():**
1. Reads JSON
2. Manually reconstructs nested dataclasses:
   - `scan_results` → `[Network(**n) for n in data["scan_results"]]`
   - `clients` → `[Client(**c) for c in data["clients"]]`
   - `selected_target` → `Network(**data["selected_target"])` or None
   - `handshake` → `HandshakeResult(**data["handshake"])` or None
   - `cracked_passwords` → `[CrackResult(**c) for c in data["cracked_passwords"]]`
3. Returns `Session(**data)`

---

## 12. Configuration

**Path:** `~/.sidewinder/config.json`

**Auto-created on first run with defaults:**
```json
{
    "capture_dir": "~/.sidewinder/captures",
    "wordlist_dir": "~/.sidewinder/wordlists",
    "results_dir": "~/.sidewinder/results",
    "default_wordlist": "/usr/share/wordlists/rockyou.txt",
    "default_channel": 1,
    "default_deauth_count": 10,
    "capture_timeout_seconds": 300.0,
    "deauth_cooldown_seconds": 10.0,
    "regulatory_domain": "00",
    "mac_randomization": false,
    "theme": "midnight"
}
```

**expand_user_path():** Handles `~` expansion with `SUDO_USER` awareness.

---

## 13. Edge Cases & Known Issues

### 13.1 Mock Mode
Any interface containing "MOCK" in its name triggers simulated behavior — no real airodump-ng/aireplay-ng calls. Useful for CLI development.

### 13.2 EAPOL Detection
- airodump-ng stdout does NOT contain EAPOL data — it prints screen refreshes
- EAPOL detection MUST poll the PCAP file with scapy
- `poll_eapol()` uses `PcapReader` with incremental reads (seeks to end each cycle)

### 13.3 Service Restore
- Services restored in REVERSE kill order (wpa_supplicant before NetworkManager)
- Each service polled with `systemctl is-active` every 0.5s for 15s max

### 13.4 Process Cleanup
- All processes use `start_new_session=True` → process group isolation
- Kill chain: `SIGTERM` → 0.5s → `SIGKILL` via `os.killpg()`
- `cleanup_all()` kills all tracked processes on shutdown

### 13.5 MT7902 Protection
- `check_adapter_allowed("MT7902", "deauth")` → raises `SidewinderError` with actionable message
- MT7902 is NEVER used for attack operations — only internet

### 13.6 Session Load Bug
- `json.load()` returns plain dicts for nested objects
- Manual deserialization required for `Network`, `Client`, `HandshakeResult`, `CrackResult`

### 13.7 iwpriv Deprecation
- `iwpriv` removed from modern kernels (deprecated since 5.x)
- Power save control uses `iw dev {iface} set power_save off` instead

### 13.8 Regulatory Domain
- Default `"00"` = global/world
- Can be set to `"US"`, `"GB"`, etc. in config
- Hardcoding `"BO"` (Bolivia) to unlock all channels is NOT recommended

---

## Appendix: File Structure

```
sidewinder/
├── __init__.py
├── __main__.py
├── cli.py                    # Current TUI entry point (to be replaced)
├── adapters/
│   ├── __init__.py           # AdapterManager, FailoverManager
│   ├── base.py               # Adapter ABC, CARD_SETTINGS
│   ├── rt5370.py             # RT5370 adapter
│   ├── rtl8821au.py          # RTL8821AU adapter
│   └── mt7902.py             # MT7902 adapter (protection)
├── attacks/
│   ├── __init__.py           # Exports
│   ├── deauth.py             # DeauthConfig, DeauthResult, run_deauth
│   ├── evil_twin.py          # EvilTwinEngine
│   ├── pmkid.py              # PMKIDEngine
│   └── wps.py                # WPSEngine
├── core/
│   ├── __init__.py
│   ├── adapter.py            # AdapterInfo, detect, discover
│   ├── attack.py             # BaseAttackEngine, AttackConfig, AttackResult
│   ├── capture.py            # capture_passive, capture_deauth, poll_eapol, validate_handshake
│   ├── cleanup.py            # CleanupManager
│   ├── config.py             # SidewinderConfig
│   ├── cracker.py            # crack_aircrack, crack_hashcat
│   ├── errors.py             # SidewinderError, ERROR_DB, ADAPTER_ERRORS
│   ├── fingerprint.py        # Fingerprinter (OUI lookup)
│   ├── intelligence.py       # IntelligenceEngine (attack recommendations)
│   ├── logger.py             # Rotating file logger
│   ├── monitor.py            # enter/exit monitor mode
│   ├── scanner.py            # ScanEngine, AirodumpParser
│   ├── services.py           # ServiceManager
│   ├── session.py            # Session, Network, Client, HandshakeResult, CrackResult
│   ├── subprocess_mgr.py     # SubprocessManager
│   └── tooltips.py           # Tooltip database
└── ui/                       # TUI layer (to be replaced by SWCLI)
```
