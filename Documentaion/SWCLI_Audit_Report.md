# SWCLI Architecture & Audit Report

---

## 1. Executive Summary

SWCLI is a WiFi auditing CLI tool wrapping the aircrack-ng suite. This report documents the current architecture, how core components work, bugs discovered, and fixes applied.

**Key Finding:** The scanner **does use airodump-ng** for channel hopping and discovery — it does not implement native channel hopping via the WiFi chip directly.

---

## 2. System Architecture

### 2.1 Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        SWCLI (CLI/REPL)                         │
│  REPL: Interactive Command Palette (/)                          │
│  CLI:  Direct argparse commands                                 │
├─────────────────────────────────────────────────────────────────┤
│                         CORE LAYER                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ adapter  │  │ monitor  │  │ services │  │  subprocess  │   │
│  │ .py      │  │ .py      │  │ .py      │  │  _mgr.py     │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ scanner  │  │ capture  │  │ cracker  │  │   cleanup    │   │
│  │ .py      │  │ .py      │  │ .py      │  │   .py        │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
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

### 2.2 Audit Workflow

```
1. Preflight     → root check, deps check, rfkill check
2. Hardware      → detect adapters, kill conflicting services
3. Monitor Mode  → enter monitor mode on best adapter
4. Scan          → airodump-ng discovers APs + clients
5. Select Target → user picks BSSID from scan results
6. Capture       → passive listen or deauth to force handshake
7. Validate      → check EAPOL M1-M4 in .cap file
8. Crack         → aircrack-ng (CPU) or hashcat (GPU) with wordlist
9. Result        → display cracked password
10. Cleanup      → exit monitor, restore services, delete temp files
```

---

## 3. Component Deep Dive

### 3.1 Monitor Mode (`sidewinder/core/monitor.py`)

**Two paths for entering monitor mode:**

| Path | Command | Interface Name | Use Case |
|------|---------|----------------|----------|
| **Standard** | `iw phy {phy} interface add {iface}mon type monitor` | `{iface}mon` | Most drivers (RT5370, RTL8821AU) |
| **Bad Driver** | `iw dev {iface} set type monitor` | Same `{iface}` | mt7601u, RTL8821AU morrownr |

**Standard mac80211 path:**
```
1. ip link set {iface} down
2. iw phy {phy} interface add {iface}mon type monitor
3. ip link set {iface}mon up
4. iw dev {iface}mon set channel {ch}
5. iw dev {iface}mon set txpower fixed 3000
```

**Bad driver path:**
```
1. ip link set {iface} down
2. iw dev {iface} set type monitor
3. iw dev {iface} set monitor otherbss
4. ip link set {iface} up
5. iw dev {iface} set channel {ch}
```

**Key difference:** Standard path creates a new virtual interface. Bad driver path changes the existing interface in-place.

### 3.2 Scanning (`sidewinder/core/scanner.py`)

**Confirmed: Scanner uses airodump-ng**

The scan engine runs `airodump-ng` as a background process:
```python
cmd = [
    "airodump-ng",
    mon_iface,
    "--write", capture_prefix,
    "--output-format", "csv",
    "-a",     # Only show associated clients
    "--wps",  # Show WPS status
]
```

**How it works:**
1. Launches `airodump-ng` with `--output-format csv`
2. Polls the CSV file every 1 second
3. Parses AP and client data using a state machine
4. Returns `Network` and `Client` objects via callbacks

**Channel hopping:** Handled by `airodump-ng` internally (unless `--channel` is specified).

### 3.3 Adapter Detection (`sidewinder/core/adapter.py`)

**Known devices registry:**
```python
KNOWN_DEVICES = {
    (0x148F, 0x5370): {"name": "RT5370",   "bands": ["2.4G"],        "monitor": True,  "injection": True},
    (0x148F, 0x7601): {"name": "MT7601U",  "bands": ["2.4G"],        "monitor": True,  "injection": False},
    (0x2357, 0x0120): {"name": "RTL8821AU","bands": ["2.4G", "5G"],  "monitor": True,  "injection": True},
    (0x0BDA, 0x8812): {"name": "RTL8812AU","bands": ["2.4G", "5G"],  "monitor": True,  "injection": True},
    (0x14C3, 0x7902): {"name": "MT7902",   "bands": ["2.4G","5G","6G"],"monitor": True,"injection": True},
}
```

**Adapter priority:**
```
RTL8821AU (10) > RTL8812AU (9) > RT5370 (5) > MT7601U (3) > MT7902 (1)
```

### 3.4 Handshake Capture (`sidewinder/core/capture.py`)

**EAPOL message classification (IEEE 802.11-2020):**
```
M1: Pairwise=1, Install=0, ACK=1, MIC=0, Secure=0
M2: Pairwise=1, Install=0, ACK=0, MIC=1, Secure=0
M3: Pairwise=1, Install=1, ACK=1, MIC=1, Secure=1
M4: Pairwise=1, Install=0, ACK=0, MIC=1, Secure=1
```

**Capture methods:**
- **Passive:** `airodump-ng` listens for handshake
- **Active (deauth):** `aireplay-ng --deauth` forces clients to reconnect

**Critical design:** EAPOL detection polls the PCAP file with scapy — airodump-ng stdout does NOT contain EAPOL data.

### 3.5 Password Cracking (`sidewinder/core/cracker.py`)

**Aircrack-ng (CPU):**
```
aircrack-ng -w {wordlist} -b {bssid} {cap_file}
```
- Password in stdout: `KEY FOUND! [ password123 ]`

**Hashcat (GPU):**
```
1. hcxpcapngtool -o {hash_file} {cap_file}
2. hashcat -m 22000 {hash_file} -a 0 {wordlist} --status --status-timer 2
```
- Password in potfile only: `~/.hashcat/hashcat.potfile`

---

## 4. Bugs Discovered

### 4.1 BUG-001: `adapters` command — list vs dict mismatch
- **Command:** `python3 -m swcli adapters`
- **Error:** `Unexpected error: 'list' object has no attribute 'items'`
- **File:** `cli.py:137`
- **Cause:** `AdapterManager.discover()` returns `list[AdapterInfo]`, but `handle_adapters()` calls `.items()` on the result expecting a `dict`.
- **Status:** OPEN

### 4.2 BUG-002: `kill` command — tuple vs object mismatch
- **Command:** `python3 -m swcli kill`
- **Error:** `Unexpected error: 'tuple' object has no attribute 'pid'`
- **File:** `cli.py:153`
- **Cause:** `ServiceManager.find_conflicting()` returns `list[tuple[int, str]]`, but `handle_kill()` accesses `.pid` and `.name` on tuples instead of unpacking.
- **Status:** OPEN

### 4.3 BUG-003: `monitor status` — argparse ambiguity
- **Command:** `python3 -m swcli monitor status wlx5c628b765de2`
- **Error:** `invalid choice: 'wlx5c628b765de2' (choose from stop, status)`
- **File:** `cli.py:549-560`
- **Cause:** `iface` is an optional positional arg + `monitor_cmd` is an optional subparser. When both are present, argparse gets confused.
- **Status:** OPEN

### 4.4 BUG-004: `monitor start` — kernel rejects monitor VIF on mt7601u
- **Command:** `/monitor` (REPL) with adapter wlx001ea6c65744 (mt7601u)
- **Error:**
  ```
  Command failed (rc=234): iw phy phy1 interface add wlx001ea6c65744mon type monitor
  stderr: kernel reports: Attribute failed policy validation
  command failed: Invalid argument (-22)
  ```
- **File:** `sidewinder/core/monitor.py`
- **Cause:** The mt7601u driver does not support creating a new monitor VIF via `iw phy ... interface add`.
- **Fix:** Added try/except fallback in `enter_monitor_mode()` — tries standard path first, falls back to `enter_monitor_mode_bad_driver()` on failure.
- **Tested:** CONFIRMED WORKING on mt7601u (wlx001ea6c65744)
- **Status:** FIXED

### 4.5 BUG-005: `wordlists` — returns empty list
- **Command:** `python3 -m swcli wordlists`
- **Output:** `Available wordlists:` (empty)
- **File:** `sidewinder/core/cracker.py`
- **Cause:** `find_wordlists()` found no wordlists at default paths.
- **Status:** OPEN

### 4.6 BUG-006: `session list` — not implemented
- **Command:** `python3 -m swcli session list`
- **Output:** `Not fully implemented.`
- **File:** `cli.py:505`
- **Status:** OPEN

---

## 5. Design Issues

### 5.1 Channel Prompt During Monitor Mode Entry

**Current behavior:** The `/monitor` command prompts for a channel before entering monitor mode.

**Issue:** This channel is set once during monitor mode entry, but for scanning you want channel hopping (handled by `airodump-ng` internally).

**Recommendation:** Remove the channel prompt from monitor mode entry. Set a sensible default (ch 6) silently, or let the scan/capture commands set the channel when needed.

### 5.2 UI Feedback During Fallback

**Current behavior:** When standard monitor mode fails and falls back to bad driver path, the user sees:
```
Command failed (rc=234): iw phy phy1 interface add ...
Standard monitor mode failed for wlx001ea6c65744, trying bad driver path
  [+] Monitor mode active: wlx001ea6c65744
```

**Issue:** The error message from the failed standard path is confusing — users may think something is wrong.

**Recommendation:** Add clearer UI messaging:
- Show info message before fallback: "Standard path not supported, using alternative method..."
- Suppress verbose error output from failed standard attempt
- Show success with explicit method used: "[+] Monitor mode active (bad driver): wlx001ea6c65744"

---

## 6. Recommendations

### 6.1 Priority Fixes
1. **BUG-001/002** — Fix type mismatches in CLI commands
2. **BUG-003** — Fix argparse structure for monitor command
3. **Channel prompt** — Remove from monitor mode entry
4. **UI feedback** — Improve fallback messaging

### 6.2 Future Enhancements
1. Implement native channel hopping (bypass airodump-ng for scanning)
2. Add `session list` command
3. Add wordlist auto-discovery from common paths
4. Improve error messages with HowToFix guidance

---

## 7. File Structure

```
SWCLI/
├── sidewinder/
│   ├── __init__.py
│   ├── __main__.py
│   ├── adapters/
│   │   ├── __init__.py           # AdapterManager, FailoverManager
│   │   ├── base.py               # Adapter ABC, CARD_SETTINGS
│   │   ├── rt5370.py             # RT5370 adapter
│   │   ├── rtl8821au.py          # RTL8821AU adapter
│   │   └── mt7902.py             # MT7902 adapter profile
│   ├── attacks/
│   │   ├── __init__.py
│   │   ├── deauth.py             # DeauthConfig, DeauthResult, run_deauth
│   │   ├── evil_twin.py          # EvilTwinEngine
│   │   ├── pmkid.py              # PMKIDEngine
│   │   └── wps.py                # WPSEngine
│   └── core/
│       ├── __init__.py
│       ├── adapter.py            # AdapterInfo, detect, discover
│       ├── attack.py             # BaseAttackEngine, AttackConfig
│       ├── capture.py            # capture_passive, capture_deauth
│       ├── cleanup.py            # CleanupManager
│       ├── config.py             # SidewinderConfig
│       ├── cracker.py            # crack_aircrack, crack_hashcat
│       ├── errors.py             # SidewinderError, ERROR_DB
│       ├── fingerprint.py        # Fingerprinter (OUI lookup)
│       ├── intelligence.py       # IntelligenceEngine
│       ├── logger.py             # Rotating file logger
│       ├── monitor.py            # enter/exit monitor mode
│       ├── scanner.py            # ScanEngine, AirodumpParser
│       ├── services.py           # ServiceManager
│       ├── session.py            # Session, Network, Client
│       └── subprocess_mgr.py     # SubprocessManager
├── swcli/
│   ├── __init__.py
│   ├── __main__.py               # Entry point
│   ├── cli.py                    # CLI argparse commands
│   └── repl/
│       ├── __init__.py
│       ├── commands/             # REPL command handlers
│       ├── loop.py               # Main REPL loop
│       ├── palette.py            # Command palette
│       ├── prompts.py            # Input prompts
│       ├── renderer.py           # Output formatting
│       └── session_ui.py         # UI session state
├── TestBugs.md                   # Bug tracker
└── SWCLI_Audit_Report.md         # This report
```

---

*Report generated: 2026-06-07*
