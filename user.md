# SWCLI User Guide: End-to-End WiFi Audit

This guide walks you through a complete WiFi auditing session using the Sidewinder Command Line Interface (SWCLI). SWCLI is built around a fully interactive Command Palette REPL, making it extremely easy to build complex attacks step-by-step.

> **Note on OS Requirements:** SWCLI requires root privileges (`sudo`) and Linux-native networking tools (`airodump-ng`, `aircrack-ng`, `iw`, etc.) to interface directly with wireless hardware. **You must run this on a Linux system (like Ubuntu, Kali, or Parrot OS)** for the hardware components to function correctly.

---

## Starting the Interactive REPL

To start the interactive interface, open your terminal and run:

```bash
sudo python3 -m swcli
```

You will see the SWCLI banner. From here, **type `/` (forward slash)** to open the Command Palette. 
- Use the **Up/Down arrow keys** or **j/k** to navigate commands.
- **Type to filter** the command list dynamically.
- Press **Enter** to select a command.
- Press **Esc** to go back or close the palette.

---

## The Auditing Workflow

### Step 1: Preflight Checks

Before starting an attack, ensure your system is ready.

1. **Check Dependencies:** Open the palette (`/`) and select `/deps`. This ensures you have `aircrack-ng`, `iw`, and other tools installed.
2. **Check Radio Status:** Run `/rfkill`. If your WiFi is soft-blocked, run `/rfkill unblock`.

### Step 2: Hardware Preparation

We need to prepare the wireless adapter.

1. **Find Your Adapter:** Run `/adapters` to see your connected WiFi interfaces (e.g., `wlan0`). You can also run `/adapters info` for chipset details.
2. **Kill Conflicting Services:** Linux network managers interfere with hacking tools. Run `/services` to kill `NetworkManager` and `wpa_supplicant`. *(Note: You will lose internet access temporarily).*

### Step 3: Enter Monitor Mode

Your WiFi card needs to be in Monitor Mode to sniff raw packets.

1. Run `/monitor`.
2. The REPL will auto-detect available interfaces and show their chipsets.
3. If only one monitor-capable adapter is found, it is selected automatically.
4. Once confirmed, it will create a new monitor interface (e.g., `wlan0mon`).
5. Check status anytime with `/monitor status`.

### Step 4: Reconnaissance (Scanning)

Discover target Access Points (APs) and connected clients.

1. Run `/scan`.
2. The REPL will:
   - Auto-detect monitor interfaces and show chipset info.
   - Auto-select if only one monitor adapter exists.
   - Ask for a **band** (2.4GHz, 5GHz, or All) and channel preset.
   - Ask for a **timing preset** (Default, Fast, Thorough, or Custom).
3. The scan runs a real-time live display powered by a custom JSON FIFO pipeline from airodump-ng — data updates every 100ms.
4. During the scan, press **`P`** to toggle **probe-only mode** (shows only networks with probe responses).
5. Press **Ctrl+C** to stop. Results are saved automatically even on Ctrl+C.
6. Run `/scan results` to view a formatted table of all discovered networks and clients.

#### Scan Display Columns

**Networks:** BSSID, PWR, RXQ, Beacons, Data, Data/s, Channel, Speed, Encryption, Cipher, Auth, ESSID, WPS

**Clients:** ESSID (resolved), Station MAC, BSSID (AP), PWR, Rate, Lost, Frames, Notes (EAPOL), Probes

#### Channel Selection Options

| Preset | Description |
|--------|-------------|
| All Channels | Scan all channels (slowest, most complete) |
| 1, 6, 11 | Standard 2.4GHz non-overlapping channels |
| UNII-1 (36-48) | 5GHz low band |
| UNII-2 (52-64) | 5GHz mid band (DFS) |
| UNII-3 (100-144) | 5GHz upper band (DFS) |
| UNII-4 (149-165) | 5GHz highest band |
| Custom | Manually enter channels |

#### Timing Presets

| Preset | UI Refresh | Channel Hop | Description |
|--------|-----------|-------------|-------------|
| Default | 100ms | 250ms | Balanced |
| Fast | 50ms | 150ms | Quick updates |
| Thorough | 200ms | 400ms | More beacons |
| Custom | User-set | User-set | Full control |

### Step 5: Check Handshake Status

During or after a scan, you can check if any WPA EAPOL handshake frames were detected.

1. Run `/scan handshakes`.
2. Shows which clients triggered EAPOL detection.
3. Confirms the `.cap` file was saved (at `/tmp/swcli_scan-01.cap`).
4. The scan automatically writes a pcap capture file alongside the JSON data — no extra steps needed.

### Step 6: Capture Handshake

You need a WPA 4-way handshake to crack a password. Open the palette and navigate to `/capture` → `deauth` (Active capture).

1. Select `/capture deauth`.
2. The REPL will intelligently **auto-fill** prompts for the interface, target BSSID, and channel based on your last scan! Just press **Enter** to accept the defaults.
3. The attack will run, disconnecting clients to force a handshake, and save the `.cap` file for you.

*(Alternative methods like `/capture passive` or `/capture pmkid` are also available in the palette).*

### Step 7: Validate the Capture

Ensure the `.cap` file actually contains a usable handshake.

1. Run `/validate`.
2. Press **Enter** to accept the auto-filled capture file path. Look for `Status: FULL` or `Status: PARTIAL`.

### Step 8: Password Cracking

1. **Find Wordlists:** Run `/wordlists` to locate wordlists on your system (like `rockyou.txt`).
2. **Start Cracking:** Select `/crack aircrack` (CPU) or `/crack hashcat` (GPU).
3. Follow the prompts (the capture file and BSSID will auto-fill). The system will attempt to crack the password.

### Step 9: Save and Resume Sessions

Your scan data, clients, and capture file paths persist in memory, but you can also save/load sessions to disk.

1. **Save:** Run `/session save`. You can accept the default path (`~/.sidewinder/session.json`) or type a directory path (it will auto-create `session.json` inside it).
2. **Load:** Run `/session load` to pick from previously saved sessions.
3. **List:** Run `/session list` to see all saved sessions with timestamps and sizes.

Saved sessions include: network list, clients, adapter info, capture file paths, and handshake data.

### Step 10: Clean Up and Restore

Once you've retrieved the password, restore your system back to normal.

1. Run `/cleanup`.
2. The system will tear down monitor mode, kill any lingering background attacks, restore `NetworkManager`, and get your internet working again.

---

## All Commands Reference

### Scan
| Command | Description |
|---------|-------------|
| `/scan` | Start WiFi scan (auto-detects interface, selects band/channels) |
| `/scan results` | Show last scan results (networks + clients tables) |
| `/scan handshakes` | Show EAPOL handshake detection status and capture file |

### Capture
| Command | Description |
|---------|-------------|
| `/capture passive` | Passive handshake capture (wait for natural handshake) |
| `/capture deauth` | Deauth + capture (force handshake by disconnecting clients) |
| `/capture pmkid` | PMKID capture (clientless attack) |
| `/validate` | Validate .cap file for usable handshake |

### Attack
| Command | Description |
|---------|-------------|
| `/attack evil-twin` | Create Evil Twin AP |
| `/attack wps` | WPS Pixie-Dust attack |
| `/attack deauth` | Deauth attack |

### Crack
| Command | Description |
|---------|-------------|
| `/wordlists` | List available wordlists on the system |
| `/crack aircrack` | Crack WPA with aircrack-ng (CPU) |
| `/crack hashcat` | Crack WPA with hashcat (GPU) |

### Setup
| Command | Description |
|---------|-------------|
| `/monitor` | Enter monitor mode |
| `/monitor stop` | Exit monitor mode |
| `/monitor status` | Check monitor mode status |
| `/services` | Kill conflicting services (NetworkManager, wpa_supplicant) |
| `/services restore` | Restore killed services |

### Hardware
| Command | Description |
|---------|-------------|
| `/adapters` | List wireless adapters |
| `/adapters info` | Show adapter chipset and capability details |

### Session
| Command | Description |
|---------|-------------|
| `/session save` | Save current session to file |
| `/session load` | Load a saved session |
| `/session list` | List all saved sessions |

### Config
| Command | Description |
|---------|-------------|
| `/config show` | Show current configuration |
| `/config set` | Update a config value |

### System
| Command | Description |
|---------|-------------|
| `/help` | List all commands |
| `/cleanup` | Full cleanup (monitor mode, procs, files, services) |
| `/cleanup procs` | Kill attack processes only |
| `/cleanup files` | Clean temp files only |

---

## Keyboard Shortcuts During Scan

| Key | Action |
|-----|--------|
| `P` | Toggle probe-only display mode |
| `Ctrl+C` | Stop scan (results auto-saved) |

---

## Direct Command Mode (For Scripts)

If you know exactly what you want to do and don't want the interactive prompts, you can bypass the REPL entirely by passing arguments directly:

```bash
# Example: Instantly scan on wlan0mon without the UI
sudo python -m swcli scan wlan0mon --band bg
```
Use `python -m swcli --help` to see all direct commands.

---

## Technical Details

### JSON FIFO Pipeline

SWCLI uses a custom-patched `airodump-ng` with a `--json <fifo_path>` flag that streams real-time JSON data through a named pipe (FIFO). This replaces the old CSV polling approach and provides:

- **100ms update latency** (vs 5s with CSV polling)
- **Immediate entry purge** — clients/networks vanish instantly when absent from JSON
- **No stale data** — no 120-second timeout needed

### Capture Files

When you run `/scan`, airodump-ng writes pcap files alongside the JSON FIFO:
- `/tmp/swcli_scan-01.cap` — Raw packet capture (contains EAPOL handshakes)
- Extra files (csv, kismet, netxml) are auto-cleaned after scan stops

The `.cap` file can be used directly with:
- `/validate` — Check for complete/partial handshake
- `/crack aircrack` — CPU-based cracking
- `/crack hashcat` — GPU-based cracking
- Manual: `aircrack-ng -w wordlist.txt /tmp/swcli_scan-01.cap`
