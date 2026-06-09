# SWCLI

**Sidewinder Wireless Audit Console**

SWCLI is a Python-based wireless auditing console built around a fast interactive REPL, guided workflows, live scan tables, capture validation, cracking helpers, adapter checks, and explicit confirmation before any workflow that changes wireless state or transmits frames.

It is designed for operators who want the power of tools such as `aircrack-ng`, `airodump-ng`, `aireplay-ng`, `airbase-ng`, `reaver`, `hashcat`, and `hcxpcapngtool`, but with a cleaner command palette, better session context, safer prompts, and more readable terminal UI.

> Use SWCLI only on networks, devices, and lab environments where you have clear authorization. Wireless attacks can disrupt connectivity, trigger lockouts, and violate law or policy when used outside an approved scope.

## Highlights

- Interactive command palette with categorized workflows.
- Live `airodump-ng` scan view with access point and client tables.
- Real-time scan data handling without showing stale rows as current activity.
- Target selection from scan results instead of repeatedly typing BSSIDs.
- Passive, deauth-assisted (with custom packet rates), and PMKID capture workflows.
- Handshake validation and M1-M4 key-info inspection.
- Aircrack-ng and Hashcat cracking helpers.
- Advanced Evil Twin Pass with Captive Portal OS-detection, DNS Blackholing, and cloned UI variants (TP-Link, Hotel, etc.).
- Multi-Band Evasion Detection `[MB]` and Dual-Adapter/Channel Hopping support for Deauth.
- Guided WPS workflows with target selection and confirmation plans.
- Adapter discovery, monitor-mode handling, and injection testing.
- Session save/load/autosave support.
- Professional Rich-based terminal output, help panels, `/about`, and `/help scan`.
- Main prompt command history with Up/Down and live command coloring.
- Config UI with typed values, descriptions, validation, and reset support.

## Current Status

SWCLI is currently a direct-from-repository Python CLI. There is no committed package metadata yet, so run it from the repository root with:

```bash
python3 -m swcli
```

Many operational commands require root privileges and a Linux wireless stack:

```bash
sudo python3 -m swcli
```

## Requirements

### Operating System

SWCLI targets Linux systems with wireless tooling support. Kali, Debian, Ubuntu, and similar distributions are the most natural fit.

### Python

- Python 3.10 or newer recommended.
- `rich` is required for the REPL UI.

Install Python UI dependency:

```bash
python3 -m pip install --user rich
```

When running with `sudo`, SWCLI attempts to include the invoking user's local site-packages so user-installed Python packages remain visible.

### System Tools

Required for core scan/capture/crack workflows:

```bash
sudo apt update
sudo apt install -y aircrack-ng iw iproute2
```

Recommended optional tools:

```bash
sudo apt install -y hashcat hcxtools reaver dnsmasq
```

Tool usage by feature:

| Feature | Tools |
| --- | --- |
| Adapter and monitor workflows | `iw`, `ip`, `airmon-ng` style Linux wireless support |
| Live scanning | `airodump-ng` |
| Deauth capture | `aireplay-ng`, capture parser logic |
| Aircrack cracking | `aircrack-ng` |
| Hashcat cracking | `hashcat`, `hcxpcapngtool` |
| Evil Twin | `airbase-ng` |
| WPS Pixie-Dust | `reaver` |
| Cleanup and service control | `systemctl`, process tools, network service tools |

Check dependencies from the direct CLI:

```bash
python3 -m swcli deps
```

Or from the REPL:

```text
/doctor
```

## Installation

Clone the repository:

```bash
git clone https://github.com/sillypari/SWCLI.git
cd SWCLI
```

Install Python dependency:

```bash
python3 -m pip install --user rich
```

Check external tools:

```bash
python3 -m swcli deps
```

Start SWCLI:

```bash
sudo python3 -m swcli
```

## First Run Workflow

The recommended workflow is REPL-first:

```bash
sudo python3 -m swcli
```

Then:

```text
/doctor
/adapters
/monitor
/scan
/target
/capture passive
/validate
/crack aircrack
```

For most users, the command palette is the easiest way to navigate. Press `/` at the `swcli>` prompt to open it.

## REPL UX

SWCLI opens with a splash screen and command palette.

Main prompt controls:

| Key/Input | Behavior |
| --- | --- |
| `/` | Open command palette |
| `?` | Show basic help |
| `Up/Down` | Recall command history at `swcli>` |
| `/config show` | Commands are highlighted while typing |
| `/ quit`, `/quit`, `quit`, `exit` | Exit the REPL |
| `!<command>` | Run a shell command |

Palette controls:

| Key | Behavior |
| --- | --- |
| `Up/Down` | Move selection |
| `PageUp/PageDown` | Move by page |
| `Enter` | Select |
| `Esc` | Back or close |
| Type text | Search/filter commands |

## Command Reference

### Control

| Command | Purpose |
| --- | --- |
| `/status` | Show current session state |
| `/doctor` | Read-only readiness checks |
| `/target` | Select active target from scan results |
| `/next` | Suggest next actions |

### Setup

| Command | Purpose |
| --- | --- |
| `/services` | Kill conflicting services after confirmation |
| `/services restore` | Restore services stopped by SWCLI |
| `/monitor` | Enter monitor mode |
| `/monitor stop` | Exit monitor mode |
| `/monitor status` | Check interface mode |

### Scan

| Command | Purpose |
| --- | --- |
| `/scan` | Start live Wi-Fi scan |
| `/scan results` | Show last scan results |
| `/scan handshakes` | Show M1-M4 key-info bits from scan/capture context |
| `/help scan` | Explain scan table fields |

### Capture

| Command | Purpose |
| --- | --- |
| `/capture passive` | Capture handshakes without transmitting deauth frames |
| `/capture deauth` | Capture while sending confirmed deauth frames |
| `/capture pmkid` | Attempt clientless PMKID capture |
| `/validate` | Validate a `.cap` or `.pcap` handshake |
| `/handshake` | Show M1-M4 key-info details |

### Crack

| Command | Purpose |
| --- | --- |
| `/wordlists` | List discovered wordlists |
| `/crack aircrack` | Crack with `aircrack-ng` |
| `/crack hashcat` | Convert and crack with Hashcat |

### Attack

| Command | Purpose |
| --- | --- |
| `/attack evil-twin` | Alias for Evil Twin Simple open AP + logging |
| `/attack evil-twin-simple` | Start open AP with notice/captive portal and metadata logging |
| `/attack evil-twin-pass` | Start password-validation portal workflow with Captive Portal OS-detection |
| `/attack wps` | Start guided WPS Pixie-Dust workflow |
| `/attack deauth` | Start guided deauth workflow (supports Custom Deauth Rates and Dual-Adapter) |
| `/help attack` | Explain attack workflows |

Attack flows require explicit confirmation. Evil Twin and WPS workflows prefer selecting from the active target or current scan results before falling back to manual input.

### Hardware

| Command | Purpose |
| --- | --- |
| `/adapters` | List wireless adapters |
| `/adapters info` | Show adapter details |
| `/adapters test injection` | Actively test packet injection |

### Session

| Command | Purpose |
| --- | --- |
| `/session save` | Save current session state |
| `/session load` | Load saved session |
| `/session list` | List saved sessions |
| `/session autosaves` | List recent autosaves |
| `/session load autosave` | Load an autosaved session |

### Config

| Command | Purpose |
| --- | --- |
| `/config show` | Show typed configuration table |
| `/config set` | Select and update a config value |
| `/config reset` | Reset configuration to defaults |

Configuration is stored at:

```text
~/.sidewinder/config.json
```

### System

| Command | Purpose |
| --- | --- |
| `/cleanup` | Full cleanup |
| `/cleanup procs` | Kill attack/capture helper processes only |
| `/cleanup files` | Clean temporary files only |
| `/help` | List commands and field meanings |
| `/about` | Show version and developer information |

## Direct CLI Mode

The REPL is the preferred interface, but some direct commands are also available:

```bash
python3 -m swcli deps
python3 -m swcli adapters
python3 -m swcli monitor status wlan0
```

Use direct mode for simple status checks and automation. Use the REPL for guided capture, target selection, and attack workflows.

## Scan Table Guide

Access point fields:

| Field | Meaning |
| --- | --- |
| `ESSID` | Network name. `[HIDDEN]` means not visible in scan data |
| `BSSID` | Access point MAC address |
| `PWR` | Signal strength. Closer to zero is stronger; `-1` means unknown |
| `Beacons` | Beacon frames observed from the AP |
| `#Data` | Captured AP data packets |
| `#/s` | Recent data packet rate per second |
| `CH` | Channel |
| `MB` | Multi-Band indicator `[MB]`. Appears if the ESSID spans multiple channels |
| `HE` | 802.11ax / High Efficiency indicator when detected |
| `ENC` | Encryption family |
| `CIPHER` | Traffic cipher |
| `AUTH` | Authentication method |
| `CL` | Client count associated with the AP |
| `FLAGS` | SWCLI highlights such as WPS or EAPOL |

Client fields:

| Field | Meaning |
| --- | --- |
| `ESSID` | Associated network name when known |
| `STATION` | Client MAC address |
| `BSSID` | Associated AP MAC address |
| `PWR` | Client signal strength |
| `PKTS` | Packets seen from the client |
| `PROBE` | SSID requested by a probing client |
| `HE` | 802.11ax indicator when detected |
| `FLAGS` | Client-side notes such as EAPOL |

## Project Structure

```text
sidewinder/
  adapters/    Chipset and adapter discovery support
  attacks/     Deauth, Evil Twin, PMKID, WPS modules
  core/        Scanner, monitor, capture, session, config, cleanup, subprocess logic

swcli/
  cli.py       Direct argparse CLI
  repl/        Interactive command palette and terminal UI

Documentaion/  Project notes and long-form guides
Test/          Script-style probe checks
```

## Validation

There is no formal pytest configuration yet. Existing checks are script-style probes in `Test/`.

Run a syntax pass:

```bash
python3 -m py_compile $(find sidewinder swcli -name '*.py')
```

Run an individual probe:

```bash
python3 Test/test_loop.py
```

Hardware workflows should be tested only on authorized lab adapters and networks.

## Troubleshooting

### `This command requires root`

Start the REPL with:

```bash
sudo python3 -m swcli
```

### `No monitor interfaces found`

Run:

```text
/adapters
/monitor
```

Then rerun the scan or capture workflow.

### Python cannot import `rich`

Install it for your user:

```bash
python3 -m pip install --user rich
```

If running under `sudo`, confirm your user site-packages path is readable, or install Rich system-wide in your lab environment.

### External tools missing

Run:

```bash
python3 -m swcli deps
```

Then install missing packages with your distribution package manager.

### WPS target not flagged but you know it supports WPS

The WPS workflow lists scanned APs and prioritizes WPS-flagged entries, but still allows manual or non-flagged selection. SWCLI warns before running if scan data did not mark WPS support.

## Security Notes

- Treat capture files, MAC addresses, wordlists, and scan exports as sensitive operational data.
- Do not commit local captures, cracked keys, scan exports, or private reference tool trees.
- The local `Refrence Tools/` and `Reference Tools/` folders are ignored intentionally.
- Prefer passive capture before transmitting frames.
- Use deauth, Evil Twin, WPS, and injection tests only inside an authorized scope.

## Developer

Created by **Parikshit Singh Bais**.

GitHub: [@sillypari](https://github.com/sillypari)

## License

No license file is currently committed. Until a license is added, all rights are reserved by the repository owner.
