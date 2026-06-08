# SWCLI Documentation

SWCLI is the command-line interface for the Sidewinder wireless audit toolkit. It provides an operator-controlled workflow for adapter discovery, monitor mode, live WiFi scanning, capture validation, PMKID/handshake capture, cracking, session persistence, and cleanup.

> Use SWCLI only on networks and devices you own or are explicitly authorized to audit. Many commands can change wireless adapter state, disconnect network services, capture traffic, or transmit deauthentication frames.

## Table of Contents

1. [Project Layout](#project-layout)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Starting SWCLI](#starting-swcli)
5. [Recommended First Run](#recommended-first-run)
6. [Interactive REPL Commands](#interactive-repl-commands)
7. [Direct CLI Commands](#direct-cli-commands)
8. [Common Workflows](#common-workflows)
9. [Scan Table Field Guide](#scan-table-field-guide)
10. [Sessions, Captures, and Config Files](#sessions-captures-and-config-files)
11. [Troubleshooting](#troubleshooting)
12. [Safety and Operational Notes](#safety-and-operational-notes)
13. [About](#about)

## Project Layout

```text
sidewinder/
  core/       Scanner, monitor mode, capture validation, cracking, paths, sessions, config, cleanup
  adapters/   Adapter profiles and chipset-specific behavior
  attacks/    Deauth, Evil Twin, PMKID, WPS modules

swcli/
  __main__.py  Entry point for python -m swcli
  cli.py       Direct argparse command mode
  repl/        Interactive command palette and REPL UI
```

Run commands from the repository root:

```bash
cd /path/to/SWCLI
```

## Requirements

### Operating System

SWCLI is designed for Linux systems with `iw`, `ip`, `/sys/class/net`, and the aircrack-ng toolchain available. Many workflows require root privileges.

### Python

Python 3.11+ is recommended.

Check your Python version:

```bash
python3 --version
```

### Python Packages

Required or commonly used Python modules:

```bash
python3 -m pip install rich scapy
```

If running SWCLI with `sudo`, this project attempts to add the invoking user's local site-packages to `sys.path`, but system Python packaging can vary. If imports fail under sudo, install packages system-wide or into the environment used by `sudo python3`.

### System Tools

Required for core workflows:

```text
aircrack-ng
airodump-ng
aireplay-ng
iw
ip
rfkill
ps
pkill
systemctl
```

Optional tools:

```text
hashcat
hcxpcapngtool
hcxdumptool
airbase-ng
reaver
dnsmasq
```

Install typical dependencies on Debian/Kali/Ubuntu-style systems:

```bash
sudo apt update
sudo apt install aircrack-ng iw iproute2 rfkill hashcat hcxtools hcxdumptool reaver dnsmasq
python3 -m pip install rich scapy
```

Package names can differ by distribution.

## Installation

There is no packaging metadata committed yet, so run SWCLI directly from the repository root.

1. Clone or place the repository on disk.

```bash
cd /path/to/SWCLI
```

2. Install Python dependencies.

```bash
python3 -m pip install rich scapy
```

3. Check required binaries.

```bash
python3 -m swcli deps
```

4. For hardware workflows, run with root.

```bash
sudo python3 -m swcli
```

## Starting SWCLI

### Interactive REPL Mode

Start the interactive command palette:

```bash
sudo python3 -m swcli
```

If no arguments are passed, SWCLI opens the REPL. The REPL starts with a splash screen and command palette.

Navigation:

```text
/       Open command palette
?       Show basic help
Up/Down Move in command palette, or recall command history at swcli>
Enter   Select command
Esc     Back or close palette
quit    Exit
exit    Exit
!cmd    Run a shell command from the REPL
```

At the `swcli>` prompt, typed commands are highlighted as you enter them. Commands such as `/scan`, `/config show`, `/ quit`, `quit`, `?`, and `!cmd` get distinct coloring before execution.

### Direct CLI Mode

Pass a command after `python3 -m swcli`:

```bash
python3 -m swcli deps
python3 -m swcli adapters
sudo python3 -m swcli monitor start wlan0 --channel 1
```

## Recommended First Run

1. Check dependencies.

```bash
python3 -m swcli deps
```

2. Start the REPL as root.

```bash
sudo python3 -m swcli
```

3. Run read-only readiness checks.

```text
/doctor
```

4. List adapters.

```text
/adapters
```

5. Enter monitor mode.

```text
/monitor
```

6. Start a live scan.

```text
/scan
```

7. Select a target from scan results.

```text
/target
```

8. Capture passively first.

```text
/capture passive
```

9. Validate or inspect handshakes.

```text
/validate
/handshake
/scan handshakes
```

10. Crack only after you have an authorized capture.

```text
/crack aircrack
/crack hashcat
```

11. Restore/cleanup when done.

```text
/monitor stop
/services restore
/cleanup
```

## Interactive REPL Commands

### Control

```text
/status       Show current session state
/doctor       Read-only readiness checks
/target       Select active target from scan results
/next         Suggest next actions without running them
```

`/doctor` is read-only. Adapter capability rows are reported capability, not proof. Use `/adapters test injection` for an explicit active test.

### Hardware and Setup

```text
/adapters                 List wireless adapters
/adapters info            Show detailed adapter info
/adapters test injection  Run confirmed runtime injection test on a monitor interface
/services                 Kill conflicting services after confirmation
/services restore         Restore services previously stopped by SWCLI
/monitor                  Enter monitor mode
/monitor stop             Exit monitor mode
/monitor status           Show tracked and live monitor status
```

Monitor and injection fields are reports from chipset/driver detection. Some drivers under-report or over-report capability; runtime behavior can differ.

### Scan

```text
/scan             Start live WiFi scan
/scan results     Show last scan results from session
/scan handshakes  Show M1-M4 key-info bits for latest successful capture
```

The live scan table is realtime-first. Rows represent the current scan frame. If APs or clients were seen recently but are not in the current frame, SWCLI reports that separately in the footer instead of mixing stale rows into the live table.

SWCLI preserves EAPOL state once observed during a scan. If a later airodump update drops the EAPOL flag, the AP remains marked for the session. Client-side EAPOL also promotes the associated AP to EAPOL so `/handshake`, `/crack`, and later capture selection can see that handshake traffic was observed.

The scanner writes capture output under `./swcli-output/scans/` by default and records the latest scan capture in the current session when EAPOL frames are validated.

Stop a live scan with `Ctrl+C`. SWCLI keeps the scan results in the current session.

### Capture and Validation

```text
/capture passive  Capture handshakes without transmitting deauth frames
/capture deauth   Capture while sending confirmed deauth frames
/capture pmkid    Try clientless PMKID capture
/validate         Validate a .cap/.pcap handshake file
/handshake        Show M1-M4 key-info bit details
```

Passive capture is the safest first attempt. Deauth capture transmits frames and should only be used with explicit authorization.

Capture validation checks rotated airodump output segments together. For example, validating `deauth_YYYYMMDD_HHMMSS-01.cap` also considers matching `deauth_YYYYMMDD_HHMMSS-02.cap`, `-03.cap`, and later segments when present. This matters because airodump can rotate files during longer captures, and the M1-M4 handshake frames may not all land in `-01.cap`.

### Crack

```text
/wordlists        List discovered wordlists
/crack aircrack   Crack a capture with aircrack-ng
/crack hashcat    Convert and crack with hashcat
```

Common wordlist paths are auto-discovered, including `rockyou.txt` locations and common system wordlists. You can also enter a wordlist path manually.

The Aircrack-ng crack screen follows native aircrack-style progress: elapsed time, tested keys, total keys when known, speed in `K/s`, ETA, percent, current passphrase, and any master key, transient key, or EAPOL HMAC fields printed by aircrack-ng. `/crash` is accepted as an alias for the crack screen.

### Attack

```text
/attack evil-twin  Start Evil Twin workflow
/attack wps        Start WPS Pixie-Dust workflow
/attack deauth     Start deauth attack workflow
/help attack       Explain Evil Twin and WPS target selection
```

Attack commands require confirmation and appropriate hardware support. In the REPL, Evil Twin and WPS now prefer selecting from the active `/target` or the current `/scan` results before falling back to manual BSSID/channel entry.

### Session

```text
/session save           Save current state
/session load           Load a saved session
/session list           List saved sessions
/session autosaves      List last 5 autosaves
/session load autosave  Load an autosaved session
```

### Config

```text
/config show   Show configuration
/config set    Update configuration value
/config reset  Reset configuration to defaults
```

### System and Help

```text
/help           List commands and scan field meanings
/help scan      Explain scan table fields
/about          Show SWCLI version and developer info
/cleanup        Full cleanup
/cleanup procs  Kill attack processes only
/cleanup files  Clean temp files only
```

## Direct CLI Commands

Direct mode is useful for scripting or one-off operations.

### Preflight

```bash
python3 -m swcli root
python3 -m swcli deps
python3 -m swcli rfkill
python3 -m swcli rfkill unblock
python3 -m swcli rfkill unblock phy0
```

### Adapters

```bash
python3 -m swcli adapters
python3 -m swcli adapters info wlan0
```

### Services

```bash
sudo python3 -m swcli kill
sudo python3 -m swcli restore
```

### Monitor Mode

```bash
sudo python3 -m swcli monitor start wlan0 --channel 1
sudo python3 -m swcli monitor status wlan0mon
sudo python3 -m swcli monitor stop wlan0mon --interface wlan0 --phy phy0
```

### Scan

```bash
sudo python3 -m swcli scan wlan0mon --band bg
sudo python3 -m swcli scan wlan0mon --band a
sudo python3 -m swcli scan wlan0mon --band abg
sudo python3 -m swcli scan wlan0mon --channels 1,6,11
python3 -m swcli scan results
```

Direct scans write capture output under `./swcli-output/scans/` by default.

### Capture

Passive capture:

```bash
sudo python3 -m swcli capture passive wlan0mon AA:BB:CC:DD:EE:FF 6 --timeout 300
```

If `--output` is omitted, SWCLI writes to `./swcli-output/captures/passive_YYYYMMDD_HHMMSS-01.cap`.

Deauth capture:

```bash
sudo python3 -m swcli capture deauth wlan0mon AA:BB:CC:DD:EE:FF 6 \
  --client FF:FF:FF:FF:FF:FF \
  --count 10 \
  --bursts 3 \
  --timeout 300
```

If `--output` is omitted, SWCLI writes to `./swcli-output/captures/deauth_YYYYMMDD_HHMMSS-01.cap`.

PMKID capture:

```bash
sudo python3 -m swcli capture pmkid wlan0mon AA:BB:CC:DD:EE:FF 6 --timeout 300
```

PMKID captures are written under `./swcli-output/captures/`. Converted PMKID hash files are written under `./swcli-output/hashes/`.

### Validate

```bash
python3 -m swcli validate ./swcli-output/captures/deauth_YYYYMMDD_HHMMSS-01.cap
```

### Crack

Aircrack-ng:

```bash
python3 -m swcli wordlists
python3 -m swcli crack aircrack ./swcli-output/captures/deauth_YYYYMMDD_HHMMSS-01.cap \
  --bssid AA:BB:CC:DD:EE:FF \
  --wordlist /usr/share/wordlists/rockyou.txt
```

Hashcat:

```bash
python3 -m swcli crack hashcat ./swcli-output/captures/deauth_YYYYMMDD_HHMMSS-01.cap \
  --wordlist /usr/share/wordlists/rockyou.txt
```

### Attack Modules

Evil Twin:

```bash
sudo python3 -m swcli
/scan
/target
/attack evil-twin
```

The Evil Twin REPL flow selects a monitor interface, lets you choose a scanned target, pre-fills the ESSID when visible, asks whether to clone the target BSSID, then shows a confirmation plan before starting airbase-ng.

WPS:

```bash
sudo python3 -m swcli
/scan
/attack wps
```

The WPS flow prefers APs marked with the WPS flag in scan data, confirms the BSSID/channel pair, then runs the Pixie-Dust workflow and reports recovered PIN/PSK values when reaver returns them.

### Cleanup

```bash
sudo python3 -m swcli cleanup
sudo python3 -m swcli cleanup procs
python3 -m swcli cleanup files --dry-run
sudo python3 -m swcli cleanup files
```

`cleanup files` targets generated files under the configured output root. With the default config, that is `./swcli-output/`.

### Session

```bash
python3 -m swcli session save --file ~/.sidewinder/session.json
python3 -m swcli session load ~/.sidewinder/session.json
python3 -m swcli session list
```

### Config

```bash
python3 -m swcli config show
python3 -m swcli config set default_channel 6
python3 -m swcli config set default_deauth_count 5
```

## Common Workflows

### Workflow 1: Read-Only Discovery

Use this to inspect hardware and nearby APs without capturing or attacking.

```bash
sudo python3 -m swcli
```

Then:

```text
/doctor
/adapters
/monitor
/scan
/scan results
/monitor stop
```

### Workflow 2: Passive Handshake Capture

Use this before deauth.

```text
/monitor
/scan
/target
/capture passive
/validate
/handshake
```

If a full or partial handshake is captured, move to cracking.

### Workflow 3: Confirmed Deauth Capture

Only on authorized networks.

```text
/scan
/target
/capture deauth
/validate
/handshake
```

Prefer selecting a specific associated client when one is visible. Broadcast deauth is available but noisier.

### Workflow 4: PMKID Capture

PMKID does not require connected clients, but success depends on AP behavior.

```text
/monitor
/target
/capture pmkid
```

Requires `hcxdumptool` and `hcxpcapngtool`.

### Workflow 5: Crack a Capture

Aircrack-ng:

```text
/wordlists
/crack aircrack
```

Hashcat:

```text
/crack hashcat
```

Hashcat requires `hcxpcapngtool` conversion and a working hashcat setup.

### Workflow 6: Save and Resume

```text
/session save
/session list
/session load
/session autosaves
/session load autosave
```

Autosaves are written on exit and rotated to keep the newest entries.

## Scan Table Field Guide

### Access Point Table

```text
ESSID    Network name. [HIDDEN] means SSID is not visible.
BSSID    AP MAC address.
PWR      Signal strength. Closer to zero is stronger. -1 means unknown.
Beacons  Beacon frames seen from the AP.
#Data    Captured data packets. For WEP, effectively IV count.
#/s      Recent data packet rate per second.
CH       AP channel.
MB       Maximum AP data rate reported by airodump-ng.
HE       High Efficiency / 802.11ax indicator when detected.
ENC      Encryption family such as OPN, WEP, WPA, WPA2, WPA3.
CIPHER   Cipher such as CCMP or TKIP.
AUTH     Authentication such as PSK or MGT.
CL       SWCLI client count associated with the AP.
FLAGS    SWCLI highlights such as WPS or EAPOL.
```

### Client Table

```text
ESSID    Associated AP network name when known.
STATION  Client MAC address.
BSSID    Associated AP MAC address.
PWR      Client signal strength.
PKTS     Packets seen from the client.
PROBE    SSID requested by the client while searching.
HE       High Efficiency / 802.11ax indicator when detected.
FLAGS    Client-side notes such as EAPOL.
```

### Reading the Scan

Good target indicators:

```text
Strong PWR, for example -30 to -60
Rising #Data or #/s
Visible associated clients
WPS flag if testing WPS
EAPOL flag if handshake traffic appears
Known channel and stable BSSID
```

## Sessions, Captures, and Config Files

### Default Runtime Paths

```text
~/.sidewinder/config.json       User config
~/.sidewinder/session.json      Default current session
~/.sidewinder/sessions/         Saved session archive
~/.sidewinder/autosaves/        Rotating REPL autosaves
./swcli-output/                 Default app-local output root
./swcli-output/scans/           Scan capture files and scan FIFOs
./swcli-output/captures/        Passive, deauth, and PMKID capture files
./swcli-output/attacks/         Attack workflow output files
./swcli-output/hashes/          Converted PMKID/hashcat hash files
./swcli-output/wordlists/       App-local wordlist directory
```

SWCLI keeps user configuration and sessions under `~/.sidewinder/`, but generated audit artifacts are now stored in the repository working directory by default so they are easy to find and clean up. The output root comes from `results_dir`; the default is `./swcli-output`.

Existing configs that still contain the old defaults `~/.sidewinder/captures` or `~/.sidewinder/results` are migrated in memory to the new app-local paths when loaded. Manually customized absolute paths are left unchanged.

Generated filename prefixes include timestamps:

```text
./swcli-output/scans/scan_YYYYMMDD_HHMMSS-01.cap
./swcli-output/captures/passive_YYYYMMDD_HHMMSS-01.cap
./swcli-output/captures/deauth_YYYYMMDD_HHMMSS-01.cap
./swcli-output/attacks/deauth_YYYYMMDD_HHMMSS-01.cap
./swcli-output/hashes/pmkid_AABBCCDDEEFF.hc22000
```

`/status` shows the active output directory. `/doctor` verifies that the output directory is writable. `/cleanup files` removes generated files under `./swcli-output/`.

### Configuration Keys

Defaults are defined by `SidewinderConfig`:

```text
capture_dir
wordlist_dir
results_dir
default_wordlist
default_channel
default_deauth_count
capture_timeout_seconds
deauth_cooldown_seconds
regulatory_domain
mac_randomization
theme
theme_directory
load_user_themes
load_builtin_themes
theme_preview
```

Show config:

```bash
python3 -m swcli config show
```

Set config:

```bash
python3 -m swcli config set default_channel 6
```

## Troubleshooting

### No Wireless Adapters Found

Check:

```bash
ip link
iw dev
ls /sys/class/net
python3 -m swcli adapters
```

If using USB, reconnect the adapter and check `dmesg`.

### No Monitor Interfaces Found

Run:

```text
/adapters
/monitor
/monitor status
```

Or direct:

```bash
sudo python3 -m swcli monitor start wlan0 --channel 1
```

### Tool Missing

Run:

```bash
python3 -m swcli deps
```

Install the missing system package or Python package.

### Scapy Missing

Handshake validation depends on Scapy.

```bash
python3 -m pip install scapy
```

If running under sudo and Scapy is still missing, install in the Python environment used by sudo.

### Scan Shows No APs

Check:

```text
Adapter is in monitor mode
Correct band selected: bg, a, or abg
Channel list includes nearby AP channel
Conflicting services are not changing channels
RFKill is not blocking WiFi
```

Commands:

```bash
python3 -m swcli rfkill
sudo python3 -m swcli rfkill unblock
sudo python3 -m swcli monitor status wlan0mon
```

### Capture Times Out

Common causes:

```text
Wrong BSSID or channel
Target signal too weak
No connected clients
Adapter not actually capturing on selected channel
No client reconnect during passive capture
Deauth blocked by AP/client protections
```

Try:

```text
/scan
/target
/capture passive
/capture deauth
/handshake
```

### EAPOL Seen During Scan But Not Reflected Later

SWCLI now preserves EAPOL once it is observed during `/scan`. If EAPOL is seen on a client row, the associated AP is also marked with EAPOL. After the scan stops, SWCLI validates the latest scan capture and stores it in the current session when EAPOL frames are present.

Check:

```text
/scan results
/handshake
/crack aircrack
```

If `/crack` cannot find a capture in the session, it also searches recent files under `./swcli-output/scans/` and `./swcli-output/captures/`.

### M1-M4 Missing During Deauth Capture

Airodump-ng can rotate capture files during a run. The live capture validator now checks every matching rotated segment, not only `-01.cap`, before reporting M1-M4.

Example set:

```text
./swcli-output/captures/deauth_YYYYMMDD_HHMMSS-01.cap
./swcli-output/captures/deauth_YYYYMMDD_HHMMSS-02.cap
./swcli-output/captures/deauth_YYYYMMDD_HHMMSS-03.cap
```

Validating any one of the matching segment files checks the whole set.

### Crack Screen Looks Stuck Or Appears In The Wrong Place

The crack UI uses a full-screen Rich live display so progress stays at the top of the terminal while aircrack-ng runs. Aircrack-ng progress is rendered in its native shape: keys tested, ETA, percent, current passphrase, and key material fields when aircrack-ng prints them.

Speed is displayed as `K/s`. Internally, SWCLI normalizes aircrack-ng speed output so the UI does not show ambiguous `M/s` or raw `keys/s` labels.

### Injection Report Says No, But Hardware Works

Some drivers under-report capabilities. SWCLI separates reported capability from runtime tests.

Use:

```text
/adapters test injection
```

This command requires root, a monitor interface, and explicit confirmation.

### Cleanup After Interrupted Run

```bash
sudo python3 -m swcli cleanup procs
sudo python3 -m swcli restore
sudo python3 -m swcli monitor stop wlan0mon --interface wlan0 --phy phy0
```

## Safety and Operational Notes

- Start with `/doctor`, `/adapters`, and `/scan`.
- Prefer passive capture before deauth.
- Treat capture files, MAC addresses, ESSIDs, and wordlists as sensitive.
- Do not kill services unless you understand that WiFi/internet may disconnect.
- Restore services after audits with `/services restore` or direct `restore`.
- Use `/cleanup` after interrupted capture or attack workflows.
- Keep captures in a controlled directory and remove temporary files when done.

## About

```text
Application: SWCLI
Version:     0.1.0
Developer:   Parikshit Singh Bais
GitHub:      @sillypari
URL:         https://github.com/sillypari
```

Inside the REPL:

```text
/about
```
