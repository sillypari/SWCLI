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

1. **Find Your Adapter:** Run `/adapters` to see your connected WiFi interfaces (e.g., `wlan0`).
2. **Kill Conflicting Services:** Linux network managers interfere with hacking tools. Run `/services` to kill `NetworkManager` and `wpa_supplicant`. *(Note: You will lose internet access temporarily).*

### Step 3: Enter Monitor Mode

Your WiFi card needs to be in Monitor Mode to sniff raw packets.

1. Run `/monitor`.
2. The REPL will prompt you to select an adapter and a channel.
3. Once confirmed, it will create a new monitor interface (e.g., `wlan0mon`).

### Step 4: Reconnaissance (Scanning)

Discover target Access Points (APs) and connected clients.

1. Run `/scan`.
2. The REPL will ask which interface to use. Press **Enter** to use the default `wlan0mon` that the session remembered.
3. The scan will run in the background. Press **Ctrl+C** to stop scanning when you see your target.
4. Run `/scan results` to view a formatted table of all discovered networks. Note your target's BSSID.

### Step 5: Capture Handshake

You need a WPA 4-way handshake to crack a password. Open the palette and navigate to `/capture` → `deauth` (Active capture).

1. Select `/capture deauth`.
2. The REPL will intelligently **auto-fill** prompts for the interface, target BSSID, and channel based on your last scan! Just press **Enter** to accept the defaults.
3. The attack will run, disconnecting clients to force a handshake, and save the `.cap` file for you.

*(Alternative methods like `/capture passive` or `/capture pmkid` are also available in the palette).*

### Step 6: Validate the Capture

Ensure the `.cap` file actually contains a usable handshake.

1. Run `/validate`.
2. Press **Enter** to accept the auto-filled capture file path. Look for `Status: FULL` or `Status: PARTIAL`.

### Step 7: Password Cracking

1. **Find Wordlists:** Run `/wordlists` to locate wordlists on your system (like `rockyou.txt`).
2. **Start Cracking:** Select `/crack aircrack` (CPU) or `/crack hashcat` (GPU).
3. Follow the prompts (the capture file and BSSID will auto-fill). The system will attempt to crack the password.

### Step 8: Clean Up and Restore

Once you've retrieved the password, restore your system back to normal.

1. Run `/cleanup`.
2. The system will tear down monitor mode, kill any lingering background attacks, restore `NetworkManager`, and get your internet working again.

---

## Direct Command Mode (For Scripts)

If you know exactly what you want to do and don't want the interactive prompts, you can bypass the REPL entirely by passing arguments directly:

```bash
# Example: Instantly scan on wlan0mon without the UI
sudo python -m swcli scan wlan0mon --band bg
```
Use `python -m swcli --help` to see all direct commands.
