# Sidewinder CLI: Custom Airodump-ng JSON FIFO Implementation

### What We Changed

**1. `airodump-ng` C Source Code Patches**
We directly injected code into your `Refrence Tools/aircrack-ng` source folder.
* **`airodump-ng.c`**: Added a new command-line flag (`--json`) that accepts a file or FIFO pipe path.
* **`dump_write.h`**: Injected the required function signatures to resolve implicit declaration warnings during compilation.
* **`dump_write.c`**: Injected a new `dump_write_json()` function. This function uses non-blocking (`O_NONBLOCK`) pipes to prevent `airodump-ng` from hanging, gracefully handles string escaping for ESSIDs/Probes with control characters, and dumps raw memory state:
  * Network/Client Signal
  * Network/Client Manufacturer (OUI)
  * Data packets and `data_per_sec` (packets/s)
  * WPS state configuration dynamically
  * Deep Packet Tracking natively (AssocReq, ProbeReq, Deauth, and EAPOL)
  * WiFi 6 (HE) capabilities via Beacon IE parsing

**2. Python Architecture (`scanner.py`)**
We ripped out the old `AirodumpParser` and the CSV polling loops entirely.
* SWCLI now creates a high-speed memory pipe (`os.mkfifo`) right before starting a scan.
* It launches our custom `airodump-ng` with the `--json` flag, pointing it to the pipe.
* A background thread instantly deserializes the JSON streams as they arrive.
* The rewritten `scanner.py` and `session.py` models have been fully synced to both the `SWCLI` and `Sidewinder` codebases so they perfectly mirror each other. 

---

### Instructions for Ubuntu

When you reboot into your Ubuntu partition, follow these exact steps to compile the custom binary and run SWCLI:

**Step 1: Install Build Dependencies**
Open a terminal and ensure you have the required packages to compile `aircrack-ng` from source:
```bash
sudo apt update
sudo apt install build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre2-dev libhwloc-dev libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils
```

**Step 2: Compile the Custom Binary**
Navigate to the `Refrence Tools/aircrack-ng` folder (which now contains our custom C patches) and compile it:
```bash
cd "/path/to/Sidewinder/Refrence Tools/aircrack-ng"
autoreconf -i
./configure --with-experimental
make
```

**Step 3: Install the Binary System-Wide**
Install your compiled version over the default system version so SWCLI can use it:
```bash
sudo make install
```

**Step 4: Run SWCLI**
Launch your Python environment and start SWCLI normally. When you type `/scan`, it will automatically use the new JSON FIFO pipeline and you will see the UI update instantly with zero lag!
