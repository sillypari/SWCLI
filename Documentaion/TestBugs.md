# TestBugs — SWCLI Bug Tracker

Track bugs discovered during debugging. Strikethrough once fixed.

---

## Open Bugs

### ~~BUG-001: `adapters` command — list vs dict mismatch~~
- **Command:** `python3 -m swcli adapters`
- **Error:** `Unexpected error: 'list' object has no attribute 'items'`
- **File:** `cli.py:137`
- **Cause:** `AdapterManager.discover()` returns `list[AdapterInfo]`, but `handle_adapters()` calls `.items()` on the result expecting a `dict`.
- **Status:** FIXED

### ~~BUG-002: `kill` command — tuple vs object mismatch~~
- **Command:** `python3 -m swcli kill`
- **Error:** `Unexpected error: 'tuple' object has no attribute 'pid'`
- **File:** `cli.py:153`
- **Cause:** `ServiceManager.find_conflicting()` returns `list[tuple[int, str]]`, but `handle_kill()` accesses `.pid` and `.name` on tuples instead of unpacking.
- **Status:** FIXED

### ~~BUG-003: `monitor status` — argparse ambiguity~~
- **Command:** `python3 -m swcli monitor status wlx5c628b765de2`
- **Error:** `invalid choice: 'wlx5c628b765de2' (choose from stop, status)`
- **File:** `cli.py:549-560`
- **Cause:** `iface` is an optional positional arg + `monitor_cmd` is an optional subparser. When both are present, argparse gets confused.
- **Status:** FIXED

### ~~BUG-005: `wordlists` — returns empty list~~
- **Command:** `python3 -m swcli wordlists`
- **Output:** `Available wordlists:` (empty)
- **File:** `sidewinder/core/cracker.py`
- **Cause:** `find_wordlists()` found no wordlists. Could be expected if none installed, or paths may not include common locations on this system.
- **Status:** FIXED

### ~~BUG-006: `session list` — not implemented~~
- **Command:** `python3 -m swcli session list`
- **Output:** `Not fully implemented.`
- **File:** `cli.py:505`
- **Status:** FIXED

### ~~DESIGN-003: Missing airodump-ng display fields in scan output~~
- **Issue:** Scan display is missing 4 fields that airodump-ng shows: `#/s` (data/s), `Rate`, `Lost`, `Notes`
- **File:** `swcli/repl/commands/scan.py` (_build_scan_display)
- **Analysis:** All 4 fields are **not in the CSV file** — airodump-ng computes them internally but never writes them. They are display-only diagnostics:
  - `#/s` = data delta / time delta — accurate within refresh interval but not critical for auditing
  - `Rate` = driver-reported data rate — diagnostic only
  - `Lost` = estimated packet loss — approximate
  - `Notes` = internal state, almost always empty
- **Fix:** Implemented custom C patch for `airodump-ng` adding a `--json` FIFO output, bypassing CSV entirely and delivering exact internal memory state instantly to the Python backend.
- **Status:** FIXED

### ~~BUG-008: Scan reads stale CSV — missing networks and clients~~
- **Command:** `/scan` (REPL)
- **Error:** Display shows fewer networks/clients than airodump-ng actually finds (e.g. 2 networks, 1 client vs actual 3 networks, 4 clients)
- **File:** `sidewinder/core/scanner.py:323` (scan method)
- **Cause:** airodump-ng creates numbered CSV files (`-01.csv`, `-02.csv`, ...) as it hops channels. Code always read `capture_prefix-01.csv`, which was stale from a previous scan. Each new `/scan` run created new numbered files, so the latest data was in `-05.csv` or `-06.csv` but we kept reading the old `-01.csv`.
- **Fix:** Architecture overhauled to use real-time JSON FIFO, completely eliminating all CSV file management issues.
- **Tested:** CONFIRMED — user verified fix shows correct data
- **Status:** FIXED

---

## Fixed Bugs

### ~~BUG-007: Scanner returns empty results (CSV 0 bytes)~~
- **Command:** `/scan` (REPL) or `ScanEngine.scan()`
- **Error:** airodump-ng runs but CSV file is 0 bytes; no networks discovered
- **File:** `sidewinder/core/subprocess_mgr.py:173-176`
- **Cause:** `start_background()` piped stdout/stderr to `asyncio.subprocess.PIPE` but never consumed them. airodump-ng writes screen refresh escape sequences to stdout; when the 64KB pipe buffer fills, the process blocks and cannot write the CSV file.
- **Fix:** Changed `start_background()` to redirect stdout/stderr to `asyncio.subprocess.DEVNULL` instead of `PIPE`.
- **Tested:** CONFIRMED WORKING — scan now discovers NASA, Camp, vivo Y29 5G; CSV is 775 bytes
- **Status:** FIXED

### ~~BUG-004: `monitor start` — kernel rejects monitor VIF on mt7601u~~
- **Command:** `/monitor` (REPL) with adapter wlx001ea6c65744 (mt7601u)
- **Error:**
  ```
  Command failed (rc=234): iw phy phy1 interface add wlx001ea6c65744mon type monitor
  stderr: kernel reports: Attribute failed policy validation
  command failed: Invalid argument (-22)
  ```
- **File:** `sidewinder/core/monitor.py`
- **Cause:** The mt7601u driver does not support creating a new monitor VIF via `iw phy ... interface add`.
- **Fix:** Added try/except fallback in `enter_monitor_mode()` — tries standard path first with `check=False`, falls back to `enter_monitor_mode_bad_driver()` on failure. Also fixed `exit_monitor_mode()` to handle bad driver path correctly.
- **Tested:** CONFIRMED WORKING on mt7601u (wlx001ea6c65744) — enter and exit cycle clean
- **Status:** FIXED

### ~~DESIGN-001: Remove channel prompt from monitor mode entry~~
- **Issue:** Channel prompt during monitor mode entry is unnecessary — airodump-ng handles channel hopping during scan.
- **Fix:** Removed channel prompt from REPL `/monitor` command. Channel defaults to 6 silently.
- **Status:** FIXED

### ~~DESIGN-002: Clean up error output during fallback~~
- **Issue:** When standard monitor mode fails, verbose error messages were printed before fallback, confusing users.
- **Fix:** Changed `enter_monitor_mode()` to use `check=False` for VIF creation and handle errors silently. Updated REPL to show clean success message.
- **Tested:** CONFIRMED WORKING — clean output on mt7601u
- **Status:** FIXED

### ~~BUG-009: Scan refresh rate sluggishness & JSON queue starvation~~
- **Command:** `/scan` (REPL)
- **Error:** Refresh rate and channel hopping did not update in real-time.
- **File:** `sidewinder/core/scanner.py`, `swcli/repl/commands/scan.py`
- **Cause:** 
  1. `airodump-ng` is called with `--update 0.1` but uses `strtol()` in C which parses floats as `0` and sets update interval to 100,000 seconds (disabling UI/CSV updates, but writing JSON to FIFO on every packet).
  2. Python's main thread spun in a tight loop with `await asyncio.sleep(0)`, starving the async queue consumer and background reader threads.
  3. Reading and parsing every packet's JSON dump created high CPU overhead.
- **Fix:**
  - Omitted `--update` when `< 1` to fall back to `airodump-ng`'s native 100ms refresh cycle.
  - Used `collections.deque(maxlen=1)` in Python to efficiently drop intermediate updates and only parse the absolute latest state.
  - Replaced `await asyncio.sleep(0)` with `await asyncio.sleep(poll_ms / 1000.0)` in the UI render loop to allow GIL sharing.
  - Dynamically set the `Live` screen refresh FPS: `refresh_fps = max(1, int(1000 / poll_ms))` to align UI with polling.
- **Status:** FIXED

### ~~BUG-010: Unawaited `detect_adapter` coroutine warning~~
- **Command:** Launching/exiting `/scan` (REPL)
- **Error:** `RuntimeWarning: coroutine 'detect_adapter' was never awaited`
- **File:** `swcli/repl/commands/scan.py:177`
- **Cause:** `detect_adapter` is an async function but was called synchronously as `chip = detect_adapter(iface_name)`.
- **Fix:** Changed to `chip = await detect_adapter(iface_name)`.
- **Status:** FIXED

### ~~BUG-011: All (2.4+5GHz) band selection shows 5GHz channel prompt~~
- **Command:** `/scan` (REPL) -> All (2.4+5GHz)
- **Error:** Prompts user to select 5GHz UNII channels.
- **File:** `swcli/repl/commands/scan.py:202`
- **Cause:** Condition was `"5GHz" in band_val`, which evaluated to `True` for `"All (2.4+5GHz)"`.
- **Fix:** Replaced with exact equality check `band_val == "5GHz (a)"` and added `band_val == "All (2.4+5GHz)"` handling.
### ~~BUG-012: Power -1 (unknown) networks sorted at top and not evicted correctly~~
- **Command:** `/scan` (REPL)
- **Error:** Networks with unknown signal (`-1`) were sorted at the very top of the scan results and never evicted during capacity limits.
- **File:** `swcli/repl/commands/scan.py:123`, `sidewinder/core/scanner.py:197,234`
- **Cause:** Python sorts negative integers in ascending order, meaning `-1` was evaluated as a stronger signal than actual RSSI values (e.g. `-50` to `-90`). Thus, unknown networks hovered at the top of the UI and avoided being identified as the `weakest` for limit eviction.
- **Fix:** Used a sorting lambda that maps `-1` to `-999` to ensure unknown signal networks are sorted at the bottom and evicted first.
- **Status:** FIXED

### ~~BUG-013: Scan table duplicate printing / header wrapping misalignment~~
- **Command:** `/scan` (REPL)
- **Error:** When the terminal size is narrow or when rows are added, Rich's `Live(screen=False)` cursor repositioning calculations get corrupted, leaving residual headers and tables printed repeatedly below the current view.
- **File:** `swcli/repl/commands/scan.py:293`
- **Cause:** Carriage return (`\r`) and cursor-up movement escape sequences get misaligned when wide table headers/rows wrap onto multiple physical lines or when the table size increases dynamically.
- **Fix:** Switched `Live` to use the alternate screen buffer (`screen=True`) to perform flicker-free, isolated rendering. Added code to render and print the final, complete scan table onto the normal console scrollback *after* the live view terminates, so the scan results remain visible in standard scrollback history.
- **Status:** FIXED

### ~~BUG-014: Scapy PcapReader raises Scapy_Exception: No data could be read!~~
- **Command:** `/capture deauth` (REPL)
- **Error:** `UNEXPECTED ERROR: Scapy_Exception: No data could be read!`
- **File:** `sidewinder/core/capture.py:197`
- **Cause:** When the capture command initializes, `PcapReader` is instantiated immediately on the new cap file. If `airodump-ng` has not yet flushed the initial 24-byte PCAP header to disk, Scapy fails to parse the empty/short file and raises a `Scapy_Exception`.
- **Fix:** Delayed `PcapReader` instantiation in `poll_eapol` until the PCAP file has grown to at least 24 bytes (the minimal PCAP file header size) and wrapped initialization in a try/except retry block inside the polling loop.
- **Status:** FIXED

---

## Features Added

### FEAT-001: Configurable scan timing and refresh rates
- **File:** `sidewinder/core/scanner.py`, `swcli/repl/commands/scan.py`
- **Change:** Renamed `Timing preset` prompt to `Refresh rate` and mapped custom input properties (`update_secs`, `hop_ms`, `poll_ms`) to dynamically configure both the `airodump-ng` channel hopping frequency and the Rich `Live` screen render FPS.
- **Status:** DONE

### FEAT-002: Memory management
- **File:** `sidewinder/core/scanner.py`
- **Changes:**
  - **Max networks (500):** Evicts weakest-signal entries when full
  - **Max clients (1000):** Evicts oldest `last_seen` entries when full
  - **Stale eviction (120s):** Removes entries not seen for >120s (runs every ~10 cycles)
  - **Dedup callbacks:** Tracks `_nets_reported` / `_clis_reported`, only fires callback on first seen or changed data
  - **Reuse parser:** `AirodumpParser` reused across cycles with `reset()` instead of creating new instance
  - **Line-by-line CSV read:** Reads file line-by-line instead of loading entire file into memory
  - **`get_stats()` method:** Returns eviction counts and current store sizes
- **Tested:** CONFIRMED
  - Cap eviction: 600 → 500 networks, weakest (-529 dBm) removed first
  - Stale eviction: Old entries (6 days) removed correctly
  - Client cap: 1100 → 1000 clients, oldest removed
  - Dedup: 3 callbacks vs 28 before (same 8s scan)
  - Memory: 268KB current, 406KB peak
- **Status:** DONE

### FEAT-003: Scan UX simplification
- **File:** `swcli/repl/commands/scan.py`, `sidewinder/core/scanner.py`
- **Changes:**
  - Replaced 4 individual timing prompts with a single "Scan Speed" preset choice (renamed to "Refresh rate"): Fast (default), Balanced, Slow, Custom. Custom mode still shows prompts for power users.
  - Implemented a 3.5s initialization countdown warm-up message when starting a scan to inform the user about the dump startup delay.
  - Scan completion now shows elapsed time, network count, and memory eviction stats.
- **Tested:** CONFIRMED — countdown prints, clearing screen only when warm-up completes
- **Status:** DONE

### FEAT-004: `/monitor status` command
- **File:** `swcli/repl/commands/monitor.py`
- **Change:** New subcommand that shows monitor mode status from session state and live sysfs check (type=803 = monitor).
- **Tested:** CONFIRMED — correctly shows "INACTIVE" when in managed mode
- **Status:** DONE

### FEAT-005: Custom airodump-ng JSON FIFO Pipeline
- **File:** `airodump-ng.c`, `dump_write.c`, `scanner.py`, `session.py`, `scan.py`
- **Changes:**
  - Patched `airodump-ng` C source to support `--json <fifo>` output using `O_NONBLOCK` pipes.
  - Replaced Python CSV polling loops with real-time background FIFO reading.
  - Implemented deep packet parsing in C: WiFi 6 (HE) capabilities, per-station EAPOL, AssocReq, ProbeReq, and Deauth counters, dynamic WPS state, data/s, and OUI manufacturers.
  - Updated SWCLI Rich UI tables to show `HE`, `Data/s`, and `EAPOL/Assoc` live.
- **Tested:** CONFIRMED — JSON correctly parsed by Python backend and updates UI instantly.
### FEAT-006: Interactive keyboard shortcuts & unassociated probes
- **File:** `swcli/repl/commands/scan.py`, `sidewinder/core/scanner.py`
- **Changes:**
  - Removed BSSID broadcast filter to allow processing and tracking of unassociated probing clients.
  - Rendered unassociated client entries with BSSID displayed as `(not associated)` and empty ESSID.
  - Removed interactive key commands mimicking `airodump-ng` (`o`, `p`, `s`, `i`, `space`, `a`, `tab`, arrow keys) to ensure zero input latency or terminal lockups.
- **Status:** DONE

### FEAT-007: Interactive target & adapter selection for Deauth commands
- **File:** `swcli/repl/commands/capture.py`, `swcli/repl/commands/attack.py`
- **Changes:**
  - Implemented automatic monitor interface discovery & prompt choice interface for selection.
  - Implemented interactive BSSID (AP) selection listing active scanned networks from the session, with manual fallback.
  - Implemented client station target selection listing clients associated with the targeted AP, with manual and broadcast (`FF:FF:FF:FF:FF:FF`) choices.
  - Added custom prompt option to specify the number of deauth packets to send.
  - Shared this logic across both `/capture deauth` and `/attack deauth`, fixing a crash bug in `/attack deauth` caused by a missing `output_prefix` argument.
- **Status:** DONE

### FEAT-008: Real-time progress feedback during handshake capture
- **File:** `swcli/repl/commands/capture.py`
- **Changes:**
  - Added real-time progress printing callback `on_progress` to both `/capture passive` and `/capture deauth`.
  - The UI now shows the live status (e.g. `WAITING`, `PARTIAL`, `FULL`) and indicates exactly which handshake messages (`M1`, `M2`, `M3`, `M4`) have been captured so far.
  - Added user interrupt handling (`Ctrl+C`) to cleanly abort passive and active capture processes instead of hanging/freezing.
- **Status:** DONE

---

## Architecture Analysis: SWCLI vs Original Sidewinder

### airmon-ng Bypass
**Confirmed:** Both SWCLI and original Sidewinder **bypass airmon-ng** for monitor mode management.
- Use direct `iw`/`ip` calls instead
- 10x faster (0.2s vs 2s)
- Full adapter-specific control

**What was bypassed vs what's still used:**

| Tool | Purpose | Status in SWCLI |
|------|---------|-----------------|
| **airmon-ng** | Start/stop monitor mode | **BYPASSED** (direct `iw`/`ip`) |
| **airodump-ng** | Scan networks (channel hop + capture) | **USED** |
| **aireplay-ng** | Send deauth frames | **USED** |
| **aircrack-ng** | Crack passwords | **USED** |

**Why bypass airmon-ng but keep airodump-ng?**
- airmon-ng is a 1,439-line bash wrapper that does nothing magic — just calls `iw`/`ip`
- airodump-ng is a compiled C binary that does real-time channel hopping and packet capture at kernel level — reimplementing in Python would be slower and pointless

### Original Sidewinder Code Quality Assessment
**Verdict: ROBUST** — Well-designed async architecture with:
- Clean ABC adapter pattern (`Adapter` base class)
- CARD_SETTINGS matrix for per-adapter optimization
- MonitorWatcher for mode loss detection
- Proper docstrings and error handling
- sysfs-based mode detection (no polling)

### SWCLI Improvements Over Original
SWCLI has improved on the original in key areas:

| Feature | Original | SWCLI | Impact |
|---------|----------|-------|--------|
| Auto-fallback (standard → bad driver) | ❌ | ✅ | mt7601u works without manual selection |
| check=False on VIF creation | ❌ | ✅ | No verbose error output on fallback |
| VIF existence verification | ❌ | ✅ | Catches silent failures |
| Bad driver: channel + TX power | ❌ | ✅ | Proper initialization |
| Exit: detect bad driver path | ❌ | ✅ | Correct cleanup for both paths |
| Configurable scan timing rates | ❌ | ✅ | User controls update/hop/write/poll rates |
| Memory management (caps + stale) | ❌ | ✅ | Prevents unbounded memory growth |
| Dedup callbacks | ❌ | ✅ | Only fires on first seen or changed data |
| Reuse parser across cycles | ❌ | ✅ | No alloc per poll cycle |

### Remaining Open Bugs
See Open Bugs section above (BUG-001 to BUG-003, BUG-005, BUG-006)

---

## Pipeline Test Results

| Step | Component | Status | Notes |
|------|-----------|--------|-------|
| 1 | Adapter detection | PASS | mt7601u detected correctly |
| 2 | Monitor mode entry | PASS | Falls back to bad driver path silently |
| 3 | Scan (airodump-ng) | PASS | Networks discovered, CSV created |
| 4 | CSV parser | PASS | Networks and clients parsed correctly |
| 5 | Exit monitor mode | PASS | Restores managed mode cleanly |
| 6 | Memory management | PASS | Caps, stale eviction, dedup all working |
| 7 | Validate handshake | NOT TESTED | Requires target network |
| 8 | Capture handshake | NOT TESTED | Requires target network |
| 9 | Cleanup | NOT TESTED | — |
