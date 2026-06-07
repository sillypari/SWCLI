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

---

## Features Added

### FEAT-001: Configurable scan timing rates
- **File:** `sidewinder/core/scanner.py`, `swcli/repl/commands/scan.py`
- **Change:** `ScanEngine.scan()` now accepts `update_secs`, `hop_ms`, `write_interval_secs`, `poll_ms` params. Passed through to airodump-ng as `--update`, `-f`, `--write-interval`. REPL `/scan` prompts for each rate with defaults.
- **Tested:** CONFIRMED — fast (100ms poll) vs slow (500ms poll) both work
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
  - Replaced 4 individual timing prompts with a single "Scan Speed" preset choice: Fast (default), Balanced, Slow, Custom. Custom mode still shows all 4 prompts for power users.
  - Added smart CSV wait: polls for CSV file with data (>100 bytes) before starting the main scan loop, instead of fixed sleep. Handles airodump-ng's 4-5s initialization delay.
  - Added "Waiting for airodump-ng to initialize" status message so user knows scan is starting.
  - Scan completion now shows elapsed time, network count, and memory eviction stats.
- **Tested:** CONFIRMED — first network appears ~5s after scan start (airodump-ng init time)
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
