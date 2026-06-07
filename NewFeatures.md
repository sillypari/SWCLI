# SWCLI: Fork Features to Integrate

> This document tracks what's been done, what's missing, and what to cherry-pick
> from airodump_mod (maroviher/aircrack-ng fork) into our aircracked-ng fork.

---

## 1. What's Already Done

### 1.1 C Source Patches (`Refrence Tools/aircrack-ng/`)

| File | Change | Status |
|------|--------|--------|
| `airodump-ng.c:58-60` | Global vars `opt_json_fifo`, `f_json_file`, forward decl of `dump_write_json()` | DONE |
| `airodump-ng.c:5994` | `long_options[]` does NOT have `--json` entry yet | **MISSING** |
| `airodump-ng.c:6222` | `getopt` string has `J:` for `--json` flag | DONE |
| `airodump-ng.c:6315` | `case 'J':` handler sets `opt_json_fifo = optarg` | DONE |
| `airodump-ng.c:7125,7553` | Calls `dump_write_json()` alongside CSV/Kismet writes | DONE |
| `dump_write.c:1594-1656` | `dump_write_json()` function — outputs single-line JSON per update | DONE |
| `dump_write.h` | Declaration of `dump_write_json()` | **MISSING** |

### 1.2 Python Scanner (`sidewinder/core/scanner.py`)

| Feature | Status |
|---------|--------|
| `os.mkfifo()` FIFO creation | DONE |
| `--json <fifo_path>` flag in airodump-ng cmd | DONE |
| Background thread FIFO reader (`fifo_reader()`) | DONE |
| `json.loads()` parsing in `_parse_json()` | DONE |
| Dedup callbacks (only fire on signal/data change) | DONE |
| Memory limits: MAX_NETWORKS=500, MAX_CLIENTS=1000 | DEFINED but **NOT ENFORCED** |
| Stale eviction (>120s timeout) | DEFINED but **NOT ENFORCED** |
| `get_stats()` method | DONE |
| `on_init` callback | DONE |

---

## 2. What's Missing — Bugs & Gaps

### 2.1 C Source Gaps

#### `dump_write.h` — Missing Declaration
```c
// ADD after line 54, before #endif:
void dump_write_json(struct AP_info * ap_1st,
                     struct ST_info * st_1st,
                     unsigned int f_encrypt);
```
**Impact:** Implicit function declaration warning. May cause linker issues on strict compilers.

#### `long_options[]` — Missing `--json` Entry
The getopt string has `J:` but `long_options[]` at line 5994 has no `{"json", 1, 0, 'J'}` entry. This means `--json` only works via short flag `-J`. Need to add:
```c
// ADD before {0, 0, 0, 0} at line 6029:
{"json", 1, 0, 'J'},
```

#### `dump_write_json()` — Hardcoded `wps: false`
Line 1636 hardcodes `"wps":false`. Should read `ap_cur->wps` (AP_info struct has a `wps` field). Fix:
```c
// Replace "wps":false with:
"wps":%s
// And add to fprintf args:
ap_cur->wps ? "true" : "false"
```

#### `dump_write_json()` — Incomplete JSON String Escaping
Line 1629-1634 only escapes `"` and `\`. Misses:
- Control chars: `\n`, `\r`, `\t`, `\b`, `\f`
- Non-ASCII bytes (UTF-8 ESSIDs like Japanese/Chinese)
- Null bytes in ESSID

Replace with a proper `json_escape_string()` helper:
```c
static void json_escape_string(char *dst, size_t dst_size, const char *src, int src_len) {
    int j = 0;
    for (int i = 0; i < src_len && j < (int)dst_size - 6; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"')  { dst[j++] = '\\'; dst[j++] = '"'; }
        else if (c == '\\') { dst[j++] = '\\'; dst[j++] = '\\'; }
        else if (c == '\n') { dst[j++] = '\\'; dst[j++] = 'n'; }
        else if (c == '\r') { dst[j++] = '\\'; dst[j++] = 'r'; }
        else if (c == '\t') { dst[j++] = '\\'; dst[j++] = 't'; }
        else if (c < 0x20) { j += snprintf(dst+j, dst_size-j, "\\u%04x", c); }
        else { dst[j++] = c; }
    }
    dst[j] = '\0';
}
```

#### `dump_write_json()` — FIFO Deadlock Risk
Line 1600 opens FIFO with `fopen(opt_json_fifo, "w")` which blocks until a reader opens the other end. If Python's `os.mkfifo()` + `open()` races with airodump-ng's `fopen()`, either side can deadlock.

**Fix:** Open with `fopen` in non-blocking mode or use `open(O_WRONLY | O_NONBLOCK)` + `fdopen()`:
```c
int fd = open(opt_json_fifo, O_WRONLY | O_NONBLOCK);
if (fd < 0) return;
f_json_file = fdopen(fd, "w");
```
And in Python, the FIFO reader thread already opens before starting airodump-ng, which is correct. But the C side should also handle EAGAIN gracefully.

#### `dump_write_json()` — Missing `probe` in Client Output
Line 1648 outputs `{mac, bssid, signal, packets}`. Missing `probe` field (probed ESSIDs). Add:
```c
// Add to client fprintf:
",\"probe\":\"%s\""
// And escape st_cur->probes[0] (first probe SSID)
```

#### `dump_write_json()` — No `first_seen`/`last_seen` Timestamps
The Python `Network` and `Client` dataclasses have `first_seen` and `last_seen` fields, but `dump_write_json()` never outputs them. AP_info has `tinit` and `tlast` timestamps. Add:
```c
",\"first_seen\":%ld,\"last_seen\":%ld"
// Add args:
(long)ap_cur->tinit, (long)ap_cur->tlast
```

### 2.2 Python Scanner Gaps

#### Memory Limits Not Enforced
`MAX_NETWORKS=500` and `MAX_CLIENTS=1000` are defined but `_parse_json()` never evicts. Add to `_parse_json()`:
```python
def _enforce_limits(self):
    if len(self.networks) > MAX_NETWORKS:
        # Evict weakest signal
        weakest = min(self.networks, key=lambda b: self.networks[b].signal)
        del self.networks[weakest]
    if len(self.clients) > MAX_CLIENTS:
        # Evict oldest last_seen
        oldest = min(self.clients, key=lambda m: self.clients[m].last_seen)
        del self.clients[oldest]
```

#### Stale Eviction Not Running
`STALE_TIMEOUT_SECS=120` defined but never called. Need a periodic task:
```python
async def _stale_eviction_loop(self):
    while self._running:
        await asyncio.sleep(30)
        now = time.time()
        stale = [b for b, n in self.networks.items()
                 if n.last_seen and (now - float(n.last_seen)) > STALE_TIMEOUT_SECS]
        for b in stale:
            del self.networks[b]
```

#### `probe` Field Missing in Client JSON
`_parse_json()` does `Client(**c_dict)` but `dump_write_json()` doesn't output `probe`. Once C is fixed, Python will auto-receive it.

---

## 3. Cherry-Pick from airodump_mod (maroviher)

These features exist in airodump_mod and should be added to our fork.

### 3.1 Packets/Second Display
**What airodump_mod does:** Calculates `packets/sec` per AP from delta of `nb_data` between update intervals. Displayed as `#/s` column.

**Where to add in C:**
- `dump_write.c`: Add `"packets_per_sec":%d` to JSON output
- Calculate in `dump_write_json()` from `ap_cur->nb_data` delta stored in a static variable
- Or better: add `nb_data_prev` to AP_info struct in `station.h` and compute delta in main loop

**Where to add in Python:**
- `session.py`: Add `packets_per_sec: int = 0` to Network dataclass
- `scanner.py`: `_parse_json()` already handles it via `Network(**n_dict)`

### 3.2 Bytes/Second Display
**What airodump_mod does:** Shows `bytes/sec` from raw data packet sizes.

**Where to add in C:**
- Add `"bytes_per_sec":%lu` to JSON
- Requires tracking `total_bytes` delta in AP_info

**Where to add in Python:**
- `session.py`: Add `bytes_per_sec: int = 0` to Network dataclass

### 3.3 Client Manufacturer (OUI Lookup)
**What airodump_mod does:** Looks up first 3 bytes of client MAC against manufacturer OUI database. Shows vendor name (e.g. "Apple", "Samsung").

**Where to add in C:**
- airodump_mod has `manuf.c` / `manuf.h` with OUI table
- Add `"manufacturer":"%s"` to client JSON output
- Call OUI lookup on `st_cur->stmac` during JSON write

**Where to add in Python:**
- `session.py`: Add `manufacturer: str = ""` to Client dataclass
- `scanner.py`: Handles via `Client(**c_dict)`

### 3.4 Per-Station Protocol Counters
**What airodump_mod does:** Counts EAPOL, Association Request, Association Response, Probe Request, Probe Response, Deauth, Disassoc per client. Displayed as extra columns.

**Where to add in C:**
- ST_info struct in `station.h` already has some counters
- Add `"eapol":%d,"assoc_req":%d,"probe_req":%d,"deauth":%d` to client JSON
- Counters incremented in the frame processing path (aircrack-ng internal)

**Where to add in Python:**
- `session.py`: Add `eapol: int = 0`, `assoc_req: int = 0`, `probe_req: int = 0`, `deauth: int = 0` to Client dataclass

### 3.5 Selection Stability
**What airodump_mod does:** When cursor-selecting a target in interactive mode, the selection doesn't jump around as APs get sorted. Uses a stable sort key.

**Relevance to SWCLI:** LOW — SWCLI doesn't use interactive cursor selection. The REPL selects by BSSID string. Skip unless we add interactive mode later.

### 3.6 802.11ax (WiFi 6) Detection
**What theweefies fork has:** Recognizes HE (High Efficiency) capability in beacon frames. Shows "WPA2" with HE indicator.

**Where to add in C:**
- `airodump-ng.c`: Parse HE capabilities from beacon/tagged parameters
- Add `"he":true/false` to network JSON output
- Already partially in theweefies fork — check if our base has it

**Where to add in Python:**
- `session.py`: Add `he: bool = False` to Network dataclass

---

## 4. Implementation Order

### Phase 1: Fix Current Gaps (C + Python)
1. Add `dump_write_json` declaration to `dump_write.h`
2. Add `{"json", 1, 0, 'J'}` to `long_options[]`
3. Fix WPS hardcoded `false` → read `ap_cur->wps`
4. Add proper `json_escape_string()` for ESSID
5. Add `first_seen`/`last_seen` timestamps to JSON
6. Add `probe` field to client JSON
7. Enforce memory limits in Python `_parse_json()`
8. Add stale eviction loop in Python

### Phase 2: Cherry-Pick airodump_mod Features (C)
1. Add `packets_per_sec` calculation + JSON field
2. Add OUI manufacturer lookup + JSON field
3. Add per-station protocol counters + JSON field
4. Add 802.11ax (HE) detection + JSON field

### Phase 3: Update Python Dataclasses
1. Add new fields to `Network` dataclass: `packets_per_sec`, `bytes_per_sec`, `he`
2. Add new fields to `Client` dataclass: `manufacturer`, `eapol`, `assoc_req`, `probe_req`, `deauth`
3. `scanner.py` `_parse_json()` auto-handles via `**dict` unpacking — no changes needed

### Phase 4: Compile & Test
1. `autoreconf -i && ./configure --with-experimental && make -j$(nproc)`
2. `sudo make install`
3. Test with RTL8821AU on 5GHz
4. Test with RT5370 on 2.4GHz
5. Verify JSON output in FIFO
6. Verify SWCLI display shows all columns

---

## 5. File Reference

| File | What to Change |
|------|----------------|
| `dump_write.h` | Add `dump_write_json()` declaration |
| `dump_write.c` | Fix WPS, add json_escape_string, add timestamps, add probe, add packets_per_sec, add OUI, add protocol counters, add HE flag |
| `airodump-ng.c` | Add `{"json",1,0,'J'}` to long_options[], add HE parsing from beacons |
| `station.h` | Add `nb_data_prev`, `tinit`, `tlast` fields if not present, add per-station counters |
| `scanner.py` | Enforce memory limits, add stale eviction loop |
| `session.py` | Add new fields to Network and Client dataclasses |
