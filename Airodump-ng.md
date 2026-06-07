# Airodump-ng Keyboard Shortcuts

> Reference from `airodump-ng.c` source code.
> Used by SWCLI's custom JSON FIFO pipeline (`--json` flag).

---

## Interactive Keys (during scan)

| Key | Action | Details |
|-----|--------|---------|
| `s` | Cycle sort mode | first seen → BSSID → power → beacon → data → packet rate → channel → Mbps → encryption → cipher → auth → ESSID |
| `i` | Invert sort order | Toggles between normal and reversed sort |
| `r` | Toggle realtime sorting | Re-sorts display on every update |
| `TAB` | Toggle AP selection | Enables/disables arrow key navigation |
| `↑` | Navigate to next AP | When selection enabled, moves to previous AP |
| `↓` | Navigate to previous AP | When selection enabled, moves to next AP |
| `m` | Mark selected AP | Highlights the currently selected AP |
| `d` | Reset selection | Resets to default selection state |
| `a` | Cycle display mode | AP+STA → AP only → STA only → AP+STA+ACK |
| `o` | Color ON | Enables colored output |
| `p` | Color OFF | Disables colored output |
| `SPACE` | Pause/resume | Pauses or resumes screen output |
| `q` | Quit | Press twice to confirm exit |

---

## Sort Modes (cycles with `s`)

| Mode | Sort By |
|------|---------|
| 0 | First seen (default) |
| 1 | BSSID |
| 2 | Power level |
| 3 | Beacon count |
| 4 | Data packet count |
| 5 | Packet rate |
| 6 | Channel |
| 7 | Max data rate (Mbps) |
| 8 | Encryption |
| 9 | Cipher |
| 10 | Authentication |
| 11 | ESSID |

---

## Display Modes (cycles with `a`)

| State | show_ap | show_sta | show_ack | Description |
|-------|---------|----------|----------|-------------|
| 1 | 1 | 1 | 0 | AP + STA (default) |
| 2 | 1 | 0 | 0 | AP only |
| 3 | 0 | 1 | 0 | STA only |
| 4 | 1 | 1 | 1 | AP + STA + ACK stats |

---

## Key Source Locations

- Key handling: `airodump-ng.c:455-701`
- Sort definitions: `airodump-ng.c:249-250` (`sort_by`, `sort_inv`)
- Color functions: `airodump-ng.c:324` (`color_on()`)
- Display toggle: `airodump-ng.c:651-683` (`show_ap`, `show_sta`, `show_ack`)
- Pause: `airodump-ng.c:561-577` (`do_pause`)
- Selection: `airodump-ng.c:631-649` (`p_selected_ap`)
- SORT constants: `airodump-ng.h` (SORT_BY_NOTHING through SORT_BY_ESSID)

---

## SWCLI Integration Status

| Key | SWCLI Support | Notes |
|-----|---------------|-------|
| `p` | Implemented | Toggles probe-only client filter |
| `s` | Not implemented | Would toggle sort order in display |
| `a` | Not implemented | Would toggle AP/client/both display |
| `SPACE` | Not implemented | Would pause/resume live display |
| `TAB` | Not implemented | Would enable target selection mode |
| `o`/`p` color | N/A | SWCLI uses Rich for styling |
