# Patched airodump-ng JSON for SWCLI Scan Tables

## Why this exists

SWCLI can display extra scan table fields, but only if the `airodump-ng` binary
emits those fields in its JSON FIFO output.

The Python/SWCLI code and the `airodump-ng` executable are separate:

- SWCLI code reads and displays JSON fields.
- The patched `airodump-ng` binary creates those JSON fields.

If SWCLI is updated from GitHub but the machine still runs the stock
`/usr/sbin/airodump-ng`, some fields will show default or unknown values.

## Fields that require patched JSON

Access point fields:

- `MANUF` - manufacturer from MAC OUI lookup.
- `RXQ` - receive quality. SWCLI shows this only when advanced scan info is enabled and the scan is fixed to one channel.

Client fields:

- `MANUF` - client manufacturer from MAC OUI lookup.
- `RATE` - AP-to-client/client-to-AP bitrate in Mbit/s. Hidden by default.
- `LOST` - airodump estimated missed packets. Hidden by default.
- `FRAMES` - client frame count. Hidden by default.

## Default lightweight scan mode

SWCLI keeps the scan table lightweight by default:

- Manufacturer is shown because it is useful and low cost.
- Advanced fields are hidden unless `advanced_scan_info` is enabled.
- Raw scan `.cap` writing is disabled unless `keep_scan_captures` is enabled.

To show the advanced fields:

```bash
/config set
```

Then choose:

```text
advanced_scan_info = true
```

For a one-off shell override:

```bash
export SWCLI_ADVANCED_SCAN_INFO=1
```

## Current local binary

On the working machine, the patched executable was installed here:

```bash
/home/codex/Tools/bin/airodump-ng
```

The original system link was backed up here:

```bash
/home/codex/Tools/bin/airodump-ng.system-link.bak
```

SWCLI prefers the patched path by default, but it also supports an override:

```bash
export SWCLI_AIRODUMP_NG=/path/to/patched/airodump-ng
```

## How to verify the binary is patched

Run:

```bash
which airodump-ng
strings "$(which airodump-ng)" | grep -E '"rxq"|"rate_to"|"rate_from"|"frames"|"lost"'
```

Expected output should include JSON format strings containing:

```text
"rxq"
"frames"
"rate_to"
"rate_from"
"lost"
```

If those strings are missing, the active binary is not patched.

## How to verify SWCLI is using the patched binary

From Python:

```bash
python3 - <<'PY'
from sidewinder.core.scanner import _airodump_ng_path
print(_airodump_ng_path())
PY
```

Expected output on this machine:

```text
/home/codex/Tools/bin/airodump-ng
```

If using another path, set:

```bash
export SWCLI_AIRODUMP_NG=/path/to/patched/airodump-ng
```

## Important behavior notes

- `RXQ` is only meaningful on fixed-channel scans. Do not show or trust it while channel hopping.
- `RATE` is displayed as `AP-to-client/client-to-AP`, for example `24/6`.
- `RATE` is diagnostic. It comes from radiotap metadata and can jump between packets.
- Low rates like `1`, `2`, or `6` can be normal for management/control/fallback traffic.
- Old saved sessions will not magically get these fields. Run a fresh scan after using the patched binary.

## Scan capture disk usage

The advanced table fields do not directly make `.cap` files larger. They are
counters derived from packets seen by `airodump-ng`.

Large scan files happen when `airodump-ng` is asked to write raw packet captures
while a scan is running. Busy fixed-channel scans can grow quickly, and hop mode
can still grow if the area is busy.

SWCLI does not write raw scan `.cap` files by default. Use `/capture` when the
goal is to collect a handshake.

To make `/scan` write raw scan captures anyway, set this in SWCLI config:

```bash
/config set
```

Then choose:

```text
keep_scan_captures = true
```

For a one-off shell override:

```bash
export SWCLI_KEEP_SCAN_CAP=1
```

## If fields show defaults

Symptoms:

- `RXQ` shows `-`
- `RATE` shows `-/-`
- `FRAMES` shows `0`

Checklist:

1. Confirm SWCLI was restarted after changes.
2. Confirm `SWCLI_AIRODUMP_NG` points to a patched binary, or that `/home/codex/Tools/bin/airodump-ng` exists.
3. Confirm the patched binary contains the JSON keys with `strings`.
4. Run a fresh scan. Old session data may still be missing the fields.
5. If `RATE` still shows `-/-` but `FRAMES` works, the adapter/driver may not be reporting bitrate metadata for those packets.

## Rebuild reminder

The patched binary is local machine state and is not committed to the SWCLI GitHub
repo. GitHub contains the SWCLI reader/display code, not the compiled
`airodump-ng` executable.

On a new machine, rebuild or copy a patched `airodump-ng`, then point SWCLI at it
with `SWCLI_AIRODUMP_NG`.
