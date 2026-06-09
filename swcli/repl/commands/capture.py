import os
import asyncio
import time
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_mac, prompt_channel, prompt_confirm, prompt_choice
from swcli.repl.session_ui import auto_fill_prompt
from sidewinder.core.capture import (
    capture_passive,
    capture_deauth,
    delete_capture_segments,
    extract_handshake_messages,
    validate_handshake,
)
from sidewinder.core.config import SidewinderConfig
from sidewinder.core.paths import capture_prefix
from sidewinder.attacks.pmkid import PMKIDEngine
from sidewinder.core.attack import AttackConfig
from rich.live import Live
from swcli.repl.renderer import (
    build_handshake_progress_panel,
    console,
    print_success,
    print_error,
    print_warning,
)

def _keep_or_delete_capture(repl, cap_file, result):
    cfg = SidewinderConfig.load()
    cap_exists = os.path.exists(cap_file)
    validation = result or (validate_handshake(cap_file) if cap_exists else None)
    has_eapol = bool(validation and validation.eapol_count)

    if cap_exists and (has_eapol or cfg.save_captures_without_eapol):
        repl.session.last_cap_file = cap_file
        if cap_file not in repl.session.captures:
            repl.session.captures.append(cap_file)
        if validation:
            repl.session.handshake = validation
        return True, validation

    deleted = delete_capture_segments(cap_file)
    if deleted:
        print_warning(
            "No EAPOL detected; generated .cap file was not saved. "
            "Toggle save_captures_without_eapol in /config set to keep these files."
        )
    return False, validation


async def _get_capture_params(repl):
    from sidewinder.core.adapter import list_interfaces, get_interface_mode, detect_adapter
    
    monitor_ifaces = []
    for iface_name in list_interfaces():
        mode = get_interface_mode(iface_name)
        if mode == "monitor":
            chip = await detect_adapter(iface_name)
            chip_str = f" ({chip.chipset})" if (chip and chip.chipset) else ""
            monitor_ifaces.append((iface_name, chip_str))
            
    if not monitor_ifaces:
        print_error("No monitor interfaces found. Run /monitor first.")
        return None
        
    if len(monitor_ifaces) == 1:
        iface = monitor_ifaces[0][0]
        repl.print(f"  Using monitor interface: [cyan]{iface}[/cyan]{monitor_ifaces[0][1]}")
    else:
        choices = [f"{name}{chip}" for name, chip in monitor_ifaces]
        res = prompt_choice("Select monitor interface", choices)
        if res.cancelled:
            return None
        iface = res.value.split(" ")[0]

    selected = getattr(repl.session, "selected_target", None)
    if selected:
        repl.print(f"  Active target: [cyan]{selected.display_name()}[/cyan] ({selected.bssid}) ch {selected.channel}")
    bssid_res = prompt_mac(*auto_fill_prompt(repl.session, "bssid", "Target BSSID"))
    if bssid_res.cancelled: return None
    
    ch = repl.session.get_channel_for_bssid(bssid_res.value)
    if ch: repl.session.last_channel = ch
    
    ch_res = prompt_channel("Channel", default=ch or 6)
    if ch_res.cancelled: return None
    
    repl.session.last_iface = iface
    repl.session.last_bssid = bssid_res.value
    repl.session.last_channel = ch_res.value
    return iface, bssid_res.value, ch_res.value

async def _get_deauth_params(repl, default_count=10):
    from sidewinder.core.adapter import list_interfaces, get_interface_mode, detect_adapter
    
    # 1. Interface selection
    monitor_ifaces = []
    for iface_name in list_interfaces():
        mode = get_interface_mode(iface_name)
        if mode == "monitor":
            chip = await detect_adapter(iface_name)
            chip_str = f" ({chip.chipset})" if (chip and chip.chipset) else ""
            monitor_ifaces.append((iface_name, chip_str))
            
    if not monitor_ifaces:
        print_error("No monitor interfaces found. Run /monitor first.")
        return None
        
    if len(monitor_ifaces) == 1:
        iface = monitor_ifaces[0][0]
        repl.print(f"  Using monitor interface: [cyan]{iface}[/cyan]{monitor_ifaces[0][1]}")
    else:
        choices = [f"{name}{chip}" for name, chip in monitor_ifaces]
        res = prompt_choice("Select monitor interface", choices)
        if res.cancelled:
            return None
        iface = res.value.split(" ")[0]

    # 2. BSSID selection (Access Point)
    bssid = None
    channel = None
    
    scan_results = repl.session.scan_results
    selected = getattr(repl.session, "selected_target", None)
    if selected:
        repl.print(f"  Active target: [cyan]{selected.display_name()}[/cyan] ({selected.bssid}) ch {selected.channel}")
    if scan_results:
        # Construct list of discovered networks
        choices = []
        net_map = {}
        if selected:
            label = f"Use active target: {selected.display_name()} ({selected.bssid}) - Ch {selected.channel} [signal: {selected.signal} dBm]"
            choices.append(label)
            net_map[label] = selected
        for net in scan_results:
            label = f"{net.display_name()} ({net.bssid}) - Ch {net.channel} [signal: {net.signal} dBm]"
            choices.append(label)
            net_map[label] = net
            
        choices.append("Enter BSSID manually")
        res = prompt_choice("Select target Access Point", choices)
        if res.cancelled:
            return None
            
        if res.value == "Enter BSSID manually":
            bssid_res = prompt_mac(*auto_fill_prompt(repl.session, "bssid", "Target BSSID"))
            if bssid_res.cancelled: return None
            bssid = bssid_res.value
            
            ch = repl.session.get_channel_for_bssid(bssid)
            ch_res = prompt_channel("Channel", default=ch or 6)
            if ch_res.cancelled: return None
            channel = ch_res.value
        else:
            selected_net = net_map[res.value]
            bssid = selected_net.bssid
            channel = selected_net.channel
            repl.print(f"  Selected AP: [cyan]{selected_net.display_name()}[/cyan] ({bssid}) on Channel {channel}")
    else:
        # No scan results, prompt manually
        bssid_res = prompt_mac(*auto_fill_prompt(repl.session, "bssid", "Target BSSID"))
        if bssid_res.cancelled: return None
        bssid = bssid_res.value
        
        ch = repl.session.get_channel_for_bssid(bssid)
        ch_res = prompt_channel("Channel", default=ch or 6)
        if ch_res.cancelled: return None
        channel = ch_res.value

    # Check for multi-band target
    scan_results = getattr(repl.session, "scan_results", [])
    target_net = next((n for n in scan_results if n.bssid.upper() == bssid.upper()), None)
    if target_net and target_net.essid and target_net.display_name() not in ("[HIDDEN]", "[MANUAL]"):
        target_name = target_net.display_name().strip()
        related = [n for n in scan_results if n.bssid != target_net.bssid and n.display_name().strip() == target_name and n.channel != target_net.channel]
        if related:
            repl.print("\n  [bold yellow][WARNING] Multi-Band Target Detected![/bold yellow]")
            repl.print(f"  Target ESSID '{target_net.display_name()}' spans channels: {channel} and {', '.join(str(n.channel) for n in related)}")
            repl.print("  [yellow]Deauthenticating clients may cause them to seamlessly roam to the other band,[/yellow]")
            repl.print("  [yellow]resulting in a missed handshake if only monitoring one channel.[/yellow]\n")
            
            choices = [f"Continue on current channel {channel} only (May miss roam)"]
            avail_ifaces = [name for name, chip in monitor_ifaces if name != iface]
            if avail_ifaces:
                choices.insert(0, "Dual-Adapter Capture - Monitor both bands simultaneously (Recommended)")
            choices.append(f"Follow the Roam - Hop between {channel} and {related[0].channel} (Not recommended)")
            
            res = prompt_choice("How would you like to proceed?", choices)
            if res.cancelled: return None
            
            if "Follow the Roam" in res.value:
                channel = f"{channel},{related[0].channel}"
            elif "Dual-Adapter" in res.value:
                if len(avail_ifaces) == 1:
                    sec_iface = avail_ifaces[0]
                else:
                    sec_res = prompt_choice("Select secondary monitor interface for 5GHz:", [f"{name}{chip}" for name, chip in monitor_ifaces if name != iface])
                    if sec_res.cancelled: return None
                    sec_iface = sec_res.value.split(" ")[0]
                iface = (iface, sec_iface)
                channel = (int(channel), int(related[0].channel))

    # 3. Client MAC selection
    client = "FF:FF:FF:FF:FF:FF"
    clients = repl.session.clients
    associated_clients = []
    if clients and bssid:
        associated_clients = [c for c in clients if c.bssid.upper() == bssid.upper()]

    if associated_clients:
        cli_choices = ["All Stations (Broadcast)"]
        cli_map = {}
        for c in associated_clients:
            label = f"{c.mac} [signal: {c.signal} dBm, packets: {c.packets}]"
            cli_choices.append(label)
            cli_map[label] = c.mac
        cli_choices.append("Enter Client MAC manually")
        
        res = prompt_choice("Select client station to target", cli_choices)
        if res.cancelled:
            return None
            
        if res.value == "All Stations (Broadcast)":
            client = "FF:FF:FF:FF:FF:FF"
        elif res.value == "Enter Client MAC manually":
            cli_res = prompt_mac("Client MAC", default="FF:FF:FF:FF:FF:FF", allow_broadcast=True)
            if cli_res.cancelled: return None
            client = cli_res.value
        else:
            client = cli_map[res.value]
            repl.print(f"  Targeting Client: [cyan]{client}[/cyan]")
    else:
        cli_res = prompt_mac("Client MAC (Enter for Broadcast)", default="FF:FF:FF:FF:FF:FF", allow_broadcast=True)
        if cli_res.cancelled: return None
        client = cli_res.value

    repl.session.selected_client = client

    # 4. Deauth packet count selection
    count_res = prompt_text("Number of deauth packets to send", default=str(default_count))
    if count_res.cancelled: return None
    try:
        count = int(count_res.value)
    except ValueError:
        count = default_count

    # 5. Deauth rate selection
    rate_choices = {
        "Recommended (128 pps)": 128,
        "Fast (256 pps)": 256,
        "Slow (64 pps)": 64,
        "Custom...": -1,
    }
    rate_res = prompt_choice("Deauth packet rate", list(rate_choices.keys()), default=0)
    if rate_res.cancelled: return None
    
    rate = rate_choices[rate_res.value]
    if rate == -1:
        custom_rate_res = prompt_text("Custom rate (packets per second)", default="128")
        if custom_rate_res.cancelled: return None
        try:
            rate = int(custom_rate_res.value)
        except ValueError:
            rate = 128

    # Save to session
    repl.session.last_iface = iface
    repl.session.last_bssid = bssid
    repl.session.last_channel = channel

    return iface, bssid, channel, client, count, rate

async def cmd_capture_passive(repl):
    params = await _get_capture_params(repl)
    if not params: return
    iface, bssid, channel = params
    
    conf = prompt_confirm("Start Passive Capture?")
    if conf.cancelled or not conf.value: return
    
    out = capture_prefix("passive")
    repl.print("\n  [cyan]Listening for handshakes...[/cyan]")
    start = time.monotonic()
    state = {"m1": False, "m2": False, "m3": False, "m4": False, "status": "waiting", "activity": "|", "analysis_passes": 0}
    activity_frames = ("|", "/", "-", "\\")
    done = False

    def render():
        return build_handshake_progress_panel(
            title="Passive Capture",
            iface=iface,
            bssid=bssid,
            client="FF:FF:FF:FF:FF:FF",
            channel=channel,
            count=0,
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

    try:
        with Live(render(), console=console, refresh_per_second=6, transient=False) as live:
            anim_task = asyncio.create_task(animate(live))
            def on_progress(m1, m2, m3, m4, status):
                state.update({"m1": m1, "m2": m2, "m3": m3, "m4": m4, "status": status})
                live.update(render(), refresh=True)

            try:
                res = await capture_passive(
                    mon_iface=iface,
                    bssid=bssid,
                    channel=channel,
                    output_prefix=out,
                    timeout=300,
                    on_progress=on_progress
                )
            finally:
                done = True
                anim_task.cancel()
                try:
                    await anim_task
                except asyncio.CancelledError:
                    pass
            live.update(render(), refresh=True)
        kept, validation = _keep_or_delete_capture(repl, out + "-01.cap", res)
        if validation and validation.status in ("partial", "full"):
            print_success(f"Status: {validation.status}")
        elif kept:
            print_warning("No handshake captured, but capture was kept by config.")
        else:
            print_error("No handshake captured (timed out).")
    except KeyboardInterrupt:
        repl.print("\n")
        print_warning("Capture cancelled by user.")
    except Exception as e:
        repl.print("\n")
        print_error(f"Error during capture: {e}")

async def cmd_capture_deauth(repl):
    params = await _get_deauth_params(repl, default_count=10)
    if not params: return
    iface, bssid, channel, client, count, rate = params
    
    conf = prompt_confirm("Start Deauth Capture?")
    if conf.cancelled or not conf.value: return
    
    out = capture_prefix("deauth")
    repl.print("\n  [cyan]Deauthenticating and capturing...[/cyan]")
    start = time.monotonic()
    state = {"m1": False, "m2": False, "m3": False, "m4": False, "status": "waiting", "activity": "|", "analysis_passes": 0}
    activity_frames = ("|", "/", "-", "\\")
    done = False

    def render():
        return build_handshake_progress_panel(
            title="Deauth Capture",
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

    try:
        with Live(render(), console=console, refresh_per_second=6, transient=False) as live:
            anim_task = asyncio.create_task(animate(live))
            def on_progress(m1, m2, m3, m4, status):
                state.update({"m1": m1, "m2": m2, "m3": m3, "m4": m4, "status": status})
                live.update(render(), refresh=True)

            try:
                res = await capture_deauth(
                    mon_iface=iface,
                    bssid=bssid,
                    client=client,
                    channel=channel,
                    output_prefix=out,
                    count=count,
                    rate=rate,
                    timeout=300,
                    on_progress=on_progress
                )
            finally:
                done = True
                anim_task.cancel()
                try:
                    await anim_task
                except asyncio.CancelledError:
                    pass
            live.update(render(), refresh=True)
        kept, validation = _keep_or_delete_capture(repl, out + "-01.cap", res)
        if validation and validation.status in ("partial", "full"):
            print_success(f"Status: {validation.status}")
        elif kept:
            print_warning("Failed to capture handshake, but capture was kept by config.")
        else:
            print_error("Failed to capture handshake (timed out).")
    except KeyboardInterrupt:
        repl.print("\n")
        print_warning("Capture cancelled by user.")
    except Exception as e:
        repl.print("\n")
        print_error(f"Error during capture: {e}")

async def cmd_capture_pmkid(repl):
    params = await _get_capture_params(repl)
    if not params: return
    iface, bssid, channel = params
    
    conf = prompt_confirm("Start PMKID Capture?")
    if conf.cancelled or not conf.value: return
    
    repl.print("\n  [cyan]Running PMKID capture...[/cyan]")
    from sidewinder.core.subprocess_mgr import get_manager
    engine = PMKIDEngine(get_manager())
    cfg = AttackConfig(target_bssid=bssid, channel=channel, timeout=300)
    try:
        res = await engine.start(cfg, iface=iface)
        if res.success:
            print_success(f"PMKID captured! Hash file: {res.stats.get('hash_file', 'unknown')}")
        else:
            print_error("Failed to capture PMKID.")
    except Exception as e:
        print_error(f"Error: {e}")

async def cmd_validate(repl):
    cap_res = prompt_text(*auto_fill_prompt(repl.session, "cap_file", "Capture File"))
    if cap_res.cancelled: return
    
    res = validate_handshake(cap_res.value)
    if res:
        repl.print(f"\n  Status: {res.status.upper()}")
        repl.print(f"  M1: {'Y' if res.m1 else 'N'} | M2: {'Y' if res.m2 else 'N'} | M3: {'Y' if res.m3 else 'N'} | M4: {'Y' if res.m4 else 'N'}")
        repl.session.last_cap_file = cap_res.value
    else:
        print_error("Invalid or empty capture file.")


def _latest_successful_capture(repl):
    candidates = []
    if repl.session.last_cap_file:
        candidates.append(repl.session.last_cap_file)
    candidates.extend(reversed(repl.session.captures))

    seen = set()
    for path in candidates:
        if not path or path in seen or not os.path.exists(path):
            continue
        seen.add(path)
        result = validate_handshake(path)
        if result and result.status in ("partial", "full"):
            return path, result
    return None, None


async def cmd_handshake(repl):
    path, result = _latest_successful_capture(repl)
    if not path:
        repl.print("  [yellow]No successful handshake capture found. Run /scan, /capture passive, or /capture deauth first.[/yellow]")
        return

    messages = extract_handshake_messages(path)
    repl.print(f"\n  [bold]Handshake Details[/bold]")
    repl.print(f"  Capture: [cyan]{path}[/cyan]")
    repl.print(f"  Status: [green]{result.status.upper()}[/green]  EAPOL frames: {result.eapol_count}")

    rows = []
    by_name = {m["message"]: m for m in messages}
    for name in ("M1", "M2", "M3", "M4"):
        m = by_name.get(name)
        if not m:
            rows.append([name, "--", "not captured", "-", "-", "-", "-", "-"])
            continue
        rows.append([
            name,
            m["packet"],
            m["key_info_binary"],
            m["pairwise"],
            m["install"],
            m["ack"],
            m["mic"],
            m["secure"],
        ])
    from swcli.repl.renderer import print_table
    print_table(["Msg", "Pkt", "Key Info Binary", "Pair", "Inst", "Ack", "Mic", "Sec"], rows, "4-Way Handshake")
    repl.session.last_cap_file = path
    repl.session.handshake = result

def register_commands(palette: CommandPalette):
    palette.register(Command("/capture passive", "Passive handshake capture", "Capture", cmd_capture_passive))
    palette.register(Command("/capture deauth", "Deauth + capture", "Capture", cmd_capture_deauth))
    palette.register(Command("/capture pmkid", "PMKID capture", "Capture", cmd_capture_pmkid))
    palette.register(Command("/validate", "Validate .cap file", "Capture", cmd_validate, requires_root=False))
    palette.register(Command("/handshake", "Show M1-M4 key-info bits", "Capture", cmd_handshake, requires_root=False))
