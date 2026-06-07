from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_mac, prompt_channel, prompt_confirm
from swcli.repl.session_ui import auto_fill_prompt
from sidewinder.core.capture import capture_passive, capture_deauth, validate_handshake
from sidewinder.attacks.pmkid import PMKIDEngine
from sidewinder.core.attack import AttackConfig
from swcli.repl.renderer import print_success, print_error

async def _get_capture_params(repl):
    iface_res = prompt_text(*auto_fill_prompt(repl.session, "iface", "Monitor Interface"))
    if iface_res.cancelled: return None
    bssid_res = prompt_mac(*auto_fill_prompt(repl.session, "bssid", "Target BSSID"))
    if bssid_res.cancelled: return None
    
    ch = repl.session.get_channel_for_bssid(bssid_res.value)
    if ch: repl.session.last_channel = ch
    
    ch_res = prompt_channel("Channel", default=ch or 6)
    if ch_res.cancelled: return None
    
    repl.session.last_iface = iface_res.value
    repl.session.last_bssid = bssid_res.value
    repl.session.last_channel = ch_res.value
    return iface_res.value, bssid_res.value, ch_res.value

async def cmd_capture_passive(repl):
    params = await _get_capture_params(repl)
    if not params: return
    iface, bssid, channel = params
    
    conf = prompt_confirm("Start Passive Capture?")
    if conf.cancelled or not conf.value: return
    
    out = "/tmp/swcli_cap"
    repl.print("\n  [cyan]Listening for handshakes...[/cyan]")
    res = await capture_passive(mon_iface=iface, bssid=bssid, channel=channel, output_prefix=out, timeout=300)
    if res:
        print_success(f"Status: {res.status}")
        repl.session.last_cap_file = out + "-01.cap"
    else:
        print_error("No handshake captured.")

async def cmd_capture_deauth(repl):
    params = await _get_capture_params(repl)
    if not params: return
    iface, bssid, channel = params
    
    cli_res = prompt_mac("Client MAC", default="FF:FF:FF:FF:FF:FF", allow_broadcast=True)
    if cli_res.cancelled: return
    
    conf = prompt_confirm("Start Deauth Capture?")
    if conf.cancelled or not conf.value: return
    
    out = "/tmp/swcli_cap"
    repl.print("\n  [cyan]Deauthenticating and capturing...[/cyan]")
    res = await capture_deauth(mon_iface=iface, bssid=bssid, client=cli_res.value, channel=channel, output_prefix=out, count=10, timeout=300)
    if res and res.handshake:
        print_success(f"Status: {res.handshake.status}")
        repl.session.last_cap_file = out + "-01.cap"
    else:
        print_error("Failed to capture handshake.")

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

def register_commands(palette: CommandPalette):
    palette.register(Command("/capture passive", "Passive handshake capture", "Capture", cmd_capture_passive))
    palette.register(Command("/capture deauth", "Deauth + capture", "Capture", cmd_capture_deauth))
    palette.register(Command("/capture pmkid", "PMKID capture", "Capture", cmd_capture_pmkid))
    palette.register(Command("/validate", "Validate .cap file", "Capture", cmd_validate, requires_root=False))
