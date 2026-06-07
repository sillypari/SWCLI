from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_choice, prompt_confirm
from sidewinder.adapters import AdapterManager
from sidewinder.core.monitor import enter_monitor_mode, exit_monitor_mode
from swcli.repl.renderer import print_success, print_error, print_info

async def cmd_monitor_start(repl):
    manager = AdapterManager()
    adapters = await manager.discover()
    monitor_capable = [a for a in adapters if a.monitor_capable]

    if not monitor_capable:
        repl.print("[red]No monitor-capable adapters found.[/red]")
        return

    if len(monitor_capable) == 1:
        iface = monitor_capable[0]
    else:
        choices = [f"{a.iface} ({a.chipset})" for a in monitor_capable]
        res = prompt_choice("Select adapter:", choices)
        if res.cancelled: return
        iface = monitor_capable[choices.index(res.value)]

    repl.print(f"\n  [bold]Adapter:[/bold]  {iface.iface} ({iface.chipset})")
    repl.print(f"  [bold]PHY:[/bold]      {iface.phy}")

    adapter = manager.get_adapter_instance(iface)
    repl.print(f"  [bold]Profile:[/bold]  [cyan]{adapter.name}[/cyan]")

    conf = prompt_confirm("Enable monitor mode?")
    if conf.cancelled or not conf.value:
        repl.print("[yellow]Cancelled.[/yellow]")
        return

    from sidewinder.adapters.base import BadDriverWarning, GenericAdapter
    try:
        mon_iface = await adapter.enter_monitor()
    except BadDriverWarning as w:
        repl.print(f"\n[bold yellow]Driver Warning:[/bold yellow] {w}")
        conf = prompt_confirm("Continue with generic fallback? (Not recommended)")
        if conf.cancelled or not conf.value:
            repl.print("[yellow]Cancelled.[/yellow]")
            return
        
        adapter = GenericAdapter(iface.iface, iface.phy, iface.chipset)
        repl.print(f"  [bold]Profile:[/bold]  [cyan]{adapter.name}[/cyan] (Generic Fallback)")
        try:
            mon_iface = await adapter.enter_monitor()
        except Exception as e:
            print_error(f"Generic fallback failed: {e}")
            return
    except Exception as e:
        print_error(f"Failed to enable monitor mode: {e}")
        return

    if mon_iface == iface.iface:
        print_success(f"Monitor mode active: {iface.iface} (Optimizations applied via {adapter.name})")
    else:
        print_success(f"Monitor mode active: {mon_iface} (created from {iface.iface}) (Optimizations applied via {adapter.name})")
        
    repl.session.adapter = adapter
    repl.session.monitor_mode = True
    repl.session.monitor_iface = mon_iface
    repl.session.last_iface = mon_iface

async def cmd_monitor_stop(repl):
    iface = repl.session.monitor_iface or repl.session.last_iface
    if not iface:
        from swcli.repl.prompts import prompt_text
        res = prompt_text("Monitor Interface (e.g. wlan0mon)")
        if res.cancelled: return
        iface = res.value
        
    repl.print(f"  Interface: {iface}")
    conf = prompt_confirm("Exit monitor mode and restore managed mode?")
    if conf.cancelled or not conf.value:
        repl.print("[yellow]Cancelled.[/yellow]")
        return
        
    try:
        adapter = getattr(repl.session, 'adapter', None)
        if adapter:
            await adapter.exit_monitor(iface)
        else:
            await exit_monitor_mode(iface, "", "") # Best effort
            
        print_success("Monitor mode stopped.")
        repl.session.monitor_mode = False
        repl.session.adapter = None
    except Exception as e:
        print_error(f"Failed: {e}")

async def cmd_monitor_status(repl):
    """Show current monitor mode status."""
    iface = repl.session.monitor_iface or repl.session.last_iface
    in_monitor = repl.session.monitor_mode

    if in_monitor and iface:
        print_info(f"Monitor mode: [green]ACTIVE[/green] on {iface}")
    elif iface:
        print_info(f"Monitor mode: [yellow]INACTIVE[/yellow] (last interface: {iface})")
    else:
        print_info("Monitor mode: [dim]UNKNOWN[/dim] (no adapter tracked)")

    # Also check live via sysfs
    try:
        import os
        for name in os.listdir("/sys/class/net/"):
            path = f"/sys/class/net/{name}/type"
            if os.path.exists(path):
                with open(path) as f:
                    iface_type = f.read().strip()
                if iface_type == "803":  # monitor mode type
                    print_info(f"  Live: {name} is in monitor mode (type=803)")
    except Exception:
        pass

def register_commands(palette: CommandPalette):
    palette.register(Command("/monitor", "Enter monitor mode", "Setup", cmd_monitor_start))
    palette.register(Command("/monitor stop", "Exit monitor mode", "Setup", cmd_monitor_stop))
    palette.register(Command("/monitor status", "Check monitor mode status", "Setup", cmd_monitor_status, requires_root=False))
