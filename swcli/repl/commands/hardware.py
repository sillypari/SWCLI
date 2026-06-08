from swcli.repl.palette import Command, CommandPalette
from swcli.repl.renderer import print_table, print_success, print_error
from sidewinder.adapters import AdapterManager
from sidewinder.core.services import get_service_manager
from sidewinder.core.subprocess_mgr import run
from swcli.repl.prompts import prompt_confirm, prompt_choice

async def cmd_adapters(repl):
    """List all wireless adapters."""
    try:
        manager = AdapterManager()
        adapters = await manager.discover()
    except Exception:
        # Graceful degradation if backend is stubbed
        adapters = []
        
    if not adapters:
        repl.print("[yellow]No wireless adapters found.[/yellow]")
        return
        
    headers = ["#", "Interface", "Chipset", "Driver", "Bands", "Mode", "Monitor Report", "Inject Report", "Status"]
    rows = []
    
    for i, a in enumerate(adapters, 1):
        rows.append([
            str(i),
            a.iface,
            a.chipset,
            a.driver[:12],
            ",".join(a.bands),
            a.current_mode,
            "[green]YES[/green]" if a.monitor_capable else "[red]NO[/red]",
            "[green]YES[/green]" if a.injection_capable else "[red]NO[/red]",
            a.status,
        ])
    
    print_table(headers, rows, "Wireless Adapters")
    repl.print(f"\n  Total: {len(adapters)} adapters")
    repl.print("  [dim]Monitor/Inject are reported capabilities. Some drivers under-report; runtime behavior can differ.[/dim]")
    repl.print("  Use: /monitor to enter monitor mode")

async def cmd_adapters_info(repl):
    """Show detailed adapter info."""
    try:
        manager = AdapterManager()
        adapters = await manager.discover()
    except Exception:
        adapters = []
        
    if not adapters:
        repl.print("[yellow]No wireless adapters found.[/yellow]")
        return
        
    choices = [a.iface for a in adapters]
    res = prompt_choice("Select adapter for details:", choices)
    if res.cancelled: return
    
    info = adapters[choices.index(res.value)]
    repl.print(f"\n  [bold cyan]Interface Details: {info.iface}[/bold cyan]")
    repl.print(f"  PHY:            {info.phy}")
    repl.print(f"  Chipset:        {info.chipset}")
    repl.print(f"  Driver:         {info.driver}")
    repl.print(f"  Bus:            {info.bus}")
    repl.print(f"  MAC:            {info.mac}")
    repl.print(f"  Bands:          {', '.join(info.bands)}")
    repl.print(f"  Current Mode:   {info.current_mode}")
    repl.print(f"  Monitor Report: {'YES' if info.monitor_capable else 'NO'}")
    repl.print(f"  Inject Report:  {'YES' if info.injection_capable else 'NO'}")
    repl.print("  Runtime Test:   not run")
    repl.print(f"  Status:         {info.status}")


async def cmd_adapters_test_injection(repl):
    """Actively test packet injection on a selected monitor interface."""
    try:
        manager = AdapterManager()
        adapters = await manager.discover()
    except Exception:
        adapters = []

    monitor_adapters = [a for a in adapters if a.current_mode == "monitor"]
    if not monitor_adapters:
        print_error("No monitor interfaces found. Run /monitor first.")
        return

    choices = [
        f"{a.iface} ({a.chipset or a.driver or 'unknown'}) reported injection={'YES' if a.injection_capable else 'NO'}"
        for a in monitor_adapters
    ]
    res = prompt_choice("Select monitor interface to test", choices)
    if res.cancelled:
        return

    adapter = monitor_adapters[choices.index(res.value)]
    repl.print("\n  [yellow]This runs aireplay-ng's active injection test on the selected monitor interface.[/yellow]")
    conf = prompt_confirm(f"Run injection test on {adapter.iface}?")
    if conf.cancelled or not conf.value:
        repl.print("  [yellow]Aborted.[/yellow]")
        return

    result = await run(["aireplay-ng", "--test", adapter.iface], timeout=45.0, check=False)
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    passed = result.success and "Injection is working" in output
    if passed:
        print_success(f"Runtime injection test passed on {adapter.iface}.")
    else:
        print_error(f"Runtime injection test did not pass on {adapter.iface}.")
    if output:
        repl.print(f"\n[dim]{output[-2000:]}[/dim]")

async def cmd_services_kill(repl):
    """Kill conflicting services."""
    manager = get_service_manager()
    repl.print("\n  [blue][i][/blue] Checking for conflicting services...")
    result = await manager.find_conflicting()
    
    if not result:
        repl.print("  [green]No conflicting services found.[/green]")
        return
        
    repl.print("\n  Conflicting services found:")
    for pid, name in result:
        repl.print(f"    PID {pid} - {name}")
        
    repl.print("\n  [yellow]WARNING: This will disconnect you from WiFi.[/yellow]")
    res = prompt_confirm("Kill these services?")
    
    if res.cancelled or not res.value:
        repl.print("  [yellow]Aborted.[/yellow]")
        return
        
    killed = await manager.kill_conflicting()
    for p in killed.killed:
        print_success(f"Stopped: {p.name} (pid={p.pid})")
    repl.print("\n  Services tracked for restore. Run /services restore to bring them back.")

async def cmd_services_restore(repl):
    """Restore killed services."""
    manager = get_service_manager()
    if not manager.killed_processes:
        repl.print("  [blue]No services to restore.[/blue]")
        return
        
    repl.print("\n  Services to restore:")
    for p in manager.killed_processes:
        repl.print(f"    - {p.name}")
        
    res = prompt_confirm("Restore these services?")
    if res.cancelled or not res.value:
        repl.print("  [yellow]Aborted.[/yellow]")
        return
        
    await manager.restore()
    print_success("Services restored.")

def register_commands(palette: CommandPalette):
    palette.register(Command("/adapters", "List wireless adapters", "Hardware", cmd_adapters, requires_root=False))
    palette.register(Command("/adapters info", "Show adapter details", "Hardware", cmd_adapters_info, requires_root=False))
    palette.register(Command("/adapters test injection", "Actively test packet injection", "Hardware", cmd_adapters_test_injection, requires_root=True))
    palette.register(Command("/services", "Kill conflicting services", "Setup", cmd_services_kill, requires_root=True))
    palette.register(Command("/services restore", "Restore services", "Setup", cmd_services_restore, requires_root=True))
