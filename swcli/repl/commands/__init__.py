from swcli.repl.palette import CommandPalette

def setup_all_commands(palette: CommandPalette):
    from swcli.repl.commands import hardware, monitor, scan, capture, attack, crack, cleanup, session, config, control, help
    
    hardware.register_commands(palette)
    monitor.register_commands(palette)
    scan.register_commands(palette)
    capture.register_commands(palette)
    attack.register_commands(palette)
    crack.register_commands(palette)
    cleanup.register_commands(palette)
    session.register_commands(palette)
    config.register_commands(palette)
    control.register_commands(palette)
    help.register_commands(palette)
