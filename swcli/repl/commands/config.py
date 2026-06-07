import os
import dataclasses
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_choice
from sidewinder.core.config import SidewinderConfig
from swcli.repl.renderer import print_success, print_error, print_table

CONFIG_PATH = "~/.sidewinder/config.json"

async def cmd_config_show(repl):
    cfg = SidewinderConfig.load(CONFIG_PATH)
    fields = dataclasses.fields(cfg)

    rows = []
    for f in fields:
        val = getattr(cfg, f.name)
        rows.append([f.name, str(val), f.type if isinstance(f.type, str) else str(f.type)])

    print_table(["Key", "Value", "Type"], rows, "Configuration")

async def cmd_config_set(repl):
    cfg = SidewinderConfig.load(CONFIG_PATH)
    fields = dataclasses.fields(cfg)

    choices = [f.name for f in fields]
    res = prompt_choice("Select config key:", choices)
    if res.cancelled: return

    key = res.value
    current = getattr(cfg, key)
    new_val_res = prompt_text(f"New value for {key}", default=str(current))
    if new_val_res.cancelled: return

    raw = new_val_res.value
    if isinstance(current, bool):
        setattr(cfg, key, raw.lower() in ("true", "1", "yes"))
    elif isinstance(current, int):
        try:
            setattr(cfg, key, int(raw))
        except ValueError:
            print_error(f"Invalid integer: {raw}")
            return
    elif isinstance(current, float):
        try:
            setattr(cfg, key, float(raw))
        except ValueError:
            print_error(f"Invalid number: {raw}")
            return
    else:
        setattr(cfg, key, raw)

    try:
        cfg.save(CONFIG_PATH)
        print_success(f"Set {key} = {getattr(cfg, key)}")
    except Exception as e:
        print_error(f"Failed to save config: {e}")

def register_commands(palette: CommandPalette):
    palette.register(Command("/config show", "Show configuration", "Config", cmd_config_show, requires_root=False))
    palette.register(Command("/config set", "Update config value", "Config", cmd_config_set, requires_root=False))
