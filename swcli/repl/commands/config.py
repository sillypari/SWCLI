import dataclasses
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_choice, prompt_confirm
from sidewinder.core.config import SidewinderConfig, expand_user_path
from swcli.repl.renderer import console, print_success, print_error, print_warning
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

CONFIG_PATH = "~/.sidewinder/config.json"


CONFIG_META = {
    "capture_dir": ("Paths", "Where captures are saved."),
    "wordlist_dir": ("Paths", "Default wordlist search directory."),
    "results_dir": ("Paths", "Where cracking and audit results are saved."),
    "default_wordlist": ("Defaults", "Default wordlist used by cracking flows."),
    "default_channel": ("Defaults", "Fallback Wi-Fi channel when no scan channel is known."),
    "default_deauth_count": ("Defaults", "Default number of deauth frames for capture workflows."),
    "advanced_scan_info": ("Defaults", "Show advanced scan traffic fields: RXQ, RATE, LOST, and FRAMES."),
    "keep_scan_captures": ("Defaults", "Make /scan write raw .cap files instead of using lightweight JSON only."),
    "save_captures_without_eapol": ("Defaults", "Keep generated .cap files even when no EAPOL frames were found."),
    "capture_timeout_seconds": ("Timeouts", "Maximum passive capture wait time."),
    "deauth_cooldown_seconds": ("Timeouts", "Pause between deauth attempts."),
    "regulatory_domain": ("Hardware", "Regulatory domain hint such as 00, US, GB, or IN."),
    "mac_randomization": ("Hardware", "Whether SWCLI should prefer randomized MAC workflows."),
    "theme": ("UI", "Active built-in or user theme name."),
    "scan_color_mode": ("UI", "Scan table colors: airodump, standard, or off."),
    "theme_directory": ("UI", "Directory for custom themes."),
    "load_user_themes": ("UI", "Load themes from the user theme directory."),
    "load_builtin_themes": ("UI", "Load packaged SWCLI themes."),
    "theme_preview": ("UI", "Show preview information when choosing themes."),
}


def _field_type(current):
    if isinstance(current, bool):
        return "boolean"
    if isinstance(current, int):
        return "integer"
    if isinstance(current, float):
        return "number"
    return "text/path"


def _format_value(value):
    if isinstance(value, bool):
        return Text("enabled" if value else "disabled", style="bold bright_green" if value else "bold red")
    return str(value)


def _config_table(cfg):
    table = Table(
        title="Configuration",
        title_style="bold cyan",
        show_header=True,
        header_style="bold bright_cyan",
        border_style="bright_black",
        box=box.SIMPLE_HEAVY,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("Section", style="cyan", no_wrap=True)
    table.add_column("Key", style="bold white", no_wrap=True)
    table.add_column("Value", overflow="fold")
    table.add_column("Type", style="dim", no_wrap=True)

    for field in dataclasses.fields(cfg):
        current = getattr(cfg, field.name)
        section, _desc = CONFIG_META.get(field.name, ("General", "Application setting."))
        table.add_row(section, field.name, _format_value(current), _field_type(current))
    return table


def _choice_label(field, cfg):
    current = getattr(cfg, field.name)
    section, desc = CONFIG_META.get(field.name, ("General", "Application setting."))
    return f"{section}: {field.name} = {current} - {desc}"


def _coerce_value(key, current, raw):
    if isinstance(current, bool):
        lowered = raw.strip().lower()
        if lowered in ("true", "1", "yes", "y", "on", "enabled", "enable"):
            return True
        if lowered in ("false", "0", "no", "n", "off", "disabled", "disable"):
            return False
        raise ValueError("Enter enabled/disabled, yes/no, true/false, or 1/0.")
    if isinstance(current, int):
        value = int(raw)
        if key == "default_channel" and value not in (set(range(1, 15)) | set(range(36, 166))):
            raise ValueError("Channel must be 1-14 or 36-165.")
        if key == "default_deauth_count" and value < 0:
            raise ValueError("Deauth count cannot be negative.")
        return value
    if isinstance(current, float):
        value = float(raw)
        if value < 0:
            raise ValueError("Timeout values cannot be negative.")
        return value
    return raw.strip()


async def cmd_config_show(repl):
    cfg = SidewinderConfig.load(CONFIG_PATH)
    path = expand_user_path(CONFIG_PATH)
    note = Text()
    note.append("Path: ", style="dim")
    note.append(path, style="cyan")
    console.print(Panel(_config_table(cfg), title="SWCLI Config", subtitle=note, border_style="bright_blue", box=box.ROUNDED))


async def cmd_config_set(repl):
    cfg = SidewinderConfig.load(CONFIG_PATH)
    fields = dataclasses.fields(cfg)

    choices = [_choice_label(field, cfg) for field in fields]
    field_by_choice = dict(zip(choices, fields))
    res = prompt_choice("Select config key", choices)
    if res.cancelled:
        return

    field = field_by_choice[res.value]
    key = field.name
    current = getattr(cfg, key)

    console.print(Panel(
        Text.assemble(
            ("Key: ", "dim"), (key, "bold cyan"), "\n",
            ("Current: ", "dim"), (str(current), "white"), "\n",
            ("Type: ", "dim"), (_field_type(current), "white"), "\n",
            ("Meaning: ", "dim"), (CONFIG_META.get(key, ("General", "Application setting."))[1], "white"),
        ),
        title="Edit Config",
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(0, 1),
    ))

    if isinstance(current, bool):
        bool_res = prompt_choice("Select value", ["enabled", "disabled"], default=0 if current else 1)
        if bool_res.cancelled:
            return
        new_value = bool_res.value == "enabled"
    else:
        new_val_res = prompt_text(f"New value for {key}", default=str(current))
        if new_val_res.cancelled:
            return
        try:
            new_value = _coerce_value(key, current, new_val_res.value)
        except ValueError as e:
            print_error(str(e))
            return

    setattr(cfg, key, new_value)

    try:
        cfg.save(CONFIG_PATH)
        print_success(f"Set {key} = {getattr(cfg, key)}")
    except Exception as e:
        print_error(f"Failed to save config: {e}")


async def cmd_config_reset(repl):
    path = expand_user_path(CONFIG_PATH)
    print_warning(f"This will replace {path} with default configuration values.")
    conf = prompt_confirm("Reset configuration?")
    if conf.cancelled or not conf.value:
        return
    try:
        SidewinderConfig().save(CONFIG_PATH)
        print_success("Configuration reset to defaults.")
    except Exception as e:
        print_error(f"Failed to reset config: {e}")


def register_commands(palette: CommandPalette):
    palette.register(Command("/config show", "Show configuration", "Config", cmd_config_show, requires_root=False))
    palette.register(Command("/config set", "Update config value", "Config", cmd_config_set, requires_root=False))
    palette.register(Command("/config reset", "Reset configuration to defaults", "Config", cmd_config_reset, requires_root=False))
