"""Output path helpers for SWCLI-generated files."""
from __future__ import annotations

import os
from datetime import datetime

from .config import SidewinderConfig, expand_user_path

CONFIG_PATH = "~/.sidewinder/config.json"


def output_root() -> str:
    cfg = SidewinderConfig.load(CONFIG_PATH)
    root = expand_user_path(cfg.results_dir)
    os.makedirs(root, exist_ok=True)
    return root


def output_dir(name: str) -> str:
    path = os.path.join(output_root(), name)
    os.makedirs(path, exist_ok=True)
    return path


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def output_prefix(kind: str, stem: str | None = None) -> str:
    base = stem or kind
    return os.path.join(output_dir(kind), f"{base}_{timestamp()}")


def scan_prefix() -> str:
    return output_prefix("scans", "scan")


def capture_prefix(kind: str) -> str:
    return output_prefix("captures", kind)


def attack_prefix(kind: str) -> str:
    return output_prefix("attacks", kind)


def hash_path(filename: str) -> str:
    return os.path.join(output_dir("hashes"), filename)
