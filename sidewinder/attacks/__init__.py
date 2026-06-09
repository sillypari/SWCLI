"""Sidewinder Attacks Package.

Attack modules for WiFi auditing.
"""
from ..core.attack import AttackConfig, AttackResult, AttackState, BaseAttackEngine
from .captive_portal import CaptivePortalConfig, CaptivePortalEngine, CaptivePortalHealth, CaptivePortalStats, PortalMode, DetectedOS
from .deauth import DeauthConfig, DeauthResult, run_deauth
from .pmkid import PMKIDEngine
from .wps import WPSEngine
from .evil_twin import EvilTwinEngine

__all__ = [
    "AttackConfig",
    "AttackResult",
    "AttackState",
    "BaseAttackEngine",
    "CaptivePortalConfig",
    "CaptivePortalEngine",
    "CaptivePortalHealth",
    "CaptivePortalStats",
    "PortalMode",
    "DetectedOS",
    "DeauthConfig",
    "DeauthResult",
    "run_deauth",
    "PMKIDEngine",
    "WPSEngine",
    "EvilTwinEngine",
]
