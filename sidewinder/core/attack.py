"""Sidewinder Attack Orchestration Base.

Provides base classes and utilities for implementing WiFi attacks
such as Deauth, Evil Twin, PMKID, and others.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


class AttackState(Enum):
    """Lifecycle state of an attack."""
    PENDING = "pending"
    INITIALIZING = "initializing"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AttackConfig:
    """Base configuration for any attack."""
    target_bssid: str
    channel: int
    timeout: float = 300.0


@dataclass
class AttackResult:
    """Base result for any attack."""
    success: bool
    errors: list[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)


class BaseAttackEngine:
    """Abstract base engine for running asynchronous attacks."""

    def __init__(self) -> None:
        self.state = AttackState.PENDING
        self._on_progress: Optional[Callable[..., Any]] = None

    def set_progress_callback(self, callback: Callable[..., Any]) -> None:
        """Set a callback for real-time progress updates."""
        self._on_progress = callback

    async def _emit_progress(self, **kwargs: Any) -> None:
        """Safely emit progress to the callback."""
        if not self._on_progress:
            return
        try:
            res = self._on_progress(**kwargs)
            if inspect.isawaitable(res):
                await res
        except Exception as e:
            logger.error("Error in attack progress callback: %s", e)

    async def start(self, config: AttackConfig, **kwargs: Any) -> AttackResult:
        """Start the attack. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement start()")

    async def stop(self) -> None:
        """Stop the attack gracefully. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement stop()")

    def is_running(self) -> bool:
        """Check if the attack is actively running."""
        return self.state in (AttackState.INITIALIZING, AttackState.RUNNING)
