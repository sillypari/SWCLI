"""Sidewinder Intelligence Engine.

Evaluates WiFi targets and recommends attack methodologies 
based on signal strength, client activity, and encryption.
Does NOT auto-execute attacks—only provides recommendations.
"""
from dataclasses import dataclass
from typing import List, Optional

from .session import Network, Client


@dataclass
class Recommendation:
    """An attack recommendation."""
    method: str
    confidence: int  # 0-100
    reason: str
    warnings: List[str]


class IntelligenceEngine:
    """Analyzes targets and provides actionable insights."""

    def __init__(self) -> None:
        self.rules = []

    def evaluate_target(self, target: Network, clients: List[Client]) -> List[Recommendation]:
        """Evaluate a target and return a sorted list of recommended attacks."""
        recommendations = []
        
        # 1. Active Clients Detection
        active_clients = [c for c in clients if c.bssid == target.bssid and c.signal > -80]
        
        if active_clients:
            recommendations.append(Recommendation(
                method="deauth_active",
                confidence=90,
                reason=f"Found {len(active_clients)} active clients with good signal. High probability of capturing EAPOL handshake.",
                warnings=[]
            ))
        else:
            recommendations.append(Recommendation(
                method="deauth_broadcast",
                confidence=40,
                reason="No active clients detected. Broadcast deauth might work if hidden/sleeping clients exist.",
                warnings=["Low success rate without active clients."]
            ))
            
            # Recommend PMKID if no clients
            if "WPA" in target.privacy:
                recommendations.append(Recommendation(
                    method="pmkid",
                    confidence=75,
                    reason="Target uses WPA/WPA2. PMKID attack does not require connected clients.",
                    warnings=["Requires router to have roaming features (802.11r/PMKID) enabled."]
                ))

        # 2. WPS Vulnerability
        if target.wps:
            recommendations.append(Recommendation(
                method="wps_pixiedust",
                confidence=85,
                reason="WPS is enabled. Vulnerable to Pixie-Dust or PIN bruteforce.",
                warnings=["WPS might lock out after several failed attempts."]
            ))

        # 3. Signal Strength Warnings
        if target.signal < -75:
            for rec in recommendations:
                rec.warnings.append(f"Target signal is very weak ({target.signal} dBm). Packet injection may fail.")
                rec.confidence = max(10, rec.confidence - 20)

        # Sort by highest confidence
        recommendations.sort(key=lambda r: r.confidence, reverse=True)
        return recommendations
