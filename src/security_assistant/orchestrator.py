"""Core orchestrator that coordinates the assistant's engines."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from security_assistant.osint.engine import OSINTEngine
from security_assistant.iot_recon.scanner import IoTReconScanner
from security_assistant.threat_scanner.scanner import ThreatScanner
from security_assistant.network.vpn_daemon import VPNDaemon

logger = logging.getLogger(__name__)


@dataclass
class Orchestrator:
    """Wires together the OSINT, IoT recon, threat scanning, and network
    modules and exposes a single entry point for running a full assessment.
    """

    osint: OSINTEngine = field(default_factory=OSINTEngine)
    iot_recon: IoTReconScanner = field(default_factory=IoTReconScanner)
    threat_scanner: ThreatScanner = field(default_factory=ThreatScanner)
    vpn_daemon: VPNDaemon = field(default_factory=VPNDaemon)

    def run_assessment(self, target: str) -> dict:
        """Run a full assessment pipeline against an authorized target."""
        logger.info("Starting assessment for target=%s", target)

        results = {
            "target": target,
            "osint": self.osint.gather(target),
            "iot_recon": self.iot_recon.scan(target),
            "threats": self.threat_scanner.scan(target),
        }

        logger.info("Assessment complete for target=%s", target)
        return results
