"""Network/VPN Daemon: manages the assistant's outbound network posture
(VPN connection lifecycle, kill-switch, egress routing) so scans run
through an authorized, controlled network path.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class VPNDaemon:
    """Controls VPN connection state for outbound scan traffic."""

    def __init__(self) -> None:
        self._connected = False

    def connect(self) -> bool:
        logger.info("Connecting VPN daemon")
        self._connected = True
        return self._connected

    def disconnect(self) -> None:
        logger.info("Disconnecting VPN daemon")
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected
