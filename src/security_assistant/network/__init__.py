"""Network automation: VPN lifecycle, kill-switch, leak validation, privileges.

This is the one module that acts on the operator's own machine rather than on
a third party, which inverts the risk model the rest of the project uses. The
failure that matters here is locking the operator out of their own host, so
three things are structural rather than advisory:

* **Nothing executes by default.** The default
  :class:`~security_assistant.network.commands.CommandRunner` is a dry run that
  records intent. Real execution requires an explicit ``SubprocessRunner``.
* **The assistant never holds root.** Privilege is acquired per command through
  a configured escalation prefix, and
  :mod:`~security_assistant.network.privileges` emits narrow sudoers grants and
  a hardened systemd unit so an administrator can review exactly what is
  allowed.
* **The kill-switch refuses to lock you out.**
  :class:`~security_assistant.network.killswitch.LockoutGuard` rejects any plan
  that would sever loopback, established connections, the VPN endpoint, or a
  named admin network, and application arms an automatic rollback unless
  confirmed.

Tunnel recovery is autonomous but bounded: a state machine with exponential
backoff that stops at ``NEEDS_OPERATOR`` rather than retrying forever.
"""

from __future__ import annotations

from security_assistant.network.commands import (
    CommandError,
    CommandResult,
    CommandRunner,
    DryRunRunner,
    Escalation,
    PrivilegeError,
    RecordingRunner,
    SubprocessRunner,
    default_runner,
)
from security_assistant.network.killswitch import (
    FirewallFamily,
    KillSwitch,
    KillSwitchError,
    KillSwitchPlan,
    LockoutGuard,
    LockoutRiskError,
    build_iptables_plan,
)
from security_assistant.network.leaks import (
    LeakCheck,
    LeakReport,
    LeakStatus,
    LeakValidator,
)
from security_assistant.network.privileges import (
    PrivilegeGrant,
    PrivilegePlan,
    launchd_plist,
    plan_for,
    sudoers_file,
    systemd_unit,
)
from security_assistant.network.vpn import (
    OpenVpnBackend,
    RecoveryState,
    SupervisorStatus,
    TunnelState,
    TunnelStatus,
    TunnelSupervisor,
    VpnBackend,
    VpnConfig,
    VpnError,
    VpnManager,
    WireGuardBackend,
    backend_for,
    parse_wg_dump,
)

__all__ = [
    # Commands / privilege boundary
    "CommandError",
    "CommandResult",
    "CommandRunner",
    "DryRunRunner",
    "Escalation",
    "PrivilegeError",
    "RecordingRunner",
    "SubprocessRunner",
    "default_runner",
    # VPN
    "OpenVpnBackend",
    "RecoveryState",
    "SupervisorStatus",
    "TunnelState",
    "TunnelStatus",
    "TunnelSupervisor",
    "VpnBackend",
    "VpnConfig",
    "VpnError",
    "VpnManager",
    "WireGuardBackend",
    "backend_for",
    "parse_wg_dump",
    # Kill-switch
    "FirewallFamily",
    "KillSwitch",
    "KillSwitchError",
    "KillSwitchPlan",
    "LockoutGuard",
    "LockoutRiskError",
    "build_iptables_plan",
    # Leak validation
    "LeakCheck",
    "LeakReport",
    "LeakStatus",
    "LeakValidator",
    # Privilege templates
    "PrivilegeGrant",
    "PrivilegePlan",
    "launchd_plist",
    "plan_for",
    "sudoers_file",
    "systemd_unit",
]
