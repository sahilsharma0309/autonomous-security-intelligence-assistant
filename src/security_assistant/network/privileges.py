"""Emitted privilege grants: sudoers rules and systemd units.

The assistant never runs as root. What it needs instead is a *narrow,
reviewable* grant for a handful of networking utilities, and this module
generates that text so an administrator can read it before installing it.
Nothing here writes to the filesystem or installs anything -- it returns
strings, and the operator decides.

**Why generated rather than documented.** A hand-written sudoers rule for this
is almost always too broad: ``NOPASSWD: /usr/bin/wg-quick`` lets the assistant
bring up *any* config, and ``NOPASSWD: /usr/sbin/iptables`` is equivalent to
root, since iptables can rewrite the rules that constrain everything else. The
templates here bind each command to its exact argument vector, so the grant is
"may bring up wg0", not "may run wg-quick".

**Why sudoers rules end with a deliberate warning.** Even a tightly scoped
iptables grant is powerful. :func:`sudoers_rules` marks those lines so the
reviewer's eye lands on them, rather than burying them in a wall of paths.

The alternative path, for hosts that prefer not to use sudo at all, is
:func:`systemd_unit` with ``AmbientCapabilities=CAP_NET_ADMIN`` -- the daemon
then holds one capability rather than passing through a general escalation
tool. Both are offered because the right answer differs per site.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

__all__ = [
    "SUPPORTED_COMMANDS",
    "PrivilegeGrant",
    "sudoers_file",
    "sudoers_rules",
    "systemd_unit",
]

#: Absolute paths are required in sudoers -- a bare name would let a binary
#: earlier on PATH satisfy the rule. Resolved at generation time with a
#: documented fallback so the output is still usable on a host where the tool
#: is not yet installed.
_DEFAULT_PATHS = {
    "wg": "/usr/bin/wg",
    "wg-quick": "/usr/bin/wg-quick",
    "openvpn": "/usr/sbin/openvpn",
    "systemctl": "/usr/bin/systemctl",
    "iptables": "/usr/sbin/iptables",
    "ip6tables": "/usr/sbin/ip6tables",
    "nft": "/usr/sbin/nft",
    "ip": "/usr/sbin/ip",
    "resolvectl": "/usr/bin/resolvectl",
}

#: Commands that are meaningfully more dangerous than the rest: a firewall
#: grant can undo every other constraint on the host.
_HIGH_RISK = frozenset({"iptables", "ip6tables", "nft"})

SUPPORTED_COMMANDS = tuple(sorted(_DEFAULT_PATHS))


def _resolve(binary: str) -> str:
    """Absolute path for a binary, falling back to a conventional location."""
    found = shutil.which(binary)
    return found or _DEFAULT_PATHS.get(binary, f"/usr/bin/{binary}")


@dataclass(slots=True)
class PrivilegeGrant:
    """One command the assistant may run with privilege."""

    binary: str
    arguments: tuple[str, ...] = ()
    purpose: str = ""

    @property
    def high_risk(self) -> bool:
        return self.binary in _HIGH_RISK

    def sudoers_command(self) -> str:
        """The command spec, bound to its exact arguments."""
        path = _resolve(self.binary)
        if not self.arguments:
            return path
        return f"{path} {' '.join(self.arguments)}"


def grants_for_wireguard(interface: str) -> list[PrivilegeGrant]:
    """Minimum grants to manage one WireGuard tunnel."""
    return [
        PrivilegeGrant("wg", ("show", interface, "dump"), "read tunnel status"),
        PrivilegeGrant("wg-quick", ("up", interface), f"bring {interface} up"),
        PrivilegeGrant("wg-quick", ("down", interface), f"bring {interface} down"),
    ]


def grants_for_openvpn(interface: str, unit: str = "") -> list[PrivilegeGrant]:
    """Minimum grants to manage one OpenVPN client unit."""
    service = unit or f"openvpn-client@{interface}"
    return [
        PrivilegeGrant("systemctl", ("start", service), f"start {service}"),
        PrivilegeGrant("systemctl", ("stop", service), f"stop {service}"),
        PrivilegeGrant("systemctl", ("is-active", service), f"query {service}"),
    ]


def grants_for_killswitch() -> list[PrivilegeGrant]:
    """Grants the kill-switch needs.

    Deliberately *not* argument-bound: a kill-switch composes rules from the
    runtime endpoint and admin networks, so the vector is not knowable in
    advance. That makes this the broadest grant in the set, and the emitted
    file says so in as many words.
    """
    return [
        PrivilegeGrant("iptables", (), "apply and roll back kill-switch rules"),
        PrivilegeGrant("ip6tables", (), "apply and roll back IPv6 kill-switch rules"),
    ]


def sudoers_rules(
    user: str,
    grants: Sequence[PrivilegeGrant],
) -> list[str]:
    """Render one ``NOPASSWD`` line per grant."""
    if not user or not user.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"Invalid system user name: {user!r}")

    lines: list[str] = []
    for grant in grants:
        marker = "  # HIGH RISK" if grant.high_risk else ""
        lines.append(f"{user} ALL=(root) NOPASSWD: {grant.sudoers_command()}{marker}")
    return lines


def sudoers_file(
    user: str,
    grants: Iterable[PrivilegeGrant],
    *,
    filename: str = "/etc/sudoers.d/security-assistant",
) -> str:
    """Render a complete, reviewable sudoers drop-in.

    Install with ``visudo -c -f`` first: a syntactically invalid sudoers file
    can lock every user out of privilege escalation on the host, which is the
    same class of mistake the kill-switch guard exists to prevent.
    """
    collected = list(grants)
    high_risk = [g for g in collected if g.high_risk]

    header = [
        "# security-assistant privilege grants",
        f"# Install as: {filename}  (mode 0440, owned by root:root)",
        "#",
        "# Generated by security_assistant.network.privileges. Review before",
        "# installing, and validate with:",
        f"#     visudo -c -f {filename}",
        "#",
        "# The assistant does not run as root. Each rule below grants exactly",
        "# one command, bound to its arguments where those are knowable.",
    ]

    if high_risk:
        header.extend(
            [
                "#",
                "# !! HIGH RISK !!",
                "# The firewall grants below are NOT argument-bound, because a",
                "# kill-switch ruleset is composed at runtime from the tunnel",
                "# endpoint and your administrative networks. A grant to run",
                "# iptables freely is close to a grant of root, since iptables",
                "# can rewrite the rules that constrain everything else.",
                "# Omit these lines if you do not intend to use the kill-switch;",
                "# every other feature works without them.",
            ]
        )

    body = sudoers_rules(user, collected)
    return "\n".join([*header, "", *body, ""])


SYSTEMD_TEMPLATE = """\
[Unit]
Description=Autonomous Security & Intelligence Assistant daemon
Documentation=https://github.com/sahilsharma0309/autonomous-security-intelligence-assistant
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={group}
WorkingDirectory={working_directory}
ExecStart={executable} run-daemon --config {config_path}
Restart=on-failure
RestartSec=10
TimeoutStopSec=30

# The daemon holds one capability rather than general escalation. With this
# set, the sudoers grants for wg/ip are unnecessary; firewall management
# still needs CAP_NET_ADMIN, which this provides.
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

# Sandboxing: the daemon reads config and writes logs, nothing more.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
ReadWritePaths={state_directory}

[Install]
WantedBy=multi-user.target
"""


def systemd_unit(
    *,
    user: str = "security-assistant",
    group: str = "security-assistant",
    executable: str = "/usr/local/bin/security-assistant",
    config_path: str = "/etc/security-assistant/config.yaml",
    working_directory: str = "/var/lib/security-assistant",
    state_directory: str = "/var/lib/security-assistant",
) -> str:
    """Render a hardened systemd unit for the daemon.

    The sandboxing directives are not decoration: this daemon runs
    continuously, holds a network capability, and processes data derived from
    hostile inputs, so the blast radius of a bug in it is worth constraining
    at the service-manager level as well as in code.
    """
    return SYSTEMD_TEMPLATE.format(
        user=user,
        group=group,
        executable=executable,
        config_path=config_path,
        working_directory=working_directory,
        state_directory=state_directory,
    )


LAUNCHD_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable}</string>
        <string>run-daemon</string>
        <string>--config</string>
        <string>{config_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>WorkingDirectory</key>
    <string>{working_directory}</string>
    <key>StandardOutPath</key>
    <string>{log_directory}/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>{log_directory}/daemon.err</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"""


def launchd_plist(
    *,
    label: str = "io.github.security-assistant.daemon",
    executable: str = "/usr/local/bin/security-assistant",
    config_path: str = "/usr/local/etc/security-assistant/config.yaml",
    working_directory: str = "/usr/local/var/security-assistant",
    log_directory: str = "/usr/local/var/log/security-assistant",
) -> str:
    """Render a launchd agent for macOS.

    macOS has no direct equivalent of ``AmbientCapabilities``; a tunnel there
    is normally managed by a privileged helper or by the VPN app itself, so
    this agent is intended for the monitoring and scanning features rather
    than for tunnel control.
    """
    return LAUNCHD_TEMPLATE.format(
        label=label,
        executable=executable,
        config_path=config_path,
        working_directory=working_directory,
        log_directory=log_directory,
    )


@dataclass(slots=True)
class PrivilegePlan:
    """Everything an administrator needs to install to enable a deployment."""

    user: str = "security-assistant"
    grants: list[PrivilegeGrant] = field(default_factory=list)

    def sudoers(self) -> str:
        return sudoers_file(self.user, self.grants)

    def systemd(self) -> str:
        return systemd_unit(user=self.user, group=self.user)

    def launchd(self) -> str:
        return launchd_plist()

    @property
    def includes_firewall(self) -> bool:
        return any(g.high_risk for g in self.grants)


def plan_for(
    *,
    user: str = "security-assistant",
    backend: str = "wireguard",
    interface: str = "wg0",
    killswitch: bool = False,
) -> PrivilegePlan:
    """Build the minimum privilege plan for a given deployment."""
    grants = (
        grants_for_openvpn(interface)
        if backend.strip().lower() in {"openvpn", "ovpn"}
        else grants_for_wireguard(interface)
    )
    if killswitch:
        grants = [*grants, *grants_for_killswitch()]
    return PrivilegePlan(user=user, grants=grants)
