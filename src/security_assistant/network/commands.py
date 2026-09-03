"""The privileged-command boundary.

Every other module in this system acts on a third party. This one acts on the
operator's own machine: it brings interfaces up, rewrites firewall rules, and
installs services. That inverts the risk. The failure that matters here is not
"we touched something we shouldn't have out there" but "we locked the operator
out of their own host", and a wrong `iptables` rule on a remote box does
exactly that, irreversibly, in one command.

Three rules follow, and they are enforced structurally rather than by
convention:

**Nothing executes by default.** :class:`DryRunRunner` is the default runner.
It records what *would* run and returns success without touching anything, so
importing this module, constructing a manager, and calling it is inert. Real
execution requires an explicit :class:`SubprocessRunner`.

**The assistant never holds privilege.** There is no setuid, no persistent
root session, no credential cache. A privileged command is handed to a
configured escalation prefix (``sudo -n``, ``pkexec``, or nothing when already
root) at the moment of use, and the operator's own system policy decides
whether it is allowed. If sudo needs a password the command fails, loudly,
rather than the assistant prompting for or storing one.

**Commands are argument vectors, never strings.** No shell is involved
anywhere in this module, so an interface name or endpoint that happens to
contain a semicolon is an invalid argument rather than a second command.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from security_assistant.core.types import utcnow

logger = logging.getLogger(__name__)

__all__ = [
    "CommandError",
    "CommandResult",
    "CommandRunner",
    "DryRunRunner",
    "Escalation",
    "PrivilegeError",
    "RecordingRunner",
    "SubprocessRunner",
    "default_runner",
]

#: Binaries this module is ever allowed to invoke. A command outside this set
#: is refused before any escalation is applied, so a bug or a bad config
#: cannot turn the privileged path into a general-purpose shell.
ALLOWED_BINARIES = frozenset(
    {
        "wg",
        "wg-quick",
        "openvpn",
        "nmcli",
        "ip",
        "iptables",
        "ip6tables",
        "nft",
        "resolvectl",
        "systemctl",
        "launchctl",
        "ping",
        "dig",
        "host",
    }
)


class CommandError(RuntimeError):
    """A command could not be run, or returned a non-zero status."""


class PrivilegeError(CommandError):
    """A privileged command could not be escalated."""


class Escalation(StrEnum):
    """How a privileged command acquires privilege."""

    NONE = "none"
    """Already root, or the command does not need privilege."""

    SUDO = "sudo"
    """``sudo -n``: non-interactive, so a missing rule fails instead of
    hanging on a password prompt in a daemon with no terminal."""

    PKEXEC = "pkexec"
    """PolicyKit, for desktop sessions with an agent available."""

    def prefix(self) -> tuple[str, ...]:
        if self is Escalation.SUDO:
            return ("sudo", "-n")
        if self is Escalation.PKEXEC:
            return ("pkexec",)
        return ()


@dataclass(frozen=True, slots=True)
class CommandResult:
    """What a command did."""

    argv: tuple[str, ...]
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    executed: bool = True
    """False for a dry run -- the command was planned, not performed."""

    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def command(self) -> str:
        """Human-readable form. For display only; never re-parsed or run."""
        return " ".join(self.argv)

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout[:4000],
            "stderr": self.stderr[:2000],
            "executed": self.executed,
            "ok": self.ok,
            "duration_ms": self.duration_ms,
        }


@runtime_checkable
class CommandRunner(Protocol):
    """Runs a system command."""

    async def run(
        self,
        argv: Sequence[str],
        *,
        privileged: bool = False,
        timeout: float = 30.0,
        check: bool = False,
    ) -> CommandResult:  # pragma: no cover - protocol declaration
        ...


def _validate(argv: Sequence[str]) -> tuple[str, ...]:
    """Reject anything that is not a plain argument vector for a known binary."""
    if not argv:
        raise CommandError("Refusing to run an empty command")
    vector = tuple(str(a) for a in argv)

    binary = os.path.basename(vector[0])
    if binary not in ALLOWED_BINARIES:
        raise CommandError(
            f"Refusing to run {binary!r}: not in the allowed binary set {sorted(ALLOWED_BINARIES)}"
        )

    for argument in vector:
        if "\x00" in argument:
            raise CommandError("Command arguments must not contain NUL bytes")
    return vector


class DryRunRunner:
    """The default runner: records intent, changes nothing.

    Returns success so that callers exercise their full logic, with
    ``executed=False`` on every result so a caller can tell a plan from a
    performed action. Stdout can be scripted per binary for testing parsers.
    """

    __slots__ = ("_responses", "calls")

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        self._responses = responses or {}
        self.calls: list[tuple[str, ...]] = []

    async def run(
        self,
        argv: Sequence[str],
        *,
        privileged: bool = False,
        timeout: float = 30.0,
        check: bool = False,
    ) -> CommandResult:
        vector = _validate(argv)
        self.calls.append(vector)
        logger.info("DRY RUN (not executed): %s", " ".join(vector))

        key = os.path.basename(vector[0])
        return CommandResult(
            argv=vector,
            returncode=0,
            stdout=self._responses.get(key, ""),
            executed=False,
        )


@dataclass(slots=True)
class RecordingRunner:
    """A dry runner that also scripts results per command, for tests.

    Keys are matched as a prefix of the argument vector joined by spaces, so
    ``"wg show"`` matches ``wg show wg0 dump``.
    """

    results: dict[str, CommandResult] = field(default_factory=dict)
    calls: list[tuple[str, ...]] = field(default_factory=list)
    default: CommandResult | None = None

    async def run(
        self,
        argv: Sequence[str],
        *,
        privileged: bool = False,
        timeout: float = 30.0,
        check: bool = False,
    ) -> CommandResult:
        vector = _validate(argv)
        self.calls.append(vector)
        joined = " ".join(vector)

        for prefix, result in self.results.items():
            if joined.startswith(prefix):
                if check and not result.ok:
                    raise CommandError(f"Command failed ({result.returncode}): {joined}")
                return CommandResult(
                    argv=vector,
                    returncode=result.returncode,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    executed=result.executed,
                )

        if self.default is not None:
            return CommandResult(
                argv=vector,
                returncode=self.default.returncode,
                stdout=self.default.stdout,
                stderr=self.default.stderr,
            )
        return CommandResult(argv=vector, returncode=0, executed=False)

    def ran(self, prefix: str) -> bool:
        """Whether any recorded call starts with ``prefix``."""
        return any(" ".join(c).startswith(prefix) for c in self.calls)


class SubprocessRunner:
    """Really executes commands. Must be constructed deliberately.

    Uses :func:`asyncio.create_subprocess_exec` -- an argument vector, no
    shell -- and enforces a timeout with a kill so a hung ``openvpn`` cannot
    stall the daemon.
    """

    __slots__ = ("_escalation",)

    def __init__(self, escalation: Escalation | None = None) -> None:
        self._escalation = escalation if escalation is not None else detect_escalation()

    @property
    def escalation(self) -> Escalation:
        return self._escalation

    async def run(
        self,
        argv: Sequence[str],
        *,
        privileged: bool = False,
        timeout: float = 30.0,
        check: bool = False,
    ) -> CommandResult:
        vector = _validate(argv)

        if privileged:
            prefix = self._escalation.prefix()
            if prefix and shutil.which(prefix[0]) is None:
                raise PrivilegeError(
                    f"{prefix[0]!r} is required to run {vector[0]!r} with "
                    "privilege but is not on PATH"
                )
            vector = (*prefix, *vector)

        started = utcnow()
        try:
            process = await asyncio.create_subprocess_exec(
                *vector,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise CommandError(f"{vector[0]!r} is not installed") from exc
        except OSError as exc:
            raise CommandError(f"Could not start {vector[0]!r}: {exc}") from exc

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError as exc:
            await self._kill(process)
            raise CommandError(f"Command timed out after {timeout}s: {' '.join(vector)}") from exc

        result = CommandResult(
            argv=vector,
            returncode=process.returncode or 0,
            stdout=stdout.decode("utf-8", "replace"),
            stderr=stderr.decode("utf-8", "replace"),
            executed=True,
            duration_ms=int((utcnow() - started).total_seconds() * 1000),
        )

        if privileged and result.returncode != 0 and "password" in result.stderr.lower():
            # sudo -n failed because it wanted a password. Say so precisely:
            # the assistant will not prompt for or store one.
            raise PrivilegeError(
                f"Escalation for {' '.join(argv)!r} requires a password. "
                "Configure a NOPASSWD rule for the specific commands, or run "
                "the daemon as a user that already holds the capability."
            )

        if check and not result.ok:
            raise CommandError(
                f"Command failed ({result.returncode}): {' '.join(vector)}\n"
                f"{result.stderr.strip()[:400]}"
            )
        return result

    @staticmethod
    async def _kill(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            process.kill()
        except ProcessLookupError:  # pragma: no cover - already gone
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except TimeoutError:  # pragma: no cover
            logger.warning("Subprocess did not exit after kill")


def detect_escalation() -> Escalation:
    """Pick an escalation method for this host."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Escalation.NONE
    if shutil.which("sudo"):
        return Escalation.SUDO
    if shutil.which("pkexec"):
        return Escalation.PKEXEC
    return Escalation.NONE


def default_runner() -> CommandRunner:
    """The default runner, which does **not** execute anything.

    Real execution is opt-in: build a :class:`SubprocessRunner` explicitly, or
    pass ``--execute`` on the CLI. Defaulting to a live runner would mean an
    import-time mistake could reconfigure a host's networking.
    """
    return DryRunRunner()
