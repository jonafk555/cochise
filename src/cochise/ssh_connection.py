from __future__ import annotations

import ipaddress
import os
import re

import asyncssh

from asyncssh import SSHClientConnection
from dataclasses import dataclass
from typing import Iterable

from cochise.common import get_or_fail


_IP_LITERAL_RE = re.compile(
    r"(?<![0-9A-Za-z_.])"
    r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
    r"(?![0-9A-Za-z_.])"
    r"|"
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:.]+(?:/\d{1,3})?"
    r"(?![0-9A-Fa-f:])"
)


def parse_network_list(value: str | Iterable[str] | None) -> tuple[ipaddress._BaseNetwork, ...]:
    """Parse comma/semicolon-separated CIDRs for the hard exclusion policy."""

    if value is None:
        return ()
    values = value.replace(";", ",").split(",") if isinstance(value, str) else value
    networks: list[ipaddress._BaseNetwork] = []
    for raw_value in values:
        raw = str(raw_value).strip()
        if not raw:
            continue
        try:
            networks.append(ipaddress.ip_network(raw, strict=False))
        except ValueError as exc:
            raise ValueError(
                f"RANGE_EXCLUDED_NETWORKS contains an invalid network: {raw}"
            ) from exc
    # Stable de-duplication keeps logs and rejection messages deterministic.
    return tuple(dict.fromkeys(networks))


def find_excluded_targets(
    command: str,
    excluded_networks: Iterable[ipaddress._BaseNetwork],
) -> list[str]:
    """Return IP/CIDR literals in ``command`` that overlap an excluded network.

    The command interface accepts arbitrary shell text, so a runtime guard can
    reliably reject literal IP/CIDR targets but cannot infer the destination of
    an opaque hostname or a script that constructs its target dynamically.
    """

    excluded = tuple(excluded_networks)
    if not excluded:
        return []

    blocked: list[str] = []
    for match in _IP_LITERAL_RE.finditer(str(command)):
        literal = match.group(0).strip("[]")
        try:
            candidate: ipaddress._BaseNetwork | ipaddress._BaseAddress
            if "/" in literal:
                candidate = ipaddress.ip_network(literal, strict=False)
            else:
                candidate = ipaddress.ip_address(literal)
        except ValueError:
            continue

        overlaps = False
        for network in excluded:
            try:
                overlaps = (
                    candidate.overlaps(network)
                    if isinstance(candidate, ipaddress._BaseNetwork)
                    else candidate in network
                )
            except TypeError:
                # IPv4 and IPv6 ranges cannot overlap.
                overlaps = False
            if overlaps:
                break
        if overlaps and literal not in blocked:
            blocked.append(literal)
    return blocked

@dataclass
class SSHConnection:
    host: str = 'localhost'
    username: str = 'changeme'
    password: str = 'changeme'
    port: int = 22
    timeout: int = 600
    excluded_networks: tuple[ipaddress._BaseNetwork, ...] = ()

    _conn: SSHClientConnection|None = None

    async def connect(self):
        self._conn = await asyncssh.connect(self.host, port=self.port, username=self.username, password=self.password, known_hosts=None)

    # execute the command. We redirect stderr to stdout (to have a unified output stream)
    # and configure a timeout.
    async def run(self, cmd) -> dict[str,str|int|bytes|None]:
        if self._conn is None:
            raise Exception("SSH Connection not established")
        
        result = await self._conn.run(cmd, timeout=self.timeout, stderr=asyncssh.STDOUT)
        return {
            'output': result.stdout,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'exit_status': result.returncode
        }
    
    async def execute_command(
        self,
        command: str,
        mitre_attack_technique: str,
        mitre_attack_procedure: str,
    ) -> str:
        """Execute a command over SSH and return the output.

        Parameters
        ----------
        command : str
            The command to execute.
        
        mitre_attack_technique : str
            The MITRE ATT&CK technique associated with the command.

        mitre_attack_procedure : str
            The MITRE ATT&CK procedure associated with the command.

        Returns
        -------
        str
            The output of the executed command.
        """
        excluded_targets = find_excluded_targets(command, self.excluded_networks)
        if excluded_targets:
            # Keep the scope boundary inside Python, but do not expose a
            # policy-specific tool result to the LLM.  The excluded command is
            # simply not sent to the SSH transport.
            return ""

        try:
            return str((await self.run(command))['stdout'])
        except asyncssh.misc.ChannelOpenError:
            print("channel wasn't able to be opened, retrying...")
            await self.connect()
            return str((await self.run(command))['stdout'])
        except asyncssh.process.TimeoutError as e:
            return f"""Timeout during command execution over SSH command execution.
The command will be stopped, if files have been generated by the command they will be left on the system.

The output so far was:

```bash
{e.stdout}
```"""
    
def get_ssh_connection_from_env() -> SSHConnection:
    host = get_or_fail("TARGET_HOST")
    username = get_or_fail("TARGET_USERNAME")
    password = get_or_fail("TARGET_PASSWORD")

    excluded_networks = parse_network_list(os.getenv("RANGE_EXCLUDED_NETWORKS", ""))
    return SSHConnection(
        host=host,
        username=username,
        password=password,
        excluded_networks=excluded_networks,
    )
