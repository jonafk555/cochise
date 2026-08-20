import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from cochise.assessment import VictimCommandRouter
from cochise.ssh_connection import (
    SSHConnection,
    find_excluded_targets,
    parse_network_list,
)


class NetworkScopeTests(unittest.TestCase):
    def test_parse_network_list_accepts_comma_and_semicolon_separators(self):
        networks = parse_network_list("192.168.100.0/24; 10.0.0.0/8,192.168.100.0/24")

        self.assertEqual(
            [str(network) for network in networks],
            ["192.168.100.0/24", "10.0.0.0/8"],
        )

    def test_invalid_excluded_network_fails_configuration(self):
        with self.assertRaisesRegex(ValueError, "RANGE_EXCLUDED_NETWORKS"):
            parse_network_list("not-a-cidr")

    def test_find_excluded_targets_detects_addresses_and_cidrs(self):
        excluded = parse_network_list("192.168.100.0/24")

        self.assertEqual(
            find_excluded_targets(
                "nmap -sV 192.168.100.25 && curl http://192.168.100.0/24:8080",
                excluded,
            ),
            ["192.168.100.25", "192.168.100.0/24"],
        )
        self.assertEqual(
            find_excluded_targets("nmap -sV 192.168.101.25", excluded),
            [],
        )

    def test_execute_command_skips_before_opening_ssh(self):
        async def scenario():
            connection = SSHConnection(
                excluded_networks=parse_network_list("192.168.100.0/24")
            )
            connection.run = AsyncMock(side_effect=AssertionError("must not run"))

            result = await connection.execute_command(
                "nmap 192.168.100.10",
                "Network Service Scanning",
                "scope guard regression",
            )

            # Excluded commands are intentionally silent: no transport call,
            # policy marker, or synthetic exit status is exposed to the LLM.
            self.assertEqual(result, "")
            connection.run.assert_not_awaited()

        asyncio.run(scenario())

    def test_get_ssh_connection_reads_excluded_networks(self):
        with patch.dict(
            "os.environ",
            {
                "TARGET_HOST": "192.0.2.10",
                "TARGET_USERNAME": "tester",
                "TARGET_PASSWORD": "secret",
                "RANGE_EXCLUDED_NETWORKS": "192.168.100.0/24",
            },
            clear=True,
        ):
            from cochise.ssh_connection import get_ssh_connection_from_env

            connection = get_ssh_connection_from_env()

        self.assertEqual(
            [str(network) for network in connection.excluded_networks],
            ["192.168.100.0/24"],
        )

    def test_victim_router_skips_excluded_target_before_adapter(self):
        class Adapter:
            async def execute_victim_command(self, *args, **kwargs):
                raise AssertionError("must not reach victim adapter")

        async def scenario():
            router = VictimCommandRouter(
                Adapter(),
                parse_network_list("192.168.100.0/24"),
            )
            result = await router.execute_victim_command(
                "192.168.100.10",
                "powershell -Command Get-Date",
            )
            self.assertEqual(result, "")

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
