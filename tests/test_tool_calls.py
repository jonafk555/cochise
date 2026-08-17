import asyncio
import unittest
from types import SimpleNamespace

from cochise.common import LLMFunctionMapping, parse_tool_call
from cochise.planner import Planner


class _Console:
    def log(self, *args, **kwargs):
        return None

    def print(self, *args, **kwargs):
        return None


class _Logger:
    def __init__(self):
        self.console = _Console()
        self.logger = object()
        self.tool_results = []
        self.history = []

    def log_tool_result(self, name, tool_call_id, result, output=True):
        self.tool_results.append((name, tool_call_id, result))

    def log_append_to_history(self, entry, source="manual", output=True):
        self.history.append((entry, source))


class _Executor:
    async def perform_task(
        self,
        next_step: str,
        next_step_context: str,
        mitre_attack_tactic: str,
        mitre_attack_technique: str,
    ) -> str:
        """Execute one delegated task."""

        return next_step

    def setLogger(self, logger):
        return None


def _call(call_id, name, arguments):
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=arguments),
    )


class ToolCallTests(unittest.TestCase):
    def test_parse_tool_call_rejects_malformed_arguments(self):
        name, arguments, error = parse_tool_call(_call("call-1", "perform_task", "{"))

        self.assertEqual(name, "perform_task")
        self.assertIsNone(arguments)
        self.assertIn("Invalid JSON arguments", error)

    def test_planner_tool_surface_matches_prompt_contract(self):
        logger = _Logger()
        planner = Planner("model", None, "scenario", None, logger)

        names = [
            item["function"]["name"]
            for item in planner._build_tool_mapping(_Executor()).get_tool_definitions()
        ]

        self.assertEqual(names[:3], ["perform_task", "ask_human", "register_host_access"])

    def test_planner_returns_tool_error_for_malformed_or_unknown_calls(self):
        async def scenario():
            logger = _Logger()
            planner = Planner("model", None, "scenario", None, logger)
            mapping = LLMFunctionMapping([planner.ask_human])
            response = SimpleNamespace(tool_calls=[
                _call("call-bad-json", "ask_human", "{"),
                _call("call-unknown", "not_registered", "{}"),
            ])

            await planner.handle_tool_calls(response, _Executor(), mapping)

            self.assertEqual(len(planner.history), 2)
            self.assertIn("Invalid JSON arguments", planner.history[0]["content"])
            self.assertIn("Unknown tool", planner.history[1]["content"])
            self.assertTrue(all(item["role"] == "tool" for item in planner.history))

        asyncio.run(scenario())
