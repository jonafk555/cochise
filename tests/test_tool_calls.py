import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cochise.assessment import AssessmentResult
from cochise.common import LLMFunctionMapping, parse_tool_call
from cochise.executor import ExecutorFactory
from cochise.knowledge import Knowledge
from cochise.planner import Planner


class _Console:
    def log(self, *args, **kwargs):
        return None

    def print(self, *args, **kwargs):
        return None

    def status(self, *args, **kwargs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _Logger:
    def __init__(self):
        self.console = _Console()
        self.logger = object()
        self.tool_results = []
        self.history = []
        self.data = []

    def log_tool_result(self, name, tool_call_id, result, output=True):
        self.tool_results.append((name, tool_call_id, result))

    def log_tool_call(self, name, tool_call_id, params, output=True):
        return None

    def log_data(self, name, data=None, output=True):
        self.data.append((name, data))

    def log_llm_call(self, name, result, costs, duration, output=True):
        return None

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
    def test_default_planner_does_not_require_assessment_coordinator(self):
        async def scenario():
            logger = _Logger()
            interaction = SimpleNamespace(enabled=False)
            planner = Planner(
                "model",
                None,
                "scenario",
                None,
                logger,
                human_interaction=interaction,
                hard_max_interactions=1,
            )

            class StoppingExecutor(_Executor):
                async def perform_task(
                    self,
                    next_step: str,
                    next_step_context: str,
                    mitre_attack_tactic: str,
                    mitre_attack_technique: str,
                ):
                    planner.human_stop_requested = True
                    return "task complete", Knowledge(logger)

            class Factory:
                def build(self, knowledge):
                    return StoppingExecutor()

            planner.executor_factory = Factory()
            planner.create_initial_plan = lambda: "1.1 Execute the first task"
            response = SimpleNamespace(
                role="assistant",
                content=None,
                tool_calls=[
                    _call(
                        "call-task",
                        "perform_task",
                        (
                            '{"next_step":"execute first task",'
                            '"next_step_context":"target context",'
                            '"mitre_attack_tactic":"Discovery",'
                            '"mitre_attack_technique":"Network Service Scanning"}'
                        ),
                    ),
                ],
            )

            with patch(
                "cochise.planner.llm_tool_call",
                return_value=(response, {"prompt_tokens": 1}, 0.01),
            ) as llm_call:
                await planner.engage()

            self.assertEqual(llm_call.call_count, 1)
            self.assertIsNone(llm_call.call_args.kwargs["tool_choice"])

        asyncio.run(scenario())

    def test_executor_tool_surface_is_original_by_default_and_extended_for_qa(self):
        async def run_executor(qa_enabled):
            logger = _Logger()
            factory = ExecutorFactory(
                "model",
                None,
                "scenario",
                [],
                logger,
                human_interaction=SimpleNamespace(enabled=False),
                qa_enabled=qa_enabled,
            )
            executor = factory.build(Knowledge(logger))
            response = SimpleNamespace(
                role="assistant",
                content="done",
                tool_calls=[],
            )
            with patch(
                "cochise.executor.llm_tool_call",
                return_value=(response, {"prompt_tokens": 1}, 0.01),
            ) as llm_call:
                await executor.perform_task(
                    "scan target",
                    "target context",
                    "Discovery",
                    "Network Service Scanning",
                )
            return [
                item["function"]["name"]
                for item in llm_call.call_args.args[2].get_tool_definitions()
            ]

        default_names = asyncio.run(run_executor(False))
        qa_names = asyncio.run(run_executor(True))

        self.assertEqual(
            default_names,
            [
                "add_compromised_account",
                "update_compromised_account",
                "add_entity_information",
                "update_entity_information",
            ],
        )
        self.assertIn("register_shell_session", qa_names)
        self.assertIn("record_host_privilege", qa_names)

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

        self.assertEqual(
            names[:3],
            ["perform_task", "add_compromised_account", "update_compromised_account"],
        )
        self.assertNotIn("ask_human", names)
        self.assertNotIn("register_host_access", names)

    def test_qa_planner_tool_surface_is_opt_in(self):
        logger = _Logger()
        planner = Planner(
            "model",
            None,
            "scenario",
            None,
            logger,
            assessment_coordinator=object(),
            qa_enabled=True,
        )

        names = [
            item["function"]["name"]
            for item in planner._build_tool_mapping(_Executor()).get_tool_definitions()
        ]

        self.assertEqual(names[:3], ["perform_task", "ask_human", "register_host_access"])

    def test_autonomous_planner_requires_perform_task(self):
        logger = _Logger()
        interaction = SimpleNamespace(enabled=False)
        planner = Planner(
            "model",
            None,
            "scenario",
            None,
            logger,
            human_interaction=interaction,
            qa_enabled=True,
        )

        self.assertEqual(
            planner._planner_tool_choice(),
            {"type": "function", "function": {"name": "perform_task"}},
        )
        self.assertIn("Do not call ask_human", planner._planner_execution_prompt())

    def test_autonomous_planner_tool_surface_excludes_ask_human(self):
        logger = _Logger()
        interaction = SimpleNamespace(enabled=False)
        planner = Planner(
            "model",
            None,
            "scenario",
            None,
            logger,
            human_interaction=interaction,
            qa_enabled=True,
        )

        names = [
            item["function"]["name"]
            for item in planner._build_tool_mapping(_Executor()).get_tool_definitions()
        ]

        self.assertNotIn("ask_human", names)
        self.assertIn("perform_task", names)

    def test_planner_reports_progress_for_valid_tool_call(self):
        async def scenario():
            logger = _Logger()
            planner = Planner("model", None, "scenario", None, logger)
            executor = _Executor()
            mapping = planner._build_tool_mapping(executor)
            response = SimpleNamespace(role="assistant", content=None, tool_calls=[
                _call(
                    "call-task",
                    "perform_task",
                    (
                        '{"next_step":"scan target",'
                        '"next_step_context":"target context",'
                        '"mitre_attack_tactic":"Discovery",'
                        '"mitre_attack_technique":"Network Service Scanning"}'
                    ),
                ),
            ])

            progressed, errors = await planner.handle_tool_calls(response, executor, mapping)

            self.assertTrue(progressed)
            self.assertEqual(errors, 0)
            self.assertEqual(len(planner.history), 1)

        asyncio.run(scenario())

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

    def test_autonomous_engage_executes_forced_task_call(self):
        async def scenario():
            logger = _Logger()
            interaction = SimpleNamespace(enabled=False)
            planner = Planner(
                "model",
                None,
                "scenario",
                None,
                logger,
                max_runtime=60,
                human_interaction=interaction,
            )

            class Preflight:
                async def run_global_preflight(self, knowledge):
                    result = AssessmentResult(
                        assessment_id="global-test",
                        scope="global",
                        mode="blackbox",
                        target="cyber-range",
                        status="pass",
                        summary="preflight ok",
                    )
                    knowledge.record_assessment_result(result)
                    return result

                async def assess_host(self, host_id, knowledge):
                    return None

            class StoppingExecutor(_Executor):
                async def perform_task(
                    self,
                    next_step: str,
                    next_step_context: str,
                    mitre_attack_tactic: str,
                    mitre_attack_technique: str,
                ):
                    planner.human_stop_requested = True
                    return "task complete", Knowledge(logger)

            class Factory:
                def build(self, knowledge):
                    return StoppingExecutor()

            planner.assessment_coordinator = Preflight()
            planner.executor_factory = Factory()
            planner.create_initial_plan = lambda: "1.1 Execute the first task"
            response = SimpleNamespace(role="assistant", content=None, tool_calls=[
                _call(
                    "call-task",
                    "perform_task",
                    (
                        '{"next_step":"execute first task",'
                        '"next_step_context":"target context",'
                        '"mitre_attack_tactic":"Discovery",'
                        '"mitre_attack_technique":"Network Service Scanning"}'
                    ),
                ),
            ])

            with patch(
                "cochise.planner.llm_tool_call",
                return_value=(response, {"prompt_tokens": 1}, 0.01),
            ) as llm_call:
                await planner.engage()

            self.assertEqual(llm_call.call_count, 1)
            self.assertEqual(
                llm_call.call_args.kwargs["tool_choice"],
                {"type": "function", "function": {"name": "perform_task"}},
            )

        asyncio.run(scenario())

    def test_autonomous_engage_stops_after_repeated_no_progress(self):
        async def scenario():
            logger = _Logger()
            interaction = SimpleNamespace(enabled=False)
            planner = Planner(
                "model",
                None,
                "scenario",
                None,
                logger,
                max_runtime=60,
                human_interaction=interaction,
            )

            class Preflight:
                async def run_global_preflight(self, knowledge):
                    return AssessmentResult(
                        assessment_id="global-test",
                        scope="global",
                        mode="blackbox",
                        target="cyber-range",
                        status="pass",
                        summary="preflight ok",
                    )

                async def assess_host(self, host_id, knowledge):
                    return None

            class Factory:
                def build(self, knowledge):
                    return _Executor()

            planner.assessment_coordinator = Preflight()
            planner.executor_factory = Factory()
            planner.create_initial_plan = lambda: "1.1 Execute the first task"
            responses = [
                SimpleNamespace(
                    role="assistant",
                    content="I need more information.",
                    tool_calls=[],
                )
                for _ in range(3)
            ]

            with patch(
                "cochise.planner.llm_tool_call",
                side_effect=[(response, {"prompt_tokens": 1}, 0.01) for response in responses],
            ) as llm_call:
                await planner.engage()

            self.assertEqual(llm_call.call_count, 3)
            self.assertIn(
                "Planner stopped after repeated non-tool responses in autonomous mode.",
                [data for name, data in logger.data if name == "completed"],
            )

        asyncio.run(scenario())

    def test_autonomous_engage_stops_when_executor_did_no_work(self):
        async def scenario():
            logger = _Logger()
            planner = Planner(
                "model",
                None,
                "scenario",
                None,
                logger,
                max_runtime=60,
                human_interaction=SimpleNamespace(enabled=False),
            )

            class Preflight:
                async def run_global_preflight(self, knowledge):
                    return AssessmentResult(
                        assessment_id="global-test",
                        scope="global",
                        mode="blackbox",
                        target="cyber-range",
                        status="pass",
                        summary="preflight ok",
                    )

                async def assess_host(self, host_id, knowledge):
                    return None

            class NoProgressExecutor(_Executor):
                last_task_progressed = False

                async def perform_task(
                    self,
                    next_step: str,
                    next_step_context: str,
                    mitre_attack_tactic: str,
                    mitre_attack_technique: str,
                ):
                    return "No command was executed", Knowledge(logger)

            class Factory:
                def build(self, knowledge):
                    return NoProgressExecutor()

            planner.assessment_coordinator = Preflight()
            planner.executor_factory = Factory()
            planner.create_initial_plan = lambda: "1.1 Execute the first task"
            response = SimpleNamespace(
                role="assistant",
                content=None,
                tool_calls=[
                    _call(
                        "call-task",
                        "perform_task",
                        (
                            '{"next_step":"execute first task",'
                            '"next_step_context":"target context",'
                            '"mitre_attack_tactic":"Discovery",'
                            '"mitre_attack_technique":"Network Service Scanning"}'
                        ),
                    ),
                ],
            )

            with patch(
                "cochise.planner.llm_tool_call",
                side_effect=[(response, {"prompt_tokens": 1}, 0.01)] * 3,
            ) as llm_call:
                await planner.engage()

            self.assertEqual(llm_call.call_count, 3)
            self.assertIn(
                "Planner stopped after repeated rounds without executable progress.",
                [data for name, data in logger.data if name == "completed"],
            )

        asyncio.run(scenario())

    def test_autonomous_engage_honors_hard_interaction_limit(self):
        async def scenario():
            logger = _Logger()
            planner = Planner(
                "model",
                None,
                "scenario",
                None,
                logger,
                max_runtime=60,
                human_interaction=SimpleNamespace(enabled=False),
                hard_max_interactions=2,
            )

            class Preflight:
                async def run_global_preflight(self, knowledge):
                    return AssessmentResult(
                        assessment_id="global-test",
                        scope="global",
                        mode="blackbox",
                        target="cyber-range",
                        status="pass",
                        summary="preflight ok",
                    )

                async def assess_host(self, host_id, knowledge):
                    return None

            class Factory:
                def build(self, knowledge):
                    return _Executor()

            planner.assessment_coordinator = Preflight()
            planner.executor_factory = Factory()
            planner.create_initial_plan = lambda: "1.1 Execute the first task"
            response = SimpleNamespace(
                role="assistant",
                content=None,
                tool_calls=[
                    _call(
                        "call-task",
                        "perform_task",
                        (
                            '{"next_step":"execute first task",'
                            '"next_step_context":"target context",'
                            '"mitre_attack_tactic":"Discovery",'
                            '"mitre_attack_technique":"Network Service Scanning"}'
                        ),
                    ),
                ],
            )

            with patch(
                "cochise.planner.llm_tool_call",
                side_effect=[(response, {"prompt_tokens": 1}, 0.01)] * 2,
            ) as llm_call:
                await planner.engage()

            self.assertEqual(llm_call.call_count, 2)
            self.assertIn(
                "Hard planner interaction limit of 2 reached.",
                [data for name, data in logger.data if name == "completed"],
            )

        asyncio.run(scenario())

    def test_autonomous_engage_stops_after_repeated_tool_errors(self):
        async def scenario():
            logger = _Logger()
            planner = Planner(
                "model",
                None,
                "scenario",
                None,
                logger,
                max_runtime=60,
                human_interaction=SimpleNamespace(enabled=False),
            )

            class Preflight:
                async def run_global_preflight(self, knowledge):
                    return AssessmentResult(
                        assessment_id="global-test",
                        scope="global",
                        mode="blackbox",
                        target="cyber-range",
                        status="pass",
                        summary="preflight ok",
                    )

                async def assess_host(self, host_id, knowledge):
                    return None

            class Factory:
                def build(self, knowledge):
                    return _Executor()

            planner.assessment_coordinator = Preflight()
            planner.executor_factory = Factory()
            planner.create_initial_plan = lambda: "1.1 Execute the first task"
            responses = [
                SimpleNamespace(
                    role="assistant",
                    content=None,
                    tool_calls=[_call("call-bad", "perform_task", "{")],
                )
                for _ in range(3)
            ]

            with patch(
                "cochise.planner.llm_tool_call",
                side_effect=[(response, {"prompt_tokens": 1}, 0.01) for response in responses],
            ) as llm_call:
                await planner.engage()

            self.assertEqual(llm_call.call_count, 3)
            self.assertIn(
                "Planner stopped after repeated tool-call repair failures.",
                [data for name, data in logger.data if name == "completed"],
            )

        asyncio.run(scenario())
