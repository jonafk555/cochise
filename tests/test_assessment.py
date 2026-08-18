import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cochise.assessment import (
    AssessmentFinding,
    AssessmentExecutor,
    AssessmentResult,
    BlackBoxRangeAdapter,
    CompositeRangeAdapter,
    RangeAssessmentCoordinator,
    load_range_spec,
    VictimCommandRouter,
)
from cochise.knowledge import Knowledge
from cochise.qa_guidance import load_qa_guidance
from cochise.qa_report import QAReportWriter


class FakeConsole:
    def log(self, *args, **kwargs):
        return None


class FakeLogger:
    def __init__(self):
        self.console = FakeConsole()
        self.events = []

    def log_data(self, name, data=None, output=True):
        self.events.append((name, data))

    def log_llm_call(self, name, result, costs, duration, output=True):
        self.events.append((name, result))

    def log_tool_call(self, name, tool_call_id, params, output=True):
        self.events.append(("tool_call", name))

    def log_tool_result(self, name, tool_call_id, result, output=True):
        self.events.append(("tool_result", name))

    def log_append_to_history(self, entry, source="manual", output=True):
        self.events.append(("history", source))


class AssessmentTests(unittest.TestCase):
    def test_autonomous_host_assessment_stops_repeated_human_requests(self):
        async def scenario():
            logger = FakeLogger()
            worker = AssessmentExecutor(
                "model",
                None,
                "scenario",
                [],
                logger,
                human_interaction=SimpleNamespace(enabled=False),
            )
            response = SimpleNamespace(
                role="assistant",
                content=None,
                tool_calls=[
                    SimpleNamespace(
                        id="human-call",
                        function=SimpleNamespace(
                            name="ask_human",
                            arguments='{"question":"help","reason":"blocked"}',
                        ),
                    )
                ],
            )
            captured_tools = []

            def fake_tool_call(*args, **kwargs):
                captured_tools.append(args[2])
                return response, {"prompt_tokens": 1}, 0.01

            with patch(
                "cochise.assessment.llm_tool_call",
                side_effect=fake_tool_call,
            ) as tool_call, patch(
                "cochise.assessment.llm_call",
                return_value=(
                    {"content": "Assessment stopped after no executable progress."},
                    0.01,
                    {"prompt_tokens": 1},
                ),
            ):
                result = await worker.assess_host("host-a", "{}", "blackbox")

            self.assertEqual(tool_call.call_count, worker.MAX_NO_PROGRESS_ROUNDS)
            self.assertTrue(captured_tools)
            self.assertFalse(captured_tools[0].has_function("ask_human"))
            self.assertIn("no executable progress", result.summary.lower())
            self.assertTrue(any(
                name == "assessment_host_no_progress"
                for name, _data in logger.events
            ))

        asyncio.run(scenario())

    def test_finding_redacts_sensitive_evidence(self):
        finding = AssessmentFinding(
            finding_id="f-1",
            scope="host",
            category="endpoint",
            title="Secret check",
            description="password=secret-value",
            evidence=["token: abc123 password=hunter2"],
        )

        payload = finding.to_dict()
        self.assertNotIn("secret-value", json.dumps(payload))
        self.assertNotIn("hunter2", json.dumps(payload))
        self.assertIn("<redacted>", json.dumps(payload))

    def test_whitebox_spec_loads_and_validates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "range.yaml"
            path.write_text(
                "scenario_ref: demo\n"
                "segments:\n"
                "  - id: internal\n"
                "hosts:\n"
                "  - id: dc01\n"
                "    ips: [10.0.0.10]\n"
            )
            spec = load_range_spec(path)

        self.assertEqual(spec.host("dc01")["ips"], ["10.0.0.10"])
        self.assertEqual(spec.validate()[0].status, "pass")

    def test_unstructured_markdown_spec_is_preserved_for_semantic_qa(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "range.md"
            path.write_text(
                "# Mixed range\n\nThe Linux web host is standalone; client01 is a Windows endpoint.\n",
                encoding="utf-8",
            )
            spec = load_range_spec(path)

        self.assertEqual(spec.format, "markdown")
        self.assertIn("Linux web host", spec.raw_content)
        self.assertIn("semantic", spec.semantic_context().lower())
        self.assertEqual(spec.validate()[0].status, "pass")

    def test_permissive_specs_keep_malformed_text_and_mapping_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "range.json"
            json_path.write_text('{ "hosts": { "dc01": { "role": "domain controller" } }', encoding="utf-8")
            malformed = load_range_spec(json_path)
            self.assertEqual(malformed.format, "json-text")
            self.assertIn('"hosts"', malformed.raw_content)

            yaml_path = Path(directory) / "range.yaml"
            yaml_path.write_text(
                "hosts:\n  dc01:\n    role: domain controller\n",
                encoding="utf-8",
            )
            mapped = load_range_spec(yaml_path)
            self.assertEqual(mapped.host("dc01")["role"], "domain controller")

    def test_knowledge_records_expectations_privilege_and_shell(self):
        async def scenario():
            knowledge = Knowledge(FakeLogger())
            await knowledge.set_expectation_manifest("v1")
            await knowledge.add_assessment_expectation(
                "exp-1",
                "client01",
                "Windows endpoint should be reachable",
                importance="high",
                manifest_version="v1",
            )
            await knowledge.update_assessment_expectation(
                "exp-1", "pass", confidence=0.9, observed="SMB reachable"
            )
            await knowledge.register_shell_session(
                "sh-1",
                "linux-web",
                platform="linux",
                identity="www-data",
                privilege_level="user",
                cwd="/var/www",
            )
            self.assertIn("sh-1", knowledge.get_shell_sessions_context())
            self.assertEqual(knowledge.assessment_expectations["exp-1"]["status"], "pass")
            self.assertEqual(knowledge.get_host("linux-web")["privilege_level"], "user")
            self.assertTrue(knowledge.privilege_events)
            self.assertIn("Privilege events", knowledge.get_compact_knowledge())

        asyncio.run(scenario())

    def test_victim_router_marks_source_and_host(self):
        class Adapter:
            async def execute_victim_command(self, host_id, command, purpose="", shell_id=""):
                return {"output": "event observed", "exit_status": 0}

        async def scenario():
            result = await VictimCommandRouter(Adapter()).execute_victim_command(
                "win01", "Get-WinEvent", "victim baseline"
            )
            self.assertEqual(result["source"], "victim")
            self.assertEqual(result["host_id"], "win01")
            self.assertEqual(result["exit_status"], 0)

        asyncio.run(scenario())

    def test_global_blackbox_preflight_records_evidence(self):
        async def runner(command, technique, procedure):
            return {"output": f"evidence for {command}", "exit_status": 0}

        async def scenario():
            logger = FakeLogger()
            knowledge = Knowledge(logger)
            adapter = BlackBoxRangeAdapter(runner, ["10.0.0.0/24"])
            with tempfile.TemporaryDirectory() as directory:
                report_writer = QAReportWriter(Path(directory) / "qa-report.md")
                coordinator = RangeAssessmentCoordinator(
                    adapter,
                    logger,
                    report_writer=report_writer,
                )

                result = await coordinator.run_global_preflight(knowledge)

                self.assertEqual(result.scope, "global")
                self.assertEqual(result.status, "pass")
                self.assertGreaterEqual(len(knowledge.assessment_findings), 4)
                self.assertEqual(knowledge.get_pending_hosts(), [])
                self.assertIn(
                    "Global: `cyber-range`",
                    report_writer.path.read_text(encoding="utf-8"),
                )

        asyncio.run(scenario())

    def test_host_access_requires_assessment_and_then_clears_gate(self):
        async def runner(command, technique, procedure):
            return {"output": "Host is up", "exit_status": 0}

        async def host_assessor(host_id, context, mode):
            return AssessmentResult(
                assessment_id="assessment-1",
                scope="host",
                mode=mode,
                target=host_id,
                status="pass",
                summary="host checked",
                findings=[AssessmentFinding(
                    finding_id="host-finding",
                    scope="host",
                    category="os",
                    title="OS observed",
                    description="Windows observed",
                    status="pass",
                    host_id=host_id,
                )],
            )

        async def scenario():
            logger = FakeLogger()
            knowledge = Knowledge(logger)
            await knowledge.register_host_access(
                "dc01",
                hostname="dc01",
                ip_addresses="10.0.0.10",
                access_method="lateral movement",
                evidence="authenticated command succeeded",
            )
            self.assertEqual(knowledge.get_pending_hosts(), ["dc01"])

            coordinator = RangeAssessmentCoordinator(
                BlackBoxRangeAdapter(runner),
                logger,
                host_assessor=host_assessor,
            )
            result = await coordinator.assess_host("dc01", knowledge)

            self.assertIsNotNone(result)
            self.assertTrue(knowledge.is_host_assessed("dc01"))
            self.assertEqual(knowledge.get_pending_hosts(), [])
            self.assertIn("host-finding", knowledge.assessment_findings)

        asyncio.run(scenario())

    def test_control_plane_evidence_reaches_host_assessor(self):
        class ControlPlane:
            async def collect_global(self, spec=None):
                return {"evidence": [{"category": "infra", "output": "control ok"}]}

            async def collect_host(self, host_id, host, spec=None):
                return {"evidence": [{"category": "control-plane", "output": "host state ok"}]}

        async def runner(command, technique, procedure):
            return {"output": "Host is up", "exit_status": 0}

        async def host_assessor(host_id, context, mode):
            self.assertIn("host state ok", context)
            return AssessmentResult(
                assessment_id="assessment-2",
                scope="host",
                mode=mode,
                target=host_id,
                status="pass",
                summary="host checked",
            )

        async def scenario():
            logger = FakeLogger()
            knowledge = Knowledge(logger)
            await knowledge.register_host_access("workstation", ip_addresses="10.0.0.20")
            adapter = CompositeRangeAdapter(
                BlackBoxRangeAdapter(runner),
                ControlPlane(),
            )
            coordinator = RangeAssessmentCoordinator(
                adapter,
                logger,
                host_assessor=host_assessor,
            )
            result = await coordinator.assess_host("workstation", knowledge)
            self.assertIsNotNone(result)
            self.assertTrue(any(
                item.get("source") == "control-plane"
                for item in result.to_dict()["evidence"]
            ))

        asyncio.run(scenario())

    def test_human_qa_guidance_reaches_host_worker_context(self):
        async def runner(command, technique, procedure):
            return {"output": "Host is up", "exit_status": 0}

        async def host_assessor(host_id, context, mode):
            self.assertIn("human_qa_instructions", context)
            self.assertIn("threat-intelligence", context)
            return AssessmentResult(
                assessment_id="assessment-guided",
                scope="host",
                mode=mode,
                target=host_id,
                status="pass",
                summary="guided host QA completed",
            )

        async def scenario():
            logger = FakeLogger()
            knowledge = Knowledge(logger)
            await knowledge.register_host_access("linux-web", ip_addresses="10.0.0.30")
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "qa.md"
                path.write_text(
                    "Use threat-intelligence to validate the web-to-Linux pivot.",
                    encoding="utf-8",
                )
                coordinator = RangeAssessmentCoordinator(
                    BlackBoxRangeAdapter(runner),
                    logger,
                    host_assessor=host_assessor,
                    qa_guidance=load_qa_guidance(path),
                )
                result = await coordinator.assess_host("linux-web", knowledge)
                self.assertIsNotNone(result)
                self.assertEqual(result.metadata["human_qa_guidance"]["format"], "markdown")

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
