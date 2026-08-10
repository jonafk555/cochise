import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from cochise.assessment import (
    AssessmentFinding,
    AssessmentResult,
    BlackBoxRangeAdapter,
    CompositeRangeAdapter,
    RangeAssessmentCoordinator,
    load_range_spec,
)
from cochise.knowledge import Knowledge


class FakeConsole:
    def log(self, *args, **kwargs):
        return None


class FakeLogger:
    def __init__(self):
        self.console = FakeConsole()
        self.events = []

    def log_data(self, name, data=None, output=True):
        self.events.append((name, data))


class AssessmentTests(unittest.TestCase):
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

    def test_global_blackbox_preflight_records_evidence(self):
        async def runner(command, technique, procedure):
            return {"output": f"evidence for {command}", "exit_status": 0}

        async def scenario():
            logger = FakeLogger()
            knowledge = Knowledge(logger)
            adapter = BlackBoxRangeAdapter(runner, ["10.0.0.0/24"])
            coordinator = RangeAssessmentCoordinator(adapter, logger)

            result = await coordinator.run_global_preflight(knowledge)

            self.assertEqual(result.scope, "global")
            self.assertEqual(result.status, "pass")
            self.assertGreaterEqual(len(knowledge.assessment_findings), 4)
            self.assertEqual(knowledge.get_pending_hosts(), [])

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


if __name__ == "__main__":
    unittest.main()
