import asyncio
import unittest

from cochise.assessment import AssessmentResult
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
        self.events = []

    def log_data(self, name, data=None, output=True):
        self.events.append((name, data))

    def log_append_to_history(self, *args, **kwargs):
        return None


class _Coordinator:
    def __init__(self):
        self.global_started = asyncio.Event()
        self.host_started = asyncio.Event()

    async def run_global_preflight(self, knowledge):
        self.global_started.set()
        await asyncio.sleep(0.02)
        result = AssessmentResult(
            assessment_id="global-parallel",
            scope="global",
            mode="blackbox",
            target="cyber-range",
            status="blocked",
            summary="blocked evidence must not stop attack planning",
        )
        knowledge.record_assessment_result(result)
        return result

    async def assess_host(self, host_id, knowledge):
        self.host_started.set()
        await asyncio.sleep(0.02)
        result = AssessmentResult(
            assessment_id=f"host-{host_id}",
            scope="host",
            mode="blackbox",
            target=host_id,
            status="blocked",
            summary="host QA completed in background",
        )
        knowledge.record_assessment_result(result)
        return result


class ParallelQATests(unittest.TestCase):
    def test_global_preflight_is_started_without_gating_attack(self):
        async def scenario():
            logger = _Logger()
            coordinator = _Coordinator()
            planner = Planner(
                "model",
                None,
                "scenario",
                None,
                logger,
                assessment_coordinator=coordinator,
                qa_enabled=True,
            )

            self.assertTrue(await planner._run_global_preflight())
            self.assertFalse(planner.preflight_complete)
            await coordinator.global_started.wait()
            await planner._global_preflight_task
            planner._poll_background_qa()
            self.assertTrue(planner.preflight_complete)
            self.assertIn(
                "assessment_global_background_complete",
                [name for name, _data in logger.events],
            )

        asyncio.run(scenario())

    def test_host_qa_is_scheduled_without_waiting_for_completion(self):
        async def scenario():
            logger = _Logger()
            coordinator = _Coordinator()
            planner = Planner(
                "model",
                None,
                "scenario",
                None,
                logger,
                assessment_coordinator=coordinator,
                qa_enabled=True,
            )
            await planner.knowledge.register_host_access(
                "host-a",
                ip_addresses="192.0.2.10",
                evidence="authorized access",
            )

            self.assertTrue(await planner._run_pending_host_assessments())
            await coordinator.host_started.wait()
            self.assertIn("host-a", planner._host_assessment_tasks)
            self.assertIn("parallel", planner._planner_execution_prompt().lower())

            await planner._host_assessment_tasks["host-a"]
            planner._poll_background_qa()

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
