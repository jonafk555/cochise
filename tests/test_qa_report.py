import tempfile
import unittest
from pathlib import Path

from cochise.assessment import AssessmentFinding, AssessmentResult
from cochise.qa_report import QAReportWriter


class QAReportTests(unittest.TestCase):
    def test_report_is_updated_and_redacts_sensitive_values(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "qa-report.md"
            writer = QAReportWriter(report_path, {"range_mode": "blackbox"})

            global_result = AssessmentResult(
                assessment_id="global-1",
                scope="global",
                mode="blackbox",
                target="cyber-range",
                status="warning",
                summary="Global preflight completed.",
                findings=[AssessmentFinding(
                    finding_id="finding-1",
                    scope="global",
                    category="infra",
                    title="Secret-shaped evidence",
                    description="password=super-secret",
                    status="fail",
                    severity="high",
                    evidence=["token=abc123"],
                )],
                evidence=[{
                    "category": "routing",
                    "command": "ip route",
                    "output": "default route observed",
                    "exit_status": 0,
                }],
            )
            writer.record_result(global_result)

            content = report_path.read_text(encoding="utf-8")
            self.assertIn("# Cochise Cyber Range QA Report", content)
            self.assertIn("Global: `cyber-range`", content)
            self.assertIn("finding-1", content)
            self.assertIn("<redacted>", content)
            self.assertNotIn("super-secret", content)
            self.assertNotIn("abc123", content)

            host_result = AssessmentResult(
                assessment_id="host-1",
                scope="host",
                mode="blackbox",
                target="dc01",
                status="pass",
                summary="Host assessment completed.",
            )
            writer.record_result(host_result)
            writer.finalize()

            content = report_path.read_text(encoding="utf-8")
            self.assertIn("Host: `dc01`", content)
            self.assertIn("Report status: **completed**", content)
            self.assertEqual(content.count("Assessment ID: `global-1`"), 1)

    def test_report_tracks_live_progress_expectations_and_deduplicates_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "qa-report.md"
            writer = QAReportWriter(report_path, {"range_mode": "whitebox"})
            writer.record_expectations([
                {
                    "expectation_id": "exp-1",
                    "subject": "win01",
                    "description": "Windows endpoint is reachable",
                    "importance": "high",
                    "confidence": 0.9,
                    "status": "pass",
                },
                {
                    "expectation_id": "exp-2",
                    "subject": "linux01",
                    "description": "Linux endpoint is reachable",
                    "importance": "medium",
                    "confidence": 0.4,
                    "status": "unknown",
                },
            ], "v1")
            writer.record_progress(
                "host-1",
                scope="host",
                mode="whitebox",
                target="win01",
                phase="victim-validation",
                round_number=2,
                summary="still collecting evidence",
            )
            writer.record_result(AssessmentResult(
                assessment_id="host-1",
                scope="host",
                mode="whitebox",
                target="win01",
                status="pass",
                summary="done",
                evidence=[
                    {"source": "victim", "category": "event", "output": "same output"},
                    {"source": "victim", "category": "event", "output": "same output"},
                ],
                metadata={
                    "expectations": [
                        {
                            "expectation_id": "exp-1",
                            "subject": "win01",
                            "description": "Windows endpoint is reachable",
                            "importance": "high",
                            "confidence": 0.9,
                            "status": "pass",
                        }
                    ],
                    "expectation_manifest_version": "v1",
                },
            ))
            content = report_path.read_text(encoding="utf-8")
            self.assertIn("Expectation coverage", content)
            self.assertIn("Expectation conformance", content)
            self.assertIn("victim-validation", content)
            self.assertIn("Artifact index", content)
            manifest = (report_path.parent / "artifacts" / "artifact-manifest.jsonl").read_text(
                encoding="utf-8"
            )
            self.assertEqual(len(manifest.splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
