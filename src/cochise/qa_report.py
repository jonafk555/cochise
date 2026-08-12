"""Incrementally rendered Markdown reports for Cyber Range assessments."""

from __future__ import annotations

import datetime as dt
import pathlib
import re
import threading
from typing import Any

from cochise.artifacts import ArtifactRegistry


_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_ -]?key|authorization|private[_ -]?key)"
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_ -]?key|authorization)\b\s*"
    r"([:=])\s*([^\s,;]+)"
)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _redact_text(value: Any) -> str:
    return _SENSITIVE_VALUE_RE.sub(r"\1\2<redacted>", str(value))


def _safe_value(value: Any, key: str = "") -> Any:
    """Return a recursively redacted value suitable for a report."""

    if _SENSITIVE_KEY_RE.search(key):
        return "<redacted>"
    if isinstance(value, dict):
        return {
            str(item_key): _safe_value(item, str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [_safe_value(item, key) for item in value]
    if isinstance(value, tuple):
        return [_safe_value(item, key) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _inline(value: Any) -> str:
    """Escape a value for use inside a Markdown table cell."""

    text = _redact_text(value)
    return text.replace("|", r"\|").replace("\n", " ").strip()


def _code_block(value: Any) -> str:
    text = _redact_text(value).replace("```", "'''" )
    return f"```text\n{text}\n```"


class QAReportWriter:
    """Continuously render assessment results to one Markdown file.

    The file is initialized when the writer is created and re-rendered after
    every global or host assessment. Rendering the complete current state keeps
    the report idempotent if an assessment is retried and leaves the latest
    completed results available if the process exits unexpectedly.
    """

    def __init__(
        self,
        path: str | pathlib.Path,
        metadata: dict[str, Any] | None = None,
        artifact_dir: str | pathlib.Path | None = None,
    ):
        self.path = pathlib.Path(path)
        self.metadata = _safe_value(metadata or {})
        self.started_at = _now()
        self.updated_at = self.started_at
        self.run_status = "in_progress"
        self.error: str | None = None
        self.results: dict[str, dict[str, Any]] = {}
        self.expectations: dict[str, dict[str, Any]] = {}
        self.expectation_manifest_version = ""
        self.artifacts = ArtifactRegistry(
            artifact_dir or (self.path.parent / "artifacts")
        )
        self._lock = threading.RLock()
        self._write()

    def record_result(self, result: Any) -> None:
        """Store and immediately render one completed assessment result."""

        payload = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        payload = _safe_value(payload)
        payload = self._compact_evidence(payload)
        assessment_id = str(payload.get("assessment_id") or f"assessment-{len(self.results) + 1}")
        with self._lock:
            previous = self.results.get(assessment_id, {})
            # A final result should preserve useful real-time fields (phase,
            # worker and round) that were reported before completion.
            merged = {**previous, **payload}
            merged["metadata"] = {
                **(previous.get("metadata", {}) or {}),
                **(payload.get("metadata", {}) or {}),
            }
            self.results[assessment_id] = merged
            self._record_expectations(merged)
            self.updated_at = _now()
            self._write()

    def record_progress(
        self,
        assessment_id: str,
        *,
        scope: str,
        mode: str,
        target: str,
        status: str = "running",
        phase: str = "",
        round_number: int | None = None,
        summary: str = "",
        findings: list[dict[str, Any]] | None = None,
        evidence_count: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Render an in-progress assessment without changing its final API."""

        payload = {
            "assessment_id": assessment_id,
            "scope": scope,
            "mode": mode,
            "target": target,
            "status": status,
            "summary": summary,
            "findings": findings or [],
            "evidence": [],
            "started_at": "",
            "completed_at": "",
            "metadata": {
                **(metadata or {}),
                "phase": phase,
                "round": round_number,
                "evidence_count": evidence_count,
            },
        }
        payload = _safe_value(payload)
        with self._lock:
            previous = self.results.get(assessment_id, {})
            self.results[assessment_id] = {**previous, **payload}
            self._record_expectations(self.results[assessment_id])
            self.updated_at = _now()
            self._write()

    def record_expectations(
        self,
        expectations: list[dict[str, Any]] | dict[str, dict[str, Any]],
        manifest_version: str = "",
    ) -> None:
        """Merge the LLM-produced semantic expectation manifest into the report."""

        values = expectations.values() if isinstance(expectations, dict) else expectations
        with self._lock:
            for value in values:
                if not isinstance(value, dict) or not value.get("expectation_id"):
                    continue
                safe = _safe_value(value)
                self.expectations[str(safe["expectation_id"])] = safe
            if manifest_version:
                self.expectation_manifest_version = str(manifest_version)
            self.updated_at = _now()
            self._write()

    def finalize(self, status: str = "completed", error: str | None = None) -> None:
        """Write the final lifecycle status without discarding findings."""

        with self._lock:
            self.run_status = status
            self.error = _redact_text(error) if error else None
            self.updated_at = _now()
            self._write()

    def _write(self) -> None:
        content = self._render()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary_path.write_text(content, encoding="utf-8")
        temporary_path.replace(self.path)

    def _record_expectations(self, payload: dict[str, Any]) -> None:
        metadata = payload.get("metadata", {}) or {}
        self.record_expectations(
            metadata.get("expectations", []) or [],
            metadata.get("expectation_manifest_version", "") or "",
        ) if metadata.get("expectations") else None

    def _compact_evidence(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Keep the report small while retaining raw evidence in the trajectory."""

        result = dict(payload)
        compacted = []
        for index, item in enumerate(payload.get("evidence", []) or []):
            if not isinstance(item, dict):
                compacted.append(item)
                continue
            value = item.get("output", item.get("error", ""))
            reference = self.artifacts.register(
                value,
                source=str(item.get("source") or "assessment"),
                category=str(item.get("category") or "assessment"),
                assessment_id=str(payload.get("assessment_id") or ""),
                host_id=str(payload.get("target") or item.get("host_id") or ""),
                tool_call_id=str(item.get("tool_call_id") or ""),
                summary=str(item.get("summary") or ""),
                raw_reference=str(item.get("raw_reference") or ""),
            )
            compact_item = {
                key: value
                for key, value in item.items()
                if key not in {"output", "error"}
            }
            compact_item.update({
                "artifact_id": reference.get("artifact_id"),
                "content_hash": reference.get("content_hash"),
                "preview": reference.get("preview", ""),
                "artifact_index": str(self.artifacts.manifest_path),
            })
            compacted.append(compact_item)
        result["evidence"] = compacted
        return result

    def _render(self) -> str:
        results = list(self.results.values())
        findings = [
            finding
            for result in results
            for finding in result.get("findings", [])
            if isinstance(finding, dict)
        ]
        blocking_count = sum(
            1
            for finding in findings
            if finding.get("severity") == "blocking"
            or (finding.get("status") == "fail" and finding.get("severity") == "high")
        )
        status_counts: dict[str, int] = {}
        for result in results:
            status = str(result.get("status") or "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        expectation_values = list(self.expectations.values())
        applicable = [
            item for item in expectation_values
            if str(item.get("status", "pending")) != "not_applicable"
        ]
        evaluated = [
            item for item in applicable
            if str(item.get("status", "pending")) in {"pass", "fail"}
        ]
        passed = [item for item in evaluated if item.get("status") == "pass"]
        coverage = (len(evaluated) / len(applicable) * 100) if applicable else None
        conformance = (len(passed) / len(evaluated) * 100) if evaluated else None

        lines = [
            "# Cochise Cyber Range QA Report",
            "",
            f"- Report status: **{_inline(self.run_status)}**",
            f"- Started at: `{_inline(self.started_at)}`",
            f"- Last updated: `{_inline(self.updated_at)}`",
            f"- Artifact index: `{_inline(self.artifacts.manifest_path)}`",
        ]
        if self.error:
            lines.append(f"- Run error: {_inline(self.error)}")
        if self.metadata:
            lines.extend(["", "## Run configuration", ""])
            for key, value in self.metadata.items():
                lines.append(f"- **{_inline(key)}:** {_inline(value)}")

        lines.extend([
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|---|---:|",
            f"| Completed assessments | {len(results)} |",
            f"| Total findings | {len(findings)} |",
            f"| Blocking findings | {blocking_count} |",
            f"| Pass results | {status_counts.get('pass', 0)} |",
            f"| Warning results | {status_counts.get('warning', 0)} |",
            f"| Blocked results | {status_counts.get('blocked', 0)} |",
            f"| White-box expectations | {len(expectation_values)} |",
            f"| Expectation coverage | {coverage:.1f}% |" if coverage is not None else "| Expectation coverage | n/a (black-box or no manifest) |",
            f"| Expectation conformance | {conformance:.1f}% |" if conformance is not None else "| Expectation conformance | n/a |",
            f"| Unknown / blocked expectations | {sum(1 for item in applicable if str(item.get('status', 'pending')) not in {'pass', 'fail'})} |",
            f"| Aggregated artifacts | {self.artifacts.count} |",
            "",
            "## Assessment index",
            "",
            "| Scope | Target | Assessment ID | Status | Findings | Completed |",
            "|---|---|---|---|---:|---|",
        ])
        for result in results:
            lines.append(
                "| "
                + " | ".join([
                    _inline(result.get("scope", "")),
                    _inline(result.get("target", "")),
                    _inline(result.get("assessment_id", "")),
                    _inline(result.get("status", "unknown")),
                    str(len(result.get("findings", []))),
                    _inline(result.get("completed_at", "")),
                ])
                + " |"
            )

        for result in results:
            lines.extend(self._render_result(result))

        if expectation_values:
            lines.extend([
                "",
                "## White-box expectation manifest",
                "",
                f"Manifest version: `{_inline(self.expectation_manifest_version or 'unknown')}`",
                "",
                "| ID | Subject | Status | Importance | Confidence | Description |",
                "|---|---|---|---|---:|---|",
            ])
            for expectation in expectation_values:
                lines.append(
                    "| " + " | ".join([
                        _inline(expectation.get("expectation_id", "")),
                        _inline(expectation.get("subject", "")),
                        _inline(expectation.get("status", "pending")),
                        _inline(expectation.get("importance", "medium")),
                        _inline(expectation.get("confidence", "")),
                        _inline(expectation.get("description", "")),
                    ]) + " |"
                )

        lines.extend([
            "",
            "---",
            "",
            "Generated continuously by Cochise. Evidence is redacted before it is written.",
            "",
        ])
        return "\n".join(lines)

    def _render_result(self, result: dict[str, Any]) -> list[str]:
        scope = _inline(result.get("scope", "assessment")).title()
        target = _inline(result.get("target", ""))
        metadata = result.get("metadata") or {}
        worker_roles = metadata.get("worker_roles") or []
        shell_sessions = metadata.get("shell_sessions") or []
        shell_ids = [
            str(item.get("shell_id"))
            for item in shell_sessions
            if isinstance(item, dict) and item.get("shell_id")
        ]
        lines = [
            "",
            f"## {scope}: `{target}`",
            "",
            f"- Assessment ID: `{_inline(result.get('assessment_id', ''))}`",
            f"- Mode: `{_inline(result.get('mode', ''))}`",
            f"- Status: **{_inline(result.get('status', 'unknown'))}**",
            f"- Phase: `{_inline(metadata.get('phase', ''))}`",
            f"- Round: `{_inline(metadata.get('round', ''))}`",
            f"- Worker roles: `{_inline(', '.join(str(item) for item in worker_roles))}`",
            f"- Active shell IDs: `{_inline(', '.join(shell_ids) or 'none')}`",
            f"- Started: `{_inline(result.get('started_at', ''))}`",
            f"- Completed: `{_inline(result.get('completed_at', ''))}`",
            "",
            "### Summary",
            "",
            _redact_text(result.get("summary", "")),
            "",
            "### Findings",
            "",
            "| ID | Category | Status | Severity | Confidence | Title |",
            "|---|---|---|---|---:|---|",
        ]
        result_findings = result.get("findings", [])
        if not result_findings:
            lines.append("| _none_ | | | | | No structured findings recorded. |")
        for finding in result_findings:
            lines.append(
                "| "
                + " | ".join([
                    _inline(finding.get("finding_id", "")),
                    _inline(finding.get("category", "")),
                    _inline(finding.get("status", "unknown")),
                    _inline(finding.get("severity", "info")),
                    _inline(finding.get("confidence", "")),
                    _inline(finding.get("title", "")),
                ])
                + " |"
            )
        for finding in result_findings:
            lines.extend([
                "",
                f"#### Finding `{_inline(finding.get('finding_id', ''))}`",
                "",
                f"- Description: {_inline(finding.get('description', ''))}",
                f"- Host: `{_inline(finding.get('host_id', ''))}`",
                f"- Expected: {_inline(finding.get('expected_value', 'unknown'))}",
                f"- Observed: {_inline(finding.get('observed_value', 'unknown'))}",
                f"- Source: `{_inline(finding.get('source', ''))}`",
                "",
                "Evidence:",
                "",
            ])
            evidence = finding.get("evidence", []) or []
            evidence_text = "\n".join(_redact_text(item) for item in evidence) or "none"
            lines.append(_code_block(evidence_text))

        evidence_items = result.get("evidence", []) or []
        if evidence_items:
            lines.extend(["", "### Adapter evidence", ""])
            for index, evidence in enumerate(evidence_items, start=1):
                if not isinstance(evidence, dict):
                    lines.extend([f"#### Evidence {index}", "", _code_block(evidence)])
                    continue
                category = _inline(evidence.get("category", "assessment"))
                command = _inline(evidence.get("command", ""))
                preview = evidence.get("preview", evidence.get("output", evidence.get("error", "")))
                lines.extend([
                    f"#### Evidence {index}: `{category}`",
                    "",
                    f"- Command: `{command}`",
                    f"- Exit status: `{_inline(evidence.get('exit_status', ''))}`",
                    f"- Artifact: `{_inline(evidence.get('artifact_id', ''))}`",
                    "",
                    _code_block(preview),
                ])
        return lines


__all__ = ["QAReportWriter"]
