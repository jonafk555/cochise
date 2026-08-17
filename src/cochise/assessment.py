"""Cyber Range assessment primitives and execution helpers.

The assessment layer deliberately sits beside the existing Planner/Executor
workflow.  It records evidence and gates work; it does not replace the
existing attack executor.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import importlib
import ipaddress
import json
import pathlib
import re
import shlex
import textwrap
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Protocol

import yaml
from jinja2 import Template

from cochise.common import (
    LLMFunctionMapping,
    is_tool_call,
    llm_call,
    llm_tool_call,
    message_to_json,
    parse_tool_call,
)
from cochise.executor import perform_tool_call
from cochise.human_interaction import HumanInteraction, is_stop_response
from cochise.knowledge import Knowledge
from cochise.qa_report import QAReportWriter
from cochise.qa_guidance import QAGuidance


TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
ASSESSMENT_PROMPT = (TEMPLATE_DIR / "assessment_prompt.md.jinja2").read_text()

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "blocking": 4,
}

SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_ -]?key|authorization)\b\s*"
    r"([:=])\s*([^\s,;]+)"
)


def redact_sensitive(value: Any) -> str:
    """Redact common secret-shaped values before they enter assessment evidence."""

    text = str(value)
    return SENSITIVE_VALUE_RE.sub(r"\1\2<redacted>", text)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _stable_id(*parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def _normalise_status(value: Any) -> str:
    value = str(value or "unknown").strip().lower().replace(" ", "_")
    return value if value in {
        "pass",
        "fail",
        "unknown",
        "not_applicable",
        "blocked_by_access",
    } else "unknown"


def _normalise_severity(value: Any) -> str:
    value = str(value or "info").strip().lower()
    return value if value in SEVERITY_ORDER else "info"


@dataclass
class AssessmentFinding:
    finding_id: str
    scope: str
    category: str
    title: str
    description: str
    status: str = "unknown"
    severity: str = "info"
    confidence: float = 0.5
    host_id: str | None = None
    expected_value: str | None = None
    observed_value: str | None = None
    evidence: list[str] = field(default_factory=list)
    source: str = "blackbox"
    assessment_id: str = ""
    timestamp: str = field(default_factory=_now)
    dirty: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.status = _normalise_status(self.status)
        self.severity = _normalise_severity(self.severity)
        try:
            self.confidence = min(1.0, max(0.0, float(self.confidence)))
        except (TypeError, ValueError):
            self.confidence = 0.5
        self.evidence = [redact_sensitive(item) for item in self.evidence]
        self.expected_value = (
            redact_sensitive(self.expected_value) if self.expected_value is not None else None
        )
        self.observed_value = (
            redact_sensitive(self.observed_value) if self.observed_value is not None else None
        )

    @property
    def is_blocking(self) -> bool:
        return self.severity == "blocking" or (
            self.status == "fail" and self.severity == "high"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "scope": self.scope,
            "category": self.category,
            "title": self.title,
            "description": redact_sensitive(self.description),
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "host_id": self.host_id,
            "expected_value": self.expected_value,
            "observed_value": self.observed_value,
            "evidence": self.evidence,
            "source": self.source,
            "assessment_id": self.assessment_id,
            "timestamp": self.timestamp,
            "dirty": self.dirty,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AssessmentFinding":
        return cls(
            finding_id=str(value.get("finding_id") or _stable_id(
                str(value.get("scope", "")),
                str(value.get("category", "")),
                str(value.get("title", "")),
                str(value.get("host_id", "")),
            )),
            scope=str(value.get("scope") or "global"),
            category=str(value.get("category") or "assessment"),
            title=str(value.get("title") or "Untitled finding"),
            description=str(value.get("description") or ""),
            status=value.get("status", "unknown"),
            severity=value.get("severity", "info"),
            confidence=value.get("confidence", 0.5),
            host_id=value.get("host_id"),
            expected_value=value.get("expected_value"),
            observed_value=value.get("observed_value"),
            evidence=[str(item) for item in value.get("evidence", [])],
            source=str(value.get("source") or "blackbox"),
            assessment_id=str(value.get("assessment_id") or ""),
            timestamp=str(value.get("timestamp") or _now()),
            dirty=bool(value.get("dirty", True)),
            metadata=dict(value.get("metadata") or {}),
        )


@dataclass
class AssessmentResult:
    assessment_id: str
    scope: str
    mode: str
    target: str
    status: str
    summary: str = ""
    findings: list[AssessmentFinding] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    started_at: str = field(default_factory=_now)
    completed_at: str = field(default_factory=_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def blocking_findings(self) -> list[AssessmentFinding]:
        return [finding for finding in self.findings if finding.is_blocking]

    @property
    def is_blocking(self) -> bool:
        return bool(self.blocking_findings) or self.status == "blocked"

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "scope": self.scope,
            "mode": self.mode,
            "target": self.target,
            "status": self.status,
            "summary": redact_sensitive(self.summary),
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence": [
                {
                    key: redact_sensitive(value) if key in {"output", "error"} else value
                    for key, value in item.items()
                }
                for item in self.evidence
            ],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "metadata": self.metadata,
        }


@dataclass
class RangeSpec:
    """A platform-neutral wrapper around a white-box Cyber Range document."""

    # ``data`` remains available for existing adapters which understand the
    # small structured subset of the original schema.  ``raw_text`` is the
    # canonical input for the LLM and allows a spec to be Markdown, plain text,
    # or a partially structured document without forcing a rigid schema.
    data: dict[str, Any] = field(default_factory=dict)
    source: str | None = None
    raw_text: str = ""
    format: str = "mapping"
    content_hash: str = ""

    @property
    def mode(self) -> str:
        return "whitebox"

    @property
    def raw_content(self) -> str:
        if self.raw_text:
            return self.raw_text
        if not self.data:
            return ""
        return json.dumps(self.data, ensure_ascii=False, indent=2)

    def semantic_context(self, max_chars: int = 120_000) -> str:
        """Return a bounded, labelled spec context for the semantic QA agent.

        The full source remains available through ``raw_content`` and is kept
        in the run log.  Bounding the prompt protects long natural-language
        specs from consuming the host worker's entire context window.
        """

        content = self.raw_content
        if len(content) > max_chars:
            content = content[:max_chars] + "\n...[spec truncated for context]"
        label = self.source or "inline"
        return textwrap.dedent(
            f"""
            White-box environment specification for semantic interpretation (source: {label}, format: {self.format},
            sha256: {self.content_hash or 'unknown'}):

            ```text
            {content}
            ```
            """
        ).strip()

    @property
    def hosts(self) -> list[dict[str, Any]]:
        hosts = self.data.get("hosts", [])
        if isinstance(hosts, dict):
            return [
                {**value, "id": str(host_id)}
                if isinstance(value, dict)
                else {"id": str(host_id), "description": str(value)}
                for host_id, value in hosts.items()
            ]
        return (
            [host for host in hosts if isinstance(host, dict)]
            if isinstance(hosts, list)
            else []
        )

    def host(self, host_id: str) -> dict[str, Any]:
        for host in self.hosts:
            if str(host.get("id") or host.get("host_id") or host.get("node_ref")) == host_id:
                return host
        return {}

    def network_cidrs(self) -> list[str]:
        values: list[Any] = []
        for key in ("networks", "segments"):
            value = self.data.get(key, []) or []
            values.extend(value if isinstance(value, list) else [value])
        for host in self.hosts:
            network_values = host.get("networks", []) or []
            values.extend(
                network_values if isinstance(network_values, list) else [network_values]
            )
            network_value = host.get("network")
            if network_value:
                values.extend(
                    network_value if isinstance(network_value, list) else [network_value]
                )

        result: list[str] = []
        for value in values:
            candidate = value
            if isinstance(value, dict):
                candidate = value.get("cidr") or value.get("network") or value.get("subnet")
            if not candidate:
                continue
            try:
                result.append(str(ipaddress.ip_network(str(candidate), strict=False)))
            except ValueError:
                continue
        return list(dict.fromkeys(result))

    def validate(self) -> list[AssessmentFinding]:
        findings: list[AssessmentFinding] = []
        if not self.raw_content.strip() and not self.data:
            findings.append(AssessmentFinding(
                finding_id="range-spec-empty",
                scope="global",
                category="infra",
                title="White-box range spec is empty",
                description="The configured Cyber Range spec contains no data.",
                status="fail",
                severity="blocking",
                confidence=1.0,
                source="whitebox",
            ))
            return findings
        findings.append(AssessmentFinding(
            finding_id="range-spec-loaded",
            scope="global",
            category="infra",
            title="White-box range spec loaded",
            description=(
                "A Cyber Range specification was loaded for LLM semantic interpretation. "
                "Unstructured or incomplete topology is allowed."
            ),
            status="pass",
            severity="info",
            confidence=1.0,
            observed_value=self.source or "inline",
            source="whitebox",
            metadata={"format": self.format, "content_hash": self.content_hash},
        ))
        return findings


def load_range_spec(path: str | pathlib.Path) -> RangeSpec:
    """Load a permissive white-box spec without executing arbitrary content.

    YAML/JSON mappings are parsed opportunistically for existing range adapters.
    Markdown and plain text remain raw semantic input.  A malformed structured
    document is also retained as text so the LLM can explain the ambiguity
    instead of the loader silently inventing a topology.
    """

    spec_path = pathlib.Path(path)
    raw_text = spec_path.read_text(encoding="utf-8")
    suffix = spec_path.suffix.lower()
    format_name = "markdown" if suffix in {".md", ".markdown"} else "text"
    data: dict[str, Any] = {}
    if suffix == ".json":
        format_name = "json"
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict):
                data = parsed
            else:
                format_name = "json-text"
        except json.JSONDecodeError:
            format_name = "json-text"
    elif suffix in {".yaml", ".yml"}:
        format_name = "yaml"
        try:
            parsed = yaml.safe_load(raw_text)
            if isinstance(parsed, dict):
                data = parsed
            else:
                format_name = "yaml-text"
        except yaml.YAMLError:
            format_name = "yaml-text"
    else:
        # A best-effort parse preserves convenient existing ``hosts`` and
        # ``networks`` hints while keeping arbitrary text as the source of
        # truth for the LLM.
        try:
            parsed = yaml.safe_load(raw_text)
            if isinstance(parsed, dict):
                data = parsed
                format_name = "yaml"
        except yaml.YAMLError:
            pass
    return RangeSpec(
        data=data,
        source=str(spec_path),
        raw_text=raw_text,
        format=format_name,
        content_hash=hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
    )


class RangeAdapter(Protocol):
    async def collect_global(self, spec: RangeSpec | None = None) -> dict[str, Any]:
        ...

    async def collect_host(
        self,
        host_id: str,
        host: dict[str, Any],
        spec: RangeSpec | None = None,
    ) -> dict[str, Any]:
        ...


class ControlPlaneAdapter(Protocol):
    """Optional management-plane adapter implemented by a Cyber Range plugin."""

    async def collect_global(self, spec: RangeSpec | None = None) -> dict[str, Any]:
        ...

    async def collect_host(
        self,
        host_id: str,
        host: dict[str, Any],
        spec: RangeSpec | None = None,
    ) -> dict[str, Any]:
        ...


class VictimAdapter(Protocol):
    """Optional victim-side command/session adapter.

    The adapter is deliberately small.  It may use WinRM, SSH, a range
    control-plane, or a reverse-shell implementation supplied by the caller.
    Cochise only routes the LLM's bounded command request and records the
    provenance; it never executes commands from the spec directly.
    """

    async def execute_victim_command(
        self,
        host_id: str,
        command: str,
        purpose: str = "",
        shell_id: str = "",
    ) -> Any:
        ...


class VictimCommandRouter:
    """Expose an optional victim adapter through LLM tool-calling.

    A router keeps attacker and victim execution visibly separate in tool
    results.  Adapters may return the legacy string or a mapping containing
    output/exit_status and optional shell metadata.
    """

    def __init__(self, adapter: VictimAdapter):
        self.adapter = adapter

    async def execute_victim_command(
        self,
        host_id: str,
        command: str,
        purpose: str = "",
        shell_id: str = "",
    ) -> Any:
        result = await self.adapter.execute_victim_command(
            host_id,
            command,
            purpose,
            shell_id,
        )
        if isinstance(result, dict):
            result = dict(result)
            result["source"] = "victim"
            result["host_id"] = host_id
            if shell_id:
                result["shell_id"] = shell_id
            return result
        return {
            "output": str(result),
            "exit_status": 0,
            "source": "victim",
            "host_id": host_id,
            "shell_id": shell_id or None,
        }

    async def execute_shell_command(
        self,
        shell_id: str,
        command: str,
        purpose: str = "",
    ) -> Any:
        method = getattr(self.adapter, "execute_shell_command", None)
        if method is None:
            return {
                "output": (
                    f"Victim adapter does not support persistent shell '{shell_id}'. "
                    "Use execute_victim_command or configure an adapter with shell support."
                ),
                "exit_status": 1,
                "source": "victim",
                "shell_id": shell_id,
                "error_type": "shell_not_supported",
            }
        result = await method(shell_id, command, purpose)
        if isinstance(result, dict):
            result = dict(result)
            result["source"] = "victim"
            result["shell_id"] = shell_id
            return result
        return {
            "output": str(result),
            "exit_status": 0,
            "source": "victim",
            "shell_id": shell_id,
        }


def load_victim_adapter(reference: str | None) -> VictimCommandRouter | None:
    """Load an optional victim adapter using the existing ``module:factory`` hook."""

    if not reference:
        return None
    module_name, separator, attribute = reference.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("RANGE_VICTIM_MODULE must use module:factory syntax")
    factory = getattr(importlib.import_module(module_name), attribute)
    adapter = factory()
    if not hasattr(adapter, "execute_victim_command"):
        raise TypeError("Victim adapter must implement execute_victim_command")
    return VictimCommandRouter(adapter)


class CompositeRangeAdapter:
    """Combine attacker-observable and optional control-plane evidence."""

    def __init__(
        self,
        attacker_view: RangeAdapter,
        control_plane: ControlPlaneAdapter | None = None,
    ) -> None:
        self.attacker_view = attacker_view
        self.control_plane = control_plane

    @staticmethod
    def _merge(primary: dict[str, Any], secondary: dict[str, Any] | None) -> dict[str, Any]:
        if not secondary:
            return primary
        evidence = list(primary.get("evidence", []))
        evidence.extend(
            {**item, "source": item.get("source", "control-plane")}
            for item in secondary.get("evidence", [])
        )
        merged = dict(primary)
        merged["evidence"] = evidence
        merged["control_plane"] = secondary.get("control_plane", True)
        return merged

    async def collect_global(self, spec: RangeSpec | None = None) -> dict[str, Any]:
        attacker = await self.attacker_view.collect_global(spec)
        control = await self.control_plane.collect_global(spec) if self.control_plane else None
        return self._merge(attacker, control)

    async def collect_host(
        self,
        host_id: str,
        host: dict[str, Any],
        spec: RangeSpec | None = None,
    ) -> dict[str, Any]:
        attacker = await self.attacker_view.collect_host(host_id, host, spec)
        control = (
            await self.control_plane.collect_host(host_id, host, spec)
            if self.control_plane
            else None
        )
        return self._merge(attacker, control)


def load_control_plane_adapter(reference: str | None) -> ControlPlaneAdapter | None:
    """Load a local Cyber Range adapter as ``module:factory``.

    The plugin is intentionally local and explicit: Cochise never guesses a
    hypervisor or calls an unconfigured management API.
    """

    if not reference:
        return None
    module_name, separator, attribute = reference.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("RANGE_CONTROL_PLANE_MODULE must use module:factory syntax")
    factory = getattr(importlib.import_module(module_name), attribute)
    adapter = factory()
    if not hasattr(adapter, "collect_global") or not hasattr(adapter, "collect_host"):
        raise TypeError("Cyber Range control-plane adapter must implement collect_global and collect_host")
    return adapter

CommandRunner = Callable[[str, str, str], Awaitable[Any]]
HostAssessor = Callable[[str, str, str], Awaitable[AssessmentResult]]


def _result_output(result: Any) -> tuple[str, int | None, str | None]:
    if isinstance(result, dict):
        output = result.get("output", result.get("stdout", ""))
        return str(output or ""), result.get("exit_status"), result.get("stderr")
    return str(result or ""), None, None


class BlackBoxRangeAdapter:
    """Collect evidence from the attacker VM without requiring range metadata."""

    def __init__(
        self,
        command_runner: CommandRunner,
        networks: list[str] | None = None,
    ) -> None:
        self.command_runner = command_runner
        self.networks = networks or []

    async def _run(self, command: str, category: str) -> dict[str, Any]:
        try:
            result = await self.command_runner(
                command,
                "T1046",
                f"Cyber Range assessment: {category}",
            )
            output, exit_status, stderr = _result_output(result)
            return {
                "command": command,
                "category": category,
                "source": "attacker",
                "output": redact_sensitive(output),
                "exit_status": exit_status,
                "stderr": redact_sensitive(stderr) if stderr else None,
            }
        except Exception as exc:  # evidence of a failed probe, not a process crash
            return {
                "command": command,
                "category": category,
                "source": "attacker",
                "output": "",
                "exit_status": None,
                "error": redact_sensitive(exc),
            }

    async def collect_global(self, spec: RangeSpec | None = None) -> dict[str, Any]:
        networks = list(dict.fromkeys(self.networks + (spec.network_cidrs() if spec else [])))
        commands = [
            ("ip -brief address", "attacker-interface"),
            ("ip route", "routing"),
            ("cat /etc/resolv.conf", "dns"),
        ]
        commands.extend(
            (f"nmap -sn -n -T3 {shlex.quote(network)}", "network-reachability")
            for network in networks
        )
        evidence = await asyncio.gather(*(self._run(command, category) for command, category in commands))
        return {"scope": "global", "evidence": evidence, "networks": networks}

    async def collect_host(
        self,
        host_id: str,
        host: dict[str, Any],
        spec: RangeSpec | None = None,
    ) -> dict[str, Any]:
        addresses = host.get("ip_addresses") or host.get("ips") or host.get("ip") or []
        if isinstance(addresses, str):
            addresses = [item.strip() for item in addresses.split(",") if item.strip()]
        evidence = []
        for address in addresses:
            try:
                ipaddress.ip_address(str(address))
            except ValueError:
                continue
            evidence.append(await self._run(
                f"nmap -Pn -n -sT --top-ports 100 {shlex.quote(str(address))}",
                "host-reachability",
            ))
        return {"scope": "host", "host_id": host_id, "evidence": evidence}


def _findings_from_evidence(
    evidence: list[dict[str, Any]],
    *,
    scope: str,
    target: str,
    mode: str,
    assessment_id: str,
) -> list[AssessmentFinding]:
    findings: list[AssessmentFinding] = []
    for index, item in enumerate(evidence):
        command = str(item.get("command", "unknown command"))
        output = str(item.get("output", ""))
        category = str(item.get("category", "assessment"))
        source = str(item.get("source") or mode)
        error = item.get("error")
        exit_status = item.get("exit_status")
        try:
            command_failed = exit_status is not None and int(exit_status) != 0
        except (TypeError, ValueError):
            command_failed = True
        probe_error = re.search(
            r"(?i)(command not found|no such file|permission denied|failed to resolve|timed out)",
            output,
        )
        if error or command_failed or probe_error:
            status, severity, description = "fail", "blocking", str(error)
            if command_failed and not error:
                description = f"The probe exited with status {exit_status}."
            elif probe_error and not error:
                description = f"The probe reported: {probe_error.group(0)}."
        elif not output.strip():
            status, severity, description = (
                "unknown",
                "high",
                "The probe returned no observable output.",
            )
        elif "reachability" in category and re.search(
            r"0 hosts up|host seems down|failed to resolve|timed out",
            output,
            re.I,
        ):
            status, severity, description = (
                "fail",
                "high",
                "The configured network probe did not observe an available host.",
            )
        else:
            status, severity, description = "pass", "info", "The probe returned evidence."

        findings.append(AssessmentFinding(
            finding_id=_stable_id(assessment_id, str(index), command),
            scope=scope,
            category=category,
            title=f"Assessment probe: {category}",
            description=f"{description} Command: {command}",
            status=status,
            severity=severity,
            confidence=1.0 if status in {"pass", "fail"} else 0.5,
            host_id=target if scope == "host" else None,
            observed_value=output[-4000:] if output else None,
            evidence=[command, output[-4000:] if output else str(error or "")],
            source=source,
            assessment_id=assessment_id,
        ))
    return findings


def _assessment_status(findings: list[AssessmentFinding], initial: str = "pass") -> str:
    if initial == "blocked" or any(item.is_blocking for item in findings):
        return "blocked"
    if initial == "warning" or any(item.severity in {"high", "medium"} for item in findings):
        return "warning"
    return "pass"


def _adapter_failure_finding(
    *,
    assessment_id: str,
    scope: str,
    target: str,
    mode: str,
    error: Exception,
) -> AssessmentFinding:
    return AssessmentFinding(
        finding_id=f"{assessment_id}-adapter-error",
        scope=scope,
        category="infra" if scope == "global" else "host",
        title="Cyber Range assessment adapter failed",
        description=redact_sensitive(error),
        status="fail",
        severity="blocking",
        confidence=1.0,
        host_id=target if scope == "host" else None,
        evidence=[redact_sensitive(error)],
        source=mode,
        assessment_id=assessment_id,
    )


class RangeAssessmentCoordinator:
    """Run global and per-host assessments and persist their gate state."""

    def __init__(
        self,
        adapter: RangeAdapter,
        logger,
        spec: RangeSpec | None = None,
        host_assessor: HostAssessor | None = None,
        report_writer: QAReportWriter | None = None,
        qa_guidance: QAGuidance | None = None,
    ) -> None:
        self.adapter = adapter
        self.logger = logger
        self.spec = spec
        self.host_assessor = host_assessor
        self.report_writer = report_writer
        self.qa_guidance = qa_guidance
        self.global_result: AssessmentResult | None = None

    async def run_global_preflight(self, knowledge: Knowledge) -> AssessmentResult:
        spec_source = self.spec.source if self.spec else "blackbox"
        assessment_id = f"global-{_stable_id(_now(), spec_source)}"
        started_at = _now()
        if self.report_writer:
            self.report_writer.record_progress(
                assessment_id,
                scope="global",
                mode="whitebox" if self.spec else "blackbox",
                target="cyber-range",
                status="running",
                phase="global-discovery",
                round_number=0,
                metadata={"worker_type": "global_discovery"},
            )
        findings = self.spec.validate() if self.spec else []
        mode = "whitebox" if self.spec else "blackbox"
        try:
            collected = await self.adapter.collect_global(self.spec)
            if not isinstance(collected, dict):
                raise TypeError("The range adapter returned a non-mapping result")
        except Exception as exc:
            collected = {}
            findings.append(_adapter_failure_finding(
                assessment_id=assessment_id,
                scope="global",
                target="cyber-range",
                mode=mode,
                error=exc,
            ))
        evidence = [item for item in collected.get("evidence", []) if isinstance(item, dict)]
        findings.extend(_findings_from_evidence(
            evidence,
            scope="global",
            target="cyber-range",
            mode=mode,
            assessment_id=assessment_id,
        ))
        if not evidence:
            findings.append(AssessmentFinding(
                finding_id=f"{assessment_id}-no-evidence",
                scope="global",
                category="infra",
                title="No Cyber Range preflight evidence",
                description="The attacker-side adapter returned no evidence.",
                status="fail",
                severity="blocking",
                confidence=1.0,
                source=mode,
                assessment_id=assessment_id,
            ))
        result = AssessmentResult(
            assessment_id=assessment_id,
            scope="global",
            mode=mode,
            target="cyber-range",
            status=_assessment_status(findings),
            summary="Global Cyber Range preflight completed.",
            findings=findings,
            evidence=evidence,
            started_at=started_at,
            completed_at=_now(),
            metadata={
                "spec_source": self.spec.source if self.spec else "",
                "spec_format": self.spec.format if self.spec else "blackbox",
                "spec_hash": self.spec.content_hash if self.spec else "",
                "worker_type": "global_discovery",
                "human_qa_guidance": self.qa_guidance.metadata()
                if self.qa_guidance
                else {},
            },
        )
        knowledge.record_assessment_result(result)
        if self.spec:
            for host in self.spec.hosts:
                host_id = str(
                    host.get("id") or host.get("host_id") or host.get("node_ref") or ""
                ).strip()
                if host_id:
                    knowledge.register_spec_host(host_id, host)
        self.global_result = result
        self.logger.log_data("assessment_global", result.to_dict(), output=False)
        if self.report_writer:
            self.report_writer.record_result(result)
        return result

    async def assess_host(self, host_id: str, knowledge: Knowledge) -> AssessmentResult | None:
        host = knowledge.get_host(host_id)
        if not host or knowledge.is_host_assessed(host_id):
            return None

        mode = "whitebox" if self.spec else "blackbox"
        assessment_id = f"host-{_stable_id(host_id, _now())}"
        started_at = _now()
        if self.report_writer:
            self.report_writer.record_progress(
                assessment_id,
                scope="host",
                mode="whitebox" if self.spec else "blackbox",
                target=host_id,
                status="running",
                phase="host-collection",
                round_number=0,
                metadata={"worker_type": "host_qa", "host_id": host_id},
            )
        expected = self.spec.host(host_id) if self.spec else {}
        adapter_findings: list[AssessmentFinding] = []
        try:
            collected = await self.adapter.collect_host(host_id, host, self.spec)
            if not isinstance(collected, dict):
                raise TypeError("The range adapter returned a non-mapping result")
            evidence = [item for item in collected.get("evidence", []) if isinstance(item, dict)]
            adapter_findings.extend(_findings_from_evidence(
                evidence,
                scope="host",
                target=host_id,
                mode=mode,
                assessment_id=assessment_id,
            ))
        except Exception as exc:
            evidence = []
            adapter_findings.append(_adapter_failure_finding(
                assessment_id=assessment_id,
                scope="host",
                target=host_id,
                mode=mode,
                error=exc,
            ))
        context = json.dumps(
            {
                "assessment_id": assessment_id,
                "host": host,
                "whitebox_expected": expected,
                # Keep repeated per-host prompts bounded; the full source hash
                # and raw document remain in the run log for replay.
                "whitebox_spec": (
                    self.spec.semantic_context(max_chars=40_000)
                    if self.spec
                    else ""
                ),
                "spec_format": self.spec.format if self.spec else "blackbox",
                "spec_hash": self.spec.content_hash if self.spec else "",
                "human_qa_instructions": (
                    self.qa_guidance.semantic_context(max_chars=40_000)
                    if self.qa_guidance
                    else ""
                ),
                "adapter_evidence": evidence,
                "current_knowledge": knowledge.get_compact_knowledge(),
                "active_shell_sessions": knowledge.get_shell_sessions_context(),
            },
            ensure_ascii=False,
            indent=2,
        )
        if self.host_assessor:
            try:
                result = await self.host_assessor(host_id, context, mode)
                if not isinstance(result, AssessmentResult):
                    raise TypeError("The host assessor returned an invalid result")
                result.findings = adapter_findings + result.findings
                result.evidence = evidence + result.evidence
                result.status = _assessment_status(result.findings, result.status)
                # The coordinator owns the gate identity.  A host worker may
                # create its own local ID, but exposing two IDs for one host
                # would duplicate real-time report rows and assessment state.
                result.assessment_id = assessment_id
                for finding in result.findings:
                    finding.assessment_id = assessment_id
                result.metadata = {
                    **result.metadata,
                    "worker_type": result.metadata.get("worker_type", "host_qa"),
                    "host_id": host_id,
                    "spec_source": self.spec.source if self.spec else "",
                    "spec_format": self.spec.format if self.spec else "blackbox",
                    "spec_hash": self.spec.content_hash if self.spec else "",
                    "human_qa_guidance": self.qa_guidance.metadata()
                    if self.qa_guidance
                    else {},
                }
            except Exception as exc:
                adapter_findings.append(_adapter_failure_finding(
                    assessment_id=assessment_id,
                    scope="host",
                    target=host_id,
                    mode=mode,
                    error=exc,
                ))
                result = AssessmentResult(
                    assessment_id=assessment_id,
                    scope="host",
                    mode=mode,
                    target=host_id,
                    status="blocked",
                    summary="The host assessment worker failed before completing the gate.",
                    findings=adapter_findings,
                    evidence=evidence,
                    started_at=started_at,
                    completed_at=_now(),
                    metadata={
                        "worker_type": "host_qa",
                        "host_id": host_id,
                        "human_qa_guidance": self.qa_guidance.metadata()
                        if self.qa_guidance
                        else {},
                    },
                )
        else:
            findings = adapter_findings
            if not evidence:
                findings.append(AssessmentFinding(
                    finding_id=f"{assessment_id}-no-evidence",
                    scope="host",
                    category="host",
                    title="No host assessment evidence",
                    description=(
                        "The adapter could not collect host evidence. A host cannot "
                        "pass the mandatory assessment gate without observable data."
                    ),
                    status="unknown",
                    severity="blocking",
                    confidence=1.0,
                    host_id=host_id,
                    source=mode,
                    assessment_id=assessment_id,
                ))
            result = AssessmentResult(
                assessment_id=assessment_id,
                scope="host",
                mode=mode,
                target=host_id,
                status=_assessment_status(findings),
                summary=f"Black-box host assessment completed for {host_id}.",
                findings=findings,
                evidence=evidence,
                started_at=started_at,
                completed_at=_now(),
                metadata={
                    "worker_type": "host_qa",
                    "host_id": host_id,
                    "human_qa_guidance": self.qa_guidance.metadata()
                    if self.qa_guidance
                    else {},
                },
            )

        knowledge.record_assessment_result(result)
        self.logger.log_data(f"assessment_host_{host_id}", result.to_dict(), output=False)
        if self.report_writer:
            self.report_writer.record_result(result)
        return result


class AssessmentExecutor:
    """Tool-calling LLM worker for the per-host assessment phase."""

    MAX_ROUNDS = 12

    def __init__(
        self,
        model,
        api_key,
        scenario: str,
        configured_tools: list[Callable],
        logger,
        human_interaction: HumanInteraction | None = None,
        victim_adapter: VictimCommandRouter | None = None,
        report_writer: QAReportWriter | None = None,
        qa_guidance: QAGuidance | None = None,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.scenario = scenario
        self.configured_tools = configured_tools
        self.logger = logger
        self.human_interaction = human_interaction or HumanInteraction(logger.console)
        self.victim_adapter = victim_adapter
        self.report_writer = report_writer
        self.qa_guidance = qa_guidance

    async def ask_human(self, question: str, reason: str) -> str:
        return await self.human_interaction.ask_human(question, reason)

    async def assess_host(self, host_id: str, context: str, mode: str) -> AssessmentResult:
        assessment_id = f"host-{_stable_id(host_id, _now())}"
        try:
            parsed_context = json.loads(context)
            context_id = (
                parsed_context.get("assessment_id")
                if isinstance(parsed_context, dict)
                else None
            )
            if context_id:
                assessment_id = str(context_id)
        except (TypeError, json.JSONDecodeError):
            # Custom host assessors may pass a non-JSON context; retain the
            # existing local ID fallback for compatibility.
            pass
        if self.qa_guidance:
            try:
                parsed_context = json.loads(context)
                if isinstance(parsed_context, dict) and not parsed_context.get(
                    "human_qa_instructions"
                ):
                    parsed_context["human_qa_instructions"] = (
                        self.qa_guidance.semantic_context(max_chars=40_000)
                    )
                    context = json.dumps(parsed_context, ensure_ascii=False, indent=2)
            except (TypeError, json.JSONDecodeError):
                # Preserve compatibility with custom callers that use a
                # non-JSON context string.
                pass
        started_at = _now()
        local_knowledge = Knowledge(self.logger)
        if self.report_writer:
            self.report_writer.record_progress(
                assessment_id,
                scope="host",
                mode=mode,
                target=host_id,
                status="running",
                phase="host-qa-start",
                round_number=0,
                metadata={"worker_type": "host_qa", "host_id": host_id},
            )
        prompt = Template(ASSESSMENT_PROMPT).render({
            "host_id": host_id,
            "context": context,
            "mode": mode,
            "max_rounds": self.MAX_ROUNDS,
        })
        history = [
            {"role": "system", "content": self.scenario},
            {"role": "user", "content": prompt},
        ]
        tools = LLMFunctionMapping(self.configured_tools + [
            self.ask_human,
            local_knowledge.add_assessment_finding,
            local_knowledge.add_entity_information,
            local_knowledge.add_assessment_expectation,
            local_knowledge.update_assessment_expectation,
            local_knowledge.set_expectation_manifest,
            local_knowledge.record_host_privilege,
            local_knowledge.register_shell_session,
            local_knowledge.update_shell_session,
        ])
        if self.victim_adapter:
            tools = LLMFunctionMapping(
                self.configured_tools
                + [
                    self.victim_adapter.execute_victim_command,
                    self.victim_adapter.execute_shell_command,
                    self.ask_human,
                    local_knowledge.add_assessment_finding,
                    local_knowledge.add_entity_information,
                    local_knowledge.add_assessment_expectation,
                    local_knowledge.update_assessment_expectation,
                    local_knowledge.set_expectation_manifest,
                    local_knowledge.record_host_privilege,
                    local_knowledge.register_shell_session,
                    local_knowledge.update_shell_session,
                ]
            )
        summary: str | None = None
        stopped = False
        tool_result_count = 0
        tool_evidence: list[dict[str, Any]] = []

        for _round in range(1, self.MAX_ROUNDS + 1):
            response_message, costs, duration = llm_tool_call(
                self.model,
                self.api_key,
                tools,
                history,
            )
            self.logger.log_llm_call("assessment_host", response_message, costs, duration, output=False)
            history.append(message_to_json(response_message))

            if not is_tool_call(response_message):
                if response_message.content:
                    summary = response_message.content
                    break
                history.append({"role": "user", "content": "Continue the assessment and record findings."})
                continue

            tool_calls = []
            tool_results = {}
            tasks = []
            for tool_call in response_message.tool_calls:
                function_name, args, parse_error = parse_tool_call(tool_call)
                tool_call_id = getattr(tool_call, "id", "")
                tool_calls.append((tool_call, function_name, args))
                if parse_error:
                    tool_results[tool_call_id] = {
                        "tool": function_name,
                        "cmd": function_name,
                        "result": parse_error,
                        "exit_status": None,
                        "metadata": {},
                        "tool_call_id": tool_call_id,
                    }
                    continue
                if not tools.has_function(function_name):
                    tool_results[tool_call_id] = {
                        "tool": function_name,
                        "cmd": function_name,
                        "result": (
                            f"Unknown tool '{function_name}'. Choose one of: "
                            f"{', '.join(tools.mapping)}."
                        ),
                        "exit_status": None,
                        "metadata": {},
                        "tool_call_id": tool_call_id,
                    }
                    continue
                self.logger.log_tool_call(function_name, tool_call_id, args, output=False)
                tasks.append(asyncio.create_task(
                    perform_tool_call(
                        tool_call_id,
                        function_name,
                        tools.get_function(function_name),
                        args,
                    )
                ))
            for task in asyncio.as_completed(tasks):
                result = await task
                tool_results[result["tool_call_id"]] = result

            for tool_call, function_name, args in tool_calls:
                result = tool_results[getattr(tool_call, "id", "")]
                tool_result_count += 1
                self.logger.log_tool_result(
                    result["tool"],
                    result["tool_call_id"],
                    result["result"],
                    output=False,
                )
                metadata = result.get("metadata", {}) or {}
                if result["tool"] in {
                    "execute_command",
                    "execute_victim_command",
                    "execute_shell_command",
                }:
                    tool_evidence.append({
                        "source": metadata.get(
                            "source",
                            "victim" if result["tool"] != "execute_command" else "attacker",
                        ),
                        "category": "victim-command"
                        if metadata.get("source") == "victim"
                        else "attacker-command",
                        "tool": result["tool"],
                        "command": result.get("cmd", result["tool"]),
                        "output": redact_sensitive(result["result"]),
                        "exit_status": result.get("exit_status"),
                        "host_id": metadata.get("host_id", host_id),
                        "shell_id": metadata.get("shell_id", ""),
                    })
                tool_content = result["result"]
                # Victim adapters can return a shell identifier or provenance
                # that is not present in their textual output.  Keep the
                # attacker/victim boundary and the continuation shell visible
                # to the next LLM turn without copying raw evidence into the
                # prompt more than once.
                if metadata.get("source") == "victim":
                    tool_content = json.dumps(
                        {
                            "output": result["result"],
                            "execution_context": metadata,
                        },
                        ensure_ascii=False,
                    )
                history.append({
                    "tool_call_id": result["tool_call_id"],
                    "role": "tool",
                    "name": result["tool"],
                    "content": tool_content,
                })
                if self.report_writer:
                    self.report_writer.record_progress(
                        assessment_id,
                        scope="host",
                        mode=mode,
                        target=host_id,
                        status="running",
                        phase=(
                            "victim-validation"
                            if metadata.get("source") == "victim"
                            else "attacker-validation"
                        ),
                        round_number=_round,
                        summary="Tool result received; semantic QA is continuing.",
                        findings=list(local_knowledge.assessment_findings.values()),
                        evidence_count=tool_result_count,
                        metadata={
                            "worker_type": "host_qa",
                            "worker_role": (
                                "victim_validation"
                                if metadata.get("source") == "victim"
                                else "attack_validation"
                            ),
                            "host_id": host_id,
                            "shell_id": metadata.get("shell_id", ""),
                        },
                    )
                if result["tool"] == "ask_human" and is_stop_response(result["result"]):
                    stopped = True
            if stopped:
                break

        if summary is None and not stopped:
            history.append({
                "role": "user",
                "content": "Provide a concise summary of all host assessment findings and unknowns.",
            })
            result, duration, costs = llm_call(self.model, self.api_key, history)
            self.logger.log_llm_call("assessment_host_summary", result, costs, duration, output=False)
            summary = result.get("content") or "The assessment did not produce a summary."
        elif summary is None:
            summary = "The human operator stopped the host assessment."

        findings = [
            AssessmentFinding.from_dict(value)
            for value in local_knowledge.assessment_findings.values()
        ]
        for finding in findings:
            finding.host_id = finding.host_id or host_id
            finding.assessment_id = assessment_id
            if finding.source not in {"attacker", "victim", "control-plane"}:
                finding.source = mode
        expectations = list(local_knowledge.assessment_expectations.values())
        if not findings:
            findings.append(AssessmentFinding(
                finding_id=f"{assessment_id}-summary",
                scope="host",
                category="assessment",
                title="Host assessment summary",
                description="The LLM returned a summary without structured findings.",
                status="unknown",
                severity="high",
                confidence=0.5,
                host_id=host_id,
                evidence=[summary],
                source=mode,
                assessment_id=assessment_id,
            ))

        status = "blocked" if stopped or any(item.is_blocking for item in findings) else (
            "warning" if any(item.severity in {"high", "medium"} for item in findings)
            else "pass"
        )
        worker_roles = [
            "qa_supervisor",
            "common_host_qa",
            "attack_validation",
            "evidence_synthesis",
        ]
        if self.victim_adapter:
            worker_roles.insert(3, "victim_validation")
        return AssessmentResult(
            assessment_id=assessment_id,
            scope="host",
            mode=mode,
            target=host_id,
            status=status,
            summary=summary,
            findings=findings,
            evidence=tool_evidence,
            started_at=started_at,
            completed_at=_now(),
            metadata={
                "worker_type": "host_qa",
                "host_id": host_id,
                "worker_roles": worker_roles,
                "expectation_manifest_version": local_knowledge.expectation_manifest_version,
                "expectations": expectations,
                "shell_sessions": list(local_knowledge.shell_sessions.values()),
                "privilege_events": list(local_knowledge.privilege_events),
                "human_qa_guidance": self.qa_guidance.metadata()
                if self.qa_guidance
                else {},
            },
        )
