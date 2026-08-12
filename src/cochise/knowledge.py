from __future__ import annotations

import datetime as dt
import hashlib
import json


# IDEA: the whole knowledge structure is ugly as hell
# IDEA: use JSON instead of table for transporting knowledge information?
# IDEA: maybe also add memory for failed attempts
class Knowledge:
    def __init__(self, logger):
        self.compromised_accounts = {}
        self.entity_information = {}
        self.hosts = {}
        self.assessment_findings = {}
        self.assessment_results = {}
        self.assessment_expectations = {}
        self.expectation_manifest_version = ""
        self.shell_sessions = {}
        self.privilege_events = []
        self.counter = 1
        self.logger = logger

    def _numeric_key(self, key) -> int | None:
        """Return the integer value of a key, or None if it is not numeric.

        The id/index of every entry is supposed to be numeric. The LLM
        occasionally passes a non-numeric identifier (e.g. a username or entity
        name) as the key, so we cannot blindly cast keys to int.
        """
        try:
            return int(str(key).strip())
        except (TypeError, ValueError):
            return None

    def merge(self, other_knowledge):
        """Merge another Knowledge instance into this one, combining compromised accounts and entity information.

        Parameters
        ----------
        other_knowledge : Knowledge
            Another Knowledge instance whose information should be merged into this one.
        """

        if not other_knowledge:
            return

        for key, value in other_knowledge.compromised_accounts.items():
            if value['dirty']:
                numeric_key = self._numeric_key(key)
                if numeric_key is not None and numeric_key >= self.counter:
                    self.counter = numeric_key + 1
                self.compromised_accounts[key] = value
                self.compromised_accounts[key]['dirty'] = False

        for key, value in other_knowledge.entity_information.items():
            if value['dirty']:
                numeric_key = self._numeric_key(key)
                if numeric_key is not None and numeric_key >= self.counter:
                    self.counter = numeric_key + 1
                self.entity_information[key] = value
                self.entity_information[key]['dirty'] = False

        for key, value in other_knowledge.hosts.items():
            if value.get('dirty', True):
                self.hosts[key] = dict(value)
                self.hosts[key]['dirty'] = False

        for key, value in other_knowledge.assessment_findings.items():
            if value.get('dirty', True):
                self.assessment_findings[key] = dict(value)
                self.assessment_findings[key]['dirty'] = False

        for key, value in other_knowledge.assessment_results.items():
            if value.get('dirty', True):
                self.assessment_results[key] = dict(value)
                self.assessment_results[key]['dirty'] = False

        for key, value in other_knowledge.assessment_expectations.items():
            if value.get('dirty', True):
                self.assessment_expectations[key] = dict(value)
                self.assessment_expectations[key]['dirty'] = False
        if other_knowledge.expectation_manifest_version:
            self.expectation_manifest_version = other_knowledge.expectation_manifest_version

        for key, value in other_knowledge.shell_sessions.items():
            if value.get('dirty', True):
                self.shell_sessions[key] = dict(value)
                self.shell_sessions[key]['dirty'] = False

        for event in other_knowledge.privilege_events:
            if event.get("dirty", True):
                copied = dict(event)
                copied["dirty"] = False
                self.privilege_events.append(copied)
                event["dirty"] = False

    async def add_compromised_account(self, username:str, password:str, context:str):
        """Save information on identified/compromised account, esp. if you a password or hash has been identified.

        Parameters
        ----------
        username : str
            the username of the identified or compromised account.
        password : str
            the account's password or password hash.
        context : str
            additional context information on the compromised account.
        """
        self.compromised_accounts[self.counter] = {
                'username': username,
                'password': password,
                'context': context,
                'dirty': True
        }
        self.counter += 1
        self.logger.console.log(f"[red]Knowledge[/red]: Added compromised account {username} with context: {context}")
        return f"noted compromised account {username} with context: {context}"

    def _resolve_key(self, store: dict, key, identity_field: str, identity_value: str) -> int:
        """Resolve the integer key of the entry that should be updated.

        Keys are always integers. If ``key`` is numeric and already identifies
        an existing entry it is used as-is. Otherwise the LLM most likely passed
        a non-numeric identifier (e.g. the username/entity name) instead of the
        numeric id from the overview table, so we try to locate the matching
        entry by its identity field. If nothing matches, a fresh numeric id is
        allocated so we never store an entry under a non-numeric key.
        """
        numeric_key = self._numeric_key(key)
        if numeric_key is not None and numeric_key in store:
            return numeric_key

        for existing_key, value in store.items():
            if value.get(identity_field) == identity_value:
                return existing_key

        new_key = self.counter
        self.counter += 1
        return new_key

    async def update_compromised_account(self, key:int, username:str, password:str, context:str):
        """Update saved information of a compromised account identified by its numeric id, esp. if you a password or hash has been identified.

        Parameters
        ----------
        key : int
            the numeric account id as given in the overview table
        username : str
            the username of the identified or compromised account.
        password : str
            the account's password or password hash.
        context : str
            additional information/context on the compromised account.
        """
        key = self._resolve_key(self.compromised_accounts, key, 'username', username)
        self.compromised_accounts[key] = {
                'username': username,
                'password': password,
                'context': context,
                'dirty': True
        }
        self.logger.console.log(f"[red]Knowledge[/red]: Updated compromised account {username} with context: {context}")
        return f"updated account {username} with context: {context}"


    async def add_entity_information(self, entity:str, information:str):
        """Note information for an entity (e.g., system or user or service or vulnerability or lead) that might be relevant for a future attack.

        Parameters
        ----------
        entity : str 
            The respective entity, e.g., an user or system or service.
        information : str
            The information about the respective entity.
        """ 
        self.entity_information[self.counter]={
            'entity': entity,
            'information': information,
            'dirty': True
        }
        self.counter += 1
        self.logger.console.log(f"[red]Knowledge[/red]: Added information for entity {entity}: {information}")
        return f"noted information for entity {entity}: {information}"

    async def update_entity_information(self, key: int, entity:str, information:str):
        """Update information for an entity (e.g., system or user or service or vulnerability or lead) that might be relevant for a future attack.

        Parameters
        ----------
        key: int
            the numeric entity id as given in the overview table
        entity : str
            The respective entity, e.g., an user or system or service.
        information : str
            The information about the respective entity.
        """
        key = self._resolve_key(self.entity_information, key, 'entity', entity)
        self.entity_information[key]={
            'entity': entity,
            'information': information,
            'dirty': True
        }
        self.logger.console.log(f"[red]Knowledge[/red]: Updated information for entity {entity}: {information}")
        return f"noted information for entity {entity}: {information}"

    async def register_host_access(
        self,
        host_id: str,
        hostname: str = "",
        ip_addresses: str = "",
        domain: str = "",
        role: str = "",
        access_method: str = "",
        evidence: str = "",
        identity: str = "",
        privilege_level: str = "",
        shell_id: str = "",
    ):
        """Register a newly confirmed host so it cannot bypass host assessment.

        The executor should call this after it has confirmed access to a host,
        for example after lateral movement.  A host remains pending until the
        assessment coordinator marks it complete or a human explicitly
        overrides the gate.
        """

        host_id = str(host_id).strip()
        if not host_id:
            raise ValueError("host_id must not be empty")
        existing = self.hosts.get(host_id, {})
        self.hosts[host_id] = {
            "host_id": host_id,
            "hostname": hostname or existing.get("hostname", ""),
            "ip_addresses": ip_addresses or existing.get("ip_addresses", ""),
            "domain": domain or existing.get("domain", ""),
            "role": role or existing.get("role", ""),
            "access_method": access_method or existing.get("access_method", ""),
            "access_evidence": evidence or existing.get("access_evidence", ""),
            "identity": identity or existing.get("identity", ""),
            "privilege_level": privilege_level or existing.get("privilege_level", ""),
            "shell_id": shell_id or existing.get("shell_id", ""),
            "access_status": "confirmed",
            "assessment_status": existing.get("assessment_status", "pending"),
            "assessment_id": existing.get("assessment_id", ""),
            "last_assessed_at": existing.get("last_assessed_at", ""),
            "dirty": True,
        }
        self.logger.console.log(f"[red]Knowledge[/red]: Registered host access {host_id}")
        return f"registered host {host_id}; host assessment is pending"

    def register_spec_host(self, host_id: str, host: dict | None = None) -> None:
        """Register a host declared by a white-box spec without claiming access."""

        host_id = str(host_id).strip()
        if not host_id:
            return
        host = dict(host or {})
        existing = self.hosts.get(host_id, {})
        addresses = host.get("ip_addresses") or host.get("ips") or host.get("ip") or ""
        if isinstance(addresses, (list, tuple)):
            addresses = ", ".join(str(item) for item in addresses)
        self.hosts[host_id] = {
            **existing,
            "host_id": host_id,
            "hostname": host.get("hostname", existing.get("hostname", "")),
            "ip_addresses": addresses or existing.get("ip_addresses", ""),
            "domain": host.get("domain", existing.get("domain", "")),
            "role": host.get("role", existing.get("role", "")),
            "platform": host.get("platform", existing.get("platform", "")),
            "spec_declared": True,
            "spec_host": host,
            "access_status": existing.get("access_status", "spec_declared"),
            "assessment_status": existing.get("assessment_status", "pending"),
            "dirty": True,
        }

    def _record_host_privilege(
        self,
        host_id: str,
        identity: str,
        privilege_level: str,
        access_method: str = "",
        shell_id: str = "",
        evidence: str = "",
    ) -> str:
        """Record the effective identity before/after an escalation attempt."""

        host_id = str(host_id).strip()
        host = self.hosts.setdefault(host_id, {
            "host_id": host_id,
            "access_status": "unknown",
            "assessment_status": "pending",
        })
        event = {
            "host_id": host_id,
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "identity": identity,
            "privilege_level": privilege_level,
            "access_method": access_method or host.get("access_method", ""),
            "shell_id": shell_id or host.get("shell_id", ""),
            "evidence": evidence,
            "dirty": True,
        }
        self.privilege_events.append(event)
        host.update({
            "identity": identity,
            "privilege_level": privilege_level,
            "access_method": access_method or host.get("access_method", ""),
            "shell_id": shell_id or host.get("shell_id", ""),
            "privilege_evidence": evidence,
            "dirty": True,
        })
        return f"recorded {privilege_level} access for {host_id} as {identity}"

    async def record_host_privilege(
        self,
        host_id: str,
        identity: str,
        privilege_level: str,
        access_method: str = "",
        shell_id: str = "",
        evidence: str = "",
    ) -> str:
        return self._record_host_privilege(
            host_id,
            identity,
            privilege_level,
            access_method,
            shell_id,
            evidence,
        )

    async def set_expectation_manifest(self, version: str, rationale: str = "") -> str:
        """Set the semantic expectation manifest version chosen by the LLM."""

        version = str(version or "").strip()
        if not version:
            raise ValueError("manifest version must not be empty")
        self.expectation_manifest_version = version
        self.entity_information[self.counter] = {
            "entity": "qa-expectation-manifest",
            "information": json.dumps({"version": version, "rationale": rationale}),
            "dirty": True,
        }
        self.counter += 1
        return f"using QA expectation manifest version {version}"

    async def add_assessment_expectation(
        self,
        expectation_id: str,
        subject: str,
        description: str,
        importance: str = "medium",
        source_excerpt: str = "",
        confidence: float = 0.5,
        status: str = "pending",
        evidence: str = "",
        manifest_version: str = "",
    ) -> str:
        """Store one LLM-interpreted white-box expectation."""

        expectation_id = str(expectation_id or "").strip()
        if not expectation_id:
            raise ValueError("expectation_id must not be empty")
        if manifest_version:
            self.expectation_manifest_version = str(manifest_version)
        try:
            confidence = min(1.0, max(0.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.5
        self.assessment_expectations[expectation_id] = {
            "expectation_id": expectation_id,
            "subject": str(subject or ""),
            "description": str(description or ""),
            "importance": str(importance or "medium"),
            "source_excerpt": str(source_excerpt or ""),
            "confidence": confidence,
            "status": str(status or "pending"),
            "evidence": [str(evidence)] if evidence else [],
            "manifest_version": manifest_version or self.expectation_manifest_version,
            "dirty": True,
        }
        return f"recorded QA expectation {expectation_id}"

    async def update_assessment_expectation(
        self,
        expectation_id: str,
        status: str,
        confidence: float = 0.5,
        evidence: str = "",
        observed: str = "",
    ) -> str:
        """Update an expectation after a worker has collected evidence."""

        expectation_id = str(expectation_id or "").strip()
        expectation = self.assessment_expectations.get(expectation_id)
        if expectation is None:
            raise ValueError(f"unknown QA expectation {expectation_id}")
        try:
            confidence = min(1.0, max(0.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.5
        expectation.update({
            "status": str(status or "unknown").strip().lower().replace(" ", "_"),
            "confidence": confidence,
            "observed": str(observed or ""),
            "dirty": True,
        })
        if evidence:
            expectation.setdefault("evidence", []).append(str(evidence))
        return f"updated QA expectation {expectation_id} to {expectation['status']}"

    async def register_shell_session(
        self,
        shell_id: str,
        host_id: str,
        platform: str = "",
        identity: str = "",
        privilege_level: str = "",
        cwd: str = "",
        transport: str = "reverse-shell",
        status: str = "active",
        purpose: str = "",
    ) -> str:
        """Make an attached reverse shell explicit to the next LLM round."""

        shell_id = str(shell_id or "").strip()
        host_id = str(host_id or "").strip()
        if not shell_id or not host_id:
            raise ValueError("shell_id and host_id must not be empty")
        self.shell_sessions[shell_id] = {
            "shell_id": shell_id,
            "host_id": host_id,
            "platform": platform,
            "identity": identity,
            "privilege_level": privilege_level,
            "cwd": cwd,
            "transport": transport,
            "status": status,
            "purpose": purpose,
            "dirty": True,
        }
        self._record_host_privilege(
            host_id,
            identity,
            privilege_level,
            access_method=transport,
            shell_id=shell_id,
        )
        return f"registered active shell {shell_id} on {host_id}; use this shell_id for follow-up commands"

    async def update_shell_session(
        self,
        shell_id: str,
        status: str = "active",
        identity: str = "",
        privilege_level: str = "",
        cwd: str = "",
    ) -> str:
        shell_id = str(shell_id or "").strip()
        session = self.shell_sessions.get(shell_id)
        if session is None:
            raise ValueError(f"unknown shell session {shell_id}")
        session.update({
            "status": status,
            "identity": identity or session.get("identity", ""),
            "privilege_level": privilege_level or session.get("privilege_level", ""),
            "cwd": cwd or session.get("cwd", ""),
            "dirty": True,
        })
        return f"updated shell {shell_id}: {session['status']}"

    def get_shell_sessions_context(self) -> str:
        active = [
            {key: value for key, value in session.items() if key != "dirty"}
            for session in self.shell_sessions.values()
            if session.get("status") not in {"closed", "dead"}
        ]
        return json.dumps(active, ensure_ascii=False, indent=2) if active else "[]"

    def get_host(self, host_id: str) -> dict:
        return self.hosts.get(str(host_id), {})

    def get_pending_hosts(self) -> list[str]:
        return [
            host_id
            for host_id, host in self.hosts.items()
            if host.get("access_status") in {"confirmed", "spec_declared"}
            and host.get("assessment_status") not in {"complete", "overridden"}
        ]

    def is_host_assessed(self, host_id: str) -> bool:
        return self.get_host(host_id).get("assessment_status") in {"complete", "overridden"}

    def mark_host_assessed(
        self,
        host_id: str,
        assessment_id: str,
        status: str,
        completed_at: str,
    ) -> None:
        if host_id not in self.hosts:
            self.hosts[host_id] = {
                "host_id": host_id,
                "access_status": "unknown",
                "assessment_status": "pending",
            }
        self.hosts[host_id].update({
            "assessment_id": assessment_id,
            "assessment_status": "complete" if status != "blocked" else "blocked",
            "last_assessed_at": completed_at,
            "dirty": True,
        })

    def override_host_assessment(self, host_id: str, reason: str) -> None:
        if host_id not in self.hosts:
            return
        self.hosts[host_id].update({
            "assessment_status": "overridden",
            "assessment_override": reason,
            "dirty": True,
        })

    async def add_assessment_finding(
        self,
        finding_id: str,
        scope: str,
        category: str,
        title: str,
        description: str,
        status: str = "unknown",
        severity: str = "info",
        confidence: float = 0.5,
        evidence: str = "",
        host_id: str = "",
        expected_value: str = "",
        observed_value: str = "",
        source: str = "blackbox",
        assessment_id: str = "",
    ):
        """Store one structured Cyber Range assessment finding."""

        from cochise.assessment import AssessmentFinding

        if not finding_id.strip():
            digest = hashlib.sha256(
                f"{scope}:{category}:{title}:{host_id}".encode("utf-8")
            ).hexdigest()[:16]
            finding_id = f"finding-{digest}"
        finding = AssessmentFinding(
            finding_id=finding_id,
            scope=scope,
            category=category,
            title=title,
            description=description,
            status=status,
            severity=severity,
            confidence=confidence,
            host_id=host_id or None,
            expected_value=expected_value or None,
            observed_value=observed_value or None,
            evidence=[evidence] if evidence else [],
            source=source,
            assessment_id=assessment_id,
        )
        self.assessment_findings[finding.finding_id] = finding.to_dict()
        self.assessment_findings[finding.finding_id]["dirty"] = True
        return f"recorded assessment finding {finding.finding_id}"

    def record_assessment_result(self, result) -> None:
        """Persist an AssessmentResult and update its host gate state."""

        payload = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        assessment_id = str(payload.get("assessment_id", ""))
        self.assessment_results[assessment_id] = {
            "assessment_id": assessment_id,
            "scope": payload.get("scope", "global"),
            "mode": payload.get("mode", "blackbox"),
            "target": payload.get("target", ""),
            "status": payload.get("status", "unknown"),
            "summary": payload.get("summary", ""),
            "started_at": payload.get("started_at", ""),
            "completed_at": payload.get("completed_at", ""),
            "metadata": payload.get("metadata", {}),
            "dirty": True,
        }
        metadata = payload.get("metadata", {}) or {}
        if metadata.get("expectation_manifest_version"):
            self.expectation_manifest_version = str(metadata["expectation_manifest_version"])
        for expectation in metadata.get("expectations", []) or []:
            if isinstance(expectation, dict) and expectation.get("expectation_id"):
                value = dict(expectation)
                value["dirty"] = True
                self.assessment_expectations[str(value["expectation_id"])] = value
        for session in metadata.get("shell_sessions", []) or []:
            if isinstance(session, dict) and session.get("shell_id"):
                value = dict(session)
                value["dirty"] = True
                self.shell_sessions[str(value["shell_id"])] = value
        existing_event_keys = {
            (
                event.get("timestamp", ""),
                event.get("host_id", ""),
                event.get("identity", ""),
                event.get("privilege_level", ""),
                event.get("shell_id", ""),
            )
            for event in self.privilege_events
        }
        for event in metadata.get("privilege_events", []) or []:
            if isinstance(event, dict):
                value = dict(event)
                event_key = (
                    value.get("timestamp", ""),
                    value.get("host_id", ""),
                    value.get("identity", ""),
                    value.get("privilege_level", ""),
                    value.get("shell_id", ""),
                )
                if event_key in existing_event_keys:
                    continue
                value["dirty"] = True
                self.privilege_events.append(value)
                existing_event_keys.add(event_key)
        for finding in payload.get("findings", []):
            finding_id = str(finding.get("finding_id", ""))
            if not finding_id:
                continue
            finding = dict(finding)
            finding["dirty"] = True
            self.assessment_findings[finding_id] = finding

        if payload.get("scope") == "host" and payload.get("target"):
            self.mark_host_assessed(
                str(payload["target"]),
                assessment_id,
                str(payload.get("status", "unknown")),
                str(payload.get("completed_at", "")),
            )

    def get_assessment_summary(self) -> str:
        blocking = sum(
            1
            for finding in self.assessment_findings.values()
            if finding.get("severity") == "blocking"
            or (finding.get("status") == "fail" and finding.get("severity") == "high")
        )
        return (
            f"{len(self.assessment_results)} assessment(s), "
            f"{len(self.assessment_findings)} finding(s), "
            f"{blocking} blocking finding(s)."
        )

    def get_compact_knowledge(self, max_chars: int = 24000) -> str:
        """Render an assessment-safe context without replaying raw evidence.

        The normal knowledge view remains backward compatible for the attack
        planner.  Host QA workers only need identities, statuses, expectation
        state, and short observations; command output stays in the trajectory
        and the artifact manifest.  This keeps repeated per-host prompts
        bounded without changing what is persisted or reported.
        """

        sections: list[str] = []
        if self.hosts:
            sections.append("## Hosts\n" + self.get_hosts_markdown_table())
        if self.assessment_findings:
            rows = [
                "| ID | Host | Category | Status | Severity | Title | Observation |",
                "|---|---|---|---|---|---|---|",
            ]
            for finding in self.assessment_findings.values():
                observation = str(finding.get("observed_value") or "unknown")
                rows.append(
                    "| "
                    + " | ".join([
                        str(finding.get("finding_id", "")),
                        str(finding.get("host_id") or ""),
                        str(finding.get("category", "")),
                        str(finding.get("status", "unknown")),
                        str(finding.get("severity", "info")),
                        str(finding.get("title", "")),
                        observation[:240].replace("|", "\\|"),
                    ])
                    + " |"
                )
            sections.append("## Assessment findings\n" + "\n".join(rows))
        if self.assessment_expectations:
            rows = [
                "| ID | Subject | Status | Importance | Description |",
                "|---|---|---|---|---|",
            ]
            for expectation in self.assessment_expectations.values():
                rows.append(
                    "| "
                    + " | ".join([
                        str(expectation.get("expectation_id", "")),
                        str(expectation.get("subject", "")),
                        str(expectation.get("status", "pending")),
                        str(expectation.get("importance", "medium")),
                        str(expectation.get("description", ""))[:300].replace("|", "\\|"),
                    ])
                    + " |"
                )
            sections.append(
                f"## QA expectations (manifest {self.expectation_manifest_version or 'unknown'})\n"
                + "\n".join(rows)
            )
        if self.shell_sessions:
            sections.append(
                "## Active shell sessions\n```json\n"
                + self.get_shell_sessions_context()
                + "\n```"
            )
        if self.privilege_events:
            rows = [
                "| Time | Host | Identity | Privilege | Method | Shell | Evidence |",
                "|---|---|---|---|---|---|---|",
            ]
            for event in self.privilege_events[-20:]:
                rows.append(
                    "| "
                    + " | ".join([
                        str(event.get("timestamp", "")),
                        str(event.get("host_id", "")),
                        str(event.get("identity", "")),
                        str(event.get("privilege_level", "")),
                        str(event.get("access_method", "")),
                        str(event.get("shell_id", "")),
                        str(event.get("evidence", ""))[:240].replace("|", "\\|"),
                    ])
                    + " |"
                )
            sections.append("## Privilege events\n" + "\n".join(rows))
        compact = "\n\n".join(sections)
        if len(compact) > max_chars:
            compact = compact[:max_chars] + "\n...[knowledge context truncated; use current tools for details]"
        return compact


    def get_compromised_accounts_markdown_table(self) -> str:
        result = "| Id | Username | Password | Context |\n|-----|----------|----------|---------|\n"
        for key, account in self.compromised_accounts.items():
            result += f"| {key} | {account['username']} | {account['password']} | {account['context']} |\n"
        return result

    def get_entity_information_markdown_table(self) -> str:
        result = "| Id | Entity | Information |\n|---|----------|---------|\n"
        for key, entity in self.entity_information.items():
            result += f"| {key} | {entity['entity']} | {entity['information']} |\n"
        return result

    def get_hosts_markdown_table(self) -> str:
        result = (
            "| Host ID | Hostname | IPs | Access | Assessment |\n"
            "|---|---|---|---|---|\n"
        )
        for host_id, host in self.hosts.items():
            result += (
                f"| {host_id} | {host.get('hostname', '')} | "
                f"{host.get('ip_addresses', '')} | {host.get('access_status', '')} | "
                f"{host.get('assessment_status', '')} |\n"
            )
        return result

    def get_assessment_findings_markdown_table(self) -> str:
        result = (
            "| ID | Scope | Host | Category | Status | Severity | Title |\n"
            "|---|---|---|---|---|---|---|\n"
        )
        for finding_id, finding in self.assessment_findings.items():
            result += (
                f"| {finding_id} | {finding.get('scope', '')} | "
                f"{finding.get('host_id') or ''} | {finding.get('category', '')} | "
                f"{finding.get('status', '')} | {finding.get('severity', '')} | "
                f"{finding.get('title', '')} |\n"
            )
        return result

    def get_knowledge(self) -> str:
        result = ''
        if len(self.compromised_accounts) > 0:
            result += "## Compromised Accounts\n\n"
            result += self.get_compromised_accounts_markdown_table()
            result += '\n\n'
        if len(self.entity_information) > 0:
            result += "## Entity Information\n\n"
            result += self.get_entity_information_markdown_table()
            result += "\n\n"
        if len(self.hosts) > 0:
            result += "## Cyber Range Hosts\n\n"
            result += self.get_hosts_markdown_table()
            result += "\n\n"
        if len(self.assessment_findings) > 0:
            result += "## Cyber Range Assessment Findings\n\n"
            result += self.get_assessment_findings_markdown_table()
            result += "\n\n"
            result += f"Assessment status: {self.get_assessment_summary()}\n"
            result += "\nFinding details:\n"
            for finding_id, finding in self.assessment_findings.items():
                evidence = " | ".join(str(item) for item in finding.get("evidence", []))
                result += (
                    f"- `{finding_id}`: {finding.get('description', '')}; "
                    f"observed={finding.get('observed_value') or 'unknown'}; "
                    f"evidence={evidence or 'none'}\n"
                )
        if len(self.assessment_expectations) > 0:
            result += "## QA Expectations\n\n"
            result += (
                f"Manifest version: {self.expectation_manifest_version or 'unknown'}\n\n"
                "| ID | Subject | Status | Importance | Description |\n"
                "|---|---|---|---|---|\n"
            )
            for expectation_id, expectation in self.assessment_expectations.items():
                result += (
                    f"| {expectation_id} | {expectation.get('subject', '')} | "
                    f"{expectation.get('status', 'pending')} | "
                    f"{expectation.get('importance', 'medium')} | "
                    f"{expectation.get('description', '')} |\n"
                )
        if self.shell_sessions:
            result += "\n## Active Shell Sessions\n\n"
            result += "```json\n" + self.get_shell_sessions_context() + "\n```\n"
        if self.privilege_events:
            result += "\n## Privilege Events\n\n"
            result += (
                "| Time | Host | Identity | Privilege | Method | Shell | Evidence |\n"
                "|---|---|---|---|---|---|---|\n"
            )
            for event in self.privilege_events[-20:]:
                result += (
                    f"| {event.get('timestamp', '')} | {event.get('host_id', '')} | "
                    f"{event.get('identity', '')} | "
                    f"{event.get('privilege_level', '')} | {event.get('access_method', '')} | "
                    f"{event.get('shell_id', '')} | {event.get('evidence', '')} |\n"
                )
        return result
