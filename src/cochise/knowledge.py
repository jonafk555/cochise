from __future__ import annotations

import hashlib


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
            "access_status": "confirmed",
            "assessment_status": existing.get("assessment_status", "pending"),
            "assessment_id": existing.get("assessment_id", ""),
            "last_assessed_at": existing.get("last_assessed_at", ""),
            "dirty": True,
        }
        self.logger.console.log(f"[red]Knowledge[/red]: Registered host access {host_id}")
        return f"registered host {host_id}; host assessment is pending"

    def get_host(self, host_id: str) -> dict:
        return self.hosts.get(str(host_id), {})

    def get_pending_hosts(self) -> list[str]:
        return [
            host_id
            for host_id, host in self.hosts.items()
            if host.get("access_status") == "confirmed"
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
            "dirty": True,
        }
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
        return result
