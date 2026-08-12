# Enterprise Network Infrastructure OPSEC

## Status

This document is a design specification. It does not implement OPSEC controls
yet.

The scope is an authorized Cyber Range that models enterprise network
infrastructure. OPSEC here means operational safety, controlled change, limited
blast radius, observability, and auditability. It does not mean disabling
security controls, deleting evidence, or adding anti-forensics behavior.

## Purpose

The existing Cochise workflow is an LLM-driven attack planner and executor. An
enterprise infrastructure OPSEC layer must sit between the agent and network
management tools so that an LLM cannot directly make an unsafe routing,
firewall, identity, availability, or management-plane change.

The policy must be enforced in code. Prompts can explain the policy to the LLM,
but the LLM must not be the final authority for allowing an action.

## Goals

- Keep every action inside the authorized Cyber Range scope.
- Protect enterprise availability and management-plane reachability.
- Limit the blast radius of network and identity changes.
- Require a known pre-change state and a credible rollback path.
- Limit repeated, high-volume, or unnecessary activity.
- Correlate actions with network and security telemetry.
- Allow autonomous execution without automatically approving critical changes.
- Produce an auditable record for every decision and result.

## Non-goals

This design must not add features for:

- disabling EDR, AV, firewall, IDS, IPS, NAC, or audit logging;
- deleting or modifying event logs to remove evidence;
- bypassing enterprise monitoring;
- hiding unauthorized activity;
- sending Cyber Range data outside the authorized environment;
- evading safeguards by disguising a high-risk action as a low-risk action.

Testing the detection capability of a range is allowed only through an explicit,
scoped assessment action and a configured control-plane or telemetry adapter.

## Runtime architecture

```text
Planner LLM
    |
    v
Executor LLM
    |
    v
+--------------------------+
| Infrastructure OPSEC     |
| Action Guard             |
|                          |
| - scope check            |
| - risk classification    |
| - change-window check    |
| - budget and concurrency |
| - snapshot requirement   |
| - rollback requirement   |
| - detection state        |
+------------+-------------+
             |
       +-----+------+
       |            |
    deny/defer    allow
       |            |
       v            v
  Re-plan or     rate-limit /
  stop           canary execute
                    |
                    v
       Router / Firewall / Switch / DNS /
       VPN / NAC / IAM / Cloud Network API
                    |
                    v
       Syslog / SIEM / IDS / NetFlow / NMS
                    |
                    v
       OPSEC Ledger + Knowledge + Findings
```

## Enterprise infrastructure scope

The policy covers both the data plane and the control plane:

- core, distribution, and access routing;
- BGP, OSPF, static routes, NAT, VRF, VLAN, and segmentation;
- Internet edge, firewall, WAF, proxy, load balancer, and DDoS controls;
- DNS, DHCP, IPAM, NTP, and service discovery;
- VPN, remote access, NAC, 802.1X, and device management access;
- TACACS/RADIUS/AAA, AD integration, privileged roles, and certificates;
- SD-WAN, cloud route tables, security groups, transit gateways, and peering;
- HA pairs, clusters, failover state, firmware, and configuration backup;
- syslog, SIEM, IDS/IPS, NetFlow, SNMP, NMS, and audit pipelines.

## Risk model

Risk is evaluated across multiple dimensions. MITRE technique metadata may help
explain an action, but it is not sufficient to determine whether an action is
safe.

| Dimension | Values | Meaning |
|---|---|---|
| Blast radius | device / segment / site / enterprise / external | How much infrastructure can be affected |
| Plane | read-only / data plane / control plane / identity plane | Which operational layer is changed |
| Availability | none / degraded / outage | Possible service impact |
| Reversibility | reversible / recoverable / rollback-dependent / unknown | Whether the exact prior state can be restored |
| Scope | single target / bounded set / wildcard | Whether the target set is explicit |
| Identity impact | none / authentication / privilege / policy | Whether users, roles, or trust are affected |
| Security-control impact | none / observable / modified / disabled | Whether protection or auditing is changed |
| Data sensitivity | metadata / credentials / secrets / enterprise data | Sensitivity of accessed or transferred data |
| Detection footprint | low / medium / high / alert-generating | Expected monitoring and alert impact |
| Recovery confidence | verified / tested / unverified / none | Confidence in recovery if the action fails |

### Irreversible action

An action is **irreversible** when it cannot be reliably rolled back, or when
its effects can persist after the process ends. Examples include:

- deleting, overwriting, or resetting data;
- deleting accounts or resetting enterprise credentials;
- changing domain-wide policy, trust, delegation, or privileged identity;
- changing core routing, DNS authority, or enterprise-wide ACL policy;
- disabling security controls or audit pipelines;
- causing an outage, device crash, or unplanned failover;
- sending data across the authorized-environment boundary.

### High-risk action

An action is **high risk** even when technically reversible if it can cause
lockout, detection, data exposure, persistent configuration, or a large
operational effect. Examples include:

- high-volume discovery or authentication attempts;
- password spraying or repeated failed authentication;
- credential or secret collection;
- lateral movement across multiple hosts or segments;
- creating services, scheduled tasks, privileged accounts, or other durable state;
- modifying one firewall, VPN, NAC, routing, or cloud-network policy;
- executing an untested operation with unknown side effects;
- making the same change concurrently on multiple devices.

### Lower-risk action

Usually lower-risk actions are read-only and explicitly scoped:

- device and interface inventory;
- reading routes, ACLs, firewall state, service state, or telemetry;
- reading OS, firmware, and software versions;
- producing a configuration diff without applying it;
- a bounded health check against one approved target.

Lower risk does not mean unlimited. Scope, rate, concurrency, and maintenance
window rules still apply.

## Default action classes

| Action class | Examples | Default decision |
|---|---|---|
| `read_only_inventory` | device, interface, version, health, route status | allow within scope |
| `bounded_probe` | limited reachability or service validation | allow with rate limit |
| `configuration_diff` | calculate a proposed change without applying it | allow if scoped |
| `authentication_activity` | repeated login or credential validation | budget and rate limit |
| `credential_access` | reading hashes, tokens, or secrets | high; defer or require approval |
| `identity_privilege_change` | role, account, trust, delegation, or policy change | critical; deny by default |
| `persistence` | durable service, task, startup, or configuration state | high/critical; defer or deny |
| `network_policy_change` | route, ACL, firewall, NAT, VPN, NAC, security group | high/critical; snapshot and approval |
| `security_control_change` | EDR, firewall, IDS, IPS, audit, or logging changes | critical; deny by default |
| `availability_change` | restart, shutdown, failover, firmware, disruptive test | critical; change window required |
| `external_transfer` | data or credentials leaving the range | critical; deny |

## OPSEC modes

### `off`

Preserves the existing Cochise behavior. No OPSEC action guard is applied.

### `monitor`

Allows read-only actions and records proposed state-changing actions. State
changes are not applied.

### `balanced`

Allows bounded low and medium-risk actions. High-risk actions require a policy
decision, explicit approval, or a safe alternative. Critical actions are denied
unless explicitly allowlisted by the range configuration.

### `strict`

Only explicitly allowed, bounded actions execute. Unknown side effects,
unexpected drift, missing snapshots, and detection alerts cause a defer or stop
according to policy.

## Proposed configuration

The following is a configuration proposal, not an implemented interface:

```env
OPSEC_MODE=off                    # off / monitor / balanced / strict
OPSEC_ON_BLOCK=defer              # defer / stop / ask
OPSEC_ON_ALERT=stop               # stop / defer / continue
OPSEC_MAX_ACTIONS_PER_HOST=50
OPSEC_MAX_ACTIONS_PER_SEGMENT=200
OPSEC_MAX_CONCURRENCY=2
OPSEC_REQUIRE_SNAPSHOT=1
OPSEC_REQUIRE_CHANGE_WINDOW=1
OPSEC_ALLOW_EXTERNAL_TARGETS=0
OPSEC_TELEMETRY_MODULE=''         # optional module:factory adapter
```

When `HUMAN_INTERACTION=0`, an `ask` decision must fall back to `defer` or a
safe alternative. It must not automatically approve a high or critical action.

## Action lifecycle

Every state-changing action follows this sequence:

```text
1. Resolve target scope
2. Collect current state and dependencies
3. Check maintenance window
4. Classify risk
5. Check budget, concurrency, and previous actions
6. Create snapshot or configuration checkpoint
7. Produce a diff and rollback plan
8. Evaluate policy
9. Execute as a canary or bounded change
10. Verify state and service health
11. Correlate telemetry and alerts
12. Record the final decision and result
```

If the observed state differs from the expected precondition, the action must
be deferred. The agent must not silently apply a change to an unexpected device
or topology.

## Telemetry and control-plane adapter

Cochise already has a `ControlPlaneAdapter` extension point in
`src/cochise/assessment.py`. Enterprise OPSEC would require additional,
platform-neutral capabilities such as:

```text
collect_topology()
collect_device_state(target)
collect_policy_state(target)
snapshot_config(target)
get_alerts(since)
verify_change(action_id)
rollback_change(action_id)
```

The adapter implementation remains vendor-specific. Cochise should not guess
the hypervisor, network vendor, cloud provider, or management API.

## Audit record

Every action should produce a structured record similar to:

```json
{
  "action_id": "action-123",
  "target": "firewall-segment-a",
  "category": "network_policy_change",
  "risk": {
    "blast_radius": "segment",
    "plane": "control_plane",
    "availability": "degraded",
    "reversibility": "rollback-dependent",
    "detection_footprint": "high"
  },
  "decision": "defer",
  "reason": "No verified configuration snapshot exists.",
  "policy": "balanced",
  "human_interaction": false,
  "telemetry": [],
  "secrets_redacted": true
}
```

Raw passwords, tokens, private keys, and unredacted credential material must
not be stored in the OPSEC ledger.

## Cochise integration points

The expected implementation would touch these areas:

```text
src/cochise/opsec.py
    OpsecPolicy, OpsecDecision, OpsecLedger, risk models

src/cochise/cli/cochise.py
    load OPSEC configuration and construct the policy

src/cochise/planner.py
    provide OPSEC context and choose alternatives after defer/deny

src/cochise/executor.py
    route all command execution through the OPSEC guard

src/cochise/knowledge.py
    persist actions, budgets, alerts, and decisions

src/cochise/assessment.py
    collect infrastructure baseline and telemetry evidence

src/cochise/templates/*.md*
    describe policy state to Planner, Executor, and AssessmentExecutor

tests/test_opsec.py
    policy, budget, scope, snapshot, alert, and autonomous-mode tests
```

There must be no direct path from an LLM-provided tool call to an infrastructure
management function that bypasses the policy guard.

## Autonomous execution semantics

With:

```env
HUMAN_INTERACTION=0
```

the agent does not wait for stdin. The expected behavior is:

```text
low-risk read-only action       -> execute
bounded medium-risk action      -> execute with limits
high-risk action                -> defer and re-plan
critical action                 -> deny
unexpected drift                -> defer or stop
detection alert                 -> follow OPSEC_ON_ALERT
```

This keeps autonomous execution active without converting the absence of a
human into permission to modify enterprise-critical infrastructure.

## Acceptance criteria

An implementation is complete only when:

- every infrastructure tool call passes through the OPSEC guard;
- wildcard or out-of-scope targets are rejected;
- high-risk actions cannot bypass snapshot and rollback checks;
- concurrent and repeated activity is limited by code;
- unexpected topology or configuration drift causes a defer or stop;
- telemetry and alerts are correlated with action IDs;
- autonomous mode does not approve critical actions;
- all decisions are recorded with secrets redacted;
- unit tests cover allow, defer, deny, budget, alert, rollback, and no-human paths;
- an end-to-end Cyber Range test verifies that one device can be used as a
  canary before broader changes are considered.

## Implementation phases

1. Add risk models, policy evaluation, budgets, and an audit ledger.
2. Wrap the existing Executor tools with the policy guard.
3. Add snapshot, diff, canary, verification, and rollback interfaces.
4. Extend the Cyber Range control-plane and telemetry adapter.
5. Add Planner/Executor context and alternative-task handling.
6. Validate with read-only, bounded-change, alert, drift, and rollback scenarios.
