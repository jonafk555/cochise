# Cochise-based LLM Cyber Range QA and Penetration-Testing Agent

> **Origin:** This repository started from the upstream
> [Cochise research prototype](https://github.com/andreashappe/cochise) by
> Andreas Happe. The default run keeps the original Planner/Executor and
> tool-calling path. Cyber Range assessment, semantic QA guidance, victim-side
> adapters, live QA reporting, and artifact aggregation are optional.
>
> **起源：** 本專案一開始源自 Andreas Happe 的 upstream Cochise 研究原型；
> 目前 fork 的預設執行保留原本的 Planner/Executor 與 tool-calling 路徑；
> Cyber Range QA、語意化 spec、victim adapter、即時報告與 artifact 彙整需明確啟用。

This project uses an LLM to plan and execute authorized penetration-testing
work in an isolated Cyber Range. The LLM decides how to interpret the scenario,
select the next task, call tools, and evaluate evidence. Python provides the
fixed Planner/Executor infrastructure: SSH, tool schemas, state management,
and bounded retries. Assessment gates, report rendering, and artifact indexing
belong to the optional QA layer.

Use this software only against systems that you own or are explicitly authorized
to test. Never point it at production, public infrastructure, or a third-party
network without written permission.

> **中文摘要：** 本專案是以 LLM 操作授權 Cyber Range 的 agent。LLM 負責
> 語意決策與工具選擇，Python 負責 SSH、狀態、QA gate、報告及安全邊界。

## What this repository currently implements

- A persistent LLM **Planner** and a short-lived **Executor** created for each
  Planner round.
- SSH command execution on a Linux attacker/Kali VM.
- LiteLLM provider mapping for OpenAI, Anthropic/Claude, Gemini, Ollama, and
  OpenAI-compatible local servers.
- An optional global Cyber Range preflight and per-host QA layer. It is not
  loaded by the default run.
- Black-box or white-box assessment when `--qa`/`QA_ENABLED=1` is enabled.
- Human-authored QA intent through `--qa-instructions`; the input can be
  Markdown, YAML, JSON, plain text, or natural language. The file is kept as
  semantic context and is never executed as a script.
- Per-host QA gates. A host declared by a structured white-box spec, or a host
  confirmed by `register_host_access`, is assessed before the next ordinary
  attack task.
- LLM-selected logical QA roles: common host QA, Windows endpoint QA,
  Windows AD QA, Linux Cyber Range QA, attack validation, victim validation,
  and evidence synthesis.
- Optional control-plane and victim-side adapters using explicit
  `module:factory` references.
- A continuously updated Markdown QA report with white-box expectation
  coverage/conformance.
- A single content-hash-deduplicated `artifact-manifest.jsonl` instead of one
  artifact file for every command result.
- JSON trajectory logging, replay, token analysis, duration analysis, and graph
  generation.

The repository does **not** include native WinRM, PowerShell Remoting, Windows
AD management, or Linux victim-agent transports. Configure
`RANGE_VICTIM_MODULE` when victim-side execution is required. Without that
adapter, QA evidence is attacker-side evidence collected from Kali.

> **中文摘要：** 目前已實作 Planner/Executor、black-box/white-box QA、每台
> 主機 gate、Windows/Linux 語意評估、victim/control-plane adapter、即時 QA
> report 與 artifact 去重；Windows/Linux victim transport 需要自行提供 adapter。

## Architecture

```text
                         .env / CLI
                              |
                              v
                    +---------------------+
                    | cochise CLI         |
                    | LLMConfig + SSH     |
                    +----------+----------+
                              |
                 optional QA layer (explicitly enabled)
                              |
        +----------------------+----------------------+
        |                                             |
        v                                             v
+------------------+   perform_task   +------------------------+
| Planner (persist) | ----------------> | Executor (ephemeral) |
| plan, knowledge   |                  | command/tool loop     |
+--------+---------+                  +-----------+------------+
         |                                        |
         | register_host_access                   | SSH execute_command
         v                                        v
+---------------------------+          +-----------------------+
| Host QA / Assessment      |          | attacker / Kali VM    |
| LLM worker + gate         |          | nmap, shell, tooling  |
+-------------+-------------+          +-----------------------+
              |
       optional victim/control-plane adapters
              |
              v
      +----------------------+      +--------------------------+
      | QAReportWriter       |      | ArtifactRegistry          |
      | logs/qa-report.md    |      | artifacts/manifest.jsonl |
      +----------------------+      +--------------------------+
```

### Planner and Executor

The Planner keeps the strategic conversation, a tree-shaped task plan, and the
shared `Knowledge` store. Each Planner round builds a fresh Executor. The
Executor has no previous round's conversation, but receives the current
knowledge snapshot and the current scenario.

The Planner normally asks the LLM to call exactly one `perform_task` tool. The
Executor then selects and executes the commands needed for that task. Multiple
tool calls emitted in one Executor response are run concurrently with
`asyncio`.

The Executor returns a summary and local knowledge. The Planner merges dirty
accounts, entities, hosts, privileges, shell sessions, and findings into the
shared store. When the Planner context reaches a configured limit, the LLM
compacts the history into a new plan and a bounded knowledge context.

### Assessment and gates

When QA is explicitly enabled, `RangeAssessmentCoordinator` runs beside the
original Planner/Executor flow; it does not replace the attack executor:

1. A global preflight runs from the attacker VM before the initial Planner plan.
2. Structured hosts in a white-box spec can be registered as pending QA hosts.
3. The Executor calls `register_host_access` after confirming access to a new
   host.
4. Before the next ordinary attack task, the Planner runs the pending host QA.
5. Blocking findings request human guidance. With `HUMAN_INTERACTION=0`, the
   finding is retained and an explicit automatic override is recorded; the
   range is not automatically repaired.

A network address discovered by a global scan is not automatically converted
into a host QA gate. It must be declared in a structured spec or confirmed by
the LLM workflow through `register_host_access`.

> **中文摘要：** QA assessment 是原本攻擊流程旁邊的 gate，不取代 Planner/
> Executor。global discovery 後，新主機要先完成 host QA 才能繼續一般攻擊。

### Execution modes: core versus QA

Entering QA mode does **not** switch to a second or legacy execution
architecture. Both modes use the same Cochise core:

```text
Planner (persistent) -> Executor (per task) -> tool calling -> SSH/Kali
```

The difference is whether the optional QA control layer is active:

| Mode | Command | Additional behavior |
|---|---|---|
| Core/default | `uv run cochise` | Original Planner/Executor and tool-calling flow only. No QA preflight, host gates, QA report, or QA-specific tool surface. |
| QA-enabled | `uv run cochise --qa` | The same core plus optional healthcheck, range preflight, semantic assessment, host-QA gates, report, and artifact index. |
| QA with human intent | `uv run cochise --qa-instructions specs/custom-qa.md` | QA-enabled mode plus bounded human-authored semantic guidance. |

QA mode therefore adds behavior around the original attack executor; it does
not replace the Planner, create a separate attack engine, or force Python to
decide the attack sequence. The LLM still interprets the scenario/spec,
decomposes work, chooses tools, and evaluates evidence. Python remains the
transport, state, retry, reporting, and safety boundary.

`scenario.md` is still supplied as system context in both modes. A white-box
environment spec and `--qa-instructions` add semantic QA context; they do not
replace the scenario or directly execute its text. Because the checked-in
scenario remains AD-oriented, custom QA guidance alone does not change the
ordinary attack objective. Change `src/cochise/templates/scenario.md` when
that objective must change.

> **中文摘要：** QA mode 是「原本 Planner/Executor 核心 + QA sidecar」，不是
> 切換成另一套舊架構。`scenario.md` 在兩種模式都會載入；spec 與 custom QA
> 只增加語意，不會自動取代 AD scenario。

## Run lifecycle

1. The CLI loads `.env` from the project directory; explicit shell variables
   retain precedence.
2. It resolves the LLM configuration, connects to SSH, and starts the original
   Planner/Executor tool-calling flow.
3. Only when `--qa` or `QA_ENABLED=1` is set does it initialize the QA report,
   adapters, global preflight, and host assessments.
4. The report is finalized as `completed` or `failed` when an enabled QA run
   ends.

## Installation

### Requirements

- Python 3.12 or newer.
- [uv](https://docs.astral.sh/uv/).
- An authorized, isolated Cyber Range or test network.
- A Linux attacker/Kali VM reachable through SSH. `TARGET_HOST` is this attacker
  VM, not automatically an AD domain controller or victim endpoint.
- An LLM API or local model server that supports chat tool/function calling.
- `nmap` on Kali when `RANGE_NETWORKS` is configured; the basic preflight also
  uses `ip` and `/etc/resolv.conf`.

### Install the repository

```bash
git clone https://github.com/jonafk555/cochise.git
cd cochise
uv sync
uv run cochise --help
```

The current SSH implementation uses password authentication, port 22, and
`known_hosts=None` in AsyncSSH. Use it only inside the authorized test range.

> **中文摘要：** 需要 Python 3.12、uv、可 SSH 連線的 Kali attacker VM、支援
> tool calling 的 LLM，以及隔離且已授權的測試環境。

## Environment configuration

Create `.env` in the repository root. Do not commit it. API keys, SSH
credentials, and run logs should all be treated as sensitive.

### Minimal working configuration

```dotenv
# Cloud LLM: openai / claude / gemini
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
OPENAI_API_KEY=sk-...

# SSH to the attacker/Kali VM, not the AD/victim host
TARGET_HOST=192.168.56.100
TARGET_USERNAME=root
TARGET_PASSWORD=kali

# The default run is the original Planner/Executor flow.
# Enable the optional QA layer only when needed:
# QA_ENABLED=1
# RANGE_MODE=blackbox
# RANGE_NETWORKS=192.168.56.0/24
```

### LLM provider examples

```dotenv
# OpenAI
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
OPENAI_API_KEY=sk-...

# Anthropic / Claude
LLM_PROVIDER=claude
LLM_MODEL=claude-sonnet-4-5
ANTHROPIC_API_KEY=sk-ant-...

# Gemini
LLM_PROVIDER=gemini
LLM_MODEL=gemini-2.5-flash
GEMINI_API_KEY=...

# Ollama
LLM_PROVIDER=local
LOCAL_LLM_BACKEND=ollama
LLM_MODEL=llama3.1
LOCAL_LLM_BASE_URL=http://127.0.0.1:11434

# LM Studio / vLLM / llama.cpp and other OpenAI-compatible servers
LLM_PROVIDER=local
LOCAL_LLM_BACKEND=openai-compatible
LLM_MODEL=your-loaded-model
LOCAL_LLM_BASE_URL=http://127.0.0.1:1234/v1
LOCAL_LLM_API_KEY=local
```

`LLM_API_KEY` and `LLM_BASE_URL` are provider-neutral overrides. For backward
compatibility, a fully qualified LiteLLM model can still be configured without
`LLM_PROVIDER`:

```dotenv
LITELLM_MODEL=openrouter/google/gemini-3-flash-preview
LITELLM_API_KEY=sk-or-...
LITELLM_API_BASE=https://openrouter.ai/api/v1
```

When `LLM_PROVIDER` is set, `LLM_MODEL` takes precedence over the provider-
specific model aliases. API keys are resolved from the general variable,
provider-specific variables, and then the legacy LiteLLM variable. Cloud
providers require an API key. Local Ollama does not. A local OpenAI-compatible
backend uses `local` as its default LiteLLM key when none is supplied.

### Complete `.env` reference

#### Required connection variables

| Variable | Required | Description |
|---|---:|---|
| `TARGET_HOST` | yes | SSH address of the attacker/Kali VM. |
| `TARGET_USERNAME` | yes | SSH username. |
| `TARGET_PASSWORD` | yes | SSH password. |

#### LLM and request controls

| Variable | Default | Description |
|---|---:|---|
| `LLM_PROVIDER` | unset | `openai`, `claude`/`anthropic`, `gemini`/`google`, or `local`. |
| `LLM_MODEL` | unset | Model name. Provider aliases: `OPENAI_MODEL`, `ANTHROPIC_MODEL`/`CLAUDE_MODEL`, `GEMINI_MODEL`/`GOOGLE_MODEL`, `LOCAL_LLM_MODEL`/`OLLAMA_MODEL`. |
| `LLM_API_KEY` | unset | General API key; provider and legacy fallbacks are supported. |
| `LLM_BASE_URL` | unset | General endpoint; provider-specific base fallbacks are supported. |
| `LOCAL_LLM_BACKEND` | `ollama` | `ollama` or `openai-compatible`. |
| `LOCAL_LLM_BASE_URL` | backend-dependent | Ollama defaults to `http://127.0.0.1:11434`; OpenAI-compatible defaults to `http://127.0.0.1:1234/v1`. |
| `LOCAL_LLM_API_KEY` | unset | Local key; `OLLAMA_API_KEY` is also accepted. |
| `LLM_REASONING_EFFORT` | `none` for GPT-5.4+ tool calls | `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, or `default`. |
| `LLM_MAX_RETRIES` | `1` | Maximum retries for transient provider/network errors. |
| `LLM_RETRY_BACKOFF_SECONDS` | `1` | Exponential backoff base in seconds. |
| `LLM_TIMEOUT_SECONDS` | unset | LiteLLM request timeout; it does not change the SSH command timeout. |

#### Planner, interaction, and QA controls

| Variable | Default | Description |
|---|---:|---|
| `QA_ENABLED` | `0` | Enable the optional Cyber Range QA/report/adapter layer. |
| `MAX_RUN_TIME` | `0` | Planner runtime in seconds; QA mode defaults to `7200`; `0` means unlimited. |
| `PLANNER_MAX_CONTEXT_SIZE` | `250000` | Planner prompt-token threshold for history compaction; `0` disables this trigger. |
| `PLANNER_MAX_INTERACTIONS` | `0` | Planner-round threshold for compaction; `0` disables this trigger. |
| `PLANNER_HARD_MAX_INTERACTIONS` | `0` | Hard Planner interaction cap; QA mode defaults to `100`; `0` means unlimited. |
| `LLM_HEALTHCHECK` | `0` | Optional forced tool-calling check in QA mode; QA defaults to `1`. |
| `HUMAN_INTERACTION` | `0` | `1` enables `ask_human` in QA mode; QA defaults to `1`. |
| `RANGE_MODE` | unset | Read only when QA is enabled; must be `blackbox` or `whitebox`. |
| `RANGE_SPEC_PATH` | unset | White-box spec path; required when `RANGE_MODE=whitebox`. |
| `RANGE_NETWORKS` | unset | Attacker-side probe CIDRs, separated by commas or semicolons. |
| `RANGE_CONTROL_PLANE_MODULE` | unset | Management/control-plane adapter in `module:factory` form. |
| `RANGE_VICTIM_MODULE` | unset | Victim command/session adapter in `module:factory` form. |
| `QA_REPORT_PATH` | `logs/qa-report.md` | Continuously updated Markdown QA report. |
| `QA_ARTIFACT_DIR` | `<report directory>/artifacts` | Directory containing `artifact-manifest.jsonl`. |

QA variables are ignored by the default run unless `QA_ENABLED=1`, `--qa`, or
`--qa-instructions` is supplied. Explicit shell variables retain precedence over
values loaded from `.env`.

> **中文摘要：** 預設不啟用 QA；使用 `QA_ENABLED=1` 或 `--qa` 才會載入
> preflight、report、adapter 與 host assessment。shell 設定優先於 `.env`。

## Command-line usage

### Main run

```text
uv run cochise [--qa-instructions PATH]
               [--qa]
               [--qa-file PATH]
               [--qa-guidance PATH]
               [--human-qa PATH]
```

The four option names are aliases for the same destination; use one of them for
clarity. The file is read as UTF-8. Markdown, YAML, JSON, plain text,
and natural language are accepted as raw semantic input. Python records the
source, format label, character count, and SHA-256; the QA LLM decides which
checks apply.

```bash
uv run cochise --help
uv run cochise
uv run cochise --qa
uv run cochise --qa-instructions specs/human-qa.md
```

`--qa` explicitly enables the optional QA layer. `--qa-instructions` also
enables it and supplies additional human-authored semantic QA intent.

`RANGE_SPEC_PATH` is not a positional argument. To combine a white-box spec
with human QA guidance, enable QA, set the spec in `.env`, and pass the guidance file:

```dotenv
QA_ENABLED=1
RANGE_MODE=whitebox
RANGE_SPEC_PATH=specs/environment.md
```

```bash
uv run cochise --qa-instructions specs/threat-informed-qa.md
```

### Run output and analysis tools

```text
uv run cochise-replay INPUT

uv run cochise-analyze-logs ANALYSIS INPUT [INPUT ...]
                            [--latex]
                            [--duration-min SECONDS]
                            [--model-eq MODEL_LIST]
                            [--model-substr TEXT]

uv run cochise-analyze-graphs ANALYSIS INPUT [INPUT ...]
```

`cochise-analyze-logs` accepts:

- `index-rounds`
- `index-rounds-and-tokens`
- `show-tokens`
- `index-tokens-and-accounts`

`cochise-analyze-graphs` accepts:

- `planner_input_size`
- `llm_duration_vs_tokens`
- `executor_input_size`
- `executor_cache_size`

Examples:

```bash
uv run cochise-replay logs/run-20260402-095548.json
uv run cochise-analyze-logs index-rounds-and-tokens logs/run-*.json
uv run cochise-analyze-graphs planner_input_size logs/run-*.json
```

The analysis utilities consume the raw JSON trajectory. Graphs write PDF files
to the current working directory. Replay primarily renders the original
Planner/Executor event subset; the complete QA result is in `QA_REPORT_PATH`
and the raw JSON trajectory.

## Scenario, environment spec, and human QA guidance

These inputs have different responsibilities:

| Input | Location | Responsibility |
|---|---|---|
| **Scenario** | `src/cochise/templates/scenario.md` | System context for Planner, Executor, and Assessment workers. It defines the attack objective, rules, range assumptions, and tool guidance. |
| **Environment spec** | `RANGE_SPEC_PATH` | White-box environment context and semantic expectations. It does not directly rewrite the attack objective and is never executed as code. |
| **Human QA guidance** | `--qa-instructions PATH` | Additional QA intent from a human engineer. It does not replace the scenario or the environment spec. |

The checked-in `scenario.md` is still AD-oriented: its current objective and
rules describe a Microsoft Active Directory assessment, including default range
assumptions. If only the QA guidance or environment spec changes, the Planner
still sees that AD scenario. To change the ordinary attack objective, edit
`src/cochise/templates/scenario.md` or add a separate scenario-selection
mechanism in a future extension.

> **中文摘要：** `scenario.md` 才是 Planner/Executor 的主要 system context，
> 目前仍以 AD 為主；Range Spec 與 `--qa-instructions` 只補充 QA 語意，不會
> 自動改變一般攻擊目標。

### White-box spec formats

`RANGE_SPEC_PATH` supports:

- `.yaml`/`.yml`: opportunistic mapping parsing while preserving the raw text;
- `.json`: opportunistic mapping parsing; malformed JSON is preserved as text;
- `.md`, plain text, and other extensions: raw semantic content, with a
  best-effort YAML mapping parse when possible.

`src/cochise/templates/range_spec.schema.json` is a permissive field hint, not
a required validator. A spec may use fixed fields, mixed formats, or natural
language. The LLM extracts explicit expectations, marks inferred assumptions,
and updates a versioned semantic expectation manifest with observed evidence.

Structured example:

```yaml
scenario_ref: isolated-mail-lab
networks:
  - 192.168.0.0/24
  - 192.168.100.0/24
hosts:
  - id: dc01
    hostname: dc01
    ip: 192.168.0.10
    role: Windows AD domain controller
  - id: machine-a
    ip: 192.168.0.20
    role: Windows endpoint, domain joined
  - id: machine-b
    ip: 192.168.0.21
    role: standalone Windows endpoint
  - id: linux-range
    ip: 192.168.100.10
    role: standalone Linux Cyber Range host
```

Markdown or natural language can describe the same topology, including an
attacker mail server, mail gateway, domain-joined or standalone endpoints,
expected reverse-shell behavior, and required evidence. The LLM maps the
description to expectations; it does not treat the document as a command list.

## Cyber Range QA

### Black-box mode (QA default)

Without a white-box spec, the global adapter runs these commands from Kali:

- `ip -brief address`
- `ip route`
- `cat /etc/resolv.conf`
- `nmap -sn -n -T3 <network>` for every configured `RANGE_NETWORKS` CIDR

For a structured host with an IP, host collection uses
`nmap -Pn -n -sT --top-ports 100 <address>`. Without host metadata, host QA
starts only after the attack workflow confirms access through
`register_host_access`.

### White-box mode

`RANGE_MODE=whitebox` requires `RANGE_SPEC_PATH`. The LLM receives a bounded
semantic context containing the raw spec, source, format, and SHA-256. It
extracts explicit expectations, marks assumptions, and verifies them using
attacker, control-plane, or victim evidence. Incomplete specs do not disable
discovery; unobservable properties remain `unknown`.

### Host QA coverage

Each host worker first performs a common observable baseline. The LLM then
selects applicable platform checks from evidence:

- **Windows endpoint:** workstation/server, domain membership, build, users and
  groups, services, firewall, Defender/EDR, SMB/WinRM/RDP, PowerShell, UAC,
  scheduled tasks, and local ACLs.
- **Windows AD:** only when evidence supports a domain-controller/AD role;
  domain/forest, DNS, Kerberos, LDAP/LDAPS, SMB, users/groups, SPNs, trusts,
  GPO/ACLs, and attack-path feasibility.
- **Linux Cyber Range:** AD-integrated or standalone distribution/kernel, users,
  sudo, SSH/PAM, systemd/cron, listeners, firewall, SELinux/AppArmor,
  SUID/capabilities, filesystem permissions, containers, web/database services,
  and LDAP/Kerberos integration.

The worker must not mark unobserved information as passing. If access is
insufficient, it attempts a reasonable authorized privilege-escalation path
first and records identity/privilege before and after. If escalation is not
possible, it records `unknown` or `blocked_by_access` rather than guessing.

### Attacker, victim, and reverse-shell evidence

Attacker-side commands use the existing SSH `execute_command` tool. Victim-side
commands are available only when `RANGE_VICTIM_MODULE` is configured through
`execute_victim_command`. Persistent victim shells require an adapter that also
implements `execute_shell_command`.

When a reverse shell is established, register it immediately:

```text
register_shell_session(
  shell_id="victim-a-rshell-1",
  host_id="machine-a",
  platform="windows",
  identity="user-or-system",
  privilege_level="user-or-admin",
  cwd="C:\\Users\\...",
  transport="reverse-shell"
)
```

`shell_id` is the routing key for subsequent LLM actions. Use the same ID with
`execute_shell_command`, and call `update_shell_session` whenever identity,
privilege, working directory, or connection status changes. The QA report keeps
attacker/victim source, host, shell ID, and evidence correlation visible. Never
confuse the Kali SSH shell with a victim shell.

> **中文摘要：** reverse shell 建立後必須註冊唯一 `shell_id`，後續用同一 ID
> 路由。Kali attacker shell 與 victim shell 是不同執行上下文。

## QA report and artifact aggregation

`QAReportWriter` creates the report at startup and atomically rewrites it after
global/host progress, completed assessments, expectation updates, and final
run status changes.

```bash
tail -f logs/qa-report.md
```

The report contains:

- run status, timestamps, configuration metadata, and artifact index path;
- global/host assessment index and current phase/round;
- finding status, severity, confidence, expected value, and observed value;
- attacker-side, victim-side, and control-plane evidence provenance;
- white-box manifest version, expectation coverage, and conformance;
- active shell IDs, privilege events, and aggregated artifact count.

Large evidence is not duplicated in the Markdown report. `ArtifactRegistry`
deduplicates content by SHA-256 and writes one `artifact-manifest.jsonl` in the
configured directory. The original content remains in the run JSON trajectory
or in the adapter-owned file referenced by `raw_reference`; the manifest is a
compact index, not a complete evidence backup.

The report and artifact index redact common password, secret, token, API-key,
and authorization patterns. The raw trajectory may still contain tool
arguments, command output, and test credentials. Protect the entire `logs/`
directory and do not put real secrets in scenario, spec, or guidance files.

## Optional adapters

### Control-plane adapter

Configure:

```dotenv
RANGE_CONTROL_PLANE_MODULE=my_range_adapters:control_plane
```

The factory receives no arguments and must return an object implementing:

```python
class ControlPlane:
    async def collect_global(self, spec=None):
        return {"evidence": []}

    async def collect_host(self, host_id, host, spec=None):
        return {"evidence": []}


def control_plane():
    return ControlPlane()
```

Evidence entries may contain `category`, `command`, `output`, `exit_status`,
`source`, and `raw_reference`. Cochise merges control-plane evidence with the
attacker view before passing it to the QA worker.

### Victim-side adapter

Configure:

```dotenv
RANGE_VICTIM_MODULE=my_range_adapters:victim
```

Minimal interface:

```python
class Victim:
    async def execute_victim_command(
        self, host_id, command, purpose="", shell_id=""
    ):
        # Implement WinRM, PowerShell Remoting, Linux SSH, an agent,
        # or another authorized victim transport here.
        return {"output": "...", "exit_status": 0}

    async def execute_shell_command(self, shell_id, command, purpose=""):
        return {"output": "...", "exit_status": 0, "shell_id": shell_id}


def victim():
    return Victim()
```

`execute_shell_command` is optional. Without it, Cochise can still issue bounded
`execute_victim_command` requests, but cannot maintain a persistent reverse-shell
transport. The adapter owns authentication, transport, session lifecycle, and
victim-side safety boundaries. Cochise routes the LLM request and records
provenance; it does not execute spec text directly.

> **中文摘要：** Windows/Linux victim 的實際命令執行由使用者提供的 adapter
> 負責；核心只做 bounded routing、session metadata 與 evidence provenance。

## Token, performance, and stability boundaries

- Planner history compacts at `PLANNER_MAX_CONTEXT_SIZE` or
  `PLANNER_MAX_INTERACTIONS`; `PLANNER_HARD_MAX_INTERACTIONS` is the final
  Planner cap.
- Each Executor task has at most 25 command-selection rounds, plus five human
  recovery rounds in interactive mode. Three consecutive no-progress rounds
  stop the task.
- Each host assessment has at most 12 LLM rounds. Three consecutive rounds with
  no executable progress stop that host worker.
- Multiple tool calls in one Executor response run concurrently with asyncio.
- The SSH command timeout is 600 seconds. `LLM_TIMEOUT_SECONDS` applies only to
  LiteLLM requests.
- Transient LLM provider/network failures receive only the bounded retry count
  configured by `LLM_MAX_RETRIES`.
- QA report evidence is compacted and artifact content is hash-deduplicated;
  raw trajectory data remains authoritative.

These limits bound execution and context growth without hard-coding a fixed
attack order. The LLM still decides strategy, task decomposition, and semantic
interpretation within the available tool and safety boundaries.

## Human interaction and unattended mode

With `HUMAN_INTERACTION=1`, Planner, Executor, and enabled Host QA may call
`ask_human` when:

- an expected file or artifact is missing;
- a blocking global or host assessment needs correction or an explicit stop;
- the Executor reaches its normal 25-round limit without a result.

With `HUMAN_INTERACTION=0`, Cochise does not read stdin and removes `ask_human`
from autonomous LLM tool surfaces. Blocking assessment findings are recorded
and automatically overridden so the run can continue; this does not make the
finding pass or repair the environment. Workers still stop after repeated
rounds without executable progress.

## Testing and development validation

```bash
# Unit tests (the repository uses unittest; pytest is not required)
uv run python -m unittest discover -s tests -q

# Syntax check
uv run python -m compileall -q src

# CLI entry points
uv run cochise --help
uv run cochise-replay --help
uv run cochise-analyze-logs --help
uv run cochise-analyze-graphs --help
```

Unit tests do not replace live Cyber Range validation. A live run still needs a
reachable attacker VM, a tool-calling model, and a test environment within the
authorized scope.

> **中文摘要：** 可用 unittest、compileall 與 CLI help 驗證本地程式；這些不
> 代表 live Cyber Range 或真實 LLM 執行已完成驗證。

## Repository layout

| Path | Responsibility |
|---|---|
| `src/cochise/cli/cochise.py` | Main entry point, `.env`, LLM/SSH/QA wiring. |
| `src/cochise/common.py` | LiteLLM wrapper, provider mapping, tool schemas, retry/timeout. |
| `src/cochise/planner.py` | Persistent Planner, plan compaction, host QA gates. |
| `src/cochise/executor.py` | Ephemeral Executor, parallel tools, human recovery. |
| `src/cochise/assessment.py` | Range specs, black-box/control-plane/victim adapters, global/host QA. |
| `src/cochise/qa_guidance.py` | Raw human QA guidance, provenance, hash, bounded semantic context. |
| `src/cochise/qa_report.py` | Live Markdown report, redaction, coverage/conformance. |
| `src/cochise/artifacts.py` | JSONL artifact manifest and content-hash deduplication. |
| `src/cochise/knowledge.py` | Accounts, entities, hosts, findings, expectations, privileges, shells. |
| `src/cochise/ssh_connection.py` | AsyncSSH attacker/Kali transport. |
| `src/cochise/logger.py` | Rich console and `logs/run-*.json` structured trajectory. |
| `src/cochise/templates/scenario.md` | Current objective, rules, and tool guidance system context. |
| `src/cochise/templates/assessment_prompt.md.jinja2` | Host QA semantic assessment and evidence contract. |
| `src/cochise/templates/range_spec.schema.json` | Optional permissive white-box field hint. |
| `tests/` | LLM config, tool call, assessment, report, and guidance tests. |
| `docs/` | Walkthrough, historical GOAD setup, and OPSEC design documents. |

## Troubleshooting

### The spec file is not found

`RANGE_SPEC_PATH` is resolved from the current working directory; it is not a
positional argument. Verify the path first:

```bash
pwd
test -r "$PWD/specs/environment.md"
```

Then set an absolute or correct relative path in `.env`:

```dotenv
QA_ENABLED=1
RANGE_MODE=whitebox
RANGE_SPEC_PATH=/absolute/path/to/specs/environment.md
```

When QA is enabled, white-box mode without `RANGE_SPEC_PATH` stops with a
configuration error. An empty file is rejected by the QA guidance loader. An
empty or malformed range spec is retained as raw text so the semantic worker can
report the ambiguity; the loader does not invent a topology.

### QA still follows the AD scenario

`scenario.md` is the system context for Planner and Executor. The checked-in
scenario is AD-oriented. When QA is enabled, the assessment worker receives the
same scenario plus the range spec and any `--qa-instructions`; these inputs do
not replace the scenario. Change
`src/cochise/templates/scenario.md` when the ordinary attack objective must be
changed.

### What should `TARGET_HOST` contain?

Use the address of the attacker/Kali VM that accepts SSH from the machine
running Cochise. It is not automatically the AD DC or a victim endpoint. Direct
victim execution requires a configured victim adapter or an LLM-driven attack
path that reaches the host and registers access.

### The run is slow or produces many LLM calls

First check whether `QA_ENABLED`, the healthcheck, global/host QA, Planner
compaction, human recovery, and retry settings are enabled. Bound the run with `MAX_RUN_TIME`,
`PLANNER_MAX_CONTEXT_SIZE`, and `PLANNER_HARD_MAX_INTERACTIONS`. Use the JSON
logs and analysis commands to inspect prompt tokens, cached tokens, duration,
and cost. `LLM_TIMEOUT_SECONDS` is not the SSH timeout; SSH remains 600 seconds.

### The reverse shell is connected but the agent cannot continue from it

Register a unique `shell_id` with host, platform, identity, privilege, working
directory, and transport. Use that same ID for subsequent shell commands. If the
victim adapter does not implement `execute_shell_command`, the core can retain
session metadata but cannot maintain the persistent transport for the agent.

> **中文摘要：** Spec 路徑、AD scenario、Kali `TARGET_HOST` 與 reverse-shell
> routing 是最常見的設定問題；先檢查 `.env` override 與 `shell_id` provenance。

## Upstream and research context

This repository is derived from the original
[andreashappe/cochise](https://github.com/andreashappe/cochise) Planner/Executor
prototype. Research background:

- [Can LLMs Hack Enterprise Networks?](https://arxiv.org/abs/2502.04227)
- [Reproducibility and replication report](https://arxiv.org/abs/2603.01789)
- [GOAD](https://github.com/Orange-Cyberdefense/GOAD) test environment

`docs/running-cochise-vs-goat.md` retains historical GOAD/VM setup material.
Its hardware, versions, and benchmark results are not guarantees for the
current fork or for a live run.

## License

MIT License; see [LICENSE](LICENSE).
