# Cochise: Autonomous LLM-Driven Pen-Testing in ~576 Lines of Python

[![arXiv Paper](https://img.shields.io/badge/cs.SE-%20arXiv:2502.04227%20(Main%20Paper)-B31B1B.svg)](https://arxiv.org/abs/2502.04227)
[![arXiv RCR](https://img.shields.io/badge/cs.SE-%20arXiv:2603.01789%20(RCR)-B31B1B.svg)](https://arxiv.org/abs/2603.01789)

> Full Active Directory domain compromise. Under $2. Less than 2 hours. No human in the loop. How?

Cochise is a minimal, readable prototype that uses LLMs to autonomously pen-test enterprise networks using Microsoft Active Directory. Point it at a testbed, pick an LLM, and watch it plan attack chains, execute commands, harvest credentials, and escalate to domain admin.

So basically, I use LLMs to hack Microsoft Active Directory networks.. what could possibly go wrong?

![AS-REP Roasting into Domain Enumeration](docs/asrep_into_enumeration.png)

**Why does this exist?** There are many autonomous hacking agent prototypes out there, but no good *baseline*. Cochise is deliberately minimal so you can:

- **Build on it**: fork it and add your ideas without fighting framework complexity. We provide analysis scripts for later analysis of log files too.
- **Benchmark LLMs**: swap models via a single env var and compare cybersecurity capabilities
- **Understand it**: the entire agent core fits in ~576 lines of readable Python. This makes it also well-suited as a base for vibe-coding sessions.. LLMs can easily understand it too.

## Key Results

I am using [GOAD](https://github.com/Orange-Cyberdefense/GOAD) (Game of Active Directory) as a testbed. This is a vulnerable Microsoft Windows Active Directory network, consisting of 3 domains with 5 servers, emulated users, and lots of vulnerabilities. When testing `cochise`, I had the following results (full evaluation to follow):

- `claude-4.6-opus` was able to fully-compromise (as in `domain dominance`) all three domains within 90 minutes.
- `gemini-3-flash-preview` is typically able to compromise 1-2 domains per run at much lower costs (typically ~$2 per run)
- `gpt-5.4` creates very long convoluted answers, need to fix context management within the *Executor* component for this. Was able to compromise 1-2 domains before my prototype crashed.
- `deepseek-v3.2` was the best open-weight model that I tested and was able to sometimes compromise a single domain but with very neglectable costs.

I also run some of the newer Chinese models (`glm-5-turbo`, `mimi-v2-pro`, `minimax-m2.7`). While they were worse than `deepseek-v3.2` their quality was very similar to the frontier models that I've tested in early/mid 2025, their progress is impressive.

## Architecture

```
                    +------------------+
                    |     Planner      |  Strategic brain: creates attack plan,
                    |   (persistent)   |  selects tasks, aggregates knowledge
                    +--------+---------+
                             |
                    delegates tasks via LLM tool-calling
                             |
                    +--------v---------+
                    |     Executor     |  Tactical: fresh instance per task,
                    |   (ephemeral)    |  runs commands, reports findings
                    +--------+---------+
                             |
                      SSH execute_command via LLM tool-calling
                             |
                    +--------v---------+
                    |  Kali Linux VM   |  Attacker machine inside the
                    |  (target network)|  target network
                    +------------------+
```

The **Planner** maintains a persistent conversation with the LLM, building and updating a hierarchical attack plan. It delegates individual tasks to short-lived **Executor** instances that run shell commands over SSH and report back. A shared **Knowledge Base** tracks compromised accounts, discovered services, and attack leads across rounds.

Context window management is built-in: when the planner's history grows too large, it's automatically compacted so runs can continue for hours.

## Quick Start

### Prerequisites

- Python 3.12+
- A target environment/testbed (I am using [GOAD](https://github.com/Orange-Cyberdefense/GOAD))
- SSH access to a Linux attacker VM (e.g., Kali) inside the testbed
- Access to an LLM API, or a local tool-calling LLM server (Ollama, LM Studio, vLLM, etc.)

### Install

```bash
git clone https://github.com/andreashappe/cochise.git
cd cochise
```

### Configure

Create a `.env` file:

```bash
# LLM configuration
# Choose one provider: openai, claude, gemini, or local.
LLM_PROVIDER='openai'
LLM_MODEL='gpt-4o'
OPENAI_API_KEY='sk-...'

# SSH connection to your attacker VM
TARGET_HOST='192.168.56.100'
TARGET_USERNAME='root'
TARGET_PASSWORD='kali'

# Optional: runtime limits
MAX_RUN_TIME=7200                  # stop after N seconds (0 = unlimited), this is best effort not a hard limit
PLANNER_MAX_CONTEXT_SIZE=250000    # compact history at N tokens
PLANNER_MAX_INTERACTIONS=0         # max planner rounds (0 = unlimited) before history compaction

# Cyber Range assessment
RANGE_MODE='blackbox'              # blackbox or whitebox
RANGE_SPEC_PATH=''                 # YAML/JSON spec for whitebox mode
RANGE_NETWORKS='192.168.122.0/24' # optional comma-separated scan targets
RANGE_CONTROL_PLANE_MODULE=''      # optional local module:factory adapter
LLM_HEALTHCHECK=1                  # verify tool calling before preflight
HUMAN_INTERACTION=1                # set to 0 to disable prompts; fail-closed as stop
```

Cochise uses LiteLLM underneath, so the planner and executor use the same
provider connection and tool-calling interface. The supported provider
configurations are:

```bash
# OpenAI
LLM_PROVIDER='openai'
LLM_MODEL='gpt-4o'
OPENAI_API_KEY='sk-...'

# Claude / Anthropic
LLM_PROVIDER='claude'
LLM_MODEL='claude-sonnet-4-5'
ANTHROPIC_API_KEY='sk-ant-...'

# Gemini
LLM_PROVIDER='gemini'
LLM_MODEL='gemini-2.5-flash'
GEMINI_API_KEY='...'

# Local Ollama (no API key required)
LLM_PROVIDER='local'
LOCAL_LLM_BACKEND='ollama'
LLM_MODEL='llama3.1'
LOCAL_LLM_BASE_URL='http://127.0.0.1:11434'

# Local OpenAI-compatible server, e.g. LM Studio, vLLM, or llama.cpp
LLM_PROVIDER='local'
LOCAL_LLM_BACKEND='openai-compatible'
LLM_MODEL='your-loaded-model-name'
LOCAL_LLM_BASE_URL='http://127.0.0.1:1234/v1'
LOCAL_LLM_API_KEY='local'
```

`LLM_BASE_URL` and `LLM_API_KEY` can be used as provider-neutral overrides.
For backwards compatibility, `LITELLM_MODEL` and `LITELLM_API_KEY` still work
with fully-qualified LiteLLM model names such as
`openrouter/google/gemini-3-flash-preview`. Local models must support chat
tool/function calling because Cochise delegates SSH and knowledge-base actions
through tools.

Cyber Range assessment is mandatory. Black-box mode collects evidence from the
attacker VM; white-box mode additionally compares observations with the
platform-neutral YAML/JSON document described by
`src/cochise/templates/range_spec.schema.json`. A global preflight runs before
the Planner creates an attack plan. Every newly accessed host must then pass a
read-only inventory and attack-feasibility assessment before ordinary attack
work continues. Blocking findings pause the run and request human guidance;
the system does not automatically repair the range. A management-plane adapter
can be supplied with `RANGE_CONTROL_PLANE_MODULE=module:factory`; it must
implement `collect_global(spec)` and `collect_host(host_id, host, spec)`.

### Run

Before you run it, check `src/cochise/templates/scenario.md`. This file contains generic instructions
for the LLM ('attack the AD network'). It also contains the target IP range (hardcoded to the default
192.168.122.0/24 IP range of GOAD when running using libvirt/KVM). Change this to fit your lab setup.

```bash
uv run cochise
```

Cochise will create a timestamped JSON log in `logs/` capturing every LLM call, command execution, and discovered credential.

### Human-in-the-loop

The agent can call `ask_human` when it is blocked or cannot find an expected
file/artifact. If an Executor reaches its normal 25-round limit without a
result, Cochise pauses in the terminal and asks for guidance automatically.
Enter a file path, copy instructions, credentials, or another next step. Enter
`stop` to stop the current run. The response is added to the agent history and
the Executor gets a short recovery window to continue.

For unattended execution, set `HUMAN_INTERACTION=0`. Cochise will not read
stdin; every human request returns `stop`, so blocking range findings stop the
run instead of being silently overridden.

## Analysis Tools

Cochise ships with tools to replay, analyze, and visualize test runs:

```bash
# replay a run in your terminal (same rich output as live)
uv run cochise-replay logs/run-20260402-095548.json

# tabular overview: rounds, tokens, costs, compromised accounts
uv run cochise-analyze-logs index-rounds-and-tokens logs/*.json

# generate graphs: context growth, token usage over time
uv run cochise-analyze-graphs logs/run-20260402-095548.json
```

The analysis tools support LaTeX table export for academic papers.

## Adapting Cochise

### Use a different scenario

Cochise is not locked to Active Directory. The attack scenario is a Markdown template at `src/cochise/templates/scenario.md` and can be changed to different domains. The pre-configured `Executor` tools always connect to a linux VM for executing the selected commands but the tool-set can be extended.

### Architecture and Implementation

The codebase is structured for readability, not abstraction. The core files (I am using `tokei` for counting python lines-of-code and are not counting doc-strings within source files):

| File | Lines Python Code | Purpose |
|---|---|---|
| `planner.py` | 131 | Strategic planning loop |
| `executor.py` | 129 | Tactical command execution |
| `knowledge.py` | 73 | Credential & entity tracking |
| `common.py` | 89 | LLM interface (litellm wrapper) |
| `logger.py` | 80 | Structured JSON + Rich console logging |
| `assessment.py` | -- | Cyber Range preflight, host gates, findings, and white-box loading |
| `ssh_connection.py` | 37 | Async SSH with timeout and reconnect |

See [walkthrough.md](docs/walkthrough.md) for a detailed code walkthrough.

## Publication

This work is published in ACM Transactions on Software Engineering and Methodology (TOSEM):

```bibtex
@article{10.1145/3766895,
author = {Happe, Andreas and Cito, J\"{u}rgen},
title = {Can LLMs Hack Enterprise Networks? Autonomous Assumed Breach Penetration-Testing Active Directory Networks},
year = {2025},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
issn = {1049-331X},
url = {https://doi.org/10.1145/3766895},
doi = {10.1145/3766895},
note = {Just Accepted},
journal = {ACM Trans. Softw. Eng. Methodol.},
month = sep,
keywords = {Security Capability Evaluation, Large Language Models, Enterprise Networks}
}
```

We also provide a reproducibility report containing install instructions as RCR report at [arxiv](https://arxiv.org/abs/2603.01789).

## Background

I have been working on [hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT), making it easier for ethical hackers to use LLMs. My main focus are single-host linux systems and privilege-escalation attacks within them.

When OpenAI opened up API access to its o1 model on January, 24th 2025 and I saw the massive quality improvement over GPT-4o, one of my initial thoughts was "could this be used for more-complex pen-testing tasks.. for example, performing Assumed Breach simulations against Active Directory networks?"

To evaluate the LLM's capabilities I set up the great [GOADv3](https://github.com/Orange-Cyberdefense/GOAD) testbed and wrote the simple prototype that you're currently looking at. This work is only intended to be used against security testbeds, never against real system (you know, as long as we do not understand how AI decision-making happens, you wouldn't want to use an LLM for taking potentially destructive decisions).

**I expect this work (especially the prototype, not the collected logs and screenshots) to end up within [hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT) eventually.**

## Disclaimer

This tool is intended for authorized security testing, academic research, and educational purposes only. Only use Cochise against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

## License

MIT License. See [LICENSE](LICENSE) for details.
