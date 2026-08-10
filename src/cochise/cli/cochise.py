import asyncio
import litellm
import os
import pathlib

from dotenv import load_dotenv
from rich.console import Console

from cochise.assessment import (
    AssessmentExecutor,
    BlackBoxRangeAdapter,
    CompositeRangeAdapter,
    RangeAssessmentCoordinator,
    load_control_plane_adapter,
    load_range_spec,
)
from cochise.common import check_llm_tool_calling, get_llm_config_from_env
from cochise.executor import ExecutorFactory
from cochise.human_interaction import HumanInteraction
from cochise.planner import Planner
from cochise.logger import Logger
from cochise.ssh_connection import get_ssh_connection_from_env

SCENARIO = (pathlib.Path(__file__).parent.parent / "templates" / "scenario.md").read_text()


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _configured_networks() -> list[str]:
    value = os.getenv("RANGE_NETWORKS", "")
    return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]

async def async_main() -> None:

    # setup configuration from environment variables
    load_dotenv()
    # Resolve the selected provider once and share the same connection details
    # with the planner and every short-lived executor.
    llm_config = get_llm_config_from_env()

    conn = get_ssh_connection_from_env()

    # disable warnings about unknown models
    litellm.suppress_debug_info = True

    # setup logging and console output
    console = Console()
    logger = Logger(console)
    human_interaction = HumanInteraction(console)
    logger.log_data("starting test-run")

    if _env_flag("LLM_HEALTHCHECK", True):
        costs, duration = check_llm_tool_calling(llm_config, None)
        logger.log_data(
            "llm_healthcheck",
            {
                "status": "pass",
                "provider": llm_config.provider,
                "model": llm_config.model,
                "duration": duration,
                "total_tokens": costs.get("total_tokens", 0),
            },
            output=False,
        )

    # when should the high-level context be compressed/compacted. The executor's
    # context will be reset with each new executor (the planner's wont).
    planner_max_context_size = int(os.getenv("PLANNER_MAX_CONTEXT_SIZE", "250000"))
    planner_max_interactions = int(os.getenv("PLANNER_MAX_INTERACTIONS", "0"))

    # should we stop the planner on the first reaction after this time has eclipsed?
    max_runtime = int(os.getenv("MAX_RUN_TIME", "0"))

    logger.log_data("configuration", {
        **llm_config.to_log_dict(),
        "ssh-host": conn.host,
        "ssh-user": conn.username,
        "scenario": SCENARIO,
        "max_runtime": max_runtime,
        "planner_max_context_size": planner_max_context_size,
        "planner_max_interactions": planner_max_interactions,
    }, output=False)

    # open SSH connection
    await conn.connect()

    # setup components..
    tools = [conn.execute_command]
    range_spec_path = os.getenv("RANGE_SPEC_PATH")
    range_spec = load_range_spec(range_spec_path) if range_spec_path else None
    range_mode = os.getenv("RANGE_MODE", "whitebox" if range_spec else "blackbox").strip().lower()
    if range_mode not in {"blackbox", "whitebox"}:
        raise ValueError("RANGE_MODE must be either 'blackbox' or 'whitebox'")
    if range_mode == "whitebox" and range_spec is None:
        raise ValueError("RANGE_MODE=whitebox requires RANGE_SPEC_PATH")

    control_plane = load_control_plane_adapter(os.getenv("RANGE_CONTROL_PLANE_MODULE"))
    range_adapter = CompositeRangeAdapter(
        BlackBoxRangeAdapter(conn.execute_command, _configured_networks()),
        control_plane,
    )
    assessment_executor = AssessmentExecutor(
        llm_config,
        None,
        SCENARIO,
        tools,
        logger,
        human_interaction,
    )
    assessment_coordinator = RangeAssessmentCoordinator(
        range_adapter,
        logger,
        range_spec if range_mode == "whitebox" else None,
        assessment_executor.assess_host,
    )
    executor_factory = ExecutorFactory(
        llm_config,
        None,
        SCENARIO,
        tools,
        logger,
        human_interaction,
    )
    planner = Planner(
        llm_config,
        None,
        SCENARIO,
        executor_factory,
        logger,
        max_runtime,
        planner_max_context_size,
        planner_max_interactions,
        human_interaction,
        assessment_coordinator,
    )

    # ..and run cochise!
    await planner.engage()

asyncio.run(async_main())
