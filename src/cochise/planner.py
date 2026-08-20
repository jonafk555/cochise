import datetime
import pathlib

from rich.markdown import Markdown
from rich.panel import Panel
from rich.pretty import Pretty

from cochise.common import (
    LLMFunctionMapping,
    LLMCallError,
    is_tool_call,
    llm_call,
    llm_tool_call,
    message_to_json,
    parse_tool_call,
)
from cochise.human_interaction import HumanInteraction, is_stop_response
from cochise.knowledge import Knowledge
from cochise.logger import Logger

TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"

PLANNER_STRUCTURE = (TEMPLATE_DIR / "planner_structure.md").read_text()
PROMPT = (TEMPLATE_DIR / "planner_prompt.md").read_text()
QA_PROMPT = (TEMPLATE_DIR / "qa_planner_prompt.md").read_text()
MAX_AUTONOMOUS_NO_PROGRESS_ROUNDS = 3
MAX_TOOL_REPAIR_ROUNDS = 3
DEFAULT_HARD_MAX_INTERACTIONS = 0

class Planner:
    
    def __init__(
        self,
        model,
        model_api_key,
        scenario,
        executor_factory,
        logger,
        max_runtime: int = 0,
        max_context_size: int = 0,
        max_interactions: int = 0,
        human_interaction=None,
        assessment_coordinator=None,
        hard_max_interactions: int = DEFAULT_HARD_MAX_INTERACTIONS,
        qa_enabled: bool = False,
    ):
        self.model = model
        self.model_api_key = model_api_key
        self.scenario = scenario
        self.executor_factory = executor_factory
        self.logger = logger
        self.max_runtime = max_runtime
        self.max_context_size = max_context_size
        self.max_interactions = max_interactions
        self.hard_max_interactions = hard_max_interactions
        self.assessment_coordinator = assessment_coordinator
        self.qa_enabled = bool(qa_enabled or assessment_coordinator is not None)
        self.human_interaction = human_interaction or HumanInteraction(
            logger.console,
            enabled=self.qa_enabled,
        )
        self.human_stop_requested = False
        self.preflight_complete = False

        self.history = []
        self.knowledge = Knowledge(self.logger)
        self._last_planner_tools = None

        if PLANNER_STRUCTURE is None or PLANNER_STRUCTURE == "":
            self.PLANNER_INITIAL_STRUCTURE = "Provide a task plan as answer. Do not include a title or an appendix."
            self.SCENARIO_AND_STRUCTURE = self.scenario
        else:
            self.PLANNER_INITIAL_STRUCTURE = PLANNER_STRUCTURE + "\n\n# Task\n\nProvide the hierarchical task plan as answer. Do not include a title or an appendix."
            self.SCENARIO_AND_STRUCTURE = self.scenario + "\n\n# Task Plan Creation and Evolution\n\n" + PLANNER_STRUCTURE

    def _qa_mode(self) -> bool:
        """Return whether the optional assessment/tool surface is active."""

        return bool(self.qa_enabled or self.assessment_coordinator is not None)

    def _planner_execution_prompt(self) -> str:
        """Return the task-selection contract for the current interaction mode."""

        prompt = QA_PROMPT if self._qa_mode() else PROMPT
        if not self._qa_mode() or getattr(self.human_interaction, "enabled", True):
            return prompt
        return (
            prompt
            + "\n\nAutonomous execution mode is enabled. Do not call ask_human. "
            "You MUST call perform_task for the most promising executable task; "
            "the worker will handle bounded recovery autonomously."
        )

    def _planner_tool_choice(self) -> dict[str, object] | None:
        """Require executable work when no human can answer a planner prompt."""

        if not self._qa_mode() or getattr(self.human_interaction, "enabled", True):
            return None
        return {
            "type": "function",
            "function": {"name": "perform_task"},
        }

    def _planner_system_context(self) -> str:
        assessment = self.knowledge.get_knowledge()
        if assessment:
            return (
                self.SCENARIO_AND_STRUCTURE
                + "\n\n# Cyber Range Assessment Context\n\n"
                + assessment
            )
        return self.SCENARIO_AND_STRUCTURE

    async def ask_human(self, question: str, reason: str) -> str:
        """Ask a human for guidance when the planner cannot choose a viable task.

        Parameters
        ----------
        question : str
            The missing information or decision needed from the human.
        reason : str
            Why the planner cannot safely continue.
        """

        return await self.human_interaction.ask_human(question, reason)

    # IDEA: unify with compact_history
    def create_initial_plan(self) -> str:
        system_context = (
            self._planner_system_context()
            if self._qa_mode()
            else self.scenario
        )
        tmp_history = [
            {"role": "system", "content": system_context},
            {"role": "user", "content": self.PLANNER_INITIAL_STRUCTURE }
        ]
        self.logger.log_append_to_history(tmp_history, "manual", False)

        result, duration, costs = llm_call(
            self.model,
            self.model_api_key,
            tmp_history,
            operation="planner initial plan",
        )

        plan = result["content"]
        self.logger.log_llm_call('planner_initial_plan', result=plan, costs=costs, duration=duration)

        return plan
    
    def compact_history(self) -> None:
        msg = {"role": "user", "content": self.PLANNER_INITIAL_STRUCTURE }

        self.history.append(msg)
        self.logger.log_append_to_history(msg, "manual", False)

        result, duration, costs = llm_call(
            self.model,
            self.model_api_key,
            self.history,
            operation="planner history compaction",
            tools=self._last_planner_tools if self._qa_mode() else None,
        )

        plan = result["content"]
        self.logger.log_llm_call('compact_history', plan, costs, duration, output=True)
        self.logger.console.print(Panel(plan, title="new plan"))

        system_context = (
            self._planner_system_context()
            if self._qa_mode()
            else self.SCENARIO_AND_STRUCTURE
        )
        self.history = [
            { "role": "system", "content": system_context},
            { "role": "user", "content": "Create me an initial plan to achieve the overall objective. Break down the overall objective into smaller tasks and subtasks. Do not include generic steps, only very specific ones that are directly relevant for achieving the overall objective. Be concise." },
            { "role": "assistant", "content": f"# Initial Plan\n\n{plan}\n\n\n # Gathered Findings\n\n{self.knowledge.get_knowledge()}" },
            { "role": "user", "content": self._planner_execution_prompt() } # always finish with user prompt
        ]
        self.logger.log_append_to_history(self.history, "manual", False)

    def _append_assessment_to_history(self, result) -> None:
        message = {
            "role": "user",
            "content": (
                f"Cyber Range assessment completed for {result.target}.\n"
                f"Status: {result.status}.\n"
                f"Summary: {result.summary}\n"
                "Use the structured findings in the current knowledge context."
            ),
        }
        self.history.append(message)
        self.logger.log_append_to_history(message, "assessment", output=False)

    def _build_tool_mapping(self, executor) -> LLMFunctionMapping:
        """Build the Planner tool surface advertised to the LLM."""

        tool_functions = [executor.perform_task]
        if getattr(self.human_interaction, "enabled", True):
            tool_functions.append(self.ask_human)
        if self._qa_mode():
            tool_functions.append(self.knowledge.register_host_access)
        tool_functions.extend([
            self.knowledge.add_compromised_account,
            self.knowledge.update_compromised_account,
            self.knowledge.add_entity_information,
            self.knowledge.update_entity_information,
        ])
        return LLMFunctionMapping(tool_functions)

    async def _run_global_preflight(self) -> bool:
        if self.assessment_coordinator is None or self.preflight_complete:
            return True

        result = await self.assessment_coordinator.run_global_preflight(self.knowledge)
        self.preflight_complete = True
        if not result.is_blocking:
            return True

        response = await self.ask_human(
            question=(
                "The Cyber Range global preflight has blocking findings. "
                "Review the assessment evidence and provide a correction or reply 'stop' "
                "to end the run."
            ),
            reason="The Cyber Range is not ready according to the global assessment gate.",
        )
        if is_stop_response(response):
            return False
        if getattr(self.human_interaction, "enabled", True):
            self.logger.log_data("assessment_global_override", response, output=False)
        else:
            self.logger.log_data(
                "assessment_global_auto_override",
                {
                    "reason": response,
                    "policy": "HUMAN_INTERACTION=0",
                },
                output=False,
            )
        return True

    async def _run_pending_host_assessments(self) -> bool:
        if self.assessment_coordinator is None:
            return True

        for host_id in list(self.knowledge.get_pending_hosts()):
            result = await self.assessment_coordinator.assess_host(host_id, self.knowledge)
            if result is None:
                continue
            self._append_assessment_to_history(result)
            if not result.is_blocking:
                continue

            response = await self.ask_human(
                question=(
                    f"Host assessment for {host_id} has blocking findings. "
                    "Provide a correction or reply 'stop' to stop the run."
                ),
                reason="A newly accessed host failed the mandatory Cyber Range assessment gate.",
            )
            if is_stop_response(response):
                return False
            autonomous = not getattr(self.human_interaction, "enabled", True)
            override_reason = response
            if autonomous:
                override_reason = (
                    "Automatically continued because HUMAN_INTERACTION=0; "
                    "the blocking assessment finding remains recorded."
                )
            self.knowledge.override_host_assessment(host_id, override_reason)
            self.logger.log_data(
                "assessment_host_auto_override" if autonomous else "assessment_host_override",
                {"host_id": host_id, "reason": override_reason},
                output=False,
            )
        return True

    async def handle_tool_calls(self, response_message, executor, tool_mapping):
        progressed = False
        errors = 0
        for tool_call in response_message.tool_calls:
            function_name, args, parse_error = parse_tool_call(tool_call)
            tool_call_id = getattr(tool_call, "id", "")

            if parse_error:
                errors += 1
                self._append_tool_error(tool_call_id, function_name, parse_error)
                continue

            if not tool_mapping.has_function(function_name):
                errors += 1
                self._append_tool_error(
                    tool_call_id,
                    function_name,
                    (
                        f"Unknown tool '{function_name}'. Choose one of: "
                        f"{', '.join(tool_mapping.mapping)}."
                    ),
                )
                continue

            self.logger.log_tool_call(function_name, tool_call_id, args, output=True)

            # this could be cleaner:
            # set tool call id in the executor logger, just in case the executor is run
            executor.setLogger(Logger(self.logger.console, tool_call_id, self.logger.logger))

            # call the method. The LLM frequently supplies tool calls that do not
            # match the specification (e.g. omitting the MITRE ATT&CK
            # classification), which makes the **args unpacking raise. Log the
            # error and feed it back as the tool result so the LLM can retry
            # instead of crashing the planner loop.
            try:
                function_to_call = tool_mapping.get_function(function_name)
                raw_result = await function_to_call(**args)
            except LLMCallError:
                raise
            except Exception as e:
                errors += 1
                error = (f"Error calling {function_name} with arguments {args}: {e}. "
                         "Please call the tool again, supplying all required arguments as described in its specification.")
                self._append_tool_error(tool_call_id, function_name, error)
                continue

            if isinstance(raw_result, tuple):
                result, new_knowledge = raw_result
                # IDEA: summary (result) often has a new plan, maybe use that explicitly?
                new_knowledge_str = new_knowledge.get_knowledge()
                if new_knowledge_str != "":
                    self.logger.log_data("new knowledge", new_knowledge_str, output=False)
                    self.logger.console.print(Panel(Markdown(new_knowledge_str), title="New Knowledge"))
                self.knowledge.merge(new_knowledge)
            else:
                result = raw_result
                new_knowledge = Knowledge(self.logger)

            if function_name == "ask_human" and is_stop_response(str(result)):
                self.human_stop_requested = True
            if function_name == "perform_task":
                progressed = progressed or bool(
                    getattr(executor, "last_task_progressed", True)
                )
            elif function_name != "ask_human":
                progressed = True

            result = str(result)
            self.logger.log_tool_result(function_name, tool_call_id, result, output=True)
            msg = {
                "role": "tool",
                "name": function_name,
                "content": result,
                "tool_call_id": tool_call_id
            }

            self.logger.log_append_to_history(msg, "agent", output=False)
            self.history.append(msg)
        return progressed, errors

    def _append_tool_error(self, tool_call_id: str, function_name: str, error: str) -> None:
        """Return a schema-valid tool error so the LLM can repair its call."""

        self.logger.log_tool_result(function_name, tool_call_id, error, output=True)
        msg = {
            "role": "tool",
            "name": function_name,
            "content": str(error),
            "tool_call_id": tool_call_id,
        }
        self.logger.log_append_to_history(msg, "manual", output=False)
        self.history.append(msg)

    
    async def engage(self) -> None:
        """Engage the planner to select the next task to perform based on the current plan and knowledge. This will be called in a loop until the overall objective is achieved.
        """

        # used for stopping and compaction logic
        interaction_counter = 0 # this is currently a round-counter actually
        last_input_tokens = 0
        non_tool_response_counter = 0
        no_progress_rounds = 0
        tool_repair_rounds = 0
        human_stopped = False
        started = datetime.datetime.now()

        if not await self._run_global_preflight():
            self.logger.log_data("completed", "Global Cyber Range preflight stopped the run.", output=True)
            return

        # create an initial plan and select the first task 
        with self.logger.console.status("[bold green]llm-call: creating initial plan"):
            plan = self.create_initial_plan()

        self.history = [
            { "role": "system", "content": self._planner_system_context() },
            { "role": "user", "content": "Create me an initial plan to achieve the overall objective. Break down the overall objective into smaller tasks and subtasks. Do not include generic steps, only very specific ones that are directly relevant for achieving the overall objective. Be concise." },
            { "role": "assistant", "content": f"# Initial Plan\n\n{plan}" },
            { "role": "user", "content": self._planner_execution_prompt() } # always finish with user prompt
        ]
        self.logger.log_append_to_history(self.history, "manual", False)

        # IDEA: I could use a progress bar to show the remaining runtime
        # IDEA: I could also output the currently used context size
        while (
            (self.max_runtime == 0 or (datetime.datetime.now() - started).total_seconds() <= self.max_runtime)
            and (
                self.hard_max_interactions == 0
                or interaction_counter < self.hard_max_interactions
            )
        ):

            if not await self._run_pending_host_assessments():
                human_stopped = True
                break

            # IDEA: do we even need the max-interaction based compaction?
            # IDEA: give the planner the option to trigger compaction itself by calling a tool
            if self.max_interactions != 0 and interaction_counter >= self.max_interactions or self.max_context_size != 0 and last_input_tokens >= self.max_context_size:
                self.logger.log_data("compaction-triggered", f"Starting compaction to prevent excessive resource usage. Interaction count: {interaction_counter}, last input token count: {last_input_tokens}", output=True)
                self.compact_history()

            # prepare new executor for this round. This should signalize that the executor
            # always starts from scratch and does not have any memory of previous rounds,
            # but it will have access to the updated knowledge base which it can use to solve
            # the task at hand.
            executor = self.executor_factory.build(self.knowledge)

            # The planner can delegate work, record newly confirmed access,
            # update shared knowledge, or ask for human guidance when no safe
            # next task is available.  Keep this surface aligned with the
            # planner prompt so the model never sees an unavailable tool.
            tool_mapping = self._build_tool_mapping(executor)
            self._last_planner_tools = tool_mapping.get_tool_definitions()

            self.logger.console.log("Planner: selecting next executable task...")
            with self.logger.console.status("[bold green]llm-call: select next task to perform"):
                response_message, costs, duration = llm_tool_call(
                    self.model,
                    self.model_api_key,
                    tool_mapping,
                    self.history,
                    tool_choice=self._planner_tool_choice(),
                    operation="planner task selection",
                )
            self.logger.console.log("LLM call completed, processing response...")
            self.logger.console.log(
                f"Planner task-selection call completed in {duration:.2f}s."
            )
            self.logger.log_llm_call('planner_task_selection', result=response_message, costs=costs, duration=duration, output=False)
            last_input_tokens = costs['prompt_tokens']

            response_json = message_to_json(response_message)
            self.history.append(response_json)
            self.logger.log_append_to_history(response_json, "agent", output=False)

            # IDEA: unify planner and executor tool call handling
            if is_tool_call(response_message):
                non_tool_response_counter = 0
                progressed, errors = await self.handle_tool_calls(
                    response_message,
                    executor,
                    tool_mapping,
                )
                if self._qa_mode():
                    if progressed:
                        no_progress_rounds = 0
                        tool_repair_rounds = 0
                    else:
                        no_progress_rounds += 1
                        tool_repair_rounds = tool_repair_rounds + 1 if errors else 0
                    if tool_repair_rounds >= MAX_TOOL_REPAIR_ROUNDS:
                        self.logger.log_data(
                            "completed",
                            "Planner stopped after repeated tool-call repair failures.",
                            output=True,
                        )
                        human_stopped = True
                        break
                    if no_progress_rounds >= MAX_AUTONOMOUS_NO_PROGRESS_ROUNDS:
                        self.logger.log_data(
                            "completed",
                            "Planner stopped after repeated rounds without executable progress.",
                            output=True,
                        )
                        human_stopped = True
                        break
                if self._qa_mode() and self.human_stop_requested:
                    human_stopped = True
                    break
            else:
                # TODO: check if we're really done and exit

                # LLM did not call a tool, but returned a message. This should not happen,
                # because the planner should only select a task to perform and call
                # the respective tool for that. You might want to check if the LLM is able
                # to call tools correctly.
                self.logger.console.print(Panel(Pretty(response_message.content), title="LLM Response Content"))
                if not self._qa_mode():
                    msg = {
                        "role": "user",
                        "content": (
                            "You MUST call the perform_task tool. Select the most promising "
                            "incomplete task from the plan and call it now."
                        ),
                    }
                    self.logger.log_append_to_history(msg, "manual", output=True)
                    self.history.append(msg)
                else:
                    non_tool_response_counter += 1
                    no_progress_rounds += 1
                    if (
                        no_progress_rounds >= MAX_AUTONOMOUS_NO_PROGRESS_ROUNDS
                        and not getattr(self.human_interaction, "enabled", True)
                    ):
                        self.logger.log_data(
                            "completed",
                            "Planner stopped after repeated non-tool responses in autonomous mode.",
                            output=True,
                        )
                        human_stopped = True
                        break
                    if non_tool_response_counter >= 2:
                        if getattr(self.human_interaction, "enabled", True):
                            human_response = await self.ask_human(
                                question=(
                                    "The planner has not produced an executable task for two rounds. "
                                    "Provide missing target/file information or tell it how to proceed. "
                                    "Reply 'stop' to end the run."
                                ),
                                reason="The planner is stalled and returned text instead of a tool call.",
                            )
                            msg = {
                                "role": "user",
                                "content": f"Human guidance: {human_response}",
                            }
                            self.logger.log_append_to_history(msg, "human", output=False)
                            self.history.append(msg)
                            non_tool_response_counter = 0
                            no_progress_rounds = 0
                            if is_stop_response(human_response):
                                human_stopped = True
                                break
                    else:
                        msg = {
                            "role": "user",
                            "content": (
                                "You MUST call the perform_task tool. Select the most promising "
                                "incomplete task from the plan and call it now."
                            ),
                        }
                        self.logger.log_append_to_history(msg, "manual", output=True)
                        self.history.append(msg)
            
            interaction_counter += 1
        
        if human_stopped:
            self.logger.log_data("completed", "Human operator stopped the planner.", output=True)
        elif self.max_runtime != 0 and (datetime.datetime.now() - started).total_seconds() > self.max_runtime:
            self.logger.log_data("completed", f"Max runtime of {self.max_runtime} seconds exceeded, stopping planner loop.", output=True)
        elif (
            self.hard_max_interactions != 0
            and interaction_counter >= self.hard_max_interactions
        ):
            self.logger.log_data(
                "completed",
                f"Hard planner interaction limit of {self.hard_max_interactions} reached.",
                output=True,
            )
