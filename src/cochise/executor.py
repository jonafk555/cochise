import asyncio
import pathlib

from jinja2 import Template
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn,TimeElapsedColumn

from cochise.common import (
    LLMFunctionMapping,
    is_tool_call,
    llm_call,
    llm_tool_call,
    message_to_json,
    parse_tool_call,
)
from cochise.human_interaction import HumanInteraction, is_stop_response
from cochise.knowledge import Knowledge


MISSING_ARTIFACT_MARKERS = (
    "no such file or directory",
    "no such file",
    "cannot access",
    "cannot open",
    "file not found",
    "not found",
    "file does not exist",
    "does not exist",
    "filenotfounderror",
)


def looks_like_missing_artifact(command: str, output: str) -> bool:
    command_text = str(command).lower()
    output_text = str(output).lower()
    if not any(marker in output_text for marker in MISSING_ARTIFACT_MARKERS):
        return False
    return "/" in command_text or "file" in command_text or "path" in command_text


async def perform_tool_call(id, tool_name, function, args):
    try:
        result = await function(**args)
    except Exception as e:
        result = f"Error executing tool {tool_name} with arguments {args}: {str(e)}"

    metadata = {}
    if isinstance(result, dict):
        metadata = {
            key: value
            for key, value in result.items()
            if key not in {"output", "stdout", "stderr"}
        }

    output = result['output'] if isinstance(result, dict) and 'output' in result else result
    if not isinstance(output, str):
        output = str(output)

    return {
        'tool': tool_name,
        'cmd': args['command'] if 'command' in args else tool_name,
        'result': output,
        'exit_status': result['exit_status'] if isinstance(result, dict) and 'exit_status' in result else None,
        'metadata': metadata,
        'tool_call_id': id
    }

TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
PROMPT = (TEMPLATE_DIR / "executor_prompt.md.jinja2").read_text()
MAX_ROUNDS:int=25
HUMAN_RECOVERY_ROUNDS:int=5

class ExecutorFactory:
    def __init__(self, model, api_key, scenario, configured_tools, logger, human_interaction=None):
        self.model = model
        self.api_key = api_key
        self.logger = logger
        self.scenario = scenario
        self.configured_tools = configured_tools
        self.human_interaction = human_interaction or HumanInteraction(logger.console)

    def build(self, system_knowledge):
        return Executor(
            self.model,
            self.api_key,
            self.scenario,
            self.configured_tools,
            system_knowledge,
            self.logger,
            self.human_interaction,
        )

class Executor:

    def __init__(
        self,
        model,
        api_key,
        scenario,
        configured_tools,
        system_knowledge,
        logger,
        human_interaction=None,
    ):
        self.model = model
        self.api_key = api_key
        self.logger = logger
        self.scenario = scenario
        self.system_knowledge = system_knowledge
        self.configured_tools = configured_tools
        self.human_interaction = human_interaction or HumanInteraction(logger.console)

    def setLogger(self, logger):
        self.logger = logger

    async def ask_human(self, question: str, reason: str) -> str:
        """Ask a human for guidance when the executor is blocked or missing a file.

        Parameters
        ----------
        question : str
            The concrete information, file path, or next step needed from the
            human.
        reason : str
            Why the executor cannot continue.
        """

        return await self.human_interaction.ask_human(question, reason)

    async def perform_task(self, next_step: str, next_step_context: str, mitre_attack_tactic: str, mitre_attack_technique: str) -> tuple[str, Knowledge]:
        """Perform the given task, which is a sub-task of the overall hacking objective.

        Parameters
        ----------
        next_step : str
            The next step to perform.
        next_step_context : str
            Concise Context for worker that executes the next step. Can be formated as a markdown list.
        mitre_attack_tactic : str
            The MITRE ATT&CK tactic associated with the next step.
        mitre_attack_technique : str
            The MITRE ATT&CK technique associated with the next step.

        Returns 
        -------
        str
            A summary of the performed task, including any relevant findings.
        """

        self.logger.log_data("executor", "Starting task: " + next_step)
        prompt = Template(PROMPT).render({
            'next_step': next_step,
            'next_step_context': next_step_context,
            'max': str(MAX_ROUNDS-1),
            'knowledge': self.system_knowledge.get_knowledge()
        })
            
        history = [
            { "role": "system", "content": self.scenario },
            { "role": "user", "content": prompt },
        ]
        self.logger.log_append_to_history(history, source='manual', output=False)

        knowledge = Knowledge(self.logger)
        tools = LLMFunctionMapping(self.configured_tools + [
            self.ask_human,
            knowledge.register_host_access,
            knowledge.add_compromised_account,
            knowledge.update_compromised_account,
            knowledge.add_entity_information,
            knowledge.update_entity_information,
            knowledge.record_host_privilege,
            knowledge.register_shell_session,
            knowledge.update_shell_session,
        ])

        prompt = f"[bold]Task: {next_step}\nCategorization:[/bold] {mitre_attack_tactic}/{mitre_attack_technique}\n\n[bold]Context:[/bold]\n{next_step_context}\n\n[bold]Existing Knowledge:[/bold]\n{self.system_knowledge.get_knowledge()}"
        self.logger.console.print(Panel(prompt, title="Executor Started"))

        # try to solve our sub-task
        round = 1
        summary = None
        human_asked = False
        human_stopped = False
        max_rounds = MAX_ROUNDS + HUMAN_RECOVERY_ROUNDS
        while round <= max_rounds:

            if round == MAX_ROUNDS + 1 and not human_asked:
                human_asked = True
                human_response = await self.ask_human(
                    question=(
                        f"The executor could not complete this task after {MAX_ROUNDS} rounds:\n"
                        f"{next_step}\n\n"
                        "If an expected file or artifact is missing, provide its exact path, "
                        "copy it to the Kali machine, or explain how to obtain it. Otherwise "
                        "provide the next step or missing information. Reply 'stop' to end the run."
                    ),
                    reason="The executor is blocked and needs human guidance to continue.",
                )
                human_message = {
                    "role": "user",
                    "content": f"Human guidance: {human_response}",
                }
                history.append(human_message)
                self.logger.log_append_to_history(human_message, source="human", output=False)

                if is_stop_response(human_response):
                    human_stopped = True
                    break

            with self.logger.console.status("[bold green]executor: selecting next action"):

                # TODO: we need some error handling here (in case of misformed tool calls)
                # TODO: we do not limit the message size here, which can lead to running-out-of-context errors
                response_message, costs, duration = llm_tool_call(
                    self.model,
                    self.api_key,
                    tools,
                    history
                )
                self.logger.log_llm_call('executor_next_cmds', response_message, costs, duration, output=False)
                
                self.logger.log_append_to_history(response_message, source='agent', output=False)
                history.append(message_to_json(response_message))

            if is_tool_call(response_message):
                # Keep the live progress renderer away from stdin.  Asking for
                # human input while Progress is active causes its refreshes to
                # redraw the input line, which makes a valid response such as
                # ``continue`` appear to be ignored in an interactive terminal.
                tool_calls = []
                tool_results = {}
                for tool_call in response_message.tool_calls:
                    function_name, args, parse_error = parse_tool_call(tool_call)
                    tool_call_id = getattr(tool_call, "id", "")
                    tool_calls.append((tool_call, function_name, args))
                    if parse_error:
                        tool_results[tool_call_id] = {
                            'tool': function_name,
                            'cmd': function_name,
                            'result': parse_error,
                            'exit_status': None,
                            'metadata': {},
                            'tool_call_id': tool_call_id,
                        }
                        continue
                    if not tools.has_function(function_name):
                        tool_results[tool_call_id] = {
                            'tool': function_name,
                            'cmd': function_name,
                            'result': (
                                f"Unknown tool '{function_name}'. Choose one of: "
                                f"{', '.join(tools.mapping)}."
                            ),
                            'exit_status': None,
                            'metadata': {},
                            'tool_call_id': tool_call_id,
                        }
                        continue
                    self.logger.log_tool_call(function_name, tool_call_id, args, output=False)

                command_calls = [
                    item for item in tool_calls
                    if item[1] != "ask_human"
                    and item[2] is not None
                    and getattr(item[0], "id", "") not in tool_results
                ]
                if command_calls:
                    tasks = []
                    display = {}
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TimeElapsedColumn(),
                        console=self.logger.console,
                    ) as progress:
                        for tool_call, function_name, args in command_calls:
                            cmd = args['command'] if 'command' in args else function_name
                            display[tool_call.id] = progress.add_task(
                                f"[bold green]Executing `{cmd}`", total=100
                            )
                            tasks.append(asyncio.create_task(
                                perform_tool_call(
                                    tool_call.id,
                                    function_name,
                                    tools.get_function(function_name),
                                    args,
                                )
                            ))

                        for done in asyncio.as_completed(tasks):
                            result = await done
                            tool_results[result['tool_call_id']] = result
                            task_id = display[result['tool_call_id']]
                            progress.update(task_id, advance=100)
                            if result['tool'] == 'execute_command':
                                progress.console.print(
                                    Panel(
                                        result['result'],
                                        title=f"Tool Result for {result['cmd']}",
                                    ),
                                    markup=False,
                                )

                # Human prompts must run after Progress has released the
                # terminal.  They are still represented as normal tool results
                # so the assistant tool-call/result ordering remains valid.
                for tool_call, function_name, args in tool_calls:
                    if (
                        function_name == "ask_human"
                        and args is not None
                        and getattr(tool_call, "id", "") not in tool_results
                    ):
                        tool_results[tool_call.id] = await perform_tool_call(
                            tool_call.id,
                            function_name,
                            tools.get_function(function_name),
                            args,
                        )

                # Append results in the same order as the assistant's tool
                # calls.  In particular, never insert a user message before a
                # required tool result.
                for tool_call, _function_name, _args in tool_calls:
                    result = tool_results.get(tool_call.id)
                    if result is None:
                        result = {
                            'tool': _function_name,
                            'cmd': _function_name,
                            'result': "Tool call failed before execution.",
                            'exit_status': None,
                            'metadata': {},
                            'tool_call_id': tool_call.id,
                        }
                    self.logger.log_tool_result(
                        result['tool'],
                        result['tool_call_id'],
                        result['result'],
                        output=False,
                    )
                    msg = {
                        "tool_call_id": result['tool_call_id'],
                        "role": "tool",
                        "name": result['tool'],
                        "content": result['result'],
                    }
                    history.append(msg)
                    self.logger.log_append_to_history(msg, source='agent', output=False)

                # An explicit ask_human call takes precedence over the
                # automatic missing-artifact prompt for this response.
                for _tool_call, _function_name, _args in tool_calls:
                    result = tool_results[_tool_call.id]
                    if result['tool'] == 'ask_human':
                        human_asked = True
                        if is_stop_response(result['result']):
                            human_stopped = True

                if not human_stopped and not human_asked:
                    for _tool_call, _function_name, _args in tool_calls:
                        result = tool_results[_tool_call.id]
                        if (
                            result['tool'] == 'execute_command'
                            and looks_like_missing_artifact(result['cmd'], result['result'])
                        ):
                            human_asked = True
                            human_response = await self.ask_human(
                                question=(
                                    f"The command `{result['cmd']}` could not access an expected "
                                    "file or artifact.\n\n"
                                    f"Command output:\n{result['result'][-2000:]}\n\n"
                                    "Provide the correct path, copy the file to the Kali machine, "
                                    "or explain how to obtain it. Reply 'stop' to end the run."
                                ),
                                reason="An SSH command reported that an expected file or artifact is unavailable.",
                            )
                            human_message = {
                                "role": "user",
                                "content": f"Human guidance: {human_response}",
                            }
                            history.append(human_message)
                            self.logger.log_append_to_history(
                                human_message,
                                source="human",
                                output=False,
                            )
                            if is_stop_response(human_response):
                                human_stopped = True
                            break

                if human_stopped:
                    break
            else:
                # the AI message has not tool_call -> this was some sort of result then
                if response_message.content is None or response_message.content == '':
                    msg = {
                        "role": "user",
                        "content": "please continue" 
                    }
                    history.append(msg)
                    self.logger.log_append_to_history(msg, source='manual', output=True)

                    self.logger.console.log(str(response_message))
                    self.logger.console.log("Empty response from executor LLM.. retrying")
                else:
                    summary = response_message.content
                    break
            round = round + 1

        if summary is None and human_stopped:
            summary = "The human operator stopped the executor before the task was completed."

        if summary is None:
            # create new summary based on history
            msg = { "role": "user", "content": "provide a summary including all findings for the high level strategy component. If there was no usable information gained, state so and hypothesize what might be the case If there was no usable information gained, state so and hypothesize what might be the case." }

            history.append(msg)
            self.logger.log_append_to_history(msg, source='manual', output=False)

            result, duration, costs = llm_call(self.model, self.api_key, history) 
            self.logger.log_llm_call('executor_no_summary', result, costs, duration, output=True)

            if result["content"] is None or result["content"] == '':
                self.logger.console.log("Executor failed to produce a summary after " + str(MAX_ROUNDS) + " rounds and a follow-up prompt.. returning empty summary")
                summary = "Experiment was not successful in gaining any relevant information for the task. This could be due to a variety of reasons, such as lack of access to necessary tools, insufficient context, or the inherent difficulty of the task. It's also possible that the AI encountered unexpected issues during execution. Further investigation and adjustments may be needed to achieve better results in future attempts."
            else:
                summary = result["content"]

        # IDEA: summary often has more findings than knowledge, do explicit transfer step?
        return summary + "\n\n\n" + knowledge.get_knowledge(), knowledge
