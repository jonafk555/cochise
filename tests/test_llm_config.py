import asyncio
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from cochise import common
from cochise.executor import looks_like_missing_artifact
from cochise.human_interaction import HumanInteraction, is_stop_response


class LLMConfigTests(unittest.TestCase):
    def test_cloud_provider_model_and_key_mapping(self):
        cases = (
            (
                {"LLM_PROVIDER": "openai", "LLM_MODEL": "gpt-4o", "OPENAI_API_KEY": "key"},
                "openai/gpt-4o",
                "key",
            ),
            (
                {
                    "LLM_PROVIDER": "claude",
                    "LLM_MODEL": "claude-sonnet-4-5",
                    "ANTHROPIC_API_KEY": "key",
                },
                "anthropic/claude-sonnet-4-5",
                "key",
            ),
            (
                {
                    "LLM_PROVIDER": "gemini",
                    "LLM_MODEL": "gemini-2.5-flash",
                    "GOOGLE_API_KEY": "key",
                },
                "gemini/gemini-2.5-flash",
                "key",
            ),
        )

        for environment, model, api_key in cases:
            with self.subTest(provider=environment["LLM_PROVIDER"]), patch.dict(
                os.environ, environment, clear=True
            ):
                config = common.get_llm_config_from_env()
                self.assertEqual(config.model, model)
                self.assertEqual(config.api_key, api_key)

    def test_local_ollama_does_not_require_an_api_key(self):
        with patch.dict(
            os.environ,
            {
                "LLM_PROVIDER": "local",
                "LOCAL_LLM_BACKEND": "ollama",
                "LLM_MODEL": "llama3.1",
            },
            clear=True,
        ):
            config = common.get_llm_config_from_env()

        self.assertEqual(config.model, "ollama/llama3.1")
        self.assertIsNone(config.api_key)
        self.assertEqual(config.api_base, "http://127.0.0.1:11434")

    def test_local_openai_compatible_server(self):
        with patch.dict(
            os.environ,
            {
                "LLM_PROVIDER": "local",
                "LOCAL_LLM_BACKEND": "openai-compatible",
                "LLM_MODEL": "qwen",
                "LOCAL_LLM_BASE_URL": "http://localhost:8000/v1",
            },
            clear=True,
        ):
            config = common.get_llm_config_from_env()

        self.assertEqual(config.model, "openai/qwen")
        self.assertEqual(config.api_key, "local")
        self.assertEqual(config.api_base, "http://localhost:8000/v1")

    def test_completion_omits_missing_local_api_key(self):
        captured = {}

        def fake_completion(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
                usage=SimpleNamespace(prompt_tokens=2, completion_tokens=3),
                _hidden_params={},
            )

        config = common.LLMConfig(
            provider="local",
            model="ollama/llama3.1",
            api_base="http://127.0.0.1:11434",
        )
        with patch.object(common.litellm, "completion", fake_completion):
            result, _, costs = common.llm_call(config, None, [{"role": "user", "content": "ping"}])

        self.assertEqual(result["content"], "ok")
        self.assertNotIn("api_key", captured)
        self.assertEqual(captured["api_base"], "http://127.0.0.1:11434")
        self.assertEqual(costs["total_tokens"], 5)

    def test_plain_call_preserves_tools_for_tool_history(self):
        captured = {}

        def fake_completion(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="summary"))],
                usage=SimpleNamespace(prompt_tokens=2, completion_tokens=1),
                _hidden_params={},
            )

        tools = [{
            "type": "function",
            "function": {
                "name": "execute_command",
                "description": "Execute a command",
                "parameters": {"type": "object", "properties": {}},
            },
        }]
        config = common.LLMConfig(provider="anthropic", model="anthropic/test")
        with patch.object(common.litellm, "completion", fake_completion):
            common.llm_call(
                config,
                None,
                [{"role": "user", "content": "summarize"}],
                operation="host assessment summary",
                tools=tools,
            )

        self.assertEqual(captured["tools"], tools)

    def test_gpt_5_4_plus_tool_calls_keep_chat_transport(self):
        captured = {}

        def fake_completion(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
                usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
                _hidden_params={},
            )

        config = common.LLMConfig(
            provider="openai",
            model="openai/gpt-5.6-luna",
        )
        tools = common.LLMFunctionMapping([common._llm_healthcheck_tool])
        with patch.object(common.litellm, "completion", fake_completion):
            common.llm_tool_call(
                config,
                None,
                tools,
                [{"role": "user", "content": "ping"}],
            )

        self.assertNotIn("reasoning_effort", captured)

    def test_tool_reasoning_effort_does_not_trigger_hidden_bridge(self):
        captured = {}

        def fake_completion(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
                usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
                _hidden_params={},
            )

        config = common.LLMConfig(
            provider="openai",
            model="openai/gpt-5.6-luna",
        )
        tools = common.LLMFunctionMapping([common._llm_healthcheck_tool])
        with patch.dict(os.environ, {"LLM_REASONING_EFFORT": "low"}), patch.object(
            common.litellm, "completion", fake_completion
        ):
            common.llm_tool_call(
                config,
                None,
                tools,
                [{"role": "user", "content": "ping"}],
            )

        self.assertNotIn("reasoning_effort", captured)

    def test_regular_openai_tool_calls_omit_reasoning_effort(self):
        captured = {}

        def fake_completion(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
                usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
                _hidden_params={},
            )

        config = common.LLMConfig(provider="openai", model="openai/gpt-4o")
        tools = common.LLMFunctionMapping([common._llm_healthcheck_tool])
        with patch.object(common.litellm, "completion", fake_completion):
            common.llm_tool_call(
                config,
                None,
                tools,
                [{"role": "user", "content": "ping"}],
            )

        self.assertNotIn("reasoning_effort", captured)

    def test_llm_healthcheck_requires_a_tool_call(self):
        captured = {}

        def fake_completion(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(
                    role="assistant",
                    content="",
                    tool_calls=[SimpleNamespace(id="1", function=SimpleNamespace(
                        name="_llm_healthcheck_tool",
                        arguments='{"status":"ok"}',
                    ))],
                ))],
                usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
                _hidden_params={},
            )

        config = common.LLMConfig(provider="local", model="ollama/test")
        with patch.object(common.litellm, "completion", fake_completion):
            costs, _duration = common.check_llm_tool_calling(config, None)

        self.assertEqual(captured["tool_choice"]["type"], "function")
        self.assertEqual(costs["total_tokens"], 2)

    def test_gpt_5_4_plus_named_tool_choice_keeps_chat_shape(self):
        captured = {}

        def fake_completion(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content="ok", tool_calls=[])
                    )
                ],
                usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
                _hidden_params={},
            )

        config = common.LLMConfig(
            provider="openai",
            model="openai/gpt-5.6-luna",
        )
        tools = common.LLMFunctionMapping([common._llm_healthcheck_tool])
        with patch.dict(os.environ, {"LLM_REASONING_EFFORT": "low"}), patch.object(
            common.litellm, "completion", fake_completion
        ):
            common.llm_tool_call(
                config,
                None,
                tools,
                [{"role": "user", "content": "ping"}],
                tool_choice={
                    "type": "function",
                    "function": {"name": "_llm_healthcheck_tool"},
                },
            )

        self.assertEqual(
            captured["tool_choice"],
            {
                "type": "function",
                "function": {"name": "_llm_healthcheck_tool"},
            },
        )

    def test_gpt_5_4_plus_healthcheck_sends_valid_chat_request(self):
        captured = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", "0"))
                captured["path"] = self.path
                captured["body"] = json.loads(self.rfile.read(length))
                response = {
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [{
                                "id": "call-test",
                                "type": "function",
                                "function": {
                                    "name": "_llm_healthcheck_tool",
                                    "arguments": '{"status":"ok"}',
                                },
                            }],
                        },
                        "finish_reason": "tool_calls",
                    }],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                }
                encoded = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_args):
                return None

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = common.LLMConfig(
                provider="openai",
                model="openai/gpt-5.6-luna",
                api_key="test-key",
                api_base=f"http://127.0.0.1:{server.server_port}/v1",
            )
            with patch.dict(
                os.environ,
                {
                    "LLM_REASONING_EFFORT": "low",
                    "LLM_MAX_RETRIES": "0",
                    "LLM_TIMEOUT_SECONDS": "5",
                },
            ):
                costs, _duration = common.check_llm_tool_calling(config, None)
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(captured["path"], "/v1/chat/completions")
        self.assertEqual(
            captured["body"]["tool_choice"],
            {
                "type": "function",
                "function": {"name": "_llm_healthcheck_tool"},
            },
        )
        self.assertNotIn("reasoning_effort", captured["body"])
        self.assertEqual(costs["total_tokens"], 2)

    def test_regular_chat_completions_keep_nested_named_tool_choice(self):
        captured = {}

        def fake_completion(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content="ok", tool_calls=[])
                    )
                ],
                usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
                _hidden_params={},
            )

        config = common.LLMConfig(provider="openai", model="openai/gpt-4o")
        tools = common.LLMFunctionMapping([common._llm_healthcheck_tool])
        expected = {
            "type": "function",
            "function": {"name": "_llm_healthcheck_tool"},
        }
        with patch.object(common.litellm, "completion", fake_completion):
            common.llm_tool_call(
                config,
                None,
                tools,
                [{"role": "user", "content": "ping"}],
                tool_choice=expected,
            )

        self.assertEqual(captured["tool_choice"], expected)

    def test_network_failure_is_wrapped_and_retried_once(self):
        config = common.LLMConfig(provider="anthropic", model="anthropic/test")
        failure = RuntimeError("[Errno 101] Network is unreachable")

        with patch.dict(
            os.environ,
            {"LLM_MAX_RETRIES": "1", "LLM_RETRY_BACKOFF_SECONDS": "0"},
            clear=False,
        ), patch.object(common.litellm, "completion", side_effect=failure) as completion:
            with self.assertRaises(common.LLMCallError) as raised:
                common.llm_call(
                    config,
                    None,
                    [{"role": "user", "content": "ping"}],
                    operation="planner task selection",
                )

        self.assertEqual(completion.call_count, 2)
        self.assertIn("planner task selection", str(raised.exception))
        self.assertIn("Network is unreachable", str(raised.exception))

    def test_human_input_is_returned_and_stop_is_recognized(self):
        interaction = HumanInteraction(Console())
        with patch("builtins.input", return_value="/tmp/missing.txt"):
            response = asyncio.run(
                interaction.ask_human(
                    "Where should I look for the missing file?",
                    "The expected artifact was not found.",
                )
            )

        self.assertEqual(response, "/tmp/missing.txt")
        self.assertTrue(is_stop_response(" stop "))
        self.assertFalse(is_stop_response("continue"))
        self.assertFalse(is_stop_response("contine"))

    def test_disabled_human_interaction_continues_without_input(self):
        interaction = HumanInteraction(Console(), enabled=False)
        with patch("builtins.input") as input_mock:
            response = asyncio.run(
                interaction.ask_human(
                    "Provide guidance",
                    "The automated agent is blocked.",
                )
            )

        input_mock.assert_not_called()
        self.assertEqual(response, "continue autonomously")
        self.assertFalse(is_stop_response(response))

    def test_missing_artifact_output_is_detected(self):
        self.assertTrue(
            looks_like_missing_artifact(
                "cat /tmp/expected.txt",
                "cat: /tmp/expected.txt: No such file or directory",
            )
        )
        self.assertFalse(looks_like_missing_artifact("nmap 127.0.0.1", "host is up"))


if __name__ == "__main__":
    unittest.main()
