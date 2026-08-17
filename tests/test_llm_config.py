import asyncio
import os
import unittest
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
