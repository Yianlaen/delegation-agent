import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError, URLError

from authorization_experiment.provider import Provider, atomic_json, parse_prediction, parse_proposal


CONFIG = {"model": "deepseek-v4-flash", "endpoint": "https://example.invalid/v1/chat/completions",
          "max_tokens": 4096, "max_attempts_per_logical": 3, "wall_seconds": 100,
          "max_physical_attempts": 30, "conservative_token_budget": 1000000,
          "max_request_bytes": 16384, "timeout_seconds": 1, "retry_delay_seconds": 0}


class Response(io.BytesIO):
    status = 200


class TransportTests(unittest.TestCase):
    def run_client(self, opener):
        with tempfile.TemporaryDirectory() as temp:
            provider = Provider(temp, CONFIG, "PRIVATE_TEST_SECRET", opener=opener)
            result = provider.invoke("test", {"model": "deepseek-v4-flash"})
            again = provider.invoke("test", {"model": "deepseek-v4-flash"})
            self.assertEqual(result, again)
            self.assertNotIn("PRIVATE_TEST_SECRET", Path(temp, "test.json").read_text())
            return result

    def test_malformed_terminal_and_refusal_not_retried(self):
        for body in (b"not JSON", b'{"choices":[{"message":{"content":"I refuse"}}],"model":"deepseek-v4-flash"}'):
            calls = []
            def opener(*args, **kwargs):
                calls.append(1)
                return Response(body)
            result = self.run_client(opener)
            self.assertEqual(len(calls), 1)
            self.assertEqual(result["status"], "provider_terminal")

    def test_transport_only_three_attempts(self):
        calls = []
        def opener(*args, **kwargs):
            calls.append(1)
            raise URLError("offline")
        result = self.run_client(opener)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result["status"], "transport_exhausted")

    def test_401_not_retried_and_error_redacted(self):
        def opener(*args, **kwargs):
            raise HTTPError("https://example.invalid", 401, "Unauthorized", {}, io.BytesIO(b"PRIVATE_TEST_SECRET"))
        result = self.run_client(opener)
        self.assertEqual(len(result["attempts"]), 1)
        self.assertTrue(result["attempts"][0]["redacted"])

    def test_transient_503_then_first_output_retained(self):
        calls = []
        def opener(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise HTTPError("https://example.invalid", 503, "unavailable", {}, io.BytesIO(b"busy"))
            return Response(b"{\"model\":\"deepseek-v4-flash\",\"choices\":[{\"message\":{\"content\":\"{}\"}}]}")
        result = self.run_client(opener)
        self.assertEqual(len(result["attempts"]), 2)
        self.assertIsNone(parse_prediction(result))

    def test_inflight_resume_never_redraws(self):
        with tempfile.TemporaryDirectory() as temp:
            def opener(*args, **kwargs):
                self.fail("must not send")
            from authorization_experiment.runtime import digest
            atomic_json(Path(temp) / "lost.json", {"status": "in_flight", "request_hash": digest({}),
                                                    "attempts": [{"reserved_tokens": 1}]})
            result = Provider(temp, CONFIG, "", opener=opener).invoke("lost", {})
            self.assertEqual(result["status"], "outcome_unknown_no_redraw")

    def test_budget_enforced_before_network(self):
        with tempfile.TemporaryDirectory() as temp:
            config = copy.deepcopy(CONFIG)
            config["max_physical_attempts"] = 0
            def opener(*args, **kwargs):
                self.fail("must not send")
            result = Provider(temp, config, "", opener=opener).invoke("limited", {})
            self.assertEqual(result["attempts"], [])
            self.assertEqual(result["status"], "attempt_budget_exhausted")

    def test_parser_invalid_categories_and_nonfinite_predictions(self):
        for content in ('{"mu":true}', '{"mu":NaN}', '{"mu":1.1}', '```json\n{"mu":0.5}\n```'):
            self.assertIsNone(parse_prediction({"body": {"choices": [{"message": {"content": content}}]}}))
        response = {"body": {"choices": [{"message": {"tool_calls": [{"function": {
            "name": "other", "arguments": "{}"}}]}}]}}
        self.assertEqual(parse_proposal(response), ("wrong_action", None))


if __name__ == "__main__":
    unittest.main()
