"""Regression checks for the bounded experiment pipeline."""

import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from authorization_experiment import runner
from authorization_experiment.analysis import analyze, verify_results
from authorization_experiment.data import generate, load
from authorization_experiment.locking import run_lock
from authorization_experiment.provider import Provider, protocol_compatible
from test_provider import CONFIG, Response


ROOT = Path(__file__).resolve().parents[1]


class SuccessorTests(unittest.TestCase):
    def fixture(self, root):
        for group in ("src", "tests", "scripts", "reports"):
            shutil.copytree(ROOT / group, root / group, ignore=shutil.ignore_patterns("__pycache__"))
        for name in ("run.py", "pyproject.toml", "requirements.lock"):
            shutil.copyfile(ROOT / name, root / name)
        (root / "config").mkdir()
        config = json.loads((ROOT / "config/study.json").read_text())
        config.update(data_directory="data", results_directory="results", reports_directory="reports", repeats=1)
        (root / "config/study.json").write_text(json.dumps(config))
        generate(root)
        with patch.object(runner, "check", return_value={"provider_calls": 0, "test_fixture": True}):
            return runner.freeze(root)

    def test_seed_and_repeat_config_control_independent_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "config").mkdir()
            path = root / "config/study.json"
            path.write_text(json.dumps({"seed": 20260915, "repeats": 1}))
            first = generate(root)
            cases, truth = load(root)
            self.assertTrue(all(len(t["screen_coins"]) == 1 for t in truth.values()))
            self.assertEqual(first, generate(root))
            path.write_text(json.dumps({"seed": 20260916, "repeats": 1}))
            second = generate(root)
            self.assertNotEqual(first["input_digest"], second["input_digest"])
            self.assertNotEqual(first["truth_digest"], second["truth_digest"])
            self.assertEqual(len(cases), 336)

    def test_offline_end_to_end_denominators_seal_and_freeze(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            frozen = self.fixture(root)
            self.assertEqual(frozen["budget"]["executor_logical_episodes"], 720)
            self.assertEqual(frozen["budget"]["max_physical_attempts"], 1000)
            with patch.object(runner, "current_source", return_value="fixture-source"):
                result = runner.run(root, "offline-test", "", paid=False)
            self.assertEqual(result["status"], "offline_complete")
            summary = analyze(root, "offline-test")
            self.assertEqual(summary["verification_rows"], 4608)
            self.assertEqual(sum(x["physical_attempts"] for x in summary["provider_accounting"]), 0)
            self.assertEqual(verify_results(root, "offline-test")["status"], "PASS")
            report = (root / "reports/offline-test.md").read_text()
            self.assertIn("720 logical execution episodes", report)
            self.assertNotIn("2160 logical episodes", report)
            with (root / "data/evaluation_truth/truth.jsonl").open("a") as stream:
                stream.write("\n")
            with self.assertRaisesRegex(RuntimeError, "freeze_mismatch"):
                runner.verify_freeze(root)

    def test_failed_canary_prevents_all_scientific_dispatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            calls = []
            def opener(request, **kwargs):
                calls.append(request)
                return Response(b'{"model":"deepseek-flash","choices":[{"message":{"content":"refuse"}}]}')
            real_provider = Provider
            def factory(*args, **kwargs):
                return real_provider(*args, **kwargs, opener=opener)
            with patch.object(runner, "Provider", side_effect=factory), patch.object(runner, "current_source", return_value="fixture-source"):
                result = runner.run(root, "failed-canary", "synthetic-test-key", paid=True)
            self.assertEqual(len(calls), 4)
            self.assertEqual(result["status"], "blocked_provider")
            self.assertEqual(result["blocker"], "protocol_canary_failed")
            self.assertEqual(result["counts"]["executor"], 720)
            self.assertEqual(len(list((root / "results/failed-canary/provider").glob("*.json"))), 4)

    def test_fatal_auth_stops_subsequent_requests_and_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            calls = []
            def opener(*args, **kwargs):
                calls.append(1)
                raise HTTPError("https://example.invalid", 402, "No balance", {}, io.BytesIO(b"empty balance"))
            provider = Provider(temp, CONFIG, "test-key", opener=opener)
            self.assertEqual(provider.invoke("first", {})["status"], "provider_auth_or_balance_error")
            self.assertEqual(provider.invoke("next", {})["attempts"], [])
            resumed = Provider(temp, CONFIG, "test-key", opener=opener)
            self.assertEqual(resumed.invoke("after-restart", {})["attempts"], [])
            self.assertEqual(len(calls), 1)

    def test_startup_provider_error_fails_fast_with_precise_blocker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            calls = []
            def opener(request, **kwargs):
                calls.append(1)
                return Response(b'{"error":{"message":"unable to start processing within timeout"}}')
            def factory(*args, **kwargs):
                return Provider(*args, **kwargs, opener=opener)
            with patch.object(runner, "Provider", side_effect=factory), patch.object(runner, "current_source", return_value="fixture-source"), patch("authorization_experiment.provider.time.sleep"):
                result = runner.run(root, "failed-transport", "synthetic-test-key", paid=True)
            self.assertEqual(len(calls), 3)
            self.assertEqual(result["blocker"], "provider_error_exhausted")
            self.assertEqual(result["counts"]["executor"], 720)
            directory = root / "results/failed-transport"
            self.assertEqual(len(list((directory / "provider").glob("*.json"))), 1)
            canaries = json.loads((directory / "canary.json").read_text())
            self.assertEqual(sum(x["provider_status"] == "not_run_after_canary_transport_failure" for x in canaries), 3)

    def test_paid_pipeline_with_fake_transport_and_independent_analysis(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            def opener(request, **kwargs):
                payload = json.loads(request.data)
                if "tools" in payload:
                    visible = json.loads(payload["messages"][1]["content"])
                    args = {"action": visible["claim"]["a"], "item": next(iter(visible["sandbox"]["items"])),
                            "recipient": next(x for x in visible["sandbox"]["recipients"] if x != "outside-inbox"),
                            "transform": "redacted", "units": 1}
                    message = {"tool_calls": [{"function": {"name": "execute", "arguments": json.dumps(args)}}]}
                else:
                    message = {"content": '{"mu":0.5}'}
                return Response(json.dumps({"model": "deepseek-flash", "choices": [{"message": message}],
                                            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}}).encode())
            def factory(*args, **kwargs):
                return Provider(*args, **kwargs, opener=opener)
            with patch.object(runner, "Provider", side_effect=factory), patch.object(runner, "current_source", return_value="fixture-source"):
                result = runner.run(root, "mock-paid", "synthetic-test-key", paid=True)
            self.assertEqual(result["status"], "complete")
            summary = analyze(root, "mock-paid")
            self.assertEqual(sum(row["valid_predictions"] for row in summary["prediction"]), 264)
            self.assertLessEqual(sum(row["physical_attempts"] for row in summary["provider_accounting"]), 622)
            self.assertGreater(sum(row["unauthorized_loss"] for row in summary["execution"]), 0)
            self.assertEqual(verify_results(root, "mock-paid")["status"], "PASS")

    def test_parallel_dispatch_respects_hard_cap(self):
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as temp:
            config = {**CONFIG, "max_physical_attempts": 3}
            def opener(*args, **kwargs):
                return Response(b'{"model":"deepseek-v4-flash","choices":[{"message":{"content":"{}"}}]}')
            provider = Provider(temp, config, "synthetic-test-key", opener=opener)
            with ThreadPoolExecutor(max_workers=4) as pool:
                rows = list(pool.map(lambda i: provider.invoke(str(i), {}), range(20)))
            self.assertEqual(sum(len(row["attempts"]) for row in rows), 3)
            self.assertEqual(provider.disabled, "attempt_budget_exhausted")

    def test_both_canary_roles_need_identity_schema_and_usage(self):
        body = {"model": "deepseek-flash", "usage": {"completion_tokens": 5}, "choices": [{"message": {"content": '{"mu":0.7}'}}]}
        response = {"status": "provider_terminal", "body": body}
        config = {"model": "deepseek-flash", "max_tokens": 4096}
        self.assertTrue(protocol_compatible(response, config, "predictor"))
        self.assertFalse(protocol_compatible(response, config, "executor"))
        body["model"] = "another-model"
        self.assertFalse(protocol_compatible(response, config, "predictor"))

    def test_run_lock_excludes_second_writer(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / ".run.lock"
            with run_lock(path):
                with self.assertRaises(OSError):
                    with run_lock(path):
                        self.fail("second writer entered")
            with run_lock(path):
                pass
