"""Exercise real local HTTP keep-alives and startup errors, without API calls."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from authorization_experiment.provider import Provider, bounded_http
from test_provider import CONFIG, Response


@contextmanager
def server_with(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/request"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class DeadlineTests(unittest.TestCase):
    def test_keepalive_bytes_cannot_extend_deadline_and_worker_is_reaped(self):
        writes = []
        class Drip(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                self.send_response(200)
                self.end_headers()
                try:
                    for _ in range(200):
                        self.wfile.write(b"\n")
                        self.wfile.flush()
                        writes.append(1)
                        time.sleep(.03)
                except OSError:
                    pass
        children = []
        real_popen = subprocess.Popen
        def spawn(args, **kwargs):
            self.assertNotIn("PRIVATE_TEST_SECRET", " ".join(args))
            child = real_popen(args, **kwargs)
            children.append(child)
            return child
        with server_with(Drip) as url, patch("authorization_experiment.provider.subprocess.Popen", side_effect=spawn):
            start = time.monotonic()
            code, raw, reason = bounded_http(url, b"{}", "PRIVATE_TEST_SECRET", .3, 1.0, 4096)
            elapsed = time.monotonic() - start
        self.assertEqual(reason, "request_deadline_exceeded_no_redraw")
        self.assertLess(elapsed, 2.5)
        self.assertGreater(len(writes), 3)
        self.assertTrue(all(child.poll() is not None for child in children))

    def test_deadline_includes_wait_for_headers(self):
        class Stall(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                time.sleep(3)
        with server_with(Stall) as url:
            start = time.monotonic()
            result = bounded_http(url, b"{}", "test-key", 10, .6, 4096)
            elapsed = time.monotonic() - start
        self.assertEqual(result[2], "request_deadline_exceeded_no_redraw")
        self.assertLess(elapsed, 2)

    def test_real_http200_error_is_read_and_classified(self):
        class Error(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                body = b'\n\n{"error":{"message":"Invalid request"}}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        with server_with(Error) as url, tempfile.TemporaryDirectory() as temp:
            config = {**CONFIG, "endpoint": url, "request_deadline_seconds": 3}
            result = Provider(temp, config, "test-key").invoke("error", {})
        self.assertEqual(result["status"], "provider_error")
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(result["attempts"][0]["http_status"], 200)

    def test_explicit_not_started_timeout_retries_then_preserves_first_output(self):
        calls = []
        def opener(*args, **kwargs):
            calls.append(1)
            if len(calls) < 3:
                return Response(b'\n{"error":{"message":"We were unable to start processing your request within the 900-second timeout limit. Please try again later."}}')
            return Response(b'{"model":"deepseek-v4-flash","choices":[{"message":{"content":"{\\"mu\\":0.5}"}}]}')
        with tempfile.TemporaryDirectory() as temp:
            provider = Provider(temp, CONFIG, "test-key", opener=opener)
            result = provider.invoke("retry", {})
            again = provider.invoke("retry", {})
        self.assertEqual(result, again)
        self.assertEqual(result["status"], "provider_terminal")
        self.assertEqual(len(calls), 3)
        self.assertEqual(result["attempts"][0]["provider_error_kind"], "provider_start_timeout")

    def test_exhausted_provider_timeout_is_not_model_output(self):
        def opener(*args, **kwargs):
            return Response(b'{"error":{"message":"unable to start processing within timeout"}}')
        with tempfile.TemporaryDirectory() as temp:
            provider = Provider(temp, CONFIG, "test-key", opener=opener)
            result = provider.invoke("exhausted", {})
            next_result = provider.invoke("next", {})
        self.assertEqual(result["status"], "provider_error_exhausted")
        self.assertEqual(len(result["attempts"]), 3)
        self.assertEqual(next_result["attempts"], [])

    def test_deadline_unknown_is_never_retried_or_redrawn(self):
        with tempfile.TemporaryDirectory() as temp, patch("authorization_experiment.provider.bounded_http", return_value=(None, b"", "request_deadline_exceeded_no_redraw")) as transport:
            provider = Provider(temp, CONFIG, "test-key")
            result = provider.invoke("unknown", {})
            self.assertEqual(provider.invoke("unknown", {}), result)
            self.assertEqual(provider.invoke("next", {})["attempts"], [])
            self.assertEqual(len(result["attempts"]), 1)
            self.assertEqual(transport.call_count, 1)
            restarted = Provider(temp, CONFIG, "test-key")
            self.assertEqual(restarted.invoke("after-restart", {})["attempts"], [])

    def test_response_size_limit_is_terminal(self):
        class Large(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                self.send_response(200)
                self.send_header("Content-Length", "2000")
                self.end_headers()
                self.wfile.write(b"x" * 2000)
        with server_with(Large) as url:
            code, raw, reason = bounded_http(url, b"{}", "test-key", 3, 3, 100)
        self.assertEqual(code, 200)
        self.assertEqual(len(raw), 100)
        self.assertEqual(reason, "response_size_exceeded_no_redraw")
