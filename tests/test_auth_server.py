"""Unit tests for PSE&G Auth Companion Server."""

import io
import json
import os
import sys
import threading
import unittest
from http.client import HTTPConnection
from http.server import HTTPServer
from unittest.mock import MagicMock, patch

# Stub external dependencies if running in minimal test environment
for mod in [
    "selenium",
    "selenium.webdriver",
    "selenium.webdriver.common",
    "selenium.webdriver.common.by",
    "selenium.webdriver.common.keys",
    "selenium.webdriver.chrome",
    "selenium.webdriver.chrome.options",
    "selenium.webdriver.chrome.service",
    "speech_recognition",
]:
    if mod not in sys.modules:
        m = MagicMock()
        sys.modules[mod] = m

# Add pseg_auth to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "pseg_auth")))

from auth_server import (
    ALLOWED_RECAPTCHA_HOSTS,
    PsegAuthHandler,
    SafeRedirectHandler,
    download_recaptcha_audio,
    is_safe_recaptcha_url,
)


class TestRecaptchaUrlValidation(unittest.TestCase):
    """Test URL safety validation for reCAPTCHA audio challenge downloads."""

    def test_valid_google_urls(self):
        self.assertTrue(is_safe_recaptcha_url("https://www.google.com/recaptcha/api2/payload?k=xyz"))
        self.assertTrue(is_safe_recaptcha_url("https://google.com/recaptcha/api2/payload"))
        self.assertTrue(is_safe_recaptcha_url("https://www.recaptcha.net/recaptcha/api2/payload?k=xyz"))
        self.assertTrue(is_safe_recaptcha_url("https://recaptcha.net/recaptcha/api2/payload"))

    def test_insecure_http_rejected(self):
        self.assertFalse(is_safe_recaptcha_url("http://www.google.com/recaptcha/api2/payload"))
        self.assertFalse(is_safe_recaptcha_url("http://recaptcha.net/payload"))

    def test_local_file_and_ssrf_schemes_rejected(self):
        self.assertFalse(is_safe_recaptcha_url("file:///etc/passwd"))
        self.assertFalse(is_safe_recaptcha_url("file:///data/browser_data/cookie"))
        self.assertFalse(is_safe_recaptcha_url("ftp://www.google.com/audio.mp3"))
        self.assertFalse(is_safe_recaptcha_url("gopher://127.0.0.1:8000"))

    def test_untrusted_domains_and_subdomain_spoofing_rejected(self):
        self.assertFalse(is_safe_recaptcha_url("https://attacker.com/payload"))
        self.assertFalse(is_safe_recaptcha_url("https://google.com.attacker.com/payload"))
        self.assertFalse(is_safe_recaptcha_url("https://127.0.0.1/payload"))
        self.assertFalse(is_safe_recaptcha_url("https://169.254.169.254/latest/meta-data"))

    def test_empty_and_malformed_inputs(self):
        self.assertFalse(is_safe_recaptcha_url(None))
        self.assertFalse(is_safe_recaptcha_url(""))
        self.assertFalse(is_safe_recaptcha_url("   "))
        self.assertFalse(is_safe_recaptcha_url("not-a-url"))
        self.assertFalse(is_safe_recaptcha_url(12345))


class TestSafeRedirectHandler(unittest.TestCase):
    """Test that HTTP redirects to untrusted destinations are rejected."""

    def setUp(self):
        self.handler = SafeRedirectHandler()

    def test_safe_redirect_allowed(self):
        req = MagicMock()
        headers = {}
        safe_url = "https://www.google.com/recaptcha/api2/payload?k=123"
        with patch("urllib.request.HTTPRedirectHandler.redirect_request") as mock_super:
            mock_super.return_value = "safe_req"
            res = self.handler.redirect_request(req, None, 302, "Found", headers, safe_url)
            self.assertEqual(res, "safe_req")

    def test_unsafe_redirect_raises_http_error(self):
        import urllib.error
        req = MagicMock()
        headers = {}
        unsafe_url = "http://169.254.169.254/latest/meta-data"
        with self.assertRaises(urllib.error.HTTPError):
            self.handler.redirect_request(req, None, 302, "Found", headers, unsafe_url)

    def test_redirect_to_different_untrusted_host_rejected(self):
        import urllib.error
        req = MagicMock()
        headers = {}
        unsafe_url = "https://attacker.com/steal"
        with self.assertRaises(urllib.error.HTTPError):
            self.handler.redirect_request(req, None, 302, "Found", headers, unsafe_url)

    def test_download_audio_untrusted_source_rejected(self):
        with self.assertRaises(ValueError):
            download_recaptcha_audio("http://evil.com/audio.mp3", "/tmp/test.mp3")


class TestAuthServerHttpHandlers(unittest.TestCase):
    """Test HTTP server routes and defensive request handling."""

    @classmethod
    def setUpClass(cls):
        # Bind ephemeral port on localhost for test isolation
        cls.server = HTTPServer(("127.0.0.1", 0), PsegAuthHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _request(self, method, path, body=None, headers=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = headers or {}
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        conn.close()
        return resp.status, data

    def test_health_check(self):
        status, body = self._request("GET", "/health")
        self.assertEqual(status, 200)
        parsed = json.loads(body)
        self.assertEqual(parsed.get("status"), "healthy")
        self.assertEqual(parsed.get("service"), "pseg_auth_server")

    def test_not_found(self):
        status, body = self._request("GET", "/nonexistent")
        self.assertEqual(status, 404)
        parsed = json.loads(body)
        self.assertIn("error", parsed)

    def test_post_oversized_payload_rejected(self):
        # Payloads over 64 KB must be rejected with 413
        oversized = "a" * (65536 + 10)
        status, body = self._request("POST", "/login", body=oversized, headers={"Content-Type": "application/json"})
        self.assertEqual(status, 413)
        parsed = json.loads(body)
        self.assertIn("exceeds maximum allowed size", parsed.get("error", ""))

    def test_post_invalid_content_length(self):
        status, body = self._request("POST", "/login", body="{}", headers={"Content-Length": "not-an-int"})
        self.assertEqual(status, 400)
        parsed = json.loads(body)
        self.assertIn("Invalid Content-Length", parsed.get("error", ""))

    def test_login_missing_credentials(self):
        status, body = self._request(
            "POST",
            "/login",
            body=json.dumps({"username": ""}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        parsed = json.loads(body)
        self.assertIn("username and password required", parsed.get("error", ""))

    def test_mfa_without_active_session(self):
        status, body = self._request(
            "POST",
            "/login/mfa",
            body=json.dumps({"code": "123456"}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        parsed = json.loads(body)
        self.assertIn("No active login session", parsed.get("error", ""))


if __name__ == "__main__":
    unittest.main()
