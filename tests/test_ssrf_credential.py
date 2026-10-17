"""Supplementary SSRF (IP-encoding bypass) and credential rules."""

from correctover_guard_ref.rules import inspect_tool_arguments


# ---------------------------------------------------------------------------
# SSRF: encoded loopback / metadata / private endpoints
# ---------------------------------------------------------------------------

SSRF_URLS = [
    "http://127.0.0.1/admin",
    "http://localhost/admin",
    "http://2130706433/admin",
    "http://0x7f000001/admin",
    "http://0177.0.0.1/admin",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/admin",
    "http://10.0.0.5/internal",
    "http://192.168.1.10/admin",
    "http://172.16.4.5/admin",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_x",
    "http://expected@127.0.0.1/",
]


def test_ssrf_urls_denied_as_bare_string():
    for url in SSRF_URLS:
        result = inspect_tool_arguments(url)
        assert result is not None, url


def test_ssrf_urls_denied_in_field():
    for url in SSRF_URLS:
        result = inspect_tool_arguments({"endpoint": url})
        assert result is not None, url


def test_public_url_allowed():
    assert inspect_tool_arguments("https://example.com/path") is None
    assert inspect_tool_arguments({"url": "https://8.8.8.8/resolve"}) is None


# ---------------------------------------------------------------------------
# Credentials: high-confidence secret material
# ---------------------------------------------------------------------------

SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ASIAIOSFODNN7EXAMPLE",
    "ghp_" + "a" * 36,
    "github_pat_" + "a" * 30,
    "sk-" + "a" * 40,
    "-----BEGIN RSA PRIVATE KEY-----\nabcd\n-----END RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----\nabcd\n-----END PRIVATE KEY-----",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "xoxb-1234567890-abcdef",
    "sk_test_" + "a" * 30,
]


def test_credentials_denied():
    for secret in SECRETS:
        assert inspect_tool_arguments(secret) == "credential-secret", secret
        assert inspect_tool_arguments({"note": secret}) == "credential-secret", secret


def test_non_secret_text_allowed():
    assert inspect_tool_arguments("here is my password: hunter2 (not a secret format)") is None
