"""Command whitelist — per-binary argument policy enforcement."""
from __future__ import annotations
import shlex

WHITELIST: dict[str, dict] = {
    "nmap": {
        "allowed_flags": ["-sV", "-sC", "-p", "--script", "safe", "-Pn", "-n", "--open", "-oN", "-oX"],
        "blocked_flags": ["-O", "-A", "-sS", "-sU", "--script=exploit", "--script=vuln", "-sP"],
        "max_args": 12,
    },
    "curl": {
        "allowed_flags": ["-s", "-I", "-L", "-v", "-o", "-H", "--max-time", "--connect-timeout", "-k", "--resolve"],
        "blocked_flags": ["--upload-file", "-T", "-X DELETE", "--data-binary", "-F"],
        "max_args": 16,
    },
    "dig":       {"allowed_flags": [], "blocked_flags": [], "max_args": 8},
    "whois":     {"allowed_flags": [], "blocked_flags": [], "max_args": 4},
    "traceroute":{"allowed_flags": ["-m", "-w", "-q"], "blocked_flags": [], "max_args": 8},
    "host":      {"allowed_flags": ["-t", "-v"], "blocked_flags": [], "max_args": 6},
    # -c/-W/-i are Unix; -n/-w are the Windows equivalents (count/timeout).
    "ping":      {"allowed_flags": ["-c", "-W", "-i", "-n", "-w"], "blocked_flags": ["-t"], "max_args": 8},
    "netstat":   {"allowed_flags": ["-tlnp", "-an", "-tuln"], "blocked_flags": [], "max_args": 4},
    "openssl":   {
        "allowed_flags": ["s_client", "-connect", "-showcerts", "-servername"],
        "blocked_flags": ["genrsa", "rsa", "enc", "dgst"],
        "max_args": 10,
    },
    "nikto":     {"allowed_flags": ["-h", "-p", "-C", "all"], "blocked_flags": [], "max_args": 8},
    "whatweb":   {"allowed_flags": ["-a", "--color=never", "-q"], "blocked_flags": [], "max_args": 6},
}

ALWAYS_BLOCKED = ["rm", "sudo", "su", "chmod", "chown", "dd", "mkfs", "wget", "python",
                   "python3", "bash", "sh", "zsh", "nc", "netcat", "socat", "ssh", "scp",
                   "curl --upload-file", "iptables", "kill", "pkill", "systemctl"]


class CommandVerdict:
    def __init__(self, allowed: bool, reason: str, sanitized: list[str] | None = None):
        self.allowed = allowed
        self.reason = reason
        self.sanitized = sanitized or []


def check_command(raw: str) -> CommandVerdict:
    raw = raw.strip()
    if not raw:
        return CommandVerdict(False, "Empty command")

    try:
        parts = shlex.split(raw)
    except ValueError as e:
        return CommandVerdict(False, f"Parse error: {e}")

    binary = parts[0].lstrip("./").split("/")[-1]

    if binary in ALWAYS_BLOCKED:
        return CommandVerdict(False, f"'{binary}' is not permitted in ARGUS terminal")

    if binary not in WHITELIST:
        return CommandVerdict(False,
            f"'{binary}' is not whitelisted. Allowed: {', '.join(sorted(WHITELIST.keys()))}")

    policy = WHITELIST[binary]
    args = parts[1:]

    if len(args) > policy["max_args"]:
        return CommandVerdict(False, f"Too many arguments (max {policy['max_args']})")

    for blocked in policy["blocked_flags"]:
        if blocked in args or blocked in raw:
            return CommandVerdict(False, f"Flag '{blocked}' is blocked for {binary}")

    return CommandVerdict(True, "OK", parts)
