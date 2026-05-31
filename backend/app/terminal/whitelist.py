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
                   "iptables", "kill", "pkill", "systemctl"]


class CommandVerdict:
    def __init__(self, allowed: bool, reason: str, sanitized: list[str] | None = None):
        self.allowed = allowed
        self.reason = reason
        self.sanitized = sanitized or []


def _is_flag(tok: str) -> bool:
    return tok.startswith("-") and tok != "-"


def _flag_allowed(tok: str, allowed: list[str]) -> bool:
    """A flag token is allowed if it matches an allowed flag exactly, as the
    `--flag` part of `--flag=value`, or as a short flag with an attached numeric
    value (e.g. `-p80`, `-p1-1000`)."""
    base = tok.split("=", 1)[0]
    for af in allowed:
        if tok == af or base == af:
            return True
        if len(af) == 2 and tok.startswith(af) and not tok[2:3].isalpha():
            return True
    return False


def check_command(raw: str) -> CommandVerdict:
    raw = raw.strip()
    if not raw:
        return CommandVerdict(False, "Empty command")

    try:
        parts = shlex.split(raw)
    except ValueError as e:
        return CommandVerdict(False, f"Parse error: {e}")

    if not parts:
        return CommandVerdict(False, "Empty command")

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

    # Explicit denylist. Multi-word entries (e.g. "-X DELETE") are matched against
    # the raw string since shlex splits them into separate tokens; single flags are
    # matched token-wise to avoid substring false-positives (e.g. "-O" inside a URL).
    for blocked in policy["blocked_flags"]:
        if (blocked in raw) if " " in blocked else (blocked in args):
            return CommandVerdict(False, f"Flag '{blocked}' is blocked for {binary}")

    # Allowlist enforcement: when a binary declares allowed_flags, every flag token
    # must be on the list. Positional arguments (targets, URLs, ports) are allowed.
    # This is what turns the policy from a denylist into a real allowlist, and it
    # also rejects argument-injection like `curl http://x; rm -rf /` (the `-rf`).
    allowed = policy["allowed_flags"]
    if allowed:
        for tok in args:
            if _is_flag(tok) and not _flag_allowed(tok, allowed):
                return CommandVerdict(False,
                    f"Flag '{tok}' is not in the allowlist for {binary}")

    return CommandVerdict(True, "OK", parts)
