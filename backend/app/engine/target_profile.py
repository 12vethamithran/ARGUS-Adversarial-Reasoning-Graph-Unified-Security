"""Deterministic per-target profiling.

The simulated layers (network, supply-chain, multi-agent, identity) cannot truly
inspect a target's infrastructure from a URL alone. Instead of emitting identical
hardcoded findings for every target — which made every scan score the same — they
derive their findings and confidences from a stable hash of the target.

Same target in  ->  same profile out (reproducible).
Different target ->  genuinely different finding mix + confidences -> different score.

Everything here is pure and deterministic: no global `random` state, no wall clock.
"""
from __future__ import annotations

import hashlib
import random
from typing import Any


def canonical_target(target: dict[str, Any] | None) -> str:
    """Stable string key for a target across url / endpoint / description."""
    if not target:
        return "argus:empty"
    return "|".join([
        (target.get("url") or "").strip().lower().rstrip("/"),
        (target.get("llm_endpoint") or "").strip().lower().rstrip("/"),
        (target.get("description") or "").strip().lower(),
    ])


def target_seed(target: dict[str, Any] | None) -> int:
    """32-bit deterministic seed derived from the canonical target."""
    digest = hashlib.sha256(canonical_target(target).encode()).hexdigest()
    return int(digest, 16) % (2**32)


def target_rng(target: dict[str, Any] | None, salt: str = "") -> random.Random:
    """A private, seeded Random — never touches the global RNG state."""
    h = hashlib.sha256(f"{canonical_target(target)}::{salt}".encode()).hexdigest()
    return random.Random(int(h[:16], 16))


def jitter(target: dict[str, Any] | None, salt: str, base: float,
           spread: float = 0.12) -> float:
    """Deterministically nudge a base confidence by ±spread for this target.

    Keeps results inside [0.05, 0.99] so a finding never reads as certain or absent.
    """
    rng = target_rng(target, salt)
    val = base + rng.uniform(-spread, spread)
    return round(max(0.05, min(0.99, val)), 3)


def gate(target: dict[str, Any] | None, salt: str, prob: float) -> bool:
    """Deterministic coin-flip for this target — used to decide whether a
    heuristic finding is present, so different targets surface different mixes."""
    return target_rng(target, salt).random() < prob
