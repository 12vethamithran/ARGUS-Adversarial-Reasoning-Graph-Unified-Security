"""Composite scoring — deterministic, unit-testable, single source of truth.

Every chain score in ARGUS flows through `compute_chain_metrics` so the heuristic
builder, the Gemini path, and the live SSE endpoint all agree. The model is designed
to *discriminate*: two targets with different finding mixes must produce different
scores.

Dimensions (all 0-1):
  exploitability — how reliably an attacker can execute the WHOLE chain. A longer
                   chain is less reliable (every hop can fail), so confidence is
                   penalised geometrically by length.
  impact         — blast radius: peak severity, amplified by how many distinct layers
                   and high-value (infra/identity) layers the chain reaches.
  novelty        — how cross-domain the chain is. A web->AI->infra chain is the kind
                   of emergent path siloed tools miss; single-domain chains are not.
  priority       — remediation urgency = weighted blend, impact & exploitability first.
"""
from __future__ import annotations

from app.models.finding import Finding
from app.models.chain import Chain

# Severity → base score (CVSS-inspired)
_SEVERITY_SCORE = {"info": 0.10, "low": 0.30, "medium": 0.55, "high": 0.78, "critical": 1.0}

# Per-layer criticality (higher = a compromise here matters more)
_LAYER_WEIGHT = {1: 0.60, 2: 0.80, 3: 0.85, 4: 0.90, 5: 0.70, 6: 0.65, 7: 0.95, 8: 0.92}

# Security domains — a chain crossing multiple domains is the novel cross-layer attack.
_WEB_LAYERS = {1}
_AI_LAYERS = {2, 3, 4, 7}
_INFRA_LAYERS = {5, 6, 8}

# Each additional hop in a chain multiplies reliability by this (hops can fail).
_HOP_RELIABILITY = 0.88


def _sev(f: Finding) -> float:
    return _SEVERITY_SCORE.get(f.severity, 0.5)


def score_finding(f: Finding) -> float:
    """0-1 composite score for a single finding."""
    layer_w = _LAYER_WEIGHT.get(f.layer, 0.7)
    exploit_bonus = 0.15 if f.exploitable else 0.0
    return round(min(1.0, _sev(f) * layer_w * f.confidence + exploit_bonus), 4)


def _domains(layers: set[int]) -> int:
    return sum([
        bool(layers & _WEB_LAYERS),
        bool(layers & _AI_LAYERS),
        bool(layers & _INFRA_LAYERS),
    ])


def compute_chain_metrics(findings: list[Finding]) -> dict[str, float]:
    """Return {exploitability, impact, novelty, priority} for an ordered chain.

    This is the ONE place chain scoring is defined. Inputs vary by target (different
    finding mixes / confidences), so outputs vary by target.
    """
    if not findings:
        return {"exploitability": 0.0, "impact": 0.0, "novelty": 0.0, "priority": 0.0}

    layers = {f.layer for f in findings}
    n_distinct = len(layers)
    exploit_steps = [f for f in findings if f.exploitable]

    # ── Exploitability ────────────────────────────────────────────────────────
    # Average confidence of the exploitable steps, penalised by chain length.
    if exploit_steps:
        avg_conf = sum(f.confidence for f in exploit_steps) / len(exploit_steps)
        coverage = len(exploit_steps) / len(findings)        # how much of the chain is live
        length_penalty = _HOP_RELIABILITY ** max(0, len(findings) - 1)
        exploitability = avg_conf * (0.55 + 0.45 * coverage) * length_penalty
    else:
        exploitability = 0.15

    # ── Impact ────────────────────────────────────────────────────────────────
    sevs = [_sev(f) for f in findings]
    peak_sev = max(sevs)
    mean_sev = sum(sevs) / len(sevs)
    # Blend peak with mean so a chain that is critical end-to-end outscores one
    # that is a single critical surrounded by low-severity noise (more accurate),
    # and so the score discriminates between targets with different severity mixes.
    sev_component = 0.6 * peak_sev + 0.4 * mean_sev
    peak_layer_w = max(_LAYER_WEIGHT.get(l, 0.7) for l in layers)
    breadth = 1 + 0.05 * (n_distinct - 1)                    # more layers = wider blast
    impact = min(sev_component * (0.7 + 0.3 * peak_layer_w) * breadth, 1.0)

    # ── Novelty ───────────────────────────────────────────────────────────────
    # Cross-domain spread is the core novelty driver; chain depth adds a little.
    domains = _domains(layers)
    novelty = min(0.26 + 0.17 * (domains - 1) + 0.06 * (n_distinct - 1), 0.97)

    # ── Priority ──────────────────────────────────────────────────────────────
    priority = 0.40 * exploitability + 0.35 * impact + 0.25 * novelty

    return {
        "exploitability": round(exploitability, 4),
        "impact": round(impact, 4),
        "novelty": round(novelty, 4),
        "priority": round(priority, 4),
    }


def score_chain(chain: Chain) -> float:
    """Recompute a chain's priority from its already-set dimensions.

    Used when the chain came from an external source (Gemini) and we want a
    consistent priority. For locally-built chains prefer `compute_chain_metrics`.
    """
    return round(
        0.40 * chain.exploitability
        + 0.35 * chain.impact
        + 0.25 * chain.novelty,
        4,
    )


def novelty_score(chain: Chain, kb_embeddings: list | None = None) -> float:
    """Embedding-based novelty against a known-technique KB; heuristic fallback."""
    if not kb_embeddings:
        return min(1.0, 0.4 + 0.06 * len(chain.steps))
    try:
        from sentence_transformers import SentenceTransformer
        import numpy as np

        model = SentenceTransformer("all-MiniLM-L6-v2")
        chain_emb = model.encode(chain.narrative, normalize_embeddings=True)
        kb_arr = np.array(kb_embeddings)
        sims = kb_arr @ chain_emb
        max_sim = float(sims.max()) if len(sims) else 0.0
        return round(1.0 - max_sim, 4)
    except Exception:
        return chain.novelty
