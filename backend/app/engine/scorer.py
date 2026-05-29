"""Composite scoring — deterministic, unit-testable."""
from __future__ import annotations
from app.models.finding import Finding
from app.models.chain import Chain

# Severity weights (CVSS-inspired)
_SEVERITY_SCORE = {"info": 0.1, "low": 0.3, "medium": 0.5, "high": 0.75, "critical": 1.0}

# Layer criticality multipliers (higher = more impactful layer)
_LAYER_WEIGHT = {1: 0.6, 2: 0.8, 3: 0.85, 4: 0.9, 5: 0.7, 6: 0.65, 7: 0.95, 8: 0.9}


def score_finding(f: Finding) -> float:
    """0-1 composite score for a single finding."""
    sev = _SEVERITY_SCORE.get(f.severity, 0.5)
    layer_w = _LAYER_WEIGHT.get(f.layer, 0.7)
    exploitability_bonus = 0.15 if f.exploitable else 0.0
    return min(1.0, sev * layer_w * f.confidence + exploitability_bonus)


def score_chain(chain: Chain) -> float:
    """Recompute priority from exploitability, impact, novelty."""
    return round(
        0.40 * chain.exploitability
        + 0.35 * chain.impact
        + 0.25 * chain.novelty,
        4,
    )


def novelty_score(chain: Chain, kb_embeddings: list | None = None) -> float:
    """
    Embedding-based novelty: compare chain narrative against known-technique KB.
    Falls back to a heuristic when no embeddings are available.
    """
    if kb_embeddings is None or len(kb_embeddings) == 0:
        # Heuristic: longer cross-layer chains are more novel
        n_layers = len(set())  # placeholder
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
