"""Gemini reasoning engine — generates cross-layer attack chains.

Upgraded for richer reasoning: the LLM is asked to think like an attacker,
produce multiple *ranked* kill-chains across layers, and justify scoring.
The heuristic fallback now also emits multiple chains with attacker-style
narratives so the UI is meaningful even with no API key.
"""
from __future__ import annotations
import json
from app.config import settings
from app.models.chain import Chain, Remediation
from app.models.finding import Finding

SYSTEM_PROMPT = """You are ARGUS, an elite AI red-team reasoning engine. You are given \
security findings spread across up to 8 attack layers (1 Web, 2 LLM, 3 RAG, 4 MCP/Agentic, \
5 Network, 6 Supply Chain, 7 Multi-Agent, 8 Identity/OAuth).

Think like an attacker. Your job is to find *cross-layer* attack chains — sequences where one \
finding enables the next across different domains (e.g. a web injection that poisons a RAG corpus \
that steers an agent into a network action). These emergent chains are what single-purpose tools miss.

Reason carefully, then output 1-3 chains ranked by priority (highest first). For each chain:
- Order steps in realistic kill-chain sequence (initial access -> execution -> impact).
- Prefer chains that cross MULTIPLE layers; a 4-layer chain is far more valuable than a 1-layer one.
- Score each dimension 0.0-1.0:
  * exploitability = how reliably an attacker can pull it off (confidence + access required)
  * impact         = blast radius / business damage
  * novelty        = how unlikely existing siloed tools would catch this exact chain
  * priority       = overall remediation urgency (weigh impact and exploitability most)
- Give a concrete, human-readable narrative naming the attacker's objective.
- Provide one actionable remediation per layer involved, citing the OWASP/MITRE id.

Respond with ONLY valid JSON (no markdown fences), exactly:
{
  "reasoning": "concise step-by-step attacker reasoning",
  "chains": [
    {
      "step_indices": [0, 2, 5],
      "narrative": "Attacker pivots from ... to ... achieving ...",
      "exploitability": 0.85,
      "impact": 0.90,
      "novelty": 0.78,
      "priority": 0.88,
      "remediations": [{"layer": 1, "action": "Fix action", "ref": "OWASP/MITRE id"}]
    }
  ]
}"""


def _target_context(target: dict | None) -> str:
    if not target:
        return ""
    bits = []
    if target.get("url"):
        bits.append(f"url={target['url']}")
    if target.get("llm_endpoint"):
        bits.append(f"llm_endpoint={target['llm_endpoint']}")
    if target.get("description"):
        bits.append(f"description={target['description']}")
    return ("\nTARGET:\n" + " | ".join(bits) + "\n") if bits else ""


async def stream_reasoning(findings: list[Finding], on_token, target: dict | None = None) -> list[Chain]:
    """Stream Gemini reasoning tokens and return validated Chain objects."""
    if not settings.gemini_api_key:
        on_token("[ARGUS] No Gemini API key — using heuristic chain builder\n")
        return _heuristic_chains(findings, on_token)

    try:
        from google import genai

        client = genai.Client(api_key=settings.gemini_api_key)

        findings_text = "\n".join(
            f"[{i}] L{f.layer} | {f.severity.upper()} | {f.title} | "
            f"exploitable={f.exploitable} | conf={f.confidence:.2f} | "
            f"owasp={f.owasp_ref} | mitre={f.mitre_ref}"
            for i, f in enumerate(findings)
        )
        prompt = f"{SYSTEM_PROMPT}\n{_target_context(target)}\nFINDINGS:\n{findings_text}"

        full_response = ""
        response = client.models.generate_content_stream(
            model=settings.gemini_model,
            contents=prompt,
        )
        for chunk in response:
            token = chunk.text or ""
            full_response += token
            on_token(token)

    except Exception as e:
        on_token(f"\n[ARGUS] Gemini error: {e} — falling back to heuristic\n")
        return _heuristic_chains(findings, on_token)

    # Strip markdown fences if present
    json_str = full_response.strip()
    for fence in ("```json", "```"):
        if json_str.startswith(fence):
            json_str = json_str[len(fence):]
    json_str = json_str.rstrip("`").strip()

    try:
        data = json.loads(json_str)
        chains = []
        for c in data.get("chains", []):
            indices = c.get("step_indices", [])
            step_ids = [findings[i].id for i in indices if isinstance(i, int) and i < len(findings)]
            if not step_ids:
                continue
            chains.append(Chain(
                steps=step_ids,
                narrative=c.get("narrative", ""),
                exploitability=float(c.get("exploitability", 0.5)),
                impact=float(c.get("impact", 0.5)),
                novelty=float(c.get("novelty", 0.5)),
                priority=float(c.get("priority", 0.5)),
                remediations=[Remediation(**r) for r in c.get("remediations", []) if isinstance(r, dict)],
            ))
        # Highest-priority first
        chains.sort(key=lambda c: c.priority, reverse=True)
        return chains or _heuristic_chains(findings, on_token)
    except Exception:
        on_token("\n[ARGUS] JSON parse failed — using heuristic\n")
        return _heuristic_chains(findings, on_token)


# ── Heuristic fallback ────────────────────────────────────────────────────────

SEVERITY_WEIGHT = {"info": 0.1, "low": 0.3, "medium": 0.55, "high": 0.78, "critical": 1.0}

# Layers that span different security domains — chains crossing these are the
# "novel" cross-domain attacks ARGUS exists to surface.
WEB_LAYERS = {1}
AI_LAYERS = {2, 3, 4, 7}
INFRA_LAYERS = {5, 6, 8}


def _build_chain(ordered: list[Finding], on_token) -> Chain | None:
    if not ordered:
        return None
    layers_hit = {f.layer for f in ordered}
    narrative = " -> ".join(f"L{f.layer}: {f.title}" for f in ordered)

    avg_conf = sum(f.confidence for f in ordered) / len(ordered)
    max_sev = max(SEVERITY_WEIGHT.get(f.severity, 0.3) for f in ordered)

    # Cross-domain bonus: a chain touching web + AI + infra is genuinely novel.
    domains = sum([
        bool(layers_hit & WEB_LAYERS),
        bool(layers_hit & AI_LAYERS),
        bool(layers_hit & INFRA_LAYERS),
    ])
    novelty = min(0.35 + 0.18 * (len(layers_hit) - 1) + 0.1 * (domains - 1), 0.97)

    exploitability = round(avg_conf, 2)
    impact = round(min(max_sev * (1 + 0.05 * (len(layers_hit) - 1)), 1.0), 2)
    priority = round(min(0.5 * impact + 0.35 * exploitability + 0.15 * novelty, 1.0), 2)

    remediations = [
        Remediation(layer=f.layer, action=f"Mitigate: {f.title}", ref=f.owasp_ref or f.mitre_ref or "N/A")
        for f in ordered if (f.owasp_ref or f.mitre_ref)
    ]

    on_token(f"[ARGUS] Chain ({len(layers_hit)} layers): {narrative}\n")
    on_token(
        f"[ARGUS]   exploit={exploitability:.2f} impact={impact:.2f} "
        f"novelty={novelty:.2f} -> priority={priority:.2f}\n"
    )

    return Chain(
        steps=[f.id for f in ordered],
        narrative=narrative,
        exploitability=exploitability,
        impact=impact,
        novelty=round(novelty, 2),
        priority=priority,
        remediations=remediations,
    )


_LAYER_NAMES = {
    1: "Web", 2: "LLM", 3: "RAG", 4: "MCP/Agentic",
    5: "Network", 6: "Supply Chain", 7: "Multi-Agent", 8: "Identity",
}


def _heuristic_chains(findings: list[Finding], on_token) -> list[Chain]:
    exploitable = [f for f in findings if f.exploitable]
    on_token("[ARGUS] Reasoning engine online — correlating findings across layers.\n")
    if not exploitable:
        on_token("[ARGUS] No exploitable findings — no cross-layer chains could be formed.\n")
        return []

    by_layer: dict[int, list[Finding]] = {}
    for f in exploitable:
        by_layer.setdefault(f.layer, []).append(f)
    # Strongest finding first within each layer.
    for fs in by_layer.values():
        fs.sort(key=lambda f: (SEVERITY_WEIGHT.get(f.severity, 0), f.confidence), reverse=True)

    layers = sorted(by_layer.keys())

    # ── Per-layer surface analysis ──────────────────────────────────────────
    on_token("\n── Surface analysis ──\n")
    on_token(f"Analyzing {len(exploitable)} exploitable findings across {len(layers)} layers.\n")
    for layer in layers:
        fs = by_layer[layer]
        name = _LAYER_NAMES.get(layer, f"L{layer}")
        top = fs[0]
        on_token(f"L{layer} {name}: {len(fs)} exploitable — highest: {top.title} "
                 f"({top.severity}, conf {top.confidence:.2f}).\n")

    # ── Cross-layer correlation ─────────────────────────────────────────────
    on_token("\n── Cross-layer correlation ──\n")
    domains = {
        "web": [l for l in layers if l in WEB_LAYERS],
        "AI": [l for l in layers if l in AI_LAYERS],
        "infra": [l for l in layers if l in INFRA_LAYERS],
    }
    crossed = [d for d, ls in domains.items() if ls]
    if len(crossed) >= 2:
        on_token(f"Findings span {len(crossed)} security domains ({', '.join(crossed)}) — "
                 "evaluating whether one enables the next.\n")
        for a, b in zip(layers, layers[1:]):
            on_token(f"→ L{a} {_LAYER_NAMES.get(a)} can feed L{b} {_LAYER_NAMES.get(b)} "
                     "as the next hop in a kill-chain.\n")
    else:
        on_token("All exploitable findings sit in a single domain — chains will be domain-local.\n")

    on_token("\n── Building chains ──\n")
    chains: list[Chain] = []

    # Primary chain: the full cross-layer kill chain (best finding per layer).
    primary = [by_layer[l][0] for l in layers]
    main = _build_chain(primary, on_token)
    if main:
        chains.append(main)

    # Secondary chain: if a single layer has multiple distinct exploitable
    # findings, surface a deeper single-domain chain there.
    deepest_layer = max(by_layer, key=lambda l: len(by_layer[l]))
    if len(by_layer[deepest_layer]) >= 2:
        deep = _build_chain(by_layer[deepest_layer][:3], on_token)
        if deep:
            chains.append(deep)

    chains.sort(key=lambda c: c.priority, reverse=True)
    on_token(f"[ARGUS] {len(chains)} chain(s) finalized.\n")
    return chains
