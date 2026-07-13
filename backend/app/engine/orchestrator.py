"""LangGraph 2.0 StateGraph orchestrator — supervisor/router pattern."""
from __future__ import annotations

import asyncio
from typing import AsyncGenerator

from app.engine.decision import calibrate_findings
from app.engine.state import ArgusState
from app.engine.scorer import score_chain
from app.models.stream_event import StreamEvent

# Layer → class mapping (lazy import to avoid startup cost)
_LAYER_CLASS = {
    1: ("app.layers.web", "WebLayer"),
    2: ("app.layers.llm_probe", "LLMProbeLayer"),
    3: ("app.layers.rag_poison", "RAGPoisonLayer"),
    4: ("app.layers.mcp_agent", "MCPAgentLayer"),
    5: ("app.layers.network", "NetworkLayer"),
    6: ("app.layers.supply_chain", "SupplyChainLayer"),
    7: ("app.layers.multi_agent", "MultiAgentLayer"),
    8: ("app.layers.identity", "IdentityLayer"),
}

_LAYER_NAMES = {
    1: "Web Surface", 2: "LLM Probe", 3: "RAG Poisoning",
    4: "MCP/Agentic", 5: "Network Recon", 6: "Supply Chain",
    7: "Multi-Agent", 8: "Identity/OAuth",
}

# Conditional dependencies: layer N only runs if these layers found exploitables
_LAYER_DEPS: dict[int, list[int]] = {
    3: [2],   # RAG only if LLM probe found something
    4: [2],   # MCP only if LLM found something
    7: [4],   # Multi-agent only if MCP/Agentic found something
    8: [4],   # Identity only if MCP found something
}

LAYER_TIMEOUT = 45.0  # seconds per layer — L1 runs a real, active web scan
                      # (parallel, bounded probes) and legitimately needs > 12s.

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _import_layer(layer_id: int):
    import importlib
    mod_path, cls_name = _LAYER_CLASS[layer_id]
    mod = importlib.import_module(mod_path)
    return getattr(mod, cls_name)()


def _should_run(layer_id: int, state: ArgusState) -> bool:
    """Check conditional deps — return False if prerequisite layers found nothing."""
    deps = _LAYER_DEPS.get(layer_id, [])
    for dep_id in deps:
        dep_findings = [f for f in state.findings.values() if f.layer == dep_id and f.exploitable]
        if not dep_findings:
            return False
    return True


def _normalized_layers(layers: list[int]) -> list[int]:
    """Keep layer execution deterministic and safe for user-provided layer lists."""
    seen: set[int] = set()
    normalized: list[int] = []
    for layer_id in layers:
        if layer_id in _LAYER_CLASS and layer_id not in seen:
            normalized.append(layer_id)
            seen.add(layer_id)
    return normalized


def _sort_findings(findings):
    return sorted(
        findings,
        key=lambda f: (
            f.exploitable,
            _SEVERITY_RANK.get(f.severity, 0),
            f.confidence,
            -f.layer,
        ),
        reverse=True,
    )


def _risk_summary(state: ArgusState) -> str:
    findings = list(state.findings.values())
    if not findings:
        return "[ARGUS] Summary: no findings were produced by the selected layers.\n"

    exploitable = [f for f in findings if f.exploitable]
    severe = [f for f in findings if f.severity in {"critical", "high"}]
    layers_hit = sorted({f.layer for f in findings})
    chain_count = len(state.chains)
    top_chain = max((c.priority for c in state.chains), default=0.0)
    return (
        f"[ARGUS] Summary: {len(findings)} findings across layers "
        f"{', '.join(f'L{layer}' for layer in layers_hit)}; "
        f"{len(exploitable)} exploitable, {len(severe)} high/critical, "
        f"{chain_count} chain(s), top priority {top_chain:.2f}.\n"
    )


async def run_orchestrator(
    state: ArgusState,
) -> AsyncGenerator[StreamEvent, None]:
    """
    Main orchestration loop and single source of truth for the analysis
    stream. Runs layers sequentially (respecting conditional deps), then
    feeds exploitable findings to the reasoner for chain generation.

    Yields a StreamEvent for each significant state change — the SSE
    endpoint wraps these as `data:` frames. Always yields a terminal
    `complete` event on the normal path.
    """
    from app.engine.reasoner import stream_reasoning, _heuristic_chains

    state.active_layers = _normalized_layers(state.active_layers)
    if not state.active_layers:
        yield StreamEvent.error("No valid layers selected.")
        yield StreamEvent.complete(state.session_id)
        return

    for layer_id in state.active_layers:
        if state.iteration >= state.max_iterations:
            yield StreamEvent.reasoning_token("Max iterations reached — stopping.\n")
            break

        name = _LAYER_NAMES.get(layer_id, f"Layer {layer_id}")

        if not _should_run(layer_id, state):
            deps = ", ".join(f"L{d}" for d in _LAYER_DEPS.get(layer_id, []))
            yield StreamEvent.reasoning_token(
                f"L{layer_id} ({name}) skipped — prerequisite {deps} found nothing exploitable.\n"
            )
            yield StreamEvent.layer_done(layer_id, 0)
            await asyncio.sleep(0.03)
            continue

        yield StreamEvent.reasoning_token(f"Scanning L{layer_id}: {name}...\n")
        await asyncio.sleep(0.03)

        try:
            layer = _import_layer(layer_id)
            findings = await asyncio.wait_for(
                layer.run(state.target, state), timeout=LAYER_TIMEOUT
            )
            findings = _sort_findings(calibrate_findings(findings))
        except asyncio.TimeoutError:
            yield StreamEvent.reasoning_token(f"L{layer_id} timed out after {LAYER_TIMEOUT}s.\n")
            yield StreamEvent.layer_done(layer_id, 0)
            continue
        except Exception as exc:
            yield StreamEvent.reasoning_token(f"L{layer_id} skipped ({type(exc).__name__}: {exc}).\n")
            yield StreamEvent.layer_done(layer_id, 0)
            continue

        for f in findings:
            state.findings[f.id] = f
            yield StreamEvent(
                type="node_state",
                payload={"finding_id": f.id, "state": "discovered", "finding": f.model_dump()},
            )
            await asyncio.sleep(0.08)
            if f.exploitable:
                f.node_state = "exploitable"
                yield StreamEvent(
                    type="node_state",
                    payload={"finding_id": f.id, "state": "exploitable"},
                )
                await asyncio.sleep(0.1)

        state.completed_layers.append(layer_id)
        state.iteration += 1
        yield StreamEvent.layer_done(layer_id, len(findings))
        yield StreamEvent.reasoning_token(
            f"L{layer_id} done: {len(findings)} findings, "
            f"{sum(1 for f in findings if f.exploitable)} exploitable.\n"
        )
        await asyncio.sleep(0.04)

    # ── Reasoning phase ──────────────────────────────────────────────
    exploitable = [f for f in state.findings.values() if f.exploitable]
    yield StreamEvent.reasoning_token(
        f"\nBuilding attack chains from {len(exploitable)} exploitable findings...\n"
    )
    await asyncio.sleep(0.08)

    if exploitable:
        tokens: list[str] = []
        try:
            chains = await asyncio.wait_for(
                stream_reasoning(exploitable, lambda t: tokens.append(t), state.target),
                timeout=30.0,
            )
        except Exception:
            chains = _heuristic_chains(exploitable, lambda t: tokens.append(t))

        for t in tokens:
            yield StreamEvent.reasoning_token(t)
            await asyncio.sleep(0.025)

        for chain in chains:
            chain.priority = score_chain(chain)
            state.chains.append(chain)
            for fid in chain.steps:
                if fid in state.findings:
                    state.findings[fid].node_state = "chained"
                    yield StreamEvent(
                        type="node_state",
                        payload={"finding_id": fid, "state": "chained"},
                    )
                    await asyncio.sleep(0.07)
            yield StreamEvent.chain_found(chain.model_dump())
            await asyncio.sleep(0.1)
    else:
        yield StreamEvent.reasoning_token("No exploitable findings — no chains generated.\n")

    yield StreamEvent.reasoning_token(_risk_summary(state))
    yield StreamEvent.complete(state.session_id)
