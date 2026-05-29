"""LangGraph 2.0 StateGraph orchestrator — supervisor/router pattern."""
from __future__ import annotations

import asyncio
from typing import Any, AsyncGenerator

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

LAYER_TIMEOUT = 12.0  # seconds per layer


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


async def run_orchestrator(
    state: ArgusState,
    on_event: Any,  # callable(StreamEvent)
) -> ArgusState:
    """
    Main orchestration loop. Runs layers sequentially (respecting deps),
    then feeds exploitable findings to the reasoner for chain generation.
    Calls on_event(StreamEvent) for each significant state change.
    """
    from app.engine.reasoner import stream_reasoning, _heuristic_chains

    on_event(StreamEvent.reasoning_token("ARGUS orchestrator starting...\n"))

    for layer_id in state.active_layers:
        if state.iteration >= state.max_iterations:
            on_event(StreamEvent.reasoning_token("Max iterations reached — stopping.\n"))
            break

        name = _LAYER_NAMES.get(layer_id, f"Layer {layer_id}")

        if not _should_run(layer_id, state):
            on_event(StreamEvent.reasoning_token(
                f"L{layer_id} ({name}) skipped — prerequisite layers have no exploitable findings.\n"
            ))
            continue

        on_event(StreamEvent.reasoning_token(f"Running L{layer_id}: {name}...\n"))

        try:
            layer = _import_layer(layer_id)
            findings = await asyncio.wait_for(
                layer.run(state.target, state), timeout=LAYER_TIMEOUT
            )
        except asyncio.TimeoutError:
            on_event(StreamEvent.reasoning_token(f"L{layer_id} timed out after {LAYER_TIMEOUT}s.\n"))
            findings = []
        except Exception as exc:
            on_event(StreamEvent.reasoning_token(f"L{layer_id} error: {type(exc).__name__}: {exc}\n"))
            findings = []

        for f in findings:
            state.findings[f.id] = f
            on_event(StreamEvent(
                type="node_state",
                payload={"finding_id": f.id, "state": "discovered", "finding": f.model_dump()},
            ))
            if f.exploitable:
                f.node_state = "exploitable"
                on_event(StreamEvent(
                    type="node_state",
                    payload={"finding_id": f.id, "state": "exploitable"},
                ))

        state.completed_layers.append(layer_id)
        state.iteration += 1
        on_event(StreamEvent.layer_done(layer_id, len(findings)))
        on_event(StreamEvent.reasoning_token(
            f"L{layer_id} complete: {len(findings)} findings "
            f"({sum(1 for f in findings if f.exploitable)} exploitable).\n"
        ))

    # ── Reasoning phase ──────────────────────────────────────────────
    exploitable = [f for f in state.findings.values() if f.exploitable]
    on_event(StreamEvent.reasoning_token(
        f"\nReasoning over {len(exploitable)} exploitable findings...\n"
    ))

    if exploitable:
        tokens: list[str] = []
        try:
            chains = await asyncio.wait_for(
                stream_reasoning(exploitable, lambda t: tokens.append(t)),
                timeout=30.0,
            )
        except Exception:
            chains = _heuristic_chains(exploitable, lambda t: tokens.append(t))

        for t in tokens:
            on_event(StreamEvent.reasoning_token(t))

        for chain in chains:
            chain.priority = score_chain(chain)
            state.chains.append(chain)
            for fid in chain.steps:
                if fid in state.findings:
                    state.findings[fid].node_state = "chained"
                    on_event(StreamEvent(
                        type="node_state",
                        payload={"finding_id": fid, "state": "chained"},
                    ))
            on_event(StreamEvent.chain_found(chain.model_dump()))
    else:
        on_event(StreamEvent.reasoning_token("No exploitable findings — no chains generated.\n"))

    on_event(StreamEvent.complete(state.session_id))
    return state
