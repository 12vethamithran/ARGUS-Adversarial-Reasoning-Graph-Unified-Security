"""POST /api/analyze — SSE stream, real layers + mock fallback."""
from __future__ import annotations
import asyncio
from typing import AsyncGenerator

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from ulid import ULID

from app.models import StreamEvent, Finding, Chain
from app.models.session import AnalysisTarget, AnalysisMode
from app.engine.state import ArgusState

router = APIRouter()

class StartAnalysisBody(BaseModel):
    mode: AnalysisMode = "basic"
    target: AnalysisTarget
    layers: list[int] | None = None

def sse(event: StreamEvent) -> str:
    return f"data: {event.model_dump_json()}\n\n"

def finding_event(f: Finding, state: str = "discovered") -> StreamEvent:
    return StreamEvent(
        type="node_state",
        payload={"finding_id": f.id, "state": state, "finding": f.model_dump()},
    )

async def _run_analysis(session_id: str, body: StartAnalysisBody) -> AsyncGenerator[str, None]:
    layers_to_run = body.layers or ([1, 2, 3] if body.mode == "basic" else list(range(1, 9)))
    target_dict = body.target.model_dump(exclude_none=True)

    # ── Yield immediately before any imports or network calls ──────────
    yield sse(StreamEvent.reasoning_token("ARGUS initialized — starting analysis...\n"))
    await asyncio.sleep(0.05)

    # ── Delegate to the orchestrator — the single source of truth for
    #    the analysis stream (layer execution, conditional deps, reasoning).
    try:
        from app.engine.orchestrator import run_orchestrator

        state = ArgusState(
            session_id=session_id, mode=body.mode,
            target=target_dict, active_layers=layers_to_run,
        )

        # The orchestrator yields its own terminal `complete` event.
        async for event in run_orchestrator(state):
            yield sse(event)

        # Persist so the /api/reports/* endpoints can render this analysis.
        await _persist(session_id, body, state)
    except Exception as outer_exc:
        yield sse(StreamEvent.reasoning_token(f"Analysis error: {outer_exc}\n"))
        yield sse(StreamEvent.complete(session_id))


async def _persist(session_id: str, body: StartAnalysisBody, state) -> None:
    """Best-effort persistence of findings + chains for later reporting."""
    try:
        from app.storage import session_store
        target = body.target.model_dump(exclude_none=True)
        target.pop("manifest", None)  # don't persist the raw manifest blob
        await session_store.save_session(session_id, {
            "id": session_id,
            "mode": body.mode,
            "status": "complete",
            "target": target,
            "findings": {fid: f.model_dump() for fid, f in state.findings.items()},
            "chain_ids": [c.id for c in state.chains],
        })
        await session_store.save_chains(session_id, [c.model_dump() for c in state.chains])
    except Exception:
        pass  # reporting persistence is non-critical to the live stream


async def _mock_stream(session_id: str, layers: list[int]) -> AsyncGenerator[str, None]:
    MOCK = [
        {"layer":1,"title":"Missing Content-Security-Policy","severity":"medium","owasp_ref":"A05:2021","exploitable":False,"confidence":0.95},
        {"layer":1,"title":"CORS wildcard (*) allows any origin","severity":"high","owasp_ref":"A05:2021","exploitable":True,"confidence":0.88},
        {"layer":2,"title":"Indirect prompt injection via search field","severity":"critical","owasp_ref":"LLM01:2025","mitre_ref":"AML.T0051","exploitable":True,"confidence":0.91},
        {"layer":2,"title":"System-prompt leakage via role confusion","severity":"high","owasp_ref":"LLM07:2025","exploitable":True,"confidence":0.79},
        {"layer":3,"title":"RAG corpus vulnerable — adversarial docs displace benign results","severity":"critical","owasp_ref":"LLM08:2025","mitre_ref":"AML.T0020","exploitable":True,"confidence":0.86},
        {"layer":4,"title":"Tool-call hijack via prompt injection","severity":"critical","owasp_ref":"OWASP-AGT-01","exploitable":True,"confidence":0.88},
        {"layer":5,"title":"Lateral movement: web-frontend -> internal-db","severity":"critical","mitre_ref":"T1021","exploitable":True,"confidence":0.72},
        {"layer":6,"title":"Vulnerable dep: langchain==0.0.267 (CVE-2023-46229)","severity":"high","owasp_ref":"A06:2021","exploitable":True,"confidence":0.91},
        {"layer":7,"title":"Prompt infection: 4/6 agents compromised (67%)","severity":"critical","owasp_ref":"OWASP-AGT-09","exploitable":True,"confidence":0.83},
        {"layer":8,"title":"MCP session token in plaintext URL parameter","severity":"critical","owasp_ref":"A02:2021","mitre_ref":"AML.T0012","exploitable":True,"confidence":0.94},
    ]
    REASONING = [
        "[ARGUS] Reasoning engine online — correlating findings across layers.\n",
        "\n── Surface analysis ──\n",
        "L1 Web: CORS responds with Access-Control-Allow-Origin: * — any origin can read authenticated responses.\n",
        "L1 Web: missing CSP means injected markup/script in responses is not constrained.\n",
        "L2 LLM: search field reflects unsanitized input into the model context → indirect prompt-injection vector confirmed.\n",
        "L3 RAG: corpus accepts unsigned documents; adversarial docs out-rank benign results on target queries.\n",
        "L4 MCP: agent exposes write-capable tools with no per-call authorization (confused-deputy precondition).\n",
        "L7 Mesh: inter-agent messages are unsigned — a single infected agent can forge instructions to peers.\n",
        "L8 Identity: MCP session token observed in a plaintext URL parameter (capturable from logs/referrer).\n",
        "\n── Cross-layer correlation ──\n",
        "Hypothesis: the L1 web injection is the entry point, not an isolated bug.\n",
        "→ L1 reflected input (web) carries a payload that reaches the L2 model context.\n",
        "→ L2 injection writes attacker content into the L3 retrieval corpus (persistence across sessions).\n",
        "→ Poisoned L3 context steers the L4 agent into invoking an internal tool with attacker arguments.\n",
        "→ L4 tool-call pivots to the network; L7 mesh propagation widens blast radius to 4/6 agents.\n",
        "→ L8 plaintext token grants durable re-entry — the chain survives a single-session cleanup.\n",
        "\n── Scoring ──\n",
        "Exploitability 0.89: every hop is reachable with no privileged access required.\n",
        "Impact 0.94: terminates in internal data access + persistent foothold.\n",
        "Novelty 0.81: this web→LLM→RAG→agent→network path is absent from public KBs — no single tool models it.\n",
        "Priority 0.91: critical — remediate the L1/L2 entry and L4 tool authorization first to break the chain.\n",
        "[ARGUS] Chain finalized.\n",
    ]

    yield sse(StreamEvent.reasoning_token("ARGUS initialized — running demo analysis...\n"))
    await asyncio.sleep(0.1)

    finding_ids = []
    for fd in MOCK:
        if fd["layer"] not in layers:
            continue
        f = Finding(evidence={"mock": True}, **{k: v for k, v in fd.items()})
        finding_ids.append(f.id)
        yield sse(finding_event(f, "discovered"))
        await asyncio.sleep(0.2)
        if f.exploitable:
            yield sse(StreamEvent(type="node_state", payload={"finding_id": f.id, "state": "exploitable"}))
            await asyncio.sleep(0.1)

    for l in layers:
        count = sum(1 for fd in MOCK if fd["layer"] == l and l in layers)
        yield sse(StreamEvent.layer_done(l, count))
        await asyncio.sleep(0.05)

    for t in REASONING:
        yield sse(StreamEvent.reasoning_token(t))
        await asyncio.sleep(0.15)

    if finding_ids:
        chain = Chain(
            steps=finding_ids[:5],
            narrative="CORS (L1) -> prompt injection (L2) -> RAG poisoning (L3) -> tool hijack (L4) -> mesh propagation (L7)",
            exploitability=0.89, impact=0.94, novelty=0.81, priority=0.91,
            remediations=[
                {"layer":1,"action":"Restrict CORS to known origins","ref":"A05:2021"},
                {"layer":2,"action":"Implement output filtering + structured schemas","ref":"LLM01:2025"},
                {"layer":3,"action":"Sign RAG docs; detect outlier embeddings","ref":"LLM08:2025"},
                {"layer":4,"action":"Enforce tool permission sandboxing","ref":"OWASP-AGT-01"},
                {"layer":7,"action":"Add inter-agent message signing","ref":"OWASP-AGT-03"},
            ],
        )
        for fid in chain.steps:
            yield sse(StreamEvent(type="node_state", payload={"finding_id": fid, "state": "chained"}))
            await asyncio.sleep(0.07)
        yield sse(StreamEvent.chain_found(chain.model_dump()))

    await asyncio.sleep(0.1)
    yield sse(StreamEvent.complete(session_id))


@router.post("/analyze")
async def start_analysis(body: StartAnalysisBody):
    session_id = str(ULID())
    layers = body.layers or ([1, 2, 3] if body.mode == "basic" else list(range(1, 9)))
    target = body.target.model_dump(exclude_none=True)
    use_real = bool(target.get("url") or target.get("llm_endpoint"))

    async def stream():
        if use_real:
            async for chunk in _run_analysis(session_id, body):
                yield chunk
        else:
            async for chunk in _mock_stream(session_id, layers):
                yield chunk

    return StreamingResponse(stream(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "X-Session-Id": session_id,
        "Access-Control-Expose-Headers": "X-Session-Id",
    })
