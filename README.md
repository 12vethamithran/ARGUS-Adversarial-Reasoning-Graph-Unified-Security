<div align="center">

# ARGUS
### Adversarial Reasoning & Graph-based Unified Security Framework

**The only red-team platform that _reasons_ about attack chains _across_ 8 security layers — modeling how a web injection feeds an LLM that poisons a RAG corpus that hijacks an agent that pivots across the network and abuses an identity boundary.**

![License](https://img.shields.io/badge/license-MIT-22c55e)
![Backend](https://img.shields.io/badge/backend-FastAPI%20%7C%20Python%203.12-0ea5e9)
![Frontend](https://img.shields.io/badge/frontend-React%2018%20%7C%20Vite%20%7C%20TS-ff3d57)
![Standards](https://img.shields.io/badge/maps%20to-OWASP%20%2B%20MITRE%20ATLAS-ffb300)
[![CI](https://github.com/12vethamithran/ARGUS-Adversarial-Reasoning-Graph-Unified-Security/actions/workflows/ci.yml/badge.svg)](https://github.com/12vethamithran/ARGUS-Adversarial-Reasoning-Graph-Unified-Security/actions/workflows/ci.yml)
[![CD](https://github.com/12vethamithran/ARGUS-Adversarial-Reasoning-Graph-Unified-Security/actions/workflows/cd.yml/badge.svg)](https://github.com/12vethamithran/ARGUS-Adversarial-Reasoning-Graph-Unified-Security/actions/workflows/cd.yml)
[![Security](https://github.com/12vethamithran/ARGUS-Adversarial-Reasoning-Graph-Unified-Security/actions/workflows/security.yml/badge.svg)](https://github.com/12vethamithran/ARGUS-Adversarial-Reasoning-Graph-Unified-Security/actions/workflows/security.yml)

</div>

---

## Table of Contents

- [The Problem ARGUS Solves](#the-problem-argus-solves)
- [Core Idea: Cross-Layer Reasoning](#core-idea-cross-layer-reasoning)
- [System Architecture](#system-architecture)
- [The 8 Attack Layers](#the-8-attack-layers)
- [Layer 1 — Full OWASP Web Top 10 Engine](#layer-1--full-owasp-web-top-10-engine)
- [Analysis Workflow (End-to-End)](#analysis-workflow-end-to-end)
- [Cross-Layer Attack Chains](#cross-layer-attack-chains)
- [Reasoning & Scoring Model](#reasoning--scoring-model)
- [Data Contracts](#data-contracts)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [CI/CD & Operations](#cicd--operations)
- [Security & Ethics](#security--ethics)
- [Deployment](#deployment)

---

## The Problem ARGUS Solves

Modern AI systems are attacked **across domains**, but every existing tool inspects a single silo:

| Tool | Scope | Structural blind spot |
|------|-------|-----------------------|
| Burp / ZAP | Web only | Can't see the LLM, the agent's tools, or the network |
| Garak / PyRIT | LLMs only | Can't see the web entry point or the agent runtime |
| Nessus / Metasploit | Network only | Can't see the AI layer at all |

A real breach **chains these together**. A reflected parameter on the web tier becomes an indirect prompt-injection channel into an LLM; that LLM retrieves a poisoned RAG document; the poisoned context steers an MCP agent into a privileged tool call; the agent reuses an over-broad OAuth token to persist. **No siloed scanner can see that path.**

> ARGUS scans all eight layers and then **reasons** about how a finding in one layer _enables_ an attack in the next — surfacing emergent cross-layer kill-chains, then ranking them by exploitability, impact, and novelty.

---

## Core Idea: Cross-Layer Reasoning

```mermaid
flowchart LR
    subgraph WEB["🌐 Web Domain"]
        L1["L1 · Web Surface<br/>SQLi · XSS · IDOR · SSRF"]
    end
    subgraph AI["🤖 AI Domain"]
        L2["L2 · LLM Probe"]
        L3["L3 · RAG Poisoning"]
        L4["L4 · MCP / Agentic"]
        L7["L7 · Multi-Agent"]
    end
    subgraph INFRA["🔧 Infra Domain"]
        L5["L5 · Network"]
        L6["L6 · Supply Chain"]
        L8["L8 · Identity / OAuth"]
    end

    L1 -->|reflected / injectable param<br/>becomes injection channel| L2
    L2 -->|injection payload written<br/>into corpus| L3
    L3 -->|poisoned context<br/>steers tool call| L4
    L4 -->|compromised agent<br/>seeds the mesh| L7
    L4 -->|hijacked agent reuses<br/>weak token| L8
    L1 -.->|version banner<br/>feeds CVE match| L6
    L1 -.->|SSRF reaches<br/>internal service| L5

    classDef web fill:#0ea5e9,stroke:#fff,color:#fff
    classDef ai fill:#a855f7,stroke:#fff,color:#fff
    classDef infra fill:#f59e0b,stroke:#fff,color:#fff
    class L1 web
    class L2,L3,L4,L7 ai
    class L5,L6,L8 infra
```

The dashed and solid arrows above are **implemented cross-layer predicates** (`backend/app/layers/xlayer.py` + per-layer wiring), not decorative. Each downstream layer queries the shared session state for the upstream finding that enables it, so a chain is **grounded in real evidence** rather than asserted.

---

## System Architecture

```mermaid
flowchart TB
    subgraph FE["Frontend · React 18 + Vite (→ Vercel)"]
        UI["Dashboard<br/>graph · reasoning console · heatmap · report · terminal"]
        STORE["Zustand store<br/>+ SSE event stream"]
    end

    subgraph BE["Backend · FastAPI + Python 3.12 (→ Render)"]
        API["Routers<br/>analyze · session · report · terminal"]
        ORCH["Orchestrator<br/>StateGraph + supervisor + conditional deps"]
        LAYERS["8 Attack Layers<br/>web · llm_probe · rag_poison · mcp_agent<br/>network · supply_chain · multi_agent · identity"]
        REASON["Reasoner<br/>Gemini Flash + heuristic fallback"]
        SCORE["Scorer<br/>deterministic composite metrics"]
        GRAPH["Graph builder<br/>NetworkX → D3 JSON"]
        KB["Knowledge base<br/>OWASP + MITRE YAML / vuln DB"]
        TERM["Sandboxed terminal<br/>whitelist · PTY bridge · audit"]
    end

    subgraph STORAGE["Zero-Database Storage (./data)"]
        FILES["ULID-keyed JSON sessions<br/>.gpickle graphs · JSONL audit · HTML/PDF/STIX reports"]
    end

    EXT["Google Gemini API<br/>(server-side only)"]

    UI <-->|REST + SSE| API
    STORE <-->|/api/analyze stream| API
    UI <-->|WS| TERM
    API --> ORCH
    ORCH --> LAYERS
    LAYERS --> KB
    ORCH --> REASON
    REASON --> SCORE
    REASON -->|optional| EXT
    SCORE --> GRAPH
    ORCH --> STORAGE
    GRAPH --> STORAGE
    TERM --> STORAGE
```

**Design principles**

- **Zero database.** Everything is files: `aiofiles` atomic writes, ULID keys, a TTL janitor. A session folder zips and ships to a colleague. No ORM, no migrations.
- **Gemini optional.** With no API key, the reasoner falls back to a deterministic heuristic that still emits ranked, narrated chains — the demo always works.
- **Deterministic where it must be.** Simulated layers derive findings from a stable hash of the target (`engine/target_profile.py`), so the same target reproduces, but different targets produce genuinely different scores.

---

## The 8 Attack Layers

| # | Layer | Focus | Standard | Mode |
|---|-------|-------|----------|------|
| **L1** | Web Surface | **Full OWASP Web Top 10** — SQLi, XSS, IDOR, broken access control, SSRF, SSTI, command injection, path traversal, misconfig, crypto, integrity, logging | OWASP Web Top 10 (2021) | Basic + Advanced |
| **L2** | LLM Probe | Direct/indirect prompt injection, jailbreaks, obfuscation, system-prompt leakage, insecure output handling, tool-call exfil | OWASP LLM01/02/06/07:2025 | Basic + Advanced |
| **L3** | RAG Poisoning | Adversarial doc injection, retrieval displacement, citation spoofing, instruction embedding | OWASP LLM08:2025 | Basic + Advanced |
| **L4** | MCP / Agentic | Tool-call hijack, confused deputy, rug-pull, tool shadowing, argument injection, excessive agency | OWASP Agentic Top 10 | Advanced |
| **L5** | Network Recon | Topology, reachable services, lateral movement, exposed inference | MITRE ATT&CK T1046 / T1021 | Advanced |
| **L6** | Supply Chain | Vulnerable deps (CVE), typosquats, unvetted skills (SkillJect) | OWASP A06:2021 | Advanced |
| **L7** | Multi-Agent | Prompt-infection diffusion across an agent mesh | MASpi / Prompt Infection | Advanced |
| **L8** | Identity / OAuth | Token interception, scope abuse, missing PKCE, refresh-token replay, session fixation, JWT alg confusion | MITRE ATLAS | Advanced |

> **Basic mode** runs L1–L3 (quick assessment, light theme). **Advanced mode** runs all 8 layers + sandboxed terminal (dark war-room theme).

---

## Layer 1 — Full OWASP Web Top 10 Engine

Layer 1 is the deepest module. It maps to **every** OWASP Web Top 10 (2021) category using a **versioned payload taxonomy** (`backend/app/layers/web_payloads.py`) and active, signature-confirmed probes (`backend/app/layers/web.py`).

```mermaid
flowchart TB
    START["Target URL"] --> BASE["Baseline GET<br/>headers · body · cookies"]
    BASE --> PASSIVE["Passive checks"]
    BASE --> DISCOVER["Param / form discovery<br/>query + &lt;input&gt; names"]
    DISCOVER --> ACTIVE["Active probes<br/>(GET-only · rate-limited · capped)"]

    PASSIVE --> P1["A02 cleartext · secrets entropy"]
    PASSIVE --> P2["A05 headers · CORS · methods · dir listing · sensitive paths"]
    PASSIVE --> P3["A06 version fingerprint → feeds L6"]
    PASSIVE --> P4["A07 session cookie flags"]
    PASSIVE --> P5["A08 missing SRI"]
    PASSIVE --> P6["A04/A09 stack-trace leakage"]

    ACTIVE --> A1["A03 SQLi<br/>error · boolean · time · union"]
    ACTIVE --> A2["A03 XSS · SSTI · cmd injection"]
    ACTIVE --> A3["A01 path traversal · IDOR · force-browse · open redirect"]
    ACTIVE --> A4["A10 SSRF<br/>loopback · metadata · file://"]

    A1 & A2 & A3 & A4 --> CONFIRM["Signature confirmation<br/>SQL-error regex · 49 eval · uid= · root: · latency Δ · reflection"]
    CONFIRM --> FIND["Finding[] (verdict + evidence)"]

    classDef ok fill:#22c55e,stroke:#fff,color:#fff
    class CONFIRM ok
```

### Attack families & techniques (multi-payload)

| Family | OWASP | Techniques (multiple payloads each) | Confirmation signal |
|--------|-------|--------------------------------------|----------------------|
| **SQL Injection** | A03 | error-based · boolean-based · **time-based (≤5 s cap)** · union-based | DB-engine error regexes (MySQL/Postgres/MSSQL/Oracle/SQLite); response-similarity diff; latency delta |
| **XSS** | A03 | HTML-body · attribute-breakout · JS-string context | Unescaped proof-token reflection |
| **SSTI** | A03 | `{{7*7}}` · `${7*7}` · `<%=7*7%>` · `#{7*7}` | Evaluated `49` present, literal absent |
| **Command Injection** | A03 | separator · subshell · time-based | `uid=…(` output or latency delta |
| **Path Traversal / LFI** | A01 | `../` · URL-encoded · nested · Windows | `root:…:0:0:` / ini-section signature |
| **IDOR** | A01 | bounded adjacent-ID probing (±1, +2) | Structurally-similar page, different object |
| **Broken Access Control** | A01 | privileged-path force-browse | Admin/management UI content reachable unauth |
| **Open Redirect** | A01 | protocol-relative · backslash · absolute | `Location` header points to attacker host |
| **SSRF** | A10 | loopback · cloud metadata · `file://` | Internal content / metadata marker reflected |

**Safety guarantees (authorized testing only):** all active probes are **GET-only and non-destructive**, requests are rate-limited (`Semaphore(6)`), the connection pool is capped (`max_connections=8`), at most 6 params are fuzzed, time-based payloads are clamped to `MAX_TIME_BASED_DELAY = 5 s`, and IDOR probing is bounded to a few adjacent IDs and never writes. Every hit is **confirmed by a content/timing signature** so catch-all 200 pages don't cause false positives.

---

## Analysis Workflow (End-to-End)

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Frontend (SSE)
    participant API as /api/analyze
    participant ORCH as Orchestrator
    participant L as Layers 1..8
    participant R as Reasoner
    participant G as Graph + Report

    U->>FE: Choose mode + define target (URL / endpoint / description)
    FE->>API: POST /api/analyze
    API->>ORCH: run_orchestrator(state)
    loop For each active layer (deps permitting)
        ORCH->>L: layer.run(target, shared state)
        L-->>ORCH: Finding[] (reads upstream findings via xlayer)
        ORCH-->>FE: node_state events (discovered → exploitable)
    end
    ORCH->>R: stream_reasoning(exploitable findings)
    R-->>FE: reasoning_token stream (Gemini or heuristic)
    R-->>ORCH: ranked Chain[]
    ORCH->>G: build_graph + score + persist
    ORCH-->>FE: chain_found events (nodes → chained)
    ORCH-->>FE: complete
    U->>G: Export HTML / PDF / STIX 2.1
```

### Conditional layer dependencies

The orchestrator (`backend/app/engine/orchestrator.py`) runs layers in order but **skips a layer when its prerequisites found nothing exploitable** — so the run mirrors a real attacker's decision tree:

```mermaid
flowchart LR
    L1["L1 Web"] --> L2["L2 LLM"]
    L2 -->|L2 exploitable?| L3["L3 RAG"]
    L2 -->|L2 exploitable?| L4["L4 MCP"]
    L4 -->|L4 exploitable?| L7["L7 Multi-Agent"]
    L4 -->|L4 exploitable?| L8["L8 Identity"]
    L1 --> L5["L5 Network"]
    L1 --> L6["L6 Supply Chain"]

    classDef gate fill:#1e293b,stroke:#38bdf8,color:#e2e8f0
    class L1,L2,L3,L4,L5,L6,L7,L8 gate
```

`_LAYER_DEPS = {3:[2], 4:[2], 7:[4], 8:[4]}` — RAG and MCP only run if the LLM probe found a live exploitable surface; multi-agent and identity only run if MCP did.

---

## Cross-Layer Attack Chains

Each downstream layer consumes upstream evidence through shared queries in `backend/app/layers/xlayer.py` and per-layer wiring. A representative full kill-chain:

```mermaid
flowchart LR
    A["L1 · SQLi / reflected param<br/>(A03 · confirmed, carries url+param)"]
    B["L2 · Indirect prompt injection<br/>(LLM01 · channel reaches model context)"]
    C["L3 · Corpus poisoning persists<br/>(LLM08 · payload written to corpus)"]
    D["L4 · Tool-call hijack<br/>(OWASP-AGT-01 · poisoned context → sink tool)"]
    E["L7 · Mesh infection<br/>(OWASP-AGT-09 · compromised agent seeds mesh)"]
    F["L8 · Durable re-entry<br/>(over-broad / leaked token reuse)"]

    A --> B --> C --> D --> E
    D --> F

    classDef crit fill:#ef4444,stroke:#fff,color:#fff
    class A,B,C,D,E,F crit
```

- **L1 → L2** (`web.py` evidence + `llm_probe._l1_channels`): a confirmed injectable/reflected param (now carrying both `param` and `url`) becomes a **high-confidence indirect prompt-injection channel**.
- **L2 → L3** (`rag_poison._l2_injection_vectors`): an exploitable L2 injection can be **written into the corpus**, turning a per-session injection into durable poison.
- **L3 → L4** (`mcp_agent._l3_poison_vectors`): retrieved poisoned context **steers the agent into a write/exec sink tool**.
- **L4 → L7** (`multi_agent` + `_l4_agent_compromise`): a confirmed hijacked agent **seeds prompt-infection** across the mesh.
- **L4 → L8** (`identity` + `_l4_agent_compromise`): the hijacked agent **reuses a weak identity boundary** for persistence.

The reasoner then orders these into a kill-chain (initial access → execution → impact), and the graph builder (`engine/graph_builder.py`) renders nodes + chain edges as D3 force-directed JSON.

---

## Reasoning & Scoring Model

**Reasoner** (`backend/app/engine/reasoner.py`) — asks Gemini Flash to think like an attacker and emit 1–3 ranked cross-layer chains as strict JSON; on no-key/parse-failure it falls back to a **heuristic builder** that constructs a primary cross-layer chain (best exploitable finding per layer) plus a deeper single-domain chain, with attacker-style narratives.

**Scorer** (`backend/app/engine/scorer.py`) — the single source of truth so Gemini and heuristic paths rank on the same scale:

```mermaid
flowchart TB
    subgraph IN["Per-finding inputs"]
        SEV["severity → CVSS-inspired base"]
        CONF["confidence (target-derived)"]
        LW["per-layer weight"]
        EXP["exploitable bonus"]
    end
    IN --> M

    subgraph M["compute_chain_metrics()"]
        E["Exploitability<br/>avg confidence × coverage<br/>× length penalty (0.88^hops)"]
        I["Impact<br/>0.6·peak + 0.4·mean severity<br/>× layer weight × breadth"]
        N["Novelty<br/>0.26 + 0.17·(domains−1)<br/>+ 0.06·(layers−1)"]
    end

    E & I & N --> P["Priority =<br/>0.40·Exploit + 0.35·Impact + 0.25·Novelty"]

    classDef out fill:#a855f7,stroke:#fff,color:#fff
    class P out
```

- **Exploitability** is penalised geometrically by chain length — every hop can fail.
- **Impact** blends peak and mean severity (a chain critical end-to-end beats one critical surrounded by noise).
- **Novelty** rewards crossing security domains (web → AI → infra) — exactly the emergent paths siloed tools miss.

---

## Data Contracts

Three Pydantic models (mirrored as TypeScript types) are the stable contract between layers, reasoner, and frontend.

```mermaid
classDiagram
    class Finding {
        +str id (ULID)
        +int layer (1-8)
        +str title
        +Severity severity
        +str owasp_ref
        +str mitre_ref
        +dict evidence
        +bool exploitable
        +float confidence
        +NodeState node_state
    }
    class Chain {
        +str id (ULID)
        +str[] steps
        +str narrative
        +float exploitability
        +float impact
        +float novelty
        +float priority
        +Remediation[] remediations
    }
    class StreamEvent {
        +EventType type
        +dict payload
        +float ts
    }
    Chain "1" --> "*" Finding : steps reference
    StreamEvent ..> Finding : node_state payload
    StreamEvent ..> Chain : chain_found payload
```

`StreamEvent.type ∈ { node_state, reasoning_token, chain_found, layer_done, error, complete }`.

---

## Tech Stack

**Backend** — Python 3.12 · FastAPI · Pydantic v2 · SSE streaming · Google Gemini (optional) · WebSocket PTY terminal bridge · NetworkX · httpx · zero-database (ULID-keyed JSON files).
**Frontend** — React 18 · Vite · TypeScript · Tailwind (CSS-variable theming) · Framer Motion · D3 · xterm.js · Zustand · lucide-react.

---

## Getting Started

### Option A — Docker Compose (both services)
```bash
cp backend/.env.example backend/.env     # add GEMINI_API_KEY (optional)
docker-compose up
```

### Option B — Manual

**Backend**
```bash
cd backend
pip install -e ".[dev]"
cp .env.example .env                      # add GEMINI_API_KEY (optional)
python -m uvicorn app.main:app --reload   # http://localhost:8000
pytest -q                                 # run the test suite
```

**Frontend**
```bash
cd frontend
npm install
cp .env.example .env
npm run dev                               # http://localhost:5173
```

| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| API docs (Swagger) | http://localhost:8000/docs |

> **No Gemini key?** ARGUS still works — the reasoning engine falls back to a deterministic heuristic and produces ranked chains.

### Sandboxed recon terminal (Advanced mode)
Whitelisted, read-only recon only — exploit/destructive flags blocked, with rate limiting and idle timeout.

```
curl -I https://target            # security headers / CORS
dig target.com                    # DNS (auto nslookup on Windows)
whois target.com                  # registrar / ownership
nmap -sV -Pn --open target        # safe service scan
openssl s_client -connect t:443   # TLS chain
whatweb -a 1 https://target       # tech fingerprint
help · clear                      # built-ins
```
Allowed binaries: `nmap · curl · dig · whois · traceroute · host · openssl · nikto · whatweb · ping · netstat`.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | Start an analysis; streams `StreamEvent`s over SSE |
| `GET` | `/api/sessions` · `/api/sessions/{id}` | List / fetch sessions |
| `POST` | `/api/reports/{id}/generate` | Generate report artifacts |
| `GET` | `/api/reports/{id}/{html\|pdf\|stix}` | Download a report |
| `WS` | `/ws/terminal/{id}` | Sandboxed terminal session |
| `GET` | `/health` | Liveness check |

---

## Project Structure

```
ARGUS/
├── backend/
│   ├── app/
│   │   ├── engine/      orchestrator · reasoner · scorer · graph_builder · state · target_profile
│   │   ├── layers/      base · xlayer (cross-layer queries)
│   │   │                web + web_payloads   (L1 · OWASP Web Top 10 taxonomy)
│   │   │                llm_probe · rag_poison · mcp_agent · network
│   │   │                supply_chain · multi_agent · identity   (L2–L8)
│   │   ├── terminal/    whitelist · PTY/subprocess bridge · audit log
│   │   ├── routers/     analyze · session · report · terminal
│   │   ├── kb/          OWASP + MITRE YAML · vuln_db · manifest parser
│   │   ├── models/      Finding · Chain · StreamEvent · Session
│   │   └── main.py      FastAPI app + CORS + /health
│   └── tests/           per-layer units · web_payloads · taxonomy · chain-matching · integration
├── frontend/
│   └── src/
│       ├── pages/       Landing · Onboarding · Dashboard · TerminalView
│       ├── components/  graph · reasoning · heatmap · report · timeline · terminal · shell
│       ├── lib/         api · types · findingKb (OWASP/MITRE knowledge base) · view
│       └── store/       Zustand session store + SSE event stream
└── docker-compose.yml
```

---

## CI/CD & Operations

```mermaid
flowchart LR
    DEV["Push / PR"] --> CI["CI<br/>backend pytest +<br/>frontend typecheck & build"]
    MAIN["Merge to main"] --> CD["CD<br/>Render deploy hook"]
    CD --> RENDER["Render backend redeploy"]
    MAIN --> VERCEL["Vercel frontend auto-deploy"]
    SCHED1["every 10 min"] --> KEEP["Keep Alive → /health"]
    SCHED2["hourly"] --> MON["Health Monitor"]
    SCHED3["push + weekly"] --> SEC["Security Scan<br/>pip-audit + npm audit"]

    classDef gh fill:#24292e,stroke:#fff,color:#fff
    class CI,CD,KEEP,MON,SEC gh
```

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| **CI** | every push / PR | Backend `pytest` + frontend typecheck & Vite build |
| **CD** | push to `main` | Triggers Render redeploy via deploy hook |
| **Keep Alive** | every 10 min | Pings `/health` to prevent Render cold starts |
| **Health Monitor** | hourly | Checks backend `/health` + frontend URL |
| **Security Scan** | push to `main` + weekly | `pip-audit` (Python) + `npm audit` (Node) |

---

## Security & Ethics

ARGUS is built for **authorized security testing only**. Reason about and test **only systems you own or have explicit written permission to assess**. Layer 1's active probes send real (but non-destructive, GET-only, rate-limited, time-capped) payloads; the terminal is restricted to a non-destructive recon whitelist with exploit flags blocked. **You are responsible for staying within authorization.** Secrets (`.env`) and runtime data (`data/`) are git-ignored and must never be committed.

---

## Deployment

| Service | Platform | Notes |
|---------|----------|-------|
| Backend API | [Render](https://render.com) | Docker, persistent `/data` disk, Starter plan (WebSocket), health check `/health` |
| Frontend | [Vercel](https://vercel.com) | Static SPA, auto-deploys on push to `main` |

**Render env:** `GEMINI_API_KEY`, `ALLOWED_ORIGINS` (Vercel URL), `DATA_DIR=/data`, `SESSION_TTL_HOURS`, `LOG_LEVEL`.
**Vercel env:** `VITE_API_URL` (`https://…onrender.com`), `VITE_WS_URL` (`wss://…onrender.com`).

**Required GitHub secrets:** `RENDER_BACKEND_URL`, `RENDER_DEPLOY_HOOK_URL`, `VERCEL_FRONTEND_URL`, `GEMINI_API_KEY`.

---

## License

[MIT](./LICENSE) © 2026 Vethamithran
