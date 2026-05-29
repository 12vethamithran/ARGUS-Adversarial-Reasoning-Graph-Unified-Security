<div align="center">

# ARGUS
### Adversarial Reasoning & Graph-based Unified Security Framework

**The only red-team platform that reasons about attack chains _across_ 8 security layers — modeling how a web injection feeds an LLM that poisons a RAG corpus that hijacks an agent that pivots across the network.**

![License](https://img.shields.io/badge/license-MIT-22c55e)
![Backend](https://img.shields.io/badge/backend-FastAPI%20%7C%20Python%203.12-0ea5e9)
![Frontend](https://img.shields.io/badge/frontend-React%2018%20%7C%20Vite%20%7C%20TS-ff3d57)
![Standards](https://img.shields.io/badge/maps%20to-OWASP%20%2B%20MITRE%20ATLAS-ffb300)

</div>

---

## Why ARGUS

Modern AI systems are attacked **across domains**, but every existing tool looks at one silo:

| Tool | Scope | Blind spot |
|------|-------|-----------|
| Burp / ZAP | Web only | Can't see the LLM or network |
| Garak / PyRIT | LLMs only | Can't see the web entry point or the agent's tools |
| Nessus / Metasploit | Network only | Can't see the AI layer at all |

A real breach chains these together. **ARGUS scans all eight layers and then _reasons_ about how a finding in one enables an attack in the next**, surfacing emergent cross-layer kill-chains that siloed scanners structurally cannot detect — then scores them by exploitability, impact, and novelty.

---

## Features

- **8 cross-domain attack layers** — Web, LLM, RAG, MCP/Agentic, Network, Supply Chain, Multi-Agent, Identity/OAuth.
- **Cross-layer reasoning engine** — Gemini-powered correlation with a deterministic heuristic fallback, so you always get ranked attack chains (even with no API key).
- **Live streaming dashboard** — findings light up across layers in real time over Server-Sent Events.
- **Interactive attack graph** — D3 force graph with drag, hover-highlight, click-to-inspect, and zoom.
- **Reasoning console** — structured, step-by-step attacker reasoning (surface analysis → correlation → scoring).
- **Chain replay** — step through / autoplay a kill-chain hop-by-hop with full per-step detail.
- **Report studio** — executive summary with risk score, severity distribution, expandable findings, and **HTML / PDF / STIX 2.1 exports**.
- **Sandboxed recon terminal** — a Kali-style, whitelisted, read-only command shell (exploit/destructive flags blocked) to validate findings against the live target.
- **Dual-mode theming** — light-blue **Basic** mode and dark-red **Advanced** war-room mode that re-skin the entire app.
- **Built-in knowledge base** — every finding carries a plain-language description, impact, and remediation mapped to its OWASP / MITRE reference.

---

## The 8 Attack Layers

| # | Layer | Focus | Standard |
|---|-------|-------|----------|
| L1 | Web Surface | Headers, CORS, CSP, TLS, exposed methods, leaked secrets | OWASP Web Top 10 |
| L2 | LLM Probe | Prompt injection, system-prompt leakage, jailbreaks | OWASP LLM01/06/07:2025 |
| L3 | RAG Poisoning | Adversarial doc injection, retrieval displacement | OWASP LLM08:2025 |
| L4 | MCP / Agentic | Tool-call hijack, confused deputy, excessive agency | OWASP Agentic Top 10 |
| L5 | Network Recon | Topology, reachable services, lateral movement | MITRE ATT&CK T1046 |
| L6 | Supply Chain | Vulnerable deps, typosquats, unvetted skills | OWASP A06:2021 / SkillJect |
| L7 | Multi-Agent Propagation | Prompt-infection spread across an agent mesh | MASpi |
| L8 | Identity / OAuth | Token interception, session hijack, scope abuse | MITRE ATLAS |

---

## Tech Stack

**Backend** — Python 3.12 · FastAPI · Pydantic · SSE streaming · Google Gemini · WebSocket terminal bridge · zero-database (ULID-keyed JSON files).
**Frontend** — React 18 · Vite · TypeScript · Tailwind (CSS-variable theming) · Framer Motion · D3 · xterm.js · Zustand · lucide-react.

---

## Getting Started

### Option A — Docker Compose (both services)
```bash
cp backend/.env.example backend/.env     # add your GEMINI_API_KEY (optional)
docker-compose up
```

### Option B — Manual

**Backend**
```bash
cd backend
pip install -e ".[dev]"
cp .env.example .env                      # add GEMINI_API_KEY (optional)
python -m uvicorn app.main:app --reload   # http://localhost:8000
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

---

## Usage

1. **Choose a mode** — **Basic** (3 layers, quick assessment, light theme) or **Advanced** (all 8 layers, terminal, dark-red theme).
2. **Define a target** — a URL, an LLM endpoint, or a plain-text description of a hypothetical system. (Description-only runs a fully self-contained demo.)
3. **Watch it stream** — findings populate the graph, sidebar, and reasoning console live; chains are built and ranked.
4. **Investigate** — click graph nodes for detail, replay chains step-by-step, expand findings in the report.
5. **Validate** (Advanced) — open the **Terminal** module and reproduce findings against the live target.
6. **Export** — HTML, PDF, or STIX 2.1 threat intel from the Report Studio.

### Sandboxed terminal
Whitelisted, read-only recon only — exploit and destructive flags are blocked, with rate limiting and idle timeout.

```
curl -I https://target            # security headers / CORS
dig target.com                    # DNS (auto-falls back to nslookup on Windows)
whois target.com                  # registrar / ownership
nmap -sV -Pn --open target        # safe service scan
openssl s_client -connect t:443   # TLS chain
whatweb -a 1 https://target       # tech fingerprint
help · clear                      # built-ins
```
Allowed binaries: `nmap · curl · dig · whois · traceroute · host · openssl · nikto · whatweb · ping · netstat`. On Windows, `dig`/`host`→`nslookup` and `traceroute`→`tracert` automatically; the rest need installation or run natively under WSL/Linux.

---

## API

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
│   │   ├── engine/      orchestrator · reasoner · scorer · state
│   │   ├── layers/      8 attack-layer modules (web, llm_probe, rag_poison, …)
│   │   ├── terminal/    PTY/subprocess bridge · whitelist · audit log
│   │   ├── routers/     analyze · session · report · terminal
│   │   ├── models/      Pydantic models (Finding, Chain, StreamEvent, Session)
│   │   └── main.py      FastAPI app + CORS
│   └── tests/
├── frontend/
│   └── src/
│       ├── pages/       Landing · Onboarding · Dashboard · TerminalView
│       ├── components/  graph · reasoning · heatmap · report · timeline · terminal · shell
│       ├── lib/         api · types · findingKb (knowledge base) · view
│       └── store/       Zustand session store + SSE event stream
└── docker-compose.yml
```

---

## Configuration

`backend/.env` (see `backend/.env.example`):

| Variable | Default | Notes |
|----------|---------|-------|
| `GEMINI_API_KEY` | _(empty)_ | Optional — enables LLM reasoning; heuristic fallback otherwise |
| `GEMINI_MODEL` | `gemini-2.0-flash` | Reasoning model |
| `ALLOWED_ORIGINS` | `localhost:5173,3000` | CORS allow-list (any localhost/127.0.0.1 port also allowed in dev) |
| `DATA_DIR` | `./data` | Session/report/log storage |
| `SESSION_TTL_HOURS` | `24` | Session retention |

`frontend/.env`: `VITE_API_URL`, `VITE_WS_URL` (default to `localhost:8000`).

---

## Security & Ethics

ARGUS is built for **authorized security testing only**. Reason about and test **only systems you own or have explicit written permission to assess**. The terminal is restricted to a non-destructive recon whitelist with exploit flags blocked, rate limiting, and idle timeouts — but **you** are responsible for staying within authorization. Secrets (`.env`) and runtime data (`data/`) are git-ignored and must never be committed.

---

## License

[MIT](./LICENSE) © 2026 Vethamithran
