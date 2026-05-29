# ARGUS — Adversarial Reasoning & Graph-based Unified Security Framework

> Dual-mode AI-augmented red-team reasoning platform modeling 8 cross-domain attack layers.

## Quick Start

### Option A: Docker Compose (both services)
```bash
cp backend/.env.example backend/.env
# Add your GEMINI_API_KEY to backend/.env
docker-compose up
```
Frontend → http://localhost:5173  
Backend → http://localhost:8000  
API docs → http://localhost:8000/docs

### Option B: Manual

**Backend**
```bash
cd backend
pip install -e ".[dev]"
cp .env.example .env   # add GEMINI_API_KEY
python -m uvicorn app.main:app --reload
```

**Frontend**
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

## Build Status

| Step | Status | Description |
|------|--------|-------------|
| 0 | ✅ | Shared Pydantic models + TypeScript types |
| 1 | ✅ | FastAPI skeleton + mock SSE stream |
| 2 | ✅ | Frontend shell + 6 demo features |
| 3 | 🔜 | Real Layers 1 + 2 + Gemini reasoner |
| 4 | 🔜 | Terminal (ptyprocess + xterm.js) |
| 5 | 🔜 | Layers 3–8 |
| 6 | 🔜 | PDF export + STIX + chain replay |
| 7 | 🔜 | Vercel + Render deploy |

## Architecture

```
frontend/          React 18 + Vite + TS + Tailwind + D3 + xterm.js
backend/           Python 3.12 + FastAPI + LangGraph 2.0 + Gemini
  app/engine/      Orchestrator (StateGraph) + Reasoner + Scorer
  app/layers/      8 attack layer modules (L1–L8)
  app/terminal/    PTY bridge + whitelist + audit log
data/              Zero-database: ULID-keyed JSON/pickle files
```

## The 8 Attack Layers

| # | Layer | Framework |
|---|-------|-----------|
| L1 | Web Surface | OWASP Web Top 10 |
| L2 | LLM Probe | OWASP LLM01/07:2025 |
| L3 | RAG Poisoning | OWASP LLM08:2025 |
| L4 | MCP/Agentic | OWASP Agentic Top 10 |
| L5 | Network Recon | MITRE T1046 |
| L6 | Supply Chain | SkillJect/STAC |
| L7 | Multi-Agent Propagation | MASpi |
| L8 | Identity/OAuth | MITRE ATLAS |

## Ethics

ARGUS reasons about and simulates attacks **only against targets you own or have explicit authorization to test**. The terminal whitelist enforces safe, non-destructive recon only.
