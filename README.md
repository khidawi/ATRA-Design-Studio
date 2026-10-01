# ST-AI Design Studio

A canvas tool for visually constructing ST-AI deployment registries: actors,
departments, AI models, and security/compliance constraints, wired together
and scored against the ST-AI PCS (Pre-deployment Compliance Score) engine.

- **Frontend**: React + TypeScript + Vite + React Flow + Zustand
- **Backend**: FastAPI wrapping the unmodified ST-AI PCS scoring engine (`backend/framework/`)
- **Chatbot**: natural-language → canvas nodes, powered by a locally-run
  [Ollama](https://ollama.com) model — no API key, no per-call cost

## Quickest start: Docker

This is the recommended way to run the whole stack (frontend + backend +
local LLM) with one command — nobody needs Python, Node, or Ollama installed
directly.

**Prerequisite:** [Docker Desktop](https://www.docker.com/products/docker-desktop/)

```bash
docker compose up --build
```

First run will take a few minutes (building images, installing dependencies).
Once it's up:

- Frontend: <http://localhost:5173>
- Backend: <http://localhost:8765> (docs at `/docs`)
- Ollama: <http://localhost:11434>

**One-time step — pull the chatbot's model** (it isn't baked into the image;
the download is ~4.7GB so it's a separate, visible step rather than a silent
part of `docker compose up`):

```bash
docker compose exec ollama ollama pull llama3.1
```

The chatbot (the "Chat" button in the app header) works once that finishes.
Everything else works immediately without it.

**Day-to-day use:**

```bash
docker compose up        # start everything again (model + images already cached)
docker compose down      # stop everything
```

The frontend container mounts your local `frontend/` folder, so editing code
on your machine hot-reloads in the browser exactly like running `npm run dev`
directly — Docker here is just a consistent, zero-setup way to get the same
Node/Python/Ollama versions everyone else has, not a black box.

## Running without Docker

If you'd rather run things directly:

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate # macOS/Linux
pip install -r requirements.txt
uvicorn main:app --port 8765
```

Copy `backend/.env.example` to `backend/.env` if you want to point at a
locally-installed Ollama (defaults already match a default local install —
see that file for the two variables it reads).

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Chatbot (optional)

Install [Ollama](https://ollama.com/download) directly on your machine, then:

```bash
ollama pull llama3.1
```

It runs as a background service after install — nothing else to start.

## Project layout

```
backend/
  framework/        the unmodified ST-AI PCS scoring engine
  main.py            FastAPI app — /health, /score, /chat, /catalogue/constraints
  schema.py          Pydantic schema for the registry/graph/score contract
  chat.py            chatbot: NL description -> canvas nodes, via Ollama
frontend/
  src/nodeSchema.tsx  declarative per-node-type field descriptors
  src/edgeRules.ts    which relation type applies between which node pair
  src/store/          the whole app's state (zustand), persisted to localStorage
  src/components/     Canvas, Sidebar, Inspector, Chat/Validation panels
docker-compose.yml    all three services together
```

## Contributing

Standard flow: branch, commit, open a PR. The `.gitignore` already excludes
`node_modules/`, `.venv/`, and `.env` — never commit real secrets (there
shouldn't be any to commit, since the chatbot runs locally with no API key).
