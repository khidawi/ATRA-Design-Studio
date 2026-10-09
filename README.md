# ST-AI Design Studio

A canvas tool for visually constructing ST-AI deployment registries: actors,
departments, AI models, and security/compliance constraints, wired together
and scored against the ST-AI PCS (Pre-deployment Compliance Score) engine.

- **Frontend**: the ASTRA Model studio (`studio/`) — a single static page served by nginx.
  Every score, risk assessment, import and contract compile is a call to the backend;
  nothing is computed in the browser. In the Agent module, "Draft model with AI" in the Design
  studio also runs through the backend and Ollama; the rest of the Agent module (inventory, drift,
  findings, packs, workspace) is still demo data.
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
- PostgreSQL: runs inside Docker (no host port); inspect with `docker compose exec db psql -U stai -d stai`

**One-time step — pull the chatbot's model** (it isn't baked into the image;
the download is ~4.7GB so it's a separate, visible step rather than a silent
part of `docker compose up`):

```bash
docker compose exec ollama ollama pull llama3.1
```

The chatbot (the "Chat" button in the app header) works once that finishes.
Everything else works immediately without it.

**Your data lives in PostgreSQL** (the `pg_data` volume). `docker compose down` keeps it;
`docker compose down -v` deletes it, along with the downloaded Ollama model.
The backend applies database migrations itself on every start.

**Day-to-day use:**

```bash
docker compose up        # start everything again (model + images already cached)
docker compose down      # stop everything
```

The studio is baked into its image, so after editing `studio/index.html` run
`docker compose up --build -d` and refresh. nginx in that container proxies
`/api`, `/chat`, `/score`, `/health` and `/catalogue` to the backend, which is why
the page needs no CORS setup or hard-coded backend URL.

## How rules are checked

Every rule is a row in PostgreSQL with a `check_type`:

- `CONSTRAINT`: graded from the Security Constraint it names.
- `ATTESTATION`: satisfied by a *Regulatory requirement* node for that regulation and clause, marked
  Satisfied **with evidence**. Satisfied without evidence does not count.
- `GRAPH`: a JSON condition on the design itself (for example "a write-capable tool needs an approval
  step"). The language is in `backend/rule_checks.py`; the OWASP agent rules in `backend/db/seed.py` are examples.

Only `APPROVED` rules are evaluated. See `GET /api/rules`.

## Organisation policies

Open **Policies** in either studio's sidebar to add rules of your own, for example "a write-capable tool needs a
human approval step" or "no third-party hosted models". A policy is a small form (an optional *when*, then a
requirement) that the backend validates against what a design can contain, then stores as a rule. It is checked
in every design it applies to, shows up as `ORG_POLICY: <title>` in the risk panel, and a violated policy stops a
model contract from compiling. **Test on the current design** shows what a policy would do before you save it, and
**Pause** keeps a policy without enforcing it.

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

The Model studio expects `/api`, `/chat` and `/score` on its own origin (nginx
does this in Docker), so Docker is the supported way to run it. The previous
React frontend is still in `frontend/` and can be run against the backend with
`npm install && npm run dev`, but it is no longer part of `docker compose`.

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
  db/                SQLAlchemy engine, models and start-up (PostgreSQL)
  migrations/        Alembic migrations (one per task that adds tables)
  organisation.py    GET/PATCH /api/organisation
  regulations.py     domains, regulations and rules from PostgreSQL (GET /api/domains, /regulations, /rules; PATCH /rules/{key})
  db/seed.py         the reference regulations/rules loaded on first start; edits made later are never overwritten
  rule_checks.py     the safe, data-driven condition language that GRAPH rules are written in (no eval)
  agent_analysis.py  POST /api/agents/analyse: the OWASP Agentic Top 10 checks, read from the database
  policies.py        organisation policies: vocabulary, validation, compiler and API (/api/policies)
  tests/             `docker compose exec backend python -m tests.test_rule_checks` and `... tests.test_policies`
  chat.py            Model studio assistant: NL description -> canvas nodes, via Ollama
  agent_chat.py      Agent design studio: NL description -> agent graph, via Ollama
  ollama_client.py   shared Ollama structured-output client used by both
studio/
  index.html          the ASTRA Model studio (single page, no build step)
  nginx.conf          serves the page and proxies API calls to the backend
frontend/             previous React frontend (not part of docker compose)
docker-compose.yml    ollama + postgres + backend + studio together
```

## Contributing

Standard flow: branch, commit, open a PR. The `.gitignore` already excludes
`node_modules/`, `.venv/`, and `.env` — never commit real secrets (there
shouldn't be any to commit, since the chatbot runs locally with no API key).

## Agent design-time risk score (RCR)

The Agent design studio scores an agent design with the Regulatory Compliance Risk method in
`RCR_Algorithm_Step_by_Step.docx`: `RCR = 100 · max(G, F)`, where G is breadth (worst regulation's uncovered
weight share) and F is depth (worst open critical requirement's floor). It is separate from the PCS score used
for AI models and from any future runtime assessment; the three share no code.

- Engine: `backend/rcr_engine.py` (pure functions); API: `backend/rcr.py` (`GET /api/rcr/profiles`, `POST /api/rcr/score`).
- Requirement registries (weights, floors, design checks) are rows in `rcr_profiles` / `rcr_requirements`.
- A critical requirement counts as Covered only with evidence and a reviewer sign-off (a typed name until sign-in exists);
  evidence alone is Partial; a claim with no evidence is a Gap.
- Weights, floors and partial credit are judgement values, not yet calibrated. Tests: `python -m tests.test_rcr_engine`.

## Regulation ingestion

The **Regulations** screen reads a source page (or pasted text) with the local Ollama model and proposes
candidate rules, each with a quote. The backend checks that every quote appears in the source word for word and
drops any that does not, so a candidate always points at real text. Candidates are stored as pending and are never
evaluated: a person reviews each one, edits its name, clause and strength, chooses where it applies, and approves
it into an attestation rule (the design must hold a Regulatory requirement for that clause with evidence) or rejects it.
The model never writes a check that runs against a design.

- Code: `backend/ingestion.py` (`/api/ingestion/runs`, `/candidates`); tables `ingestion_runs`, `rule_candidates`; approved rules keep `source_url` and `source_quote`.
- A run reads a few passages at a time in the background (CPU-only Ollama needs minutes per passage); `Start at passage` continues a long page.
- Plain requests work for gdpr-info.eu, artificialintelligenceact.eu and OWASP. EUR-Lex answers HTTP 202 and ISO returns 403, so for those paste the text. Addresses on private networks are refused.
- Tests: `python -m tests.test_ingestion`.

## Saved designs and contracts (Model studio)

The Model studio saves the design you are editing to PostgreSQL a moment after each change (`designs` table), so it
survives a browser reset or a different browser. The header has a **Saved design** list, **New** and **Delete design**,
and shows Saved / Saving / Not saved.

- Each save names the version it is based on; a save based on an older version is refused (HTTP 409), so a second
  tab cannot overwrite the first. The page then offers to reload the design.
- **Compile contract** saves the design first, and the backend stores the contract exactly as issued (`contracts` table).
  Contracts are never edited and outlive the design they came from. **Verify hash** on the contracts screen re-hashes
  the stored contract (`GET /api/contracts/{id}/verify`).
- Designs and contracts that earlier versions kept in the browser are moved once on first load. A moved contract is
  marked IMPORTED (the server did not issue it); it is accepted only if its hash matches its content.
- Code: `backend/design_store.py`; tests: `python -m tests.test_design_store`. Agent designs are persisted in Task 7.

## Agent inventory and ratification

The **Agents** screen lists the agents in the database. An agent gets there in three ways: a design ratified in the Agent
design studio (status Designed), a manual registration (**Add agent → Register by hand**; unowned until it has an owner),
or the demo set (**Load demo agents**: sample data from the prototype, marked `demo`, removable).
Discovery from a repository, telemetry or an identity provider needs connectors and is not built yet.

- The design studio saves each agent design to PostgreSQL (`designs`, subject AGENT) and reopens the last one.
- **Ratify** runs on the server against the stored design: it re-runs the OWASP analysis and the design-time RCR score,
  refuses a Blocked design, stores an agent contract (version 1.0.0, 2.0.0, …) whose snapshot holds the design, the score
  and the analysis, and creates or updates the inventory row. The reviewer is a typed name until sign-in exists (Task 8).
- Code: `backend/agent_registry.py`; tests: `python -m tests.test_agent_registry`.
- Not yet database-backed: the drift, contract-review, findings, coverage, packs, workspace and overview screens (Task 7b onward).

## Contract status and the agent contract screen

An issued contract is never edited, so its hash always verifies. What is true of it now (Active, Superseded, Revoked,
who, when, why) is stored beside it in the `contracts` table.

- Compiling or ratifying a new contract for the same model design or agent **supersedes** the earlier active one.
  A person can **revoke** an active contract with a recorded reason (`POST /api/contracts/{id}/revoke`). If an agent's
  last active contract is revoked, the agent goes back to To ratify.
- Each agent contract records what the new version **widens or narrows** compared with the previous active one
  (`backend/agent_contract.py`): a new tool, MCP server, data store, memory, input or delegation, higher autonomy or a
  removed safeguard widens; the reverse narrows. A widening version needs its own review. Scoring still runs on every
  version (it is cheap); the flag says whether the earlier approval can be read as covering the new one.
- `#/contract?agent=<name>` shows the contract: what it allows, change from the previous version, clause mappings, the
  risk score and sign-offs at ratification, the versions with their status, the generated agent.contract.yaml, and
  Verify hash / Download / Open design / Revoke. `#/contract` without a name is still the prototype's demo contract.
- Not built: dual sign-off or accepting contract fields one by one (the prototype's demo flow), and real sign-in (Task 8).

## Findings and drift review

Neither screen invents data, and neither pretends something was observed. Nothing in this repository reads code,
telemetry or an identity provider yet (that needs collectors), so each screen has a clearly labelled simulator.

**Findings** (`backend/findings.py`, `backend/divergence.py`). An observed event is checked against the agent's *active
contract* by deterministic comparisons: a tool, delegation, MCP server, memory write or data store the contract does not
allow becomes a finding with its divergence class, the threat it maps to, the permitted value, and an evidence hash.
A conforming event produces nothing. A real collector sends events to `POST /api/findings/ingest`
(`{"agent": "...", "event": {"type": "tool_call", "name": "..."}}`); the simulator produces events and sends them through the
same check, so what it shows is what a real event would produce. Severities are judgement values. A finding can be
acknowledged, turned into a drafted regression test, or have a halt requested; the halt is only recorded as evidence,
because nothing can stop a running agent yet.

**Drift review** (`backend/drift.py`, `backend/drift_engine.py`). A proposed change to an agent compared with its ratified
contract, item by item (widening, narrowing, needs review), with the threat checks and risk score before and after.
Real source: **Submit change for review** in the design studio, shown instead of Ratify once an agent has an active contract.
Simulated source: the simulator edits a copy of the ratified design. **Approve and ratify** writes the proposed design into
the agent's design and ratifies it, which issues a new contract version and supersedes the old one; it is refused, and the
item stays open, if the proposed design's risk score is Blocked. Declining only records the decision.

Demo agents come with sample findings and drift items, all marked demo and removed with them.
Tests: `python -m tests.test_findings_drift`. Not built: real collectors, enforcement, issue-tracker and pull-request links.

## Coverage scorecard

The **Coverage** screen is computed on request from the agents that have an *active contract* (demo agents are never counted).
Each agent's design held in its contract is re-checked against today's OWASP Agentic rules, so a changed rule or a new
organisation policy shows up. A check's status across agents is the **worst** one (Gap, else Partial, else Covered; No data
if no agent it applies to), so one gap is never averaged away. ASI10 also counts unowned agents in the inventory. Open
findings are counted per check from their threat mapping, and the detail shows each agent's result and reason.

Only the **owner, due date and note** for a check are stored (`coverage_assignments`); status is never stored, so it cannot go
stale. The due label is "Met" once covered, otherwise the date or "Overdue by N days".
Code: `backend/coverage_scorecard.py`; tests: `python -m tests.test_coverage`.
Not built: the prototype's control counts and evidence-item totals (they need collectors), and checks from runtime telemetry.

## Trust reports and Assurance Packs

**Generate** on the Trust and packs screen builds a pack from real data at that moment (`backend/packs.py`): the agents with an
active contract (and each contract's hash), the coverage scorecard, findings and drift decisions in the chosen period,
each agent's design-time risk and regulatory requirements, the claims made and the evidence behind each, and the **gaps**
(checks that fail, partly pass or cannot be assessed, agents with no contract or no owner) with owner and due date.
It is refused if no agent has an active contract.

- A **Trust report** is the short, shareable form: agents are "Agent 1, Agent 2…", with no owners, finding details or per-agent results.
  An **Assurance Pack** is the full form for an auditor. **Open report** shows it readably, and Print or save as PDF prints it.
- Every pack states what it does *not* claim: nothing was observed from a running agent unless a finding's source is COLLECTED, how many
  findings came from the simulator, that sign-off is a typed name, and that risk weights are uncalibrated.
- Packs are stored exactly as hashed and **chained**: each pack's hash covers its content and the previous pack's hash.
  **Verify hash chain** re-hashes the pack, walks the chain back to the first pack, and re-hashes every contract the pack cites
  (and notes any that have since been superseded or revoked). Editing an earlier pack breaks it and every later one.
- Download JSON gives the pack with its hashes. Frameworks offered are the ones with real data (OWASP Agentic, design-time
  regulatory risk); ISO/IEC 42001 stays disabled until rules are loaded for it.
- Not built: the security-questionnaire answering, PDF generation on the server, and publishing to a trust centre.
  Tests: `python -m tests.test_packs`.

## Overview and Compliance workspace

Both screens are computed on request from what the other screens keep; nothing new is stored (`backend/overview.py`).
Demo agents and their sample findings and drift are never counted, and the overview says when they are loaded.

- **Overview:** agents with an active contract, OWASP coverage, open findings and drift waiting, a "Needs your attention" list
  (open drift, high findings, coverage gaps, unowned or unratified agents), and an evidence activity feed (contracts issued or
  revoked, findings, drift proposed and decided, packs generated), newest first.
- **Workspace:** *Compliance* (sign-off queue of open drift, gap owners from the coverage assignments, drift policies in force from
  the contracts, recent packs), *Engineering* (drift, unowned agents and unratified designs waiting, tests drafted from findings)
  and *Auditor* (every pack re-verified on load, contract history, drift decisions and approvers on record).
- The three tabs are views, not permissions: there is no sign-in until Task 8.
- Dropped because nothing backs them: scheduled packs, break-glass uses, kill-switch drills, assessor access dates, CI status.
Tests: `python -m tests.test_overview`.

Note on tests: the suites assume no other agent designs, agents, findings or packs exist in the database; run them on a clean
stack (the regression script also compiles contracts for a design called `x`, which are safe to delete).

## Sign-in, roles and the audit log

Nobody can use the platform without signing in. The first visit shows **Create the first administrator** (possible only while
no account exists); that person adds everyone else on the **Users** screen. Accounts are local: a password is kept only as a
scrypt hash (at least 10 characters), a sign-in creates a server-side session whose token is stored hashed and sent in an
HttpOnly SameSite cookie (12 hours), five failed attempts lock an email out for 15 minutes, and writes must carry a custom
header a page on another site cannot add. CORS only allows the studio's own origins (`ASTRA_ALLOWED_ORIGINS` to change them).

| Role | Can |
|---|---|
| Administrator | everything, including users |
| Compliance | design, and **sign off**: ratify, decide drift, revoke contracts, acknowledge findings, generate packs, approve regulation rules and policies, set coverage owners |
| Engineer | design and propose (including submitting a change for review); cannot sign anything off |
| Auditor | read-only everywhere, plus the audit log |

Every endpoint is protected by default (`required_permission` in `backend/auth.py`): a write needs the write permission unless it
is listed as a sign-off or a pure computation. The names on contracts, drift decisions, findings, packs and revocations are the
signed-in person's, whatever the request says. A sign-off on a design requirement is the signed-in compliance user's own name; an
engineer cannot add, change or drop one by editing the design, and nobody can sign for someone else.

The **Audit log** (`backend/audit.py`) records every state-changing request, sign-in, failed sign-in and refused action (who,
what, when, outcome; never request bodies). Each event's hash covers the previous event's, so an event edited or removed from
the middle is detected by **Verify the chain**; dropping the newest events cannot be seen from inside the log, so keep the head hash elsewhere if that matters.

Not built: single sign-on, a second factor, email-based password recovery (an administrator resets passwords), per-agent
permissions, and API keys for collectors (events sent to `/api/findings/ingest` need a signed-in session for now).
Tests: `python -m tests.test_auth`. The tests sign in with throwaway users and remove them and their audit events afterwards.

## End-to-end test

`python -m tests.e2e` drives the whole platform over HTTP as four people (administrator, compliance, engineer, auditor) with real
sign-ins: users and roles, regulations and an organisation policy, a model deployment, an agent from design to a ratified contract
(including the Blocked refusal and the sign-off rules), findings, drift approval and decline, contract versions and revocation,
coverage, Trust and Assurance packs with hash verification, every PDF/JSON/CSV/YAML download, the overview and workspace, and the
audit log with its chain. It prints one PASS/FAIL line per step and removes everything it created, including its audit events.

```bash
docker compose exec backend python -m tests.e2e                 # about 5 seconds, no language model needed
docker compose exec backend python -m tests.e2e --with-ollama   # also drafts an agent with the local model
```

Run it on a stack that has no agent designs, agents, findings or packs of its own: it asserts exact counts, and its cleanup clears those
tables. The unit and API suites (`python -m tests.<name>`) run the same way.

## Importing an agent from a definition file

On **Add agent → Register an existing agent**, upload or paste a JSON or YAML file and ASTRA generates the agent's Secure Tropos
model from it (`backend/agent_import.py`). Choose **Preview the model** to see the elements, the OWASP checks on them and what the
importer guessed, then **Create the agent design**. The result is a draft design (and an inventory entry) to review, complete and ratify
in the design studio; the studio shows where it came from.

Supported formats (the screen has an example for each, and the format is detected automatically):

| Format | What it provides |
|---|---|
| ASTRA agent manifest (`agent.model.yaml`/`.json`) | everything: owner, autonomy, goal, actors, inputs, tools (read/write), MCP servers, memory, data, delegations, approvals, guardrails, constraints |
| CrewAI `agents.yaml` | the chosen agent's goal and tools; other agents as delegation targets when `allow_delegation` is true |
| MCP client config (`mcpServers`) | the MCP servers (unsigned; commands, arguments, env and headers are never read) |
| A2A agent card | name, description, provider as owner, skills as tools |
| `langgraph.json` | the graph names only (it carries no tools); a warning says so |
| OpenAI Agents SDK agent definition (YAML/JSON) | the SDK itself is configured in Python, so this reads a declarative form of an agent that mirrors its `Agent(...)` fields: function tools, hosted tools (web search becomes an untrusted input; code interpreter, computer and shell are treated as write-capable; file search adds its vector stores as data), MCP tools (`require_approval: always` adds an approval step), handoffs as delegations, input and output guardrails. The instructions are not stored (only a one-sentence goal is taken, and flagged for confirmation); model settings, addresses and credentials are not read. A file may list several agents, and you choose which one to import |

How it behaves: a fixed rulebook converts the file, with no language model and no code execution. Anything the file does not say is
left out rather than assumed (a server is never marked signed, a guardrail is never invented). What it had to guess (whether a tool
writes, whether an input is untrusted, a guardrail's kind) is listed as "Guessed from names: please confirm". Keys it did not use, and
anything that could hold a secret, are listed as ignored and never stored; only the file's SHA-256 is kept as provenance, not its content.
Anchors/aliases, files over 512 KB and models over 60 elements are refused with a reason.

An agent that already has an active contract is **not overwritten**: importing a new file for it creates a proposed change in
Drift review (source "Imported from <file>"), which compliance approves or declines like any other change. That makes the importer usable
from a pipeline once collectors get API keys; today a call needs a signed-in session (`POST /api/agents/import/preview`, `POST /api/agents/import`).
Tests: `python -m tests.test_agent_import`.

## API keys (pipelines and collectors)

An administrator makes keys on the **Users** screen (**API keys**), or with `POST /api/keys`. No key exists until one is made. A key is
shown once, at creation; only its SHA-256 is stored, so a lost key is revoked and replaced, never recovered. A key has a name, an optional
expiry, and a role:

- **Engineer**: design, import agent files, send events to `/api/findings/ingest`; it can never sign anything off.
- **Auditor**: read-only.

A key can never be compliance or administrator (sign-offs belong to people) and cannot make keys or read users. Send it as
`Authorization: Bearer astra_...` (or `X-API-Key`). Calls with a key need no cookie or CSRF header, and everything a key does is in the audit
log under "API key: <name>", never with the key itself. Revoking a key takes effect on the next request.

```bash
# import an agent definition from a pipeline (add /file-preview instead of /file to check it without saving)
curl -X POST "$ASTRA/api/agents/import/file?filename=agent.model.yaml" \
  -H "Authorization: Bearer $ASTRA_KEY" --data-binary @agent.model.yaml
```

For an agent that already has an active contract, the file becomes a proposed change in Drift review for compliance to decide. Tests: `python -m tests.test_api_keys`.

## Running the tests safely

The API and end-to-end suites create data and then clear whole tables (every drift item, finding and pack), because they assert exact counts.
They therefore refuse to start unless the database name ends in `_test`, or you set `ASTRA_TESTS_ON_THIS_DB=1` to accept that data in it may be
deleted. Do not do that against a database with real work in it.

## Organisation (departments, people, AI systems and how they connect)

The **Organisation** screen (in both modules' sidebars) holds one model of the company and draws it as seven views, designed in `mockups/organisation-view.html`:
organisation map, organisational view (goals, operations, policies), agents and tasks, data mapping, privacy by design (threats and protections), breach response plan, and models (ST-AI roles and rules).
Nothing in the other screens changes: the organisation only **reads** the agent inventory, active contracts and runtime reports.

* **Describe the company**: import a JSON or YAML file (`GET /api/company/template`, `/sample` and `/starters` give examples), describe it to the local model (it drafts departments, people, outside parties, AI agents and models with their owners, who they deal with, handoffs between agents with the data passed, and data stores with who reads or writes them; it builds on your earlier messages, returns a proposal only, never invents what you did not say, and nothing is saved until you accept; on a CPU it takes about a minute once the model is loaded; the first draft after a quiet spell also pays a one-off load of a few minutes, which opening the assistant tab starts in the background, and the model then stays loaded for 30 minutes (OLLAMA_KEEP_ALIVE). The draft runs in the background and the page shows its progress. The same description always gives the same draft: generation is fixed (temperature 0, top_k 1, top_p 1.0, repeat penalty 1.1, seed 42, a 4096-token window, set in `DRAFT_OPTIONS` in `backend/company.py`), and because Ollama's prompt cache can still make a first and a later run differ by a word, each draft is also kept against a fingerprint of the description, earlier messages, prompt, schema, settings and model and reused when they match; change any of them and a new draft is made), or build it by hand with **Add Model Component / Add Connection / Delete selected**.
  An import adds and updates by the company's own ids (EMP-1042, D-CX) and never deletes; duplicate ids, unknown references and wrong connection types are refused with reasons, and any item can be left out of an import.
* **Linked to Agent assurance**: an agent in the organisation is matched to the registered agent of the same name. A task link drawn between two agents shows whether the sender's active contract declares the handoff and whether the runtime SDK has seen it; handoffs seen at runtime but not drawn, and registered agents not yet in the organisation, are offered with one click.
* **Checks** (deterministic): role separation (validator is also deployer), missing owners and heads, handoffs across departments with no policy, handoffs not in the contract, threats with no protection, and gaps in the breach plan (no responsible person, no deputy for a decision or a legal deadline).
* **Starting the studios from the organisation**: the Agent studio's start screen lists the organisation's agents ("Design from this"), and the Model studio has a "From the organisation" menu. An agent design starts with its owner, the people it works with, approvals, delegations to other agents (and their owners) and the data it uses; a model design starts with the departments, the people in each lifecycle role (the same person as validator and deployer shows up in the assessment straight away) and where it runs. Neither carries over what the organisation cannot know (tools, MCP servers, memory, guardrails, constraints), and the saved design remembers where it started. Both are also available from an item's panel on the Organisation page (`GET /api/company/systems/{id}/agent-seed` and `/deployment-description`).
* API: `/api/company` (read), `/import/preview` and `/import`, `/nodes` and `/edges` (create, edit, delete), `/export`, `/draft`. Reading needs the read permission, editing the write permission; edits are in the audit log.
* **Menus**: after signing in you land on the main menu (Company: Organisation, Policies, Regulations; Modules: Agent assurance, Model studio). Each module has its own menu with a **← Main menu** button and no Organisation section.
* **One platform**: describing the company (a file, the assistant, or by hand) creates its AI agents in Agent assurance (origin `ORG`, owned by the person named, status To ratify or Unowned) so they can be designed and ratified there, starting from what the organisation knows (**Design it**). Agents come first; Model studio designs are started from a model on request. A **Create N agents in Agent assurance** button covers agents that were in the organisation before.
* **Removing**: an administrator can **Delete** an agent in the Agent inventory (`DELETE /api/agents/{key}`) or delete an agent or model on the Organisation page, and it goes from the whole platform: its inventory entry, designs, every contract, findings, drift items, runtime events and its place in the organisation; for a model, the Model studio designs started from it and their contracts. A confirmation lists what it takes (`GET /api/agents/{key}/removal-impact`). Contracts leave a tombstone (id, hash, who, when) so an evidence pack that cited one stays verifiable and says it was removed; the audit log records `agent.removed` / `model.removed` with the counts.
* **Starting a new company**: an administrator can use the red **Clear organisation** button (`DELETE /api/company`). It shows how much will be deleted, offers a JSON backup, and needs the organisation's name typed to confirm; the new company can be given its own name. By default it also removes the organisation's agents and models from Agent assurance and the Model studio (untick to keep them); agents that are not in the organisation are never touched. The audit log records who cleared it.
* Tests: `docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_company`.

## Runtime SDK: see an agent's drift in real time

`sdk/python` is `astra-runtime`, a dependency-free Python package an agent runs with. It reports what the agent does (tool calls, handoffs, MCP
connections, data access, memory writes: names only, never arguments or results) and ASTRA compares each event with the agent's active contract as
it arrives. See `sdk/python/README.md` for installation, the OpenAI Agents SDK and LangChain/LangGraph adapters, optional enforcement and the wire format.

* **Collector keys:** the API key role for the SDK. It can only send events and read the contract summary of an agent; nothing else.
* **Discovery:** an agent the platform has never seen is registered unowned (origin "discovered") the first time it reports, and counts against ASI10.
* **Findings and runtime drift:** an event outside the contract becomes a finding (de-duplicated for ten minutes), and a new capability also opens a
  *runtime drift* item (the ratified design plus what was observed) for compliance to approve or decline.
* **Live runtime** screen: agents live / silent / never seen, events and divergences, a feed that updates every few seconds, and contract permissions
  that were never used in 30 days. Events are kept 14 days.
* Limits: 200 events per call and 1,200 a minute per key (429 with Retry-After beyond that); the SDK's clock is only believed within a day of the server's.

Tests: `python -m tests.test_runtime` (platform side) and `cd sdk/python && python -m unittest discover -s tests` (the SDK); the end-to-end script runs the
real SDK against the platform when `sdk/python` is on `PYTHONPATH`. Run the platform suites against a scratch database
(`CREATE DATABASE stai_test;` then `docker compose exec -e DATABASE_URL=postgresql+psycopg://stai:stai@db:5432/stai_test backend python -m tests.<name>`).
