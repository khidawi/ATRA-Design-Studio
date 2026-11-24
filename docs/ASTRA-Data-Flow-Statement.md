# ASTRA: what the runtime SDK sends, where it goes, and what is kept

Status: working draft from a review of the code on branch `astra/phase-18-handoff-notices` (19 November 2026). It describes what the code does; it is not a certification. Section 7 lists what the review did not cover.

## 1. In one paragraph (for a customer)

The ASTRA runtime SDK reports what an agent does, not what it handles. Each event is a kind (tool call, handoff, MCP connection, data access, memory write), one name (a tool, server, agent or data store), a timestamp and a few flags. It does not send prompts, replies, tool arguments, tool results or data. The platform runs on infrastructure the customer controls, keeps raw events for 14 days, and lets only signed-in staff with the right role read them. Two things are the customer's to manage: names are metadata about the organisation's systems, and the default package does not set up HTTPS by itself.

## 2. What the agent SDK sends

| Field | Example | Sent |
|---|---|---|
| Event kind | `tool_call`, `delegation`, `mcp_connect`, `data_access`, `memory_write` | Always |
| One name (max 200 characters) | `stripe.refunds.create`, `order-store` | Always |
| Timestamp | ISO 8601 | Always |
| Flags | `write`, `signed`, `scope`, `confirmed`, `validated` | Where the developer sets them |
| Numeric call parameters | `{"amount": 40}` | Only if the developer passes `params`; numbers only, for the contract's bounds |
| Previous tool name | `lookup_order` | Only if the developer passes it |
| Fingerprints | first 32 characters of a SHA-256 of an action | Only if the developer uses `fingerprint()`; the action itself stays in the process |
| Inter-agent message text | up to 4,096 characters | **Only if the developer passes `payload` to `message()`**, so the platform can check the signature (see 4) |

Never sent by the SDK: prompts, model replies, tool arguments, tool results, retrieved documents, database rows. The LangChain adapter reports tool names only. The OpenAI Agents adapter reports tool names, handoff targets and MCP server names. Events wait in an in-memory queue of 5,000 and are never written to disk.

## 3. What other inputs send

- **OpenTelemetry (OTLP) traces.** The endpoint receives whatever the customer's exporter sends. The platform reads only names, kinds, durations, model names and token counts; for a database span it looks at the first word of the query and keeps nothing else. Prompts, completions, tool arguments, results and span events are not read or kept. They can still arrive in the request if the exporter includes them, so filter them out in the OpenTelemetry Collector if the customer does not want them to leave.
- **AI Models monitor.** The serving code sends what the model saw and answered. The platform reads only fields declared in the monitor's schema and keeps statistics: hourly histograms, category counts, text lengths (never text), confidence and latency buckets, group rates. Free identifiers are capped at 50 categories per window. The developer decides what goes into `inputs`, `output` and `segments`, so those fields must not carry personal data the customer has not agreed to monitor.

## 4. What the platform does with it

- **Raw events** are stored in `runtime_events` with agent, time, kind, name, an allow-listed set of attributes, the verdict against the contract and the reporting key's name. Attributes outside the allow-list are dropped. The message `payload` and `signature` are used to verify the message and are **not stored**.
- **Retention.** Runtime events and telemetry: 14 days. Model-monitor statistics: 30 days by default (7 to 90). Findings and drift items created from events are kept as findings; I did not check exactly what text they hold, which will include the name that triggered them.
- **Who can read events.** Signed-in users with the `read` permission: administrator, compliance, engineer, auditor, security. A collector key can only send events and read the contract summary of the agent it reports for; it cannot read stored events.
- **Audit log.** Changes made through the API are recorded in a hash-chained log with the path and status, not the request body.
- **Learned detectors** (optional) read event kinds and names through a collector-role key, inside the same deployment.

## 5. Where it goes

- The SDK sends to the URL it is configured with, using a bearer API key. That key sits in the agent's environment and should be stored like any secret.
- **Encryption in transit depends on the deployment.** The deployment guide states that the Docker package does not set up HTTPS, security headers or single sign-on by itself, and describes adding them with a reverse proxy. Without that, events travel in clear text on whatever network lies between the agent and the platform.
- ASTRA runs on infrastructure the customer controls. It is single-organisation per instance, and nothing is sent to ASTRA's authors.

## 6. Residual risks and who owns them

| Risk | Owner | Mitigation |
|---|---|---|
| Names reveal how systems are built (tool, store and agent names) | Customer | Limit who has a read role; use neutral names |
| A developer passes personal data or text as a name, a `payload`, or a monitor `input` | Customer's developers | Code review; only pass what the contract needs |
| Traffic not encrypted | Customer | Put the platform behind HTTPS before any agent reports to it |
| Stored events readable by every `read` role | Customer | Review who holds roles; consider a narrower role |
| Database not encrypted at rest | Customer | Use an encrypted volume; the guide recommends it, the package does not enforce it |
| A leaked collector key | Customer | The key can only send events; revoke it from the Users screen |

## 7. What this review did not cover

- I did not audit the whole backend for places that log request bodies, or the web server and database logs.
- I did not check what findings and drift items keep beyond the event name.
- I did not test the platform's behaviour under a hostile client, or run any network capture to confirm what leaves the process.
- I did not review the learned service's own storage, or the Docker images for vulnerabilities.
- Any customer claim here should be re-checked against the release the customer actually runs.

## 8. Changes that would make this easier to state

None of these is built yet.

1. An automated test that fails if the SDK ever adds a field outside an allow-list.
2. An SDK setting to refuse `payload` unless explicitly enabled.
3. HTTPS and security headers on by default in the deployment package.
4. An option to hash names before they leave the process.
5. A narrower read role for event data, and configurable retention.
