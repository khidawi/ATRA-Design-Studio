"""
Sample findings and drift for the demo agents (from the prototype). Loaded with the demo agents and removed with
them; every row is marked DEMO and is illustrative, not something observed.
"""
from datetime import datetime, timedelta, timezone

_NOW = datetime.now(timezone.utc)


def _f(agent, severity, hours_ago, title, code, observed, permitted, element, threat, evidence, event):
    return dict(agent_key=agent, severity=severity, title=title, class_code=code, observed=observed, permitted=permitted,
                element=element, threat=threat, evidence=evidence, event=event, source="DEMO", contract_version="3.0.0",
                created_at=_NOW - timedelta(hours=hours_ago))


DEMO_FINDINGS = [
    _f("invoice-agent", "High", 3, "Emailed an address outside the permitted domain", "DVG-TOOL", "send_email → billing@vendor-mail.example",
       "email to @acmepayments.example only", "egress.email", "ASI02 Tool misuse and exploitation", "sha256:7c41…a9e0 · span 3f2a91",
       {"type": "tool_call", "name": "send_email", "write": True}),
    _f("support-agent", "Medium", 5, "Delegated to refund-agent without a declared delegation", "DVG-DEL", "handoff support-agent → refund-agent",
       "delegates_to: [notify-agent]", "delegates_to", "ASI07 Insecure inter-agent communication", "sha256:1d09…44bc · span 88e1c0",
       {"type": "delegation", "name": "refund-agent"}),
    _f("research-agent", "Medium", 6, "Connected to an MCP server with no valid signature", "DVG-SUP", "mcp://docs-search v2.4.1 (unsigned)",
       "signed servers from the approved registry", "tools.supply_chain", "ASI04 Agentic supply chain vulnerabilities", "sha256:b812…0f3d · span 41c7aa",
       {"type": "mcp_connect", "name": "mcp://docs-search", "signed": False}),
    _f("support-agent", "Low", 170, "Wrote a customer note to long-term memory", "DVG-MEM", "memory.write scope=long_term",
       "memory: session only", "memory.retention", "ASI06 Memory and context poisoning", "sha256:e5a0…9b17 · span 0d93e2",
       {"type": "memory_write", "scope": "long_term"}),
]


def _c(op, text, note, cls):
    return {"op": op, "text": text, "note": note, "class": cls, "pill": {"Widening": "bad", "Narrowing": "ok", "Review": "warn", "Safeguard": "ok"}[cls]}


DEMO_DRIFT = [
    dict(agent_key="refund-assist-agent", source="DEMO", source_label="Sample data · PR #517 in acme/payments (not a real repository)", from_version="1.0.0",
         title="scope widened", kind="Widening", policy="block", gate_after="BLOCK", rcr_before=42.5, rcr_after=68.0,
         changes=[_c("add", "tool: stripe.payouts.create (write)", "write-capable, moves money", "Widening"),
                  _c("add", "mcp_server: mcp://web-search (unsigned)", "unsigned, not in approved registry", "Widening"),
                  _c("del", "tool: crm.orders.read (read)", "no longer called", "Narrowing"),
                  _c("mod", "system prompt changed", "may shift the goal; needs human review", "Review")],
         impact=["ASI02 Tool misuse: Covered → Partial (new write tool has no approval step)", "ASI04 Agentic supply chain: Covered → Gap (unsigned MCP server)"]),
    dict(agent_key="kyc-agent", source="DEMO", source_label="Sample data · PR #491 in acme/risk (not a real repository)", from_version="3.0.0",
         title="data scope widened", kind="Widening", policy="block", gate_after="REVIEW", rcr_before=30.0, rcr_after=40.0,
         changes=[_c("add", "data: customer_documents", "adds identity documents to scope", "Widening"),
                  _c("add", "constraint: documents-redacted-in-logs", "added in the same change", "Safeguard")],
         impact=["ASI03 Identity and privilege abuse: stays Covered (scope declared, redaction constraint added)"]),
    dict(agent_key="research-agent", source="DEMO", source_label="Sample data · runtime telemetry (nothing was observed)", from_version="2.0.0",
         title="runtime drift", kind="Widening", policy="warn", gate_after="REVIEW", rcr_before=20.0, rcr_after=45.0,
         changes=[_c("add", "mcp_server: mcp://docs-search v2.4.1 (unsigned)", "connected through a config change", "Widening")],
         impact=["ASI04 Agentic supply chain: Covered → Gap until the server is signed"]),
]
