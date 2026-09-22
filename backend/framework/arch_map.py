"""
ST-AI Framework v3 — Architecture-Aware Risk Map Generator (v2)
Generates SVG from RegistryState + model label + hosting type.
Called from register.py. No numeric inputs. Visual only.
"""
from framework.registry import RegistryState
from framework.rule_engine import derive_terms
from framework.enums import (
    ModelTypeEnum, AISystemTypeEnum, FeedbackLoopEnum,
    VectorTypeEnum, SilentFailureEnum, ConsumptionRoleEnum,
    AuditFrequencyEnum, RollbackModeEnum,
)
from framework.model_taxonomy import get_risk_profile, HOSTING_RISK


C = {
    "bg":           "#0f1117",
    "panel_design": "#0d1e3a",
    "panel_deploy": "#0d2a14",
    "panel_gov":    "#1a0d30",
    "panel_risk":   "#2a0a0a",
    "node":         "#1e2a45",
    "node_hi":      "#3a0a0a",
    "node_med":     "#3a2a00",
    "node_ok":      "#0a2a14",
    "border":       "#3a5088",
    "border_hi":    "#c62828",
    "border_med":   "#e65100",
    "border_ok":    "#2e7d32",
    "edge_norm":    "#3a5088",
    "edge_risk":    "#e65100",
    "edge_block":   "#c62828",
    "edge_feed":    "#2e7d32",
    "edge_drift":   "#6a1b9a",
    "accent":       "#4c8aff",
    "text":         "#e8eaf0",
    "text_sub":     "#8899bb",
    "text_risk":    "#ff8080",
    "text_warn":    "#ffcc60",
    "text_ok":      "#60d080",
    "white":        "#ffffff",
    "red":          "#c62828",
    "orange":       "#e65100",
    "yellow":       "#f9a825",
    "green":        "#2e7d32",
    "blue":         "#1565c0",
    "purple":       "#6a1b9a",
}


def _node(x, y, w, h, title, subtitle, risk="normal", blocked=False):
    fill = {"normal": C["node"], "high": C["node_hi"],
            "med": C["node_med"], "ok": C["node_ok"]}.get(risk, C["node"])
    stroke = C["border_hi"] if blocked else \
             C["border_med"] if risk == "med" else \
             C["border_hi"] if risk == "high" else C["border"]
    sw = 2.5 if blocked else 1.5
    lines = [
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="7" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>',
        f'<text x="{x+w//2}" y="{y+h//2-6}" fill="{C["text"]}" '
        f'font-size="11" font-weight="bold" text-anchor="middle" '
        f'font-family="monospace">{title}</text>',
    ]
    if subtitle:
        lines.append(
            f'<text x="{x+w//2}" y="{y+h//2+10}" fill="{C["text_sub"]}" '
            f'font-size="9" text-anchor="middle" font-family="monospace">'
            f'{subtitle}</text>'
        )
    return "\n".join(lines)


def _arrow(x1, y1, x2, y2, colour, dashed=False, label="", w=1.5):
    dash = 'stroke-dasharray="6 3"' if dashed else ''
    cid = colour.replace("#", "")
    lines = [
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
        f'stroke="{colour}" stroke-width="{w}" {dash} '
        f'marker-end="url(#arr_{cid})"/>'
    ]
    if label:
        mx, my = (x1+x2)//2, (y1+y2)//2-6
        lines.append(
            f'<text x="{mx}" y="{my}" fill="{colour}" font-size="9" '
            f'text-anchor="middle" font-family="monospace">{label}</text>'
        )
    return "\n".join(lines)


def _badge(x, y, txt, col):
    w = len(txt)*7 + 10
    return (
        f'<rect x="{x}" y="{y-12}" width="{w}" height="16" rx="4" '
        f'fill="{col}" opacity="0.9"/>'
        f'<text x="{x+w//2}" y="{y}" fill="white" font-size="9" '
        f'font-weight="bold" text-anchor="middle" '
        f'font-family="monospace">{txt}</text>'
    )


def _marker(colour):
    cid = colour.replace("#", "")
    return (
        f'<marker id="arr_{cid}" viewBox="0 0 10 10" refX="8" refY="5" '
        f'markerWidth="5" markerHeight="5" orient="auto-start-reverse">'
        f'<path d="M2 1L8 5L2 9" fill="none" stroke="{colour}" '
        f'stroke-width="1.5" stroke-linecap="round"/>'
        f'</marker>'
    )


def generate_architecture_map(
    reg: RegistryState,
    model_label: str = "",
    hosting_type: str = "",
    rag_enabled: bool = False,
    chained_ai: bool = False,
) -> str:

    terms = derive_terms(reg)
    profile = get_risk_profile(model_label)
    hosting = HOSTING_RISK.get(hosting_type, {})
    rollback_ok = hosting.get("rollback", True)
    no_rollback = not rollback_ok
    is_type3 = reg.system_type == AISystemTypeEnum.TYPE_3_THIRDPARTY_API
    is_llm  = reg.model_type == ModelTypeEnum.LLM
    is_rl   = reg.model_type == ModelTypeEnum.RL
    is_pinn = reg.model_type == ModelTypeEnum.PINN
    auto_loop = reg.feedback_loop == FeedbackLoopEnum.AUTOMATED
    chained  = chained_ai or (VectorTypeEnum.CHAINED_AI in reg.attack_vectors)
    score_txt = "UNDEFINED" if terms.pcs_score == 999.0 else f"{terms.pcs_score:.1f}/100"
    blocked  = bool(terms.blockers)

    tier_col = {
        "CRITICAL": C["red"],
        "HIGH":     C["yellow"],"MODERATE": C["green"], "LOW": C["blue"],
    }.get(terms.tier.value, C["blue"])

    W, H = 1020, 660
    parts = [
        f'<svg width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
        f'xmlns="http://www.w3.org/2000/svg" '
        f'style="background:{C["bg"]};border-radius:12px;">',
        '<defs>',
    ]
    for col in [C["edge_norm"], C["edge_risk"], C["edge_block"],
                C["edge_feed"], C["edge_drift"], C["accent"],
                C["orange"], C["red"], C["green"]]:
        parts.append(_marker(col))
    parts.append('</defs>')

    # ── Phase backgrounds ────────────────────────────────────────────────
    parts.append(f'<rect x="10" y="10" width="430" height="{H-20}" rx="10" '
                 f'fill="{C["panel_design"]}" stroke="{C["border"]}" '
                 f'stroke-width="1" opacity="0.5"/>')
    parts.append(f'<text x="225" y="32" fill="{C["accent"]}" font-size="11" '
                 f'font-weight="bold" text-anchor="middle" font-family="monospace">'
                 f'DESIGN-TIME  L1–L5</text>')

    parts.append(f'<rect x="450" y="10" width="200" height="{H-20}" rx="10" '
                 f'fill="{C["panel_deploy"]}" stroke="{C["border"]}" '
                 f'stroke-width="1" opacity="0.5"/>')
    parts.append(f'<text x="550" y="32" fill="{C["text_ok"]}" font-size="11" '
                 f'font-weight="bold" text-anchor="middle" font-family="monospace">'
                 f'DEPLOY  L6–L7</text>')

    parts.append(f'<rect x="660" y="10" width="350" height="{H-20}" rx="10" '
                 f'fill="{C["panel_gov"]}" stroke="{C["border"]}" '
                 f'stroke-width="1" opacity="0.5"/>')
    parts.append(f'<text x="835" y="32" fill="#b060ff" font-size="11" '
                 f'font-weight="bold" text-anchor="middle" font-family="monospace">'
                 f'GOVERNANCE  L8–L11</text>')

    # ── Left column nodes ─────────────────────────────────────────────────
    # 1 — Model type
    model_risk = "high" if is_llm or is_rl else "med" if is_pinn else "normal"
    parts.append(_node(20, 50, 180, 55,
        f"Model: {reg.model_type.value}",
        model_label[:28] if model_label else "",
        risk=model_risk))
    parts.append(_badge(28, 60, profile["eps_b_label"], C["red"] if is_llm else C["orange"]))

    # 2 — Organisation / RCF
    rcf = reg.rcf
    rcf_risk = "high" if rcf >= 1.30 else "med" if rcf >= 1.15 else "ok"
    parts.append(_node(20, 125, 180, 50,
        f"Roles: RCF = ×{rcf:.2f}",
        "Full consol." if rcf >= 1.30 else "Partial consol." if rcf >= 1.15 else "Fully separated",
        risk=rcf_risk,
        blocked=(rcf >= 1.30 and reg.compensating_controls == 0)))

    # 3 — Data / Feedback loop
    fb_risk = "high" if auto_loop else "med" if reg.feedback_loop == FeedbackLoopEnum.HUMAN_REVIEWED else "ok"
    parts.append(_node(20, 195, 180, 50,
        "Feedback loop",
        reg.feedback_loop.value,
        risk=fb_risk,
        blocked=(auto_loop and is_rl)))

    # 4 — Hosting / Infrastructure
    infra_risk = "high" if hosting.get("risk") == "HIGH" else "med" if hosting.get("risk") == "MEDIUM" else "ok"
    short_host = hosting_type[:24] if hosting_type else reg.system_type.value
    parts.append(_node(20, 265, 180, 50,
        "Infrastructure",
        short_host,
        risk=infra_risk))

    # 5 — Threats / Attack surface
    n_vec = len(reg.attack_vectors)
    threat_risk = "high" if chained else "med" if n_vec > 0 else "normal"
    parts.append(_node(20, 335, 180, 50,
        "Threat surface",
        f"CHAINED_AI" if chained else f"{n_vec} vectors declared",
        risk=threat_risk))

    # 6 — Silent failures / Audit
    sf_risk = "high" if (reg.silent_failures and reg.audit_frequency == AuditFrequencyEnum.QUARTERLY) else \
              "med" if reg.silent_failures else "ok"
    sf_txt = ", ".join(s.value[:12] for s in reg.silent_failures) if reg.silent_failures else "None declared"
    parts.append(_node(20, 405, 180, 50,
        f"Audit: {reg.audit_frequency.value}",
        sf_txt[:26],
        risk=sf_risk))

    # 7 — Domain law
    domain_risk = "high" if (is_pinn and reg.domain_law is None) else \
                  "med" if reg.domain_law else "ok"
    parts.append(_node(20, 475, 180, 50,
        "Domain law",
        reg.domain_law.value if reg.domain_law else "None declared",
        risk=domain_risk,
        blocked=(is_pinn and reg.domain_law is None)))

    # ── Centre — PCS Engine ───────────────────────────────────────────────
    pcs_fill = tier_col
    parts.append(
        f'<rect x="215" y="210" width="220" height="115" rx="10" '
        f'fill="{C["node_hi"] if blocked else "#1a2540"}" '
        f'stroke="{C["red"] if blocked else C["accent"]}" stroke-width="2.5"/>'
    )
    parts.append(f'<text x="325" y="238" fill="{C["accent"]}" font-size="13" '
                 f'font-weight="bold" text-anchor="middle" font-family="monospace">'
                 f'PCS ENGINE</text>')
    parts.append(f'<text x="325" y="262" fill="{pcs_fill}" font-size="22" '
                 f'font-weight="900" text-anchor="middle" font-family="monospace">'
                 f'{score_txt}</text>')
    parts.append(f'<text x="325" y="282" fill="{pcs_fill}" font-size="13" '
                 f'font-weight="bold" text-anchor="middle" font-family="monospace">'
                 f'{terms.tier.value}</text>')
    if blocked:
        parts.append(f'<text x="325" y="300" fill="{C["text_risk"]}" font-size="10" '
                     f'font-weight="bold" text-anchor="middle" font-family="monospace">'
                     f'GATE BLOCKED</text>')

    # Formula terms sub-panel
    parts.append(
        f'<rect x="215" y="335" width="220" height="52" rx="6" '
        f'fill="#12172a" stroke="{C["border"]}" stroke-width="1"/>'
    )
    parts.append(f'<text x="325" y="352" fill="{C["text_sub"]}" font-size="9" '
                 f'text-anchor="middle" font-family="monospace">'
                 f'L={terms.L:.2f}  I={terms.I:.1f}  Δ={terms.delta:.0f}d  τ={terms.tau:.0f}d</text>')
    parts.append(f'<text x="325" y="367" fill="{C["text_sub"]}" font-size="9" '
                 f'text-anchor="middle" font-family="monospace">'
                 f'Wr={terms.Wr:.2f}  Ws={terms.Ws:.2f}  Wf={terms.Wf:.2f}  Wh={terms.Wh:.2f}</text>')
    parts.append(f'<text x="325" y="382" fill="{C["text_sub"]}" font-size="8" '
                 f'text-anchor="middle" font-family="monospace">'
                 f'RCF=×{terms.rcf_adj:.2f}  ε_b={terms.eps_b:.3f}  ε_ia={terms.eps_ia:.3f}</text>')

    # ── Model-specific risk panel ─────────────────────────────────────────
    parts.append(
        f'<rect x="215" y="405" width="220" height="120" rx="6" '
        f'fill="#12172a" stroke="{C["border"]}" stroke-width="1"/>'
    )
    parts.append(f'<text x="325" y="422" fill="{C["accent"]}" font-size="10" '
                 f'font-weight="bold" text-anchor="middle" font-family="monospace">'
                 f'Model Risk Floor</text>')

    floor_items = [
        (profile.get("eps_b_label", ""), C["red"] if is_llm else C["orange"]),
        (profile.get("pcs_floor_note", "")[:40], C["text_sub"]),
    ]
    attacks = profile.get("attacks", [])[:3]
    for i, atk in enumerate(attacks):
        floor_items.append((f"⚑ {atk[:36]}", C["text_warn"]))

    fy = 436
    for txt, col in floor_items:
        if txt:
            parts.append(f'<text x="222" y="{fy}" fill="{col}" font-size="8" '
                         f'text-anchor="start" font-family="monospace">{txt}</text>')
            fy += 14

    # ── Arrows: left → PCS ───────────────────────────────────────────────
    left_x = 200
    mid_y  = 267

    parts.append(_arrow(200, 77, 215, 240, C["edge_norm"], label="ε_ia"))
    parts.append(_arrow(200, 150, 215, 250, C["edge_risk"] if rcf >= 1.15 else C["edge_norm"]))
    parts.append(_arrow(200, 220, 215, 260, C["edge_block"] if (auto_loop and is_rl) else C["edge_norm"], label="Wf"))
    parts.append(_arrow(200, 290, 215, 265, C["edge_risk"] if infra_risk == "high" else C["edge_norm"], label="Ws"))
    parts.append(_arrow(200, 360, 215, 270, C["edge_risk"] if chained else C["edge_norm"], label="Wr"))
    parts.append(_arrow(200, 430, 215, 275, C["edge_drift"] if reg.silent_failures else C["edge_norm"], label="Δ/τ"))
    parts.append(_arrow(200, 500, 215, 278, C["edge_block"] if (is_pinn and not reg.domain_law) else C["edge_norm"], label="Dm"))

    # ── Deployment gate ───────────────────────────────────────────────────
    gate_risk = "high" if blocked else "ok"
    parts.append(_node(460, 145, 175, 60,
        "Deployment Gate",
        "BLOCKED" if blocked else "APPROVED",
        risk=gate_risk, blocked=blocked))
    parts.append(_arrow(435, 267, 460, 175,
        C["edge_block"] if blocked else C["edge_feed"],
        w=2.5, label="ValidationReport"))

    # ── Model lifecycle ───────────────────────────────────────────────────
    rb_risk = "high" if no_rollback else "normal"
    parts.append(_node(460, 225, 175, 55,
        "Model Lifecycle",
        "Rollback: NOT_POSSIBLE" if no_rollback else "Rollback: available",
        risk=rb_risk))
    if not blocked:
        parts.append(_arrow(547, 205, 547, 225, C["edge_feed"]))
    else:
        parts.append(_arrow(547, 205, 547, 225, C["edge_block"], dashed=True))

    # ── Runtime monitoring ────────────────────────────────────────────────
    mon_risk = "med" if reg.audit_frequency == AuditFrequencyEnum.QUARTERLY else "normal"
    parts.append(_node(460, 300, 175, 55,
        "Runtime Monitoring",
        f"τ = {terms.tau:.0f} days  ({reg.audit_frequency.value})",
        risk=mon_risk))
    parts.append(_arrow(547, 280, 547, 300, C["edge_feed"]))

    # Drift feedback arc
    if reg.drift_detected or reg.domain_violation_occurred:
        parts.append(
            f'<path d="M 460 340 Q 420 430 325 390 Q 305 370 310 340" '
            f'fill="none" stroke="{C["edge_drift"]}" stroke-width="1.5" '
            f'stroke-dasharray="6 3" '
            f'marker-end="url(#arr_{C["edge_drift"].replace("#","")})"/>'
        )
        parts.append(f'<text x="385" y="415" fill="{C["edge_drift"]}" font-size="9" '
                     f'text-anchor="middle" font-family="monospace">drift recompute</text>')

    # RAG corpus
    if rag_enabled:
        parts.append(_node(460, 375, 175, 45,
            "RAG Corpus",
            "Full corpus = attack surface",
            risk="med"))
        parts.append(_arrow(547, 355, 547, 375, C["edge_risk"], label="corpus risk"))

    # Chained AI arc
    if chained:
        parts.append(
            f'<path d="M 20 360 Q 8 500 200 360" '
            f'fill="none" stroke="{C["red"]}" stroke-width="2" '
            f'stroke-dasharray="8 4" '
            f'marker-end="url(#arr_{C["red"].replace("#","")})"/>'
        )
        parts.append(f'<text x="6" y="450" fill="{C["red"]}" font-size="8" '
                     f'font-weight="bold" text-anchor="start" font-family="monospace">'
                     f'CHAINED</text>')
        parts.append(f'<text x="6" y="463" fill="{C["red"]}" font-size="8" '
                     f'text-anchor="start" font-family="monospace">AI path</text>')

    # ── Governance column ─────────────────────────────────────────────────
    # L8 — Compliance
    gov_risk = "med" if not reg.dpia_approved else "normal"
    parts.append(_node(670, 50, 145, 52,
        "Governance L8",
        "DPIA ✓" if reg.dpia_approved else "DPIA ✗ — raises L, I",
        risk=gov_risk))
    if not reg.dpia_approved:
        parts.append(_arrow(670, 76, 610, 255, C["edge_risk"], dashed=True, label="L↑I↑"))

    # L9 — Epistemic
    ep_risk = "high" if terms.eps_b > 0.20 else "med" if terms.eps_b > 0.10 else "normal"
    parts.append(_node(670, 120, 145, 52,
        "Epistemic L9",
        f"ε_b = {terms.eps_b:.3f}  halluc={reg.hallucination_incident_count}",
        risk=ep_risk))
    if reg.hallucination_incident_count > 0:
        parts.append(_arrow(670, 146, 610, 265, C["edge_drift"], dashed=True, label="ε_b↑"))

    # L10 — Culture / Misuse
    cult_risk = "high" if reg.misuse_incident_count > 2 else "med" if reg.misuse_incident_count > 0 else "normal"
    parts.append(_node(670, 190, 145, 52,
        "Culture L10",
        f"{reg.misuse_incident_count} misuse  {reg.automation_bias_risk.value if reg.automation_bias_risk else 'bias:OK'}",
        risk=cult_risk))
    if reg.misuse_incident_count > 0:
        parts.append(_arrow(670, 216, 610, 270, C["edge_risk"], dashed=True, label="Wh↑Δ↑"))

    # L11 — EOL
    parts.append(_node(670, 260, 145, 52,
        "End-of-Life L11",
        "Decommission plan",
        risk="normal"))

    # Vertical gov links
    for ya, yb in [(102, 120), (172, 190), (242, 260)]:
        parts.append(_arrow(742, ya, 742, yb, C["edge_norm"]))

    # Stakeholder outputs
    for i, (lbl, sub, col) in enumerate([
        ("CISO / Board",     "ThreatRegister · PCS",   C["blue"]),
        ("Operations",       "Gate · Quarantine",       C["green"]),
        ("Legal / Regulator","Liability · Evidence",    C["red"] if not reg.liability_boundary_declared else C["border"]),
    ]):
        oy = 50 + i * 70
        parts.append(
            f'<rect x="830" y="{oy}" width="145" height="50" rx="6" '
            f'fill="{C["node"]}" stroke="{col}" stroke-width="1"/>'
        )
        parts.append(f'<text x="902" y="{oy+20}" fill="{C["text"]}" font-size="10" '
                     f'font-weight="bold" text-anchor="middle" font-family="monospace">'
                     f'{lbl}</text>')
        parts.append(f'<text x="902" y="{oy+36}" fill="{C["text_sub"]}" font-size="8" '
                     f'text-anchor="middle" font-family="monospace">{sub}</text>')
        parts.append(_arrow(815, oy + 25, 830, oy + 25, C["edge_norm"]))

    # Legend
    parts.append(
        f'<rect x="460" y="445" width="195" height="105" rx="7" '
        f'fill="#12172a" stroke="{C["border"]}" stroke-width="1"/>'
    )
    parts.append(f'<text x="557" y="462" fill="{C["accent"]}" font-size="10" '
                 f'font-weight="bold" text-anchor="middle" font-family="monospace">Legend</text>')
    legend = [
        (C["edge_norm"],  "Normal flow"),
        (C["edge_risk"],  "Elevated risk path"),
        (C["edge_block"], "Blocker / hard gate"),
        (C["edge_feed"],  "Deployment flow"),
        (C["edge_drift"], "Runtime PCS feedback"),
    ]
    for i, (col, lbl) in enumerate(legend):
        ly = 476 + i * 15
        parts.append(f'<line x1="468" y1="{ly}" x2="492" y2="{ly}" '
                     f'stroke="{col}" stroke-width="2"/>')
        parts.append(f'<text x="496" y="{ly+4}" fill="{C["text_sub"]}" font-size="9" '
                     f'text-anchor="start" font-family="monospace">{lbl}</text>')

    # Title bar
    parts.append(f'<rect x="0" y="0" width="{W}" height="8" '
                 f'fill="{C["accent"]}" rx="0" stroke="none"/>')

    parts.append('</svg>')
    return "\n".join(parts)
