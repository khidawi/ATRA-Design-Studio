"""Visualisation helpers — supplementary diagrams for the framework UI.

This module is **purely rendering**. It reads the existing Tropos model
(actors, delegations, goals, anti-goals, threats, constraints) and the
existing DerivedTerms (risk vector, gate decision) and turns them into
publication-style matplotlib figures.

It introduces no new computation, no new state, and no new dependencies
beyond what the framework already uses (matplotlib + networkx).

The four functions exported:

- ``render_dataflow_layers(model)``   — layered actor / trust / data-flow
  overlay shown on the Actor Graph page.
- ``render_constraint_network(model)`` — network of constraint → actor
  attachments shown on the Constraints page.
- ``render_goal_threat_tree(model)``  — Goal → AntiGoal → Threat →
  Constraint tree shown on the Goal Tree page.
- ``render_architecture_risk_map(model, terms)`` — actor × pillar matrix
  heat map shown on the PCS Result page.

All four use the framework's dark palette (`#0f1426` background) for
visual continuity with the existing actor graph and radar dashboards.
"""
import io
import math

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import networkx as nx


# ─── Shared palette (matches existing actor_graph + pcs_result) ────────
_BG          = "#0f1426"
_PANEL       = "#14192e"
_GRID        = "#243057"
_TEXT_BRIGHT = "#ffffff"
_TEXT_BODY   = "#c8ccd8"
_TEXT_DIM    = "#8899bb"

_ROLE_COLOUR = {
    "TRAINER":   "#5b8def",
    "VALIDATOR": "#a087e6",
    "DEPLOYER":  "#d164b8",
    "OPERATOR":  "#e87959",
    "CONSUMER":  "#f0a830",
}

_TRUST_COLOUR = {
    "HARD":      "#60d080",
    "SOFT":      "#ffcc60",
    "FAIL_OPEN": "#ff6b6b",
}

_PILLAR_COLOUR = {
    "Likelihood":    "#5b8def",
    "Severity":      "#d164b8",
    "Vulnerability": "#e87959",
    "Uncertainty":   "#a087e6",
    "Autonomy":      "#f0a830",
    "Evolution":     "#60d080",
}

# A constraint's PCS term tells us which pillar it most affects.
_TERM_TO_PILLAR = {
    "L":      "Likelihood",
    "Ws":     "Severity",
    "Wr":     "Severity",
    "Wh":     "Vulnerability",
    "Wf":     "Vulnerability",
    "Dm":     "Severity",
    "acm":    "Autonomy",
    "eps_b":  "Uncertainty",
    "eps_ia": "Uncertainty",
    "rcf_adj": "Vulnerability",
    "tau":    "Likelihood",
    "delta":  "Evolution",
    "I":      "Severity",
}

# Mandatory vs. documentation tier (matches rule_engine.py composite gate)
_MANDATORY_SCS = {"SC-HITL-1", "SC-DPIA-1", "SC-CHALL-1", "SC-LIAB-1", "SC-HALLU-1"}


def _new_figure(width=12, height=6, dpi=140):
    """Create a figure with the framework's dark theme pre-applied."""
    fig, ax = plt.subplots(figsize=(width, height), dpi=dpi)
    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_BG)
    return fig, ax


def _save(fig) -> io.BytesIO:
    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format="png", facecolor=_BG, bbox_inches="tight", dpi=170)
    plt.close(fig)
    buf.seek(0)
    return buf


# ═══════════════════════════════════════════════════════════════════════
# 1. Data-flow & trust layers — extension of the actor graph
# ═══════════════════════════════════════════════════════════════════════

def render_dataflow_layers(model) -> io.BytesIO:
    """Three-band view of the trainer→consumer chain.

    Top band: actors (large discs).
    Middle band: data-flow direction (training data → model artefact →
    inferences → decisions).
    Bottom band: trust delegations (coloured by trust type, with
    consolidated pairs shown as red dashed bonds beneath).
    """
    fig, ax = _new_figure(width=13, height=6.2)

    # Layout the 5 roles left-to-right, evenly spaced
    roles = ["TRAINER", "VALIDATOR", "DEPLOYER", "OPERATOR", "CONSUMER"]
    x_positions = {r: i * 1.0 for i, r in enumerate(roles)}

    y_actor = 2.2     # top band — actors
    y_flow  = 1.3     # middle band — data flow stages
    y_trust = 0.45    # bottom band — trust edges
    y_artef = 1.75    # data-flow artefacts above middle band

    # ── Top band: actor discs ───────────────────────────────────────
    for role in roles:
        actor = next((a for a in model.actors if a.role.value == role), None)
        if actor is None:
            continue
        x = x_positions[role]
        col = _ROLE_COLOUR[role]
        ax.scatter(x, y_actor, s=4200, c=col, alpha=0.12, zorder=2)
        ax.scatter(x, y_actor, s=2000, c=col, alpha=0.95, zorder=3,
                   edgecolors="#ffffff", linewidths=1.6)
        ax.text(x, y_actor + 0.02, role, ha="center", va="center",
                fontsize=8.5, fontweight="bold", color="#ffffff", zorder=4)
        # Short identifier under the disc
        ident = (actor.identifier or "")[:14] or "—"
        ax.text(x, y_actor - 0.07, ident, ha="center", va="center",
                fontsize=7, color="#ffffff", alpha=0.85, zorder=4)

    # ── Middle band: data-flow artefacts ───────────────────────────
    artefacts = [
        ("training data",   0.5),
        ("model artefact",  1.5),
        ("validated model", 2.5),
        ("inferences",      3.5),
    ]
    for label, x in artefacts:
        ax.annotate(
            "", xy=(x + 0.5, y_flow), xytext=(x - 0.5, y_flow),
            arrowprops=dict(arrowstyle="->,head_width=0.5,head_length=0.8",
                            color="#5b8def", lw=2.2, alpha=0.85),
            zorder=2,
        )
        # Artefact pill
        ax.add_patch(FancyBboxPatch(
            (x - 0.42, y_artef - 0.10), 0.84, 0.20,
            boxstyle="round,pad=0.02,rounding_size=0.04",
            facecolor=_PANEL, edgecolor="#5b8def", linewidth=1.2, zorder=4,
        ))
        ax.text(x, y_artef, label, ha="center", va="center",
                fontsize=7.6, color="#cfd5e8", fontweight="bold", zorder=5)

    # ── Bottom band: trust delegations as labelled arcs ───────────
    for d in model.delegations:
        dep_role = d.depender.value
        dee_role = d.dependee.value
        if dep_role not in x_positions or dee_role not in x_positions:
            continue
        x1 = x_positions[dep_role]
        x2 = x_positions[dee_role]
        col = _TRUST_COLOUR.get(d.trust_type.value, "#888")
        # A subtle arc
        arc = FancyArrowPatch(
            (x1, y_trust), (x2, y_trust),
            connectionstyle=f"arc3,rad={-0.18 if x2 > x1 else 0.18}",
            color=col, lw=1.6, alpha=0.85, zorder=3,
            arrowstyle="-|>", mutation_scale=12,
        )
        ax.add_patch(arc)
        # Permission label at the midpoint
        mid_x = (x1 + x2) / 2
        ax.text(mid_x, y_trust + 0.10, d.permission[:24],
                ha="center", va="bottom", fontsize=6.5, color=col,
                alpha=0.95, zorder=4)

    # ── Consolidation bonds (red dashed bracket below trust band) ──
    seen_pairs = set()
    for a in model.actors:
        for other in a.consolidated_with:
            pair = tuple(sorted([a.role.value, other.value]))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            xa = x_positions.get(pair[0])
            xb = x_positions.get(pair[1])
            if xa is None or xb is None:
                continue
            ax.plot([xa, xb], [0.05, 0.05], color="#ff6b6b",
                    lw=2.2, linestyle=":", zorder=2)
            ax.text((xa + xb) / 2, -0.05, "consolidated (RCF risk)",
                    ha="center", va="top", fontsize=7,
                    color="#ff8080", fontweight="bold", zorder=2)

    # ── Band labels ────────────────────────────────────────────────
    for y, lbl in [(y_actor, "ACTORS"),
                   (y_artef, "DATA-FLOW"),
                   (y_trust, "TRUST DELEGATIONS")]:
        ax.text(-0.55, y, lbl, ha="right", va="center",
                fontsize=7.5, color="#8899bb", fontweight="bold")

    # ── Trust-type legend ─────────────────────────────────────────
    leg_y = -0.35
    for i, (tt, lbl) in enumerate([
        ("HARD", "HARD (auditable)"),
        ("SOFT", "SOFT (documented)"),
        ("FAIL_OPEN", "FAIL-OPEN (no enforcement)"),
    ]):
        col = _TRUST_COLOUR[tt]
        ax.plot([0 + i * 1.6, 0.2 + i * 1.6], [leg_y, leg_y],
                color=col, lw=2.4)
        ax.text(0.22 + i * 1.6, leg_y, lbl, color=col,
                fontsize=8, va="center")

    ax.set_xlim(-0.7, 4.7)
    ax.set_ylim(-0.55, 2.6)
    ax.set_aspect("auto")
    ax.axis("off")
    ax.set_title("Data Flow · Trust · Actor Consolidation",
                 fontsize=11, color="#dfe5f5", fontweight="bold",
                 loc="left", pad=12)
    return _save(fig)


# ═══════════════════════════════════════════════════════════════════════
# 2. Constraint network — actors imposed-by/dependent-on
# ═══════════════════════════════════════════════════════════════════════

def render_constraint_network(model) -> io.BytesIO:
    """Bipartite network with actors on the left and constraints on the
    right, edges showing which actor imposes / depends on each constraint.

    Mandatory constraints (those that can close the gate under composite
    gating) are tinted red; documentation constraints are tinted blue.
    Satisfied constraints get green borders, violated get red borders.
    """
    fig, ax = _new_figure(width=13, height=8)

    # ── Actors on the left column ─────────────────────────────────
    roles = ["TRAINER", "VALIDATOR", "DEPLOYER", "OPERATOR", "CONSUMER"]
    actor_y = {r: i for i, r in enumerate(reversed(roles))}  # consumer at top

    # ── Constraints down the right column ─────────────────────────
    # Order: mandatory first (top), then documentation
    constraints_sorted = sorted(
        model.constraints,
        key=lambda c: (c.constraint_id not in _MANDATORY_SCS, c.constraint_id),
    )
    n_c = len(constraints_sorted)
    if n_c == 0:
        ax.text(0.5, 0.5, "No constraints registered.", ha="center",
                color=_TEXT_DIM, fontsize=11, transform=ax.transAxes)
        ax.axis("off")
        return _save(fig)

    # Make the constraint column the same physical height as actors
    actor_y_max = max(actor_y.values()) if actor_y else 0
    spacing = max(1.0, (actor_y_max + 1) / n_c)
    constraint_y = {c.constraint_id: (n_c - 1 - i) * spacing
                    for i, c in enumerate(constraints_sorted)}

    x_actor = 0.0
    x_constr = 4.0

    # ── Draw edges first (so nodes overlay) ───────────────────────
    for c in constraints_sorted:
        # `on_dependency` is a tuple (depender_role, dependee_role)
        dep_pair = getattr(c, "on_dependency", None)
        if dep_pair is None:
            continue
        # Edge tone: red if violated, green if satisfied
        edge_col = "#60d080" if c.is_satisfied else "#ff6b6b"
        alpha = 0.85 if not c.is_satisfied else 0.45
        for role_enum in dep_pair:
            if role_enum is None:
                continue
            role_name = role_enum.value if hasattr(role_enum, "value") else str(role_enum)
            if role_name not in actor_y:
                continue
            ax.plot(
                [x_actor + 0.30, x_constr - 0.55],
                [actor_y[role_name], constraint_y[c.constraint_id]],
                color=edge_col, alpha=alpha, lw=1.1, zorder=2,
            )

    # ── Draw actor pills on the left ──────────────────────────────
    for role, y in actor_y.items():
        col = _ROLE_COLOUR[role]
        ax.add_patch(FancyBboxPatch(
            (x_actor - 0.55, y - 0.20), 0.85, 0.40,
            boxstyle="round,pad=0.02,rounding_size=0.08",
            facecolor=col, edgecolor="#ffffff", linewidth=1.4, zorder=4,
        ))
        ax.text(x_actor - 0.13, y, role, ha="center", va="center",
                fontsize=8.5, fontweight="bold", color="#ffffff", zorder=5)

    # ── Draw constraint pills on the right ────────────────────────
    for c in constraints_sorted:
        y = constraint_y[c.constraint_id]
        is_mandatory = c.constraint_id in _MANDATORY_SCS
        # Tier colour: red bg for mandatory, blue bg for documentation
        bg_col = "#3a1818" if is_mandatory else "#16263a"
        text_tier = "MANDATORY" if is_mandatory else "DOC"
        text_tier_col = "#ff8080" if is_mandatory else "#6090d0"
        # Border colour: green satisfied, red violated
        border_col = "#60d080" if c.is_satisfied else "#ff6b6b"
        status_glyph = "✓" if c.is_satisfied else "✗"

        ax.add_patch(FancyBboxPatch(
            (x_constr - 0.55, y - 0.30), 3.4, 0.60,
            boxstyle="round,pad=0.02,rounding_size=0.08",
            facecolor=bg_col, edgecolor=border_col, linewidth=1.8, zorder=4,
        ))
        # Constraint ID + status glyph
        ax.text(x_constr - 0.40, y + 0.08, f"{status_glyph}  {c.constraint_id}",
                ha="left", va="center", fontsize=8.7, fontweight="bold",
                color=border_col, zorder=5)
        # Truncated name
        short_name = c.name[:46] + ("…" if len(c.name) > 46 else "")
        ax.text(x_constr - 0.40, y - 0.10, short_name,
                ha="left", va="center", fontsize=7.4, color="#cfd5e8",
                zorder=5)
        # Tier tag on the far right
        ax.text(x_constr + 2.75, y + 0.08, text_tier,
                ha="right", va="center", fontsize=7,
                color=text_tier_col, fontweight="bold", zorder=5)

    # ── Title + legend ────────────────────────────────────────────
    ax.set_xlim(-1.0, x_constr + 3.2)
    # Add extra space at the bottom for the legend strip
    ax.set_ylim(-1.8, max(actor_y_max, (n_c - 1) * spacing) + 0.6)
    ax.axis("off")
    ax.set_title(
        "Security Constraint Network — actors (left) imposing / depending on constraints (right)",
        fontsize=10.5, color="#dfe5f5", fontweight="bold",
        loc="left", pad=10,
    )

    # Legend strip across the bottom (avoids overlapping the first constraint row)
    leg_y = -1.3
    legend_items = [
        ("MANDATORY (closes gate)",  "#ff8080"),
        ("DOC (raises to REVIEW)",   "#6090d0"),
        ("Satisfied",                 "#60d080"),
        ("Violated",                  "#ff6b6b"),
    ]
    leg_x_start = 0.0
    for i, (lbl, col) in enumerate(legend_items):
        x = leg_x_start + i * 1.95
        ax.text(x, leg_y, "■", color=col, fontsize=12,
                fontweight="bold", va="center")
        ax.text(x + 0.18, leg_y, lbl, color="#a8b8d4",
                fontsize=8, va="center")

    return _save(fig)


# ═══════════════════════════════════════════════════════════════════════
# 3. Goal → AntiGoal → Threat → Constraint tree
# ═══════════════════════════════════════════════════════════════════════

def render_goal_threat_tree(model) -> io.BytesIO:
    """Hierarchical tree-style diagram.

    Four columns left-to-right:
      Goal  →  AntiGoal  →  Threat  →  mitigating Constraint
    Constraint nodes are colour-coded by satisfaction (green = satisfied,
    red = violated). This is the *interactive structure* of the model the
    framework reasons over — readers see at a glance where every threat
    lives in the goal hierarchy and which constraints mitigate it.
    """
    # Pre-compute the chains. The actual model links are:
    #   Goal       has  pcs_term (row family) + held_by (actor roles)
    #   AntiGoal   has  threatens : list[goal_id]
    #   Threat     has  realises  : list[anti_goal_id]
    #   Constraint has  because   : threat_id or anti_goal_id (string)
    #
    # We chain from Constraint → Threat → AntiGoal → Goal.
    goals_by_id   = {g.goal_id: g for g in model.goals}
    ags_by_id     = {a.anti_goal_id: a for a in model.anti_goals}
    threats_by_id = {t.threat_id: t for t in model.threats}

    # Helper: pick the first ancestor of an anti-goal that exists in our goal index
    def _ag_to_goals(ag):
        if ag is None:
            return []
        threatens = getattr(ag, "threatens", []) or []
        return [goals_by_id[gid] for gid in threatens if gid in goals_by_id]

    # Helper: pick the first ancestor of a threat among our anti-goal index
    def _threat_to_ags(threat):
        if threat is None:
            return []
        realises = getattr(threat, "realises", []) or []
        return [ags_by_id[agid] for agid in realises if agid in ags_by_id]

    chains = []          # list of dicts: goal, ag, threat, constraints
    for c in model.constraints:
        because = getattr(c, "because", None)
        if because is None:
            continue

        # Resolve the constraint's parent — could be a threat or an anti-goal
        threat = threats_by_id.get(because)
        if threat is not None:
            parent_ags = _threat_to_ags(threat)
        else:
            ag = ags_by_id.get(because)
            if ag is None:
                continue
            parent_ags = [ag]
            threat = None  # constraint attaches directly to an anti-goal

        for ag in parent_ags:
            parent_goals = _ag_to_goals(ag)
            if not parent_goals:
                # Anti-goal exists but doesn't chain to any tracked goal
                chains.append({"goal": None, "ag": ag,
                               "threat": threat, "constraints": [c]})
                continue
            for goal in parent_goals:
                chains.append({"goal": goal, "ag": ag,
                               "threat": threat, "constraints": [c]})

    # Group rows that share the same (goal, ag, threat) so constraints
    # stack vertically beneath their parent rather than duplicating rows.
    grouped = {}
    for ch in chains:
        key = (
            ch["goal"].goal_id if ch["goal"] else None,
            ch["ag"].anti_goal_id if ch["ag"] else None,
            ch["threat"].threat_id if ch["threat"] else None,
        )
        if key not in grouped:
            grouped[key] = {"goal": ch["goal"], "ag": ch["ag"],
                            "threat": ch["threat"], "constraints": []}
        grouped[key]["constraints"].extend(ch["constraints"])
    chains = list(grouped.values())

    if not chains:
        fig, ax = _new_figure(width=10, height=4)
        ax.text(0.5, 0.5, "No goal–threat chains registered.",
                ha="center", color=_TEXT_DIM, fontsize=11,
                transform=ax.transAxes)
        ax.axis("off")
        return _save(fig)

    # Layout: every chain gets one row. Constraints stack vertically
    # within a row if there are several. Compute total height.
    row_heights = [max(1, len(ch["constraints"])) for ch in chains]
    total_rows = sum(row_heights)
    fig_height = max(6, 0.6 * total_rows + 1.2)

    fig, ax = _new_figure(width=14, height=fig_height)

    x_goal   = 0.0
    x_ag     = 3.2
    x_threat = 6.4
    x_constr = 9.6
    col_widths = {"goal": 2.9, "ag": 2.9, "threat": 2.9, "constr": 3.9}
    row_h = 0.55

    y_cursor = total_rows * row_h
    for chain in chains:
        goal = chain["goal"]
        ag = chain["ag"]
        threat = chain["threat"]
        cs = chain["constraints"]
        n_cs = max(1, len(cs))
        row_centre = y_cursor - (n_cs * row_h) / 2

        # Goal box (may be None if anti-goal does not chain to a tracked goal)
        if goal is not None:
            _draw_node_box(ax, x_goal, row_centre, col_widths["goal"], row_h * 0.9,
                           facecolor="#1a2546", edgecolor="#5b8def",
                           title=goal.goal_id, body=(goal.description or "")[:60])
            _draw_connector(ax, x_goal + col_widths["goal"], row_centre,
                            x_ag, row_centre, "#a087e6")

        # AntiGoal box
        _draw_node_box(ax, x_ag, row_centre, col_widths["ag"], row_h * 0.9,
                       facecolor="#2a1a2a", edgecolor="#d164b8",
                       title=ag.anti_goal_id, body=(ag.description or "")[:60])

        # Threat box (may be None if constraint attaches directly to AG)
        if threat is not None:
            _draw_node_box(ax, x_threat, row_centre, col_widths["threat"],
                           row_h * 0.9, facecolor="#3a1818",
                           edgecolor="#ff6b6b",
                           title=threat.threat_id,
                           body=(threat.description or "")[:60])
            _draw_connector(ax, x_ag + col_widths["ag"], row_centre,
                            x_threat, row_centre, "#ff8080")
            target_x_for_constraint = x_threat + col_widths["threat"]
        else:
            target_x_for_constraint = x_ag + col_widths["ag"]

        # Constraint boxes — one per row, stacked
        for i, c in enumerate(cs):
            cy = y_cursor - (i + 0.5) * row_h
            border = "#60d080" if c.is_satisfied else "#ff6b6b"
            bg = "#16262a" if c.is_satisfied else "#3a1820"
            status = "✓" if c.is_satisfied else "✗"
            _draw_node_box(ax, x_constr, cy, col_widths["constr"],
                           row_h * 0.85, facecolor=bg, edgecolor=border,
                           title=f"{status} {c.constraint_id}",
                           body=c.name[:55],
                           title_color=border)
            _draw_connector(ax, target_x_for_constraint, row_centre,
                            x_constr, cy, border, alpha=0.7)

        y_cursor -= n_cs * row_h

    # Column headers
    header_y = total_rows * row_h + 0.35
    for label, xc, w in [
        ("GOAL",      x_goal,   col_widths["goal"]),
        ("ANTI-GOAL", x_ag,     col_widths["ag"]),
        ("THREAT",    x_threat, col_widths["threat"]),
        ("CONSTRAINT", x_constr, col_widths["constr"]),
    ]:
        ax.text(xc + w / 2, header_y, label, ha="center", va="bottom",
                fontsize=10, fontweight="bold", color="#dfe5f5")

    ax.set_xlim(-0.4, x_constr + col_widths["constr"] + 0.6)
    ax.set_ylim(-0.4, header_y + 0.7)
    ax.axis("off")
    return _save(fig)


def _draw_node_box(ax, x, y_centre, w, h, facecolor, edgecolor,
                   title, body, title_color=None):
    """Draw a rounded box with a title line and a body line."""
    ax.add_patch(FancyBboxPatch(
        (x, y_centre - h / 2), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.06",
        facecolor=facecolor, edgecolor=edgecolor, linewidth=1.4, zorder=3,
    ))
    ax.text(x + 0.10, y_centre + h * 0.18, title,
            ha="left", va="center", fontsize=8.4, fontweight="bold",
            color=title_color or edgecolor, zorder=4)
    ax.text(x + 0.10, y_centre - h * 0.18, body,
            ha="left", va="center", fontsize=7.0, color="#cfd5e8",
            zorder=4)


def _draw_connector(ax, x1, y1, x2, y2, color, alpha=0.85):
    """Draw an arrow between two nodes."""
    arrow = FancyArrowPatch(
        (x1, y1), (x2, y2),
        arrowstyle="-|>", mutation_scale=10,
        color=color, lw=1.2, alpha=alpha, zorder=2,
    )
    ax.add_patch(arrow)


# ═══════════════════════════════════════════════════════════════════════
# 4. Architecture risk map — actor × pillar matrix
# ═══════════════════════════════════════════════════════════════════════

def render_architecture_risk_map(model, terms) -> io.BytesIO:
    """Heatmap-style map where rows are actors, columns are pillars, and
    cells show how many constraints attached to that actor affect that
    pillar — coloured by violation status.

    Reads from existing model.constraints (`on_dependency`, `pcs_term`,
    `is_satisfied`). No computation beyond counting.
    """
    roles = ["TRAINER", "VALIDATOR", "DEPLOYER", "OPERATOR", "CONSUMER"]
    pillars = ["Likelihood", "Severity", "Vulnerability",
               "Uncertainty", "Autonomy", "Evolution"]

    # Count satisfied / violated constraints per (actor, pillar) cell
    counts = {(r, p): {"sat": 0, "vio": 0} for r in roles for p in pillars}
    for c in model.constraints:
        pillar = _TERM_TO_PILLAR.get(c.pcs_term)
        if pillar is None:
            continue
        for role_enum in (c.on_dependency or ()):
            if role_enum is None:
                continue
            role = role_enum.value if hasattr(role_enum, "value") else str(role_enum)
            if role not in counts and (role, pillar) not in counts:
                continue
            key = (role, pillar)
            if key in counts:
                if c.is_satisfied:
                    counts[key]["sat"] += 1
                else:
                    counts[key]["vio"] += 1

    fig, ax = _new_figure(width=12, height=5.5)

    cell_w = 1.6
    cell_h = 0.8

    # Cell rendering
    for j, pillar in enumerate(pillars):
        for i, role in enumerate(roles):
            x = j * cell_w
            y = (len(roles) - 1 - i) * cell_h
            sat = counts[(role, pillar)]["sat"]
            vio = counts[(role, pillar)]["vio"]
            total = sat + vio

            # Cell colour: severity from violation ratio
            if total == 0:
                facecolor = "#1a2035"
                ring_col = "#243057"
            else:
                violation_ratio = vio / total
                if violation_ratio >= 0.99:
                    facecolor = "#3a1818"   # all violated — deep red
                    ring_col = "#ff6b6b"
                elif violation_ratio >= 0.5:
                    facecolor = "#3a2918"   # half violated — amber
                    ring_col = "#e87959"
                elif violation_ratio > 0:
                    facecolor = "#2a2818"   # some violated — yellow
                    ring_col = "#f9a825"
                else:
                    facecolor = "#16262a"   # all satisfied — green
                    ring_col = "#60d080"

            ax.add_patch(FancyBboxPatch(
                (x + 0.05, y + 0.05), cell_w - 0.1, cell_h - 0.1,
                boxstyle="round,pad=0.02,rounding_size=0.04",
                facecolor=facecolor, edgecolor=ring_col, linewidth=1.4,
            ))

            # Numbers inside the cell
            if total > 0:
                ax.text(x + cell_w / 2, y + cell_h / 2,
                        f"{sat}/{total}", ha="center", va="center",
                        fontsize=10, fontweight="bold",
                        color=ring_col)
            else:
                ax.text(x + cell_w / 2, y + cell_h / 2, "–",
                        ha="center", va="center",
                        fontsize=10, color="#445", alpha=0.6)

    # Row labels (actors)
    for i, role in enumerate(roles):
        y = (len(roles) - 1 - i) * cell_h
        ax.text(-0.2, y + cell_h / 2, role, ha="right", va="center",
                fontsize=9, fontweight="bold",
                color=_ROLE_COLOUR[role])

    # Column labels (pillars)
    top_y = len(roles) * cell_h
    for j, pillar in enumerate(pillars):
        x = j * cell_w
        ax.text(x + cell_w / 2, top_y + 0.15, pillar,
                ha="center", va="bottom", fontsize=9, fontweight="bold",
                color=_PILLAR_COLOUR.get(pillar, "#dfe5f5"))

    ax.set_xlim(-1.0, len(pillars) * cell_w + 0.3)
    ax.set_ylim(-0.6, top_y + 0.7)
    ax.axis("off")
    ax.set_title(
        "Architecture Risk Map — constraints per actor × pillar "
        "(cells show satisfied/total)",
        fontsize=10.5, color="#dfe5f5", fontweight="bold",
        loc="left", pad=10,
    )

    # Legend strip below
    legend_y = -0.4
    legend_items = [
        ("all satisfied",  "#60d080"),
        ("some violated",  "#f9a825"),
        ("half violated",  "#e87959"),
        ("all violated",   "#ff6b6b"),
        ("no constraints", "#445"),
    ]
    x0 = 0.0
    for lbl, col in legend_items:
        ax.add_patch(FancyBboxPatch(
            (x0, legend_y - 0.10), 0.20, 0.20,
            boxstyle="round,pad=0.02,rounding_size=0.04",
            facecolor=col, edgecolor=col, linewidth=0,
        ))
        ax.text(x0 + 0.28, legend_y, lbl, va="center", fontsize=7.5,
                color="#a8b8d4")
        x0 += 1.6

    return _save(fig)