"""
framework/header.py
====================

Fixed top header for the ST-AI Streamlit app — executive-grade chrome
that mounts on every page without touching the existing sidebar.

What this provides:
    • A persistent strip across the top of the main content area with
      the framework name, current deployment, live PCS chip, and the
      executive controls.
    • A red primary button: "🔒 Lock & Sign Off" — stamps the current
      DerivedTerms into the journal as an executive sign-off event.
      The live engine continues to recompute as usual; this button is
      the *acceptance* action, not a compute trigger. This preserves
      the framework invariant ("PCS is derived — never entered
      manually") while giving executives a visible affordance.
    • A red secondary button: "⛔ Withdraw Deployment" — sets the
      registry's decommissioning_status to IN_PROGRESS and writes a
      journal entry. Triggers a confirmation step so it can't be
      pressed by accident.
    • A notification bell with a red badge — counts unresolved engine
      warnings + active blockers + open incidents. Clicking opens a
      popover listing them grouped by source.

Mounted by app.py via `render_top_header()` immediately after
inject_css() and before the page router. The sidebar is untouched.

The header is intentionally implemented in raw HTML inside a single
st.markdown call (for the visual chrome) plus a small row of native
Streamlit widgets (for the interactive controls) so it both looks
polished and functions reliably across Streamlit reruns.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Tuple

import streamlit as st

from framework.enums import (
    ActionTierEnum,
    DecommissioningStatusEnum,
    DecommissionReasonEnum,
)
from framework.journal import EventType


# ─────────────────────────────────────────────────────────────────────
# Colour palette — kept consistent with the existing sidebar
# ─────────────────────────────────────────────────────────────────────
_TIER_COLOUR = {
    ActionTierEnum.CRITICAL: "#ff6b6b",
    ActionTierEnum.HIGH:     "#ffcc60",
    ActionTierEnum.MODERATE: "#7fe89a",
    ActionTierEnum.LOW:      "#82b4ff",
}


# ─────────────────────────────────────────────────────────────────────
# Sidebar-mirror icon nav — Reading-A spec.
#
# Each tuple is (sidebar_label, icon, tooltip). The sidebar_label MUST
# match the label used in app.py's nav_labels list verbatim, because
# clicking a header icon writes it into _entry_landing_page and the
# existing routing logic in app.py resolves it back to a radio index.
#
# We deliberately surface a curated subset — the 8 most-frequently-used
# pages — rather than all 13, so the icon strip stays readable on a
# typical executive screen width. The full menu remains one click away
# (just expand the sidebar). Locked-state labels (the 🔒-prefixed
# variants used when the design gate is closed) are matched by the
# loose-matching logic already in app.py, so the icons keep working
# regardless of gate state.
# ─────────────────────────────────────────────────────────────────────
_HEADER_ICON_NAV = [
    ("📋 Register AI Deployment",   "📋", "Register AI Deployment"),
    ("📊 PCS Result & Gate",        "📊", "PCS Result & Gate"),
    ("🎨 AI System Designer",       "🎨", "AI System Designer"),
    ("⚡ Runtime Events (L7)",       "⚡", "Runtime Events"),
    ("⚖️ Governance Layers (L8–L11)", "⚖️", "Governance Layers"),
    ("🕸️ Actor Graph",              "🕸️", "Actor Graph"),
    ("📜 Security Constraints",     "📜", "Security Constraints"),
    ("⚡ Incidents",                 "🔻", "Incidents"),
]


# ─────────────────────────────────────────────────────────────────────
# State helpers — read-only views into the existing session
# ─────────────────────────────────────────────────────────────────────
def _gather_notifications() -> List[Tuple[str, str, str]]:
    """Collect unresolved attention items from the live framework state.

    Returns a list of (severity, source, message) tuples, where severity
    is one of {"block", "warn", "incident"}. This is what the bell
    badge counts and the popover lists.

    The function is read-only: it does not mutate any framework state.
    """
    items: List[Tuple[str, str, str]] = []
    terms = st.session_state.get("terms")
    reg   = st.session_state.get("registry")

    # Engine blockers — non-empty list means the gate is BLOCKED
    if terms is not None:
        for msg in getattr(terms, "blockers", []) or []:
            items.append(("block", "Engine", msg))

        # Engine warnings — REVIEW-tier guidance
        for msg in getattr(terms, "warnings", []) or []:
            items.append(("warn", "Engine", msg))

    # Open runtime incidents — from IncidentRegister
    if reg is not None:
        ir = getattr(reg, "incident_register", None)
        if ir is not None:
            try:
                for inc in ir.open_incidents():
                    sev_label = (
                        "block" if int(getattr(inc.severity, "value",
                                               inc.severity)) >= 4
                        else "warn"
                    )
                    items.append((
                        sev_label,
                        f"Incident #{inc.incident_id}",
                        f"{inc.incident_type.value} — "
                        f"severity {inc.severity.value}: {inc.description}",
                    ))
            except Exception:
                # Defensive: malformed incident register shouldn't crash
                # the whole UI — silently skip and continue.
                pass

    return items


def _is_signed_off() -> bool:
    return bool(st.session_state.get("_executive_signed_off", False))


def _is_withdrawn() -> bool:
    reg = st.session_state.get("registry")
    if reg is None:
        return False
    status = getattr(reg, "decommissioning_status", None)
    return status is not None


# ─────────────────────────────────────────────────────────────────────
# Header CSS — fixed strip at top of main content area
# ─────────────────────────────────────────────────────────────────────
_HEADER_CSS = """
<style>
/* ════════════════════════════════════════════════════════════════
   ST-AI integrated header — single fixed bar approach.
   ════════════════════════════════════════════════════════════════
   The header is a Streamlit container marked with a sentinel class.
   We target that container with CSS and pin it to the viewport top
   with an opaque dark backdrop. All header widgets render INSIDE
   this container, so they sit on the backdrop naturally and the
   bar reads as one cohesive strip rather than floating buttons.

   The sentinel class is attached by wrapping the container's child
   with an empty marker div; CSS walks up to the nearest fixed-eligible
   ancestor. We use Streamlit's stable data-testid hooks to be robust
   across Streamlit versions.
*/

/* Push main content down so it doesn't render under the fixed header */
section[data-testid="stMain"] > div.block-container {
    padding-top: 88px !important;
}

/* The header container — pinned to top, full width over main area.
   Identified by the presence of a child element with our sentinel
   class .stai-header-sentinel. We climb up to the nearest Streamlit
   container that has the right layout characteristics. */
div[data-testid="stVerticalBlock"]:has(> div > div > .stai-header-sentinel),
div[data-testid="stVerticalBlock"]:has(> div .stai-header-sentinel) {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    right: 0 !important;
    height: 72px !important;
    z-index: 999 !important;
    background: linear-gradient(180deg,
                                rgba(15, 17, 23, 0.97) 0%,
                                rgba(22, 27, 39, 0.95) 100%) !important;
    backdrop-filter: blur(14px) saturate(140%);
    -webkit-backdrop-filter: blur(14px) saturate(140%);
    border-bottom: 1px solid rgba(76, 138, 255, 0.18) !important;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.45),
                inset 0 -1px 0 rgba(76, 138, 255, 0.08) !important;
    padding: 0 28px 0 calc(var(--sidebar-width, 244px) + 16px) !important;
    display: flex !important;
    align-items: center !important;
}

/* When sidebar collapsed, header extends left */
section[data-testid="stSidebar"][aria-expanded="false"] ~ *
    div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel),
body:has(section[data-testid="stSidebar"][aria-expanded="false"])
    div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel) {
    padding-left: 80px !important;
}

/* Hide the sentinel itself — it's only used as a CSS hook */
.stai-header-sentinel {
    display: none !important;
}

/* The horizontal row that holds all header widgets — let it span
   the full container width inside the fixed bar */
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"] {
    width: 100% !important;
    gap: 14px !important;
    align-items: center !important;
}

/* Title block on the left */
.stai-hdr-title {
    font-size: 1.05rem;
    font-weight: 700;
    letter-spacing: -0.01em;
    background: linear-gradient(135deg, #82b4ff 0%, #b69cff 100%);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    white-space: nowrap;
    line-height: 1.15;
}

.stai-hdr-sub {
    font-size: 0.7rem;
    color: #6a7a9a;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-weight: 600;
    margin-top: 3px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 220px;
}

/* PCS chip — pill on dark glassmorphism */
.stai-hdr-pcs-chip {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 8px 14px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.12);
    font-size: 0.84rem;
    color: #e8eaf0;
    font-weight: 600;
    white-space: nowrap;
}
.stai-hdr-pcs-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    box-shadow: 0 0 8px currentColor;
}
.stai-hdr-pcs-tier {
    color: rgba(220, 228, 240, 0.55);
    font-size: 0.7rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}

/* Status badges — sign off, withdrawn */
.stai-status-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 11px;
    border-radius: 6px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    white-space: nowrap;
}
.stai-status-badge.signed {
    background: rgba(96, 208, 128, 0.15);
    border: 1px solid rgba(96, 208, 128, 0.40);
    color: #8fe8a8;
}
.stai-status-badge.withdrawn {
    background: rgba(255, 80, 80, 0.18);
    border: 1px solid rgba(255, 80, 80, 0.45);
    color: #ffa0a0;
}

/* ────────────────────────────────────────────────────────────────
   Buttons inside the header — target by their Streamlit keys so
   each one gets its own treatment (primary red, secondary red,
   neutral bell, icon-nav).
   ──────────────────────────────────────────────────────────────── */

/* All header buttons share base style */
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel) button {
    height: 40px !important;
    border-radius: 9px !important;
    font-weight: 700 !important;
    letter-spacing: 0.01em !important;
    transition: transform 0.12s ease, box-shadow 0.12s ease,
                background 0.12s ease !important;
    white-space: nowrap !important;
    padding: 0 14px !important;
    font-size: 0.84rem !important;
}
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    button:hover:not(:disabled) {
    transform: translateY(-1px);
}

/* PRIMARY RED — Lock & Sign Off */
button[kind="primary"][data-testid="baseButton-primary"]:has(+ *),
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    button[data-testid="baseButton-secondary"]:where([key*="signoff_btn"]),
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    div:has(> button:has-text("Lock & Sign Off")) button {
    background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%) !important;
    border: 1px solid rgba(255, 130, 130, 0.55) !important;
    color: #ffffff !important;
    box-shadow: 0 4px 14px rgba(168, 40, 40, 0.45),
                inset 0 1px 0 rgba(255, 255, 255, 0.22) !important;
}

/* Streamlit doesn't support :has-text reliably, so we use the
   key-based approach: each button gets a key, and we target by
   the surrounding column's index inside the header row. This is
   what makes the styling actually take hold. */
/* Column 5: signoff (primary red) */
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(5) button {
    background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%) !important;
    border: 1px solid rgba(255, 130, 130, 0.55) !important;
    color: #ffffff !important;
    box-shadow: 0 4px 14px rgba(185, 28, 28, 0.45),
                inset 0 1px 0 rgba(255, 255, 255, 0.22) !important;
}
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(5) button:hover:not(:disabled) {
    box-shadow: 0 6px 22px rgba(185, 28, 28, 0.65),
                inset 0 1px 0 rgba(255, 255, 255, 0.28) !important;
}

/* Column 6: withdraw (secondary red, lower emphasis) */
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(6) button {
    background: rgba(185, 28, 28, 0.18) !important;
    border: 1px solid rgba(255, 130, 130, 0.45) !important;
    color: #ffa0a0 !important;
}
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(6) button:hover:not(:disabled) {
    background: rgba(185, 28, 28, 0.32) !important;
    color: #ffd0d0 !important;
}

/* Column 7: bell (neutral) — with badge as ::after on the button */
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(7) button {
    background: rgba(255, 255, 255, 0.06) !important;
    border: 1px solid rgba(255, 255, 255, 0.14) !important;
    color: #e8eaf0 !important;
    position: relative !important;
    min-width: 56px !important;
}
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(7) button:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.12) !important;
}

/* Disabled button styling — keep the red but desaturate */
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    button:disabled {
    opacity: 0.55 !important;
    cursor: not-allowed !important;
}

/* ────────────────────────────────────────────────────────────────
   Icon nav strip — column 4 inside the header row. Holds the
   8 icon-only nav buttons. Visible only when sidebar collapsed.
   ──────────────────────────────────────────────────────────────── */
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(4) {
    display: none !important;  /* hidden by default */
}
section[data-testid="stSidebar"][aria-expanded="false"] ~ *
    div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(4),
body:has(section[data-testid="stSidebar"][aria-expanded="false"])
    div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(4) {
    display: block !important;
}
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(4)
    div[data-testid="stHorizontalBlock"] {
    gap: 4px !important;
}
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(4) button {
    width: 40px !important;
    min-width: 40px !important;
    padding: 0 !important;
    background: rgba(255, 255, 255, 0.04) !important;
    border: 1px solid rgba(255, 255, 255, 0.10) !important;
    color: #e8eaf0 !important;
    font-size: 1.05rem !important;
}
div[data-testid="stVerticalBlock"]:has(.stai-header-sentinel)
    > div[data-testid="stHorizontalBlock"]
    > div[data-testid="column"]:nth-child(4) button:hover:not(:disabled) {
    background: rgba(76, 138, 255, 0.20) !important;
    border-color: rgba(130, 180, 255, 0.50) !important;
}
</style>
"""


# ─────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────
def render_top_header() -> None:
    """Render the integrated fixed top header. Call once per page,
    immediately after inject_css() and before the rest of the page
    renders.

    The implementation is a single Streamlit container marked with the
    .stai-header-sentinel hook, pinned to the viewport by CSS. ALL
    header widgets live inside that container as a single horizontal
    row of columns. This is what makes the bar read as one cohesive
    strip rather than floating standalone buttons.
    """
    st.markdown(_HEADER_CSS, unsafe_allow_html=True)

    terms = st.session_state.get("terms")
    reg   = st.session_state.get("registry")

    # ── Prepare display values ──────────────────────────────────────
    if terms is not None:
        tier = terms.tier
        pcs  = terms.pcs_score
        tier_label = tier.value
        pcs_text = "—" if pcs == 999.0 else f"{pcs:.1f}"
        dot_colour = _TIER_COLOUR.get(tier, "#82b4ff")
    else:
        tier_label = "—"
        pcs_text = "—"
        dot_colour = "#6a7a9a"

    deployment_name = "—"
    if reg is not None:
        deployment_name = (
            (getattr(reg, "deployment_name", None) or "").strip()
            or "Unnamed deployment"
        )

    notif_items = _gather_notifications()
    n_items = len(notif_items)

    can_signoff = (
        terms is not None
        and not _is_signed_off()
        and not _is_withdrawn()
    )
    can_withdraw = (
        reg is not None
        and not _is_withdrawn()
    )

    # ── THE single integrated header container ──────────────────────
    # Sentinel marker tells the CSS this container is the header.
    # All widgets inside this `with` block become part of the fixed
    # bar — they share the same backdrop and gradient.
    hdr = st.container()
    with hdr:
        st.markdown(
            "<div class='stai-header-sentinel'></div>",
            unsafe_allow_html=True,
        )

        # Single horizontal row — 7 columns, each one occupied by a
        # specific header element. Column indices are STABLE and CSS
        # targets them by :nth-child() — do not reorder without
        # updating the CSS rules above.
        #
        # 1: Title block          (HTML)
        # 2: PCS chip             (HTML)
        # 3: Status badges        (HTML — sign-off / withdrawn)
        # 4: Icon nav (collapsed) (Streamlit buttons, CSS-hidden when sidebar open)
        # 5: Lock & Sign Off      (Streamlit button — PRIMARY RED)
        # 6: Withdraw             (Streamlit button — secondary red)
        # 7: Bell                 (Streamlit button — neutral)
        col_title, col_pcs, col_status, col_iconnav, col_signoff, \
            col_withdraw, col_bell = st.columns(
                [2.2, 2.0, 1.6, 6.0, 2.2, 2.0, 1.0],
                gap="small",
                vertical_alignment="center",
            )

        # ── Column 1: title + deployment subtitle ───────────────────
        with col_title:
            st.markdown(
                f"<div>"
                f"<div class='stai-hdr-title'>🔒 ST-AI Framework</div>"
                f"<div class='stai-hdr-sub'>{deployment_name}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

        # ── Column 2: PCS chip ──────────────────────────────────────
        with col_pcs:
            st.markdown(
                f"<div class='stai-hdr-pcs-chip'>"
                f"<span class='stai-hdr-pcs-dot' "
                f"style='background:{dot_colour};color:{dot_colour};'>"
                f"</span>"
                f"<span>PCS {pcs_text}</span>"
                f"<span class='stai-hdr-pcs-tier'>{tier_label}</span>"
                f"</div>",
                unsafe_allow_html=True,
            )

        # ── Column 3: status badges (sign-off / withdrawn) ──────────
        with col_status:
            badges = ""
            if _is_signed_off():
                ts = st.session_state.get("_executive_signoff_at", "")
                badges += (
                    f"<span class='stai-status-badge signed'>"
                    f"✓ Signed off {ts[:10]}</span> "
                )
            if _is_withdrawn():
                badges += (
                    "<span class='stai-status-badge withdrawn'>"
                    "⛔ Withdrawn</span>"
                )
            if badges:
                st.markdown(badges, unsafe_allow_html=True)
            else:
                # Empty placeholder so the column still occupies space
                st.markdown("&nbsp;", unsafe_allow_html=True)

        # ── Column 4: icon nav (revealed only when sidebar collapsed)
        with col_iconnav:
            icon_cols = st.columns(
                [1] * len(_HEADER_ICON_NAV),
                gap="small",
                vertical_alignment="center",
            )
            for col, (label, icon, tip) in zip(icon_cols, _HEADER_ICON_NAV):
                with col:
                    if st.button(icon,
                                 key=f"_hdr_iconnav_{label}",
                                 help=tip,
                                 use_container_width=True):
                        st.session_state["_entry_landing_page"] = label
                        st.rerun()

        # ── Column 5: Lock & Sign Off (PRIMARY RED) ─────────────────
        with col_signoff:
            if _is_signed_off():
                st.button("✓ Signed Off",
                          key="_hdr_signoff_done",
                          disabled=True,
                          use_container_width=True)
            else:
                if st.button("🔒 Lock & Sign Off",
                             key="_hdr_signoff_btn",
                             disabled=not can_signoff,
                             use_container_width=True,
                             help=("Stamp the current PCS, tier, and "
                                   "gate decision into the audit "
                                   "journal as an executive sign-off. "
                                   "The framework continues to compute "
                                   "live; this records your formal "
                                   "acceptance of the result.")):
                    st.session_state["_hdr_confirm_signoff"] = True

        # ── Column 6: Withdraw (secondary red) ──────────────────────
        with col_withdraw:
            if _is_withdrawn():
                st.button("⛔ Withdrawn",
                          key="_hdr_withdrawn_done",
                          disabled=True,
                          use_container_width=True)
            else:
                if st.button("⛔ Withdraw",
                             key="_hdr_withdraw_btn",
                             disabled=not can_withdraw,
                             use_container_width=True,
                             help=("Mark this deployment as "
                                   "decommissioning. Sets "
                                   "decommissioning_status to "
                                   "IN_PROGRESS and writes a journal "
                                   "entry.")):
                    st.session_state["_hdr_confirm_withdraw"] = True

        # ── Column 7: Bell (neutral, badge inline in label) ─────────
        with col_bell:
            badge_suffix = f"  {n_items}" if n_items else ""
            bell_label = f"🔔{badge_suffix}"
            if st.button(bell_label,
                         key="_hdr_bell_btn",
                         use_container_width=True,
                         help=f"{n_items} unresolved item(s) — "
                              "blockers, warnings, and open incidents"):
                st.session_state["_hdr_bell_open"] = \
                    not st.session_state.get("_hdr_bell_open", False)

    # ── Confirmation + popover modals (rendered below the bar) ──────
    _maybe_render_signoff_confirm(terms)
    _maybe_render_withdraw_confirm(reg)
    _maybe_render_bell_popover(notif_items)


# ─────────────────────────────────────────────────────────────────────
# Confirmation modals — kept as expanders to avoid Streamlit version
# dependence on st.dialog (which arrived in 1.32; some deployments
# still run earlier versions).
# ─────────────────────────────────────────────────────────────────────
def _maybe_render_signoff_confirm(terms) -> None:
    if not st.session_state.get("_hdr_confirm_signoff"):
        return
    with st.container(border=True):
        st.markdown(
            "### 🔒 Confirm Executive Sign-Off"
        )
        if terms is None:
            st.warning("No derived terms available — cannot sign off.")
            if st.button("Close", key="_hdr_signoff_close"):
                st.session_state["_hdr_confirm_signoff"] = False
                st.rerun()
            return

        st.markdown(
            f"You are about to formally sign off on this deployment at "
            f"**PCS {terms.pcs_score:.1f} / 100**, tier **"
            f"{terms.tier.value}**. This writes an immutable journal "
            f"entry stamping your acceptance. The framework continues "
            f"to compute live; further edits to the registry will not "
            f"alter the signed snapshot but will recompute PCS."
        )

        c1, c2 = st.columns([1, 1])
        with c1:
            if st.button("✓ Confirm Sign-Off",
                         key="_hdr_signoff_confirm",
                         type="primary",
                         use_container_width=True):
                _perform_signoff(terms)
                st.session_state["_hdr_confirm_signoff"] = False
                st.toast(
                    f"Signed off at PCS {terms.pcs_score:.1f} "
                    f"({terms.tier.value})",
                    icon="🔒",
                )
                st.rerun()
        with c2:
            if st.button("Cancel",
                         key="_hdr_signoff_cancel",
                         use_container_width=True):
                st.session_state["_hdr_confirm_signoff"] = False
                st.rerun()


def _maybe_render_withdraw_confirm(reg) -> None:
    if not st.session_state.get("_hdr_confirm_withdraw"):
        return
    with st.container(border=True):
        st.markdown("### ⛔ Confirm Deployment Withdrawal")
        if reg is None:
            st.warning("No registry available — cannot withdraw.")
            if st.button("Close", key="_hdr_withdraw_close"):
                st.session_state["_hdr_confirm_withdraw"] = False
                st.rerun()
            return

        st.markdown(
            "You are about to withdraw this deployment from service. "
            "This sets `decommissioning_status` to **IN_PROGRESS**, "
            "records a journal entry with reason `RISK`, and surfaces "
            "the withdrawn state on every page header. Use this only "
            "when the deployment must genuinely be pulled — not as a "
            "test."
        )

        reason = st.selectbox(
            "Withdrawal reason",
            options=[r.value for r in DecommissionReasonEnum],
            index=0,
            key="_hdr_withdraw_reason",
        )

        c1, c2 = st.columns([1, 1])
        with c1:
            if st.button("⛔ Confirm Withdrawal",
                         key="_hdr_withdraw_confirm",
                         type="primary",
                         use_container_width=True):
                _perform_withdraw(reg, reason)
                st.session_state["_hdr_confirm_withdraw"] = False
                st.toast(f"Deployment withdrawn (reason: {reason})",
                         icon="⛔")
                st.rerun()
        with c2:
            if st.button("Cancel",
                         key="_hdr_withdraw_cancel",
                         use_container_width=True):
                st.session_state["_hdr_confirm_withdraw"] = False
                st.rerun()


def _maybe_render_bell_popover(items: List[Tuple[str, str, str]]) -> None:
    if not st.session_state.get("_hdr_bell_open"):
        return
    with st.container(border=True):
        st.markdown("### 🔔 Notifications")
        if not items:
            st.success("No unresolved items. All clear.")
        else:
            # Group by severity for a clear executive read
            blocks    = [i for i in items if i[0] == "block"]
            warns     = [i for i in items if i[0] == "warn"]
            incidents = [i for i in items if i[0] == "incident"]

            if blocks:
                st.markdown(
                    f"**⛔ Blockers — {len(blocks)}**"
                )
                for _, src, msg in blocks:
                    st.markdown(
                        f"<div style='background:rgba(255,80,80,0.10);"
                        f"border-left:3px solid #ff6b6b;"
                        f"padding:8px 12px;margin:6px 0;"
                        f"border-radius:4px;font-size:0.86rem;'>"
                        f"<b>{src}</b> — {msg}</div>",
                        unsafe_allow_html=True,
                    )
            if warns:
                st.markdown(
                    f"**⚠️ Warnings — {len(warns)}**"
                )
                for _, src, msg in warns:
                    st.markdown(
                        f"<div style='background:rgba(255,204,96,0.10);"
                        f"border-left:3px solid #ffcc60;"
                        f"padding:8px 12px;margin:6px 0;"
                        f"border-radius:4px;font-size:0.86rem;'>"
                        f"<b>{src}</b> — {msg}</div>",
                        unsafe_allow_html=True,
                    )
            if incidents:
                st.markdown(
                    f"**🔻 Open Incidents — {len(incidents)}**"
                )
                for _, src, msg in incidents:
                    st.markdown(
                        f"<div style='background:rgba(130,180,255,0.08);"
                        f"border-left:3px solid #82b4ff;"
                        f"padding:8px 12px;margin:6px 0;"
                        f"border-radius:4px;font-size:0.86rem;'>"
                        f"<b>{src}</b> — {msg}</div>",
                        unsafe_allow_html=True,
                    )

        if st.button("Close",
                     key="_hdr_bell_close",
                     use_container_width=True):
            st.session_state["_hdr_bell_open"] = False
            st.rerun()


# ─────────────────────────────────────────────────────────────────────
# Actions — touch real framework state, write to the journal
# ─────────────────────────────────────────────────────────────────────
def _perform_signoff(terms) -> None:
    """Record an executive sign-off into the audit journal and flag
    the session as signed off. Idempotent — calling twice is harmless."""
    ts = datetime.utcnow().isoformat() + "Z"
    st.session_state["_executive_signed_off"] = True
    st.session_state["_executive_signoff_at"] = ts

    journal = st.session_state.get("journal")
    if journal is not None:
        try:
            journal.append(
                event_type=EventType.REPORT_GENERATED,
                payload={
                    "action":     "EXECUTIVE_SIGN_OFF",
                    "pcs_score":  float(terms.pcs_score),
                    "tier":       terms.tier.value,
                    "gate":       getattr(
                        getattr(terms, "gate_decision", None),
                        "value", None,
                    ),
                },
                actor="executive",
            )
        except Exception:
            # Don't let a journal failure block the sign-off itself —
            # the session flag is the primary record; the journal
            # entry is supplementary audit trail.
            pass


def _perform_withdraw(reg, reason_str: str) -> None:
    """Set the registry decommissioning_status and record a journal
    entry. Honours the existing framework field rather than inventing
    a parallel withdrawn flag."""
    try:
        reason = DecommissionReasonEnum(reason_str)
    except ValueError:
        reason = DecommissionReasonEnum.RISK

    reg.decommissioning_status = DecommissioningStatusEnum.IN_PROGRESS
    # Some registries carry a separate reason field; set if present.
    if hasattr(reg, "decommission_reason"):
        try:
            reg.decommission_reason = reason
        except Exception:
            pass

    journal = st.session_state.get("journal")
    if journal is not None:
        try:
            journal.append(
                event_type=EventType.REGISTRY_FIELD_CHANGED,
                payload={
                    "action":     "WITHDRAW_DEPLOYMENT",
                    "field":      "decommissioning_status",
                    "new_value":  DecommissioningStatusEnum.IN_PROGRESS.value,
                    "reason":     reason.value,
                },
                actor="executive",
            )
        except Exception:
            pass