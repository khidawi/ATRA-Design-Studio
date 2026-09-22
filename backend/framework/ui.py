"""Shared dark-theme CSS and UI helper functions.

v4 visual refresh — modern dashboard aesthetic inspired by data-product UIs:
  • Deeper indigo background palette (#0a0d18, #131727, #1a1f33)
  • Glassmorphic cards: subtle borders, soft elevation, gentle backdrop
  • Accent gradients on headers, active radio, primary buttons
  • Richer typography (Inter fallback chain, weighted hierarchy)
  • Animated transitions on hover/focus for interactive elements
  • Auto-hiding sidebar (hover-to-peek, click-to-lock) retained
"""
import streamlit as st
from framework.enums import ActionTierEnum, PCS_TIER_COLOURS, PCS_TIER_BG, TIER_EMOJI


DARK_CSS = """
<style>
/* ════════════════════════════════════════════════════════════════════════
   GLOBAL — typography, background palette, scrollbars
   ════════════════════════════════════════════════════════════════════════ */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
    font-feature-settings: 'cv11', 'ss01', 'ss03' !important;
}

.stApp,[data-testid="stAppViewContainer"],.main{
    background:
        radial-gradient(ellipse at top left, rgba(76,138,255,0.06) 0%, transparent 50%),
        radial-gradient(ellipse at bottom right, rgba(130,84,255,0.05) 0%, transparent 50%),
        #0a0d18 !important;
    color:#e8eaf0!important;
}

::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:#0a0d18}
::-webkit-scrollbar-thumb{
    background:linear-gradient(180deg,#2a3458,#3a4878);
    border-radius:4px;
}
::-webkit-scrollbar-thumb:hover{background:#4a5a8c}

/* ════════════════════════════════════════════════════════════════════════
   SIDEBAR — auto-reveal on hover near the left edge of the viewport
   • Fully hidden by default (slides 100% off-screen).
   • A 36px-wide invisible hot zone runs down the viewport's left edge.
     Hover this zone → sidebar slides in. Hover the sidebar → stays open.
     Move the mouse away → sidebar slides back out.
   • A small accent ribbon on the left edge tells users where to hover.
   • The collapsed-state chevron remains as a click-to-lock toggle.
   ════════════════════════════════════════════════════════════════════════ */
[data-testid="stSidebar"]{
    background:linear-gradient(180deg,#0d1124 0%,#131727 100%)!important;
    border-right:1px solid rgba(76,138,255,0.12)!important;
    box-shadow:inset -1px 0 0 rgba(255,255,255,0.02)!important;
}
[data-testid="stSidebar"] *{color:#c8ccd8!important}

/* Hidden state — fully off-screen */
section[data-testid="stSidebar"][aria-expanded="false"]{
    transform:translateX(-100%)!important;
    transition:transform 280ms cubic-bezier(.16,.84,.24,1),box-shadow 280ms ease!important;
    overflow:visible!important;
    z-index:1001!important;
}
/* Hovering the sidebar itself keeps it open (slides it back into view) */
section[data-testid="stSidebar"][aria-expanded="false"]:hover{
    transform:translateX(0)!important;
    box-shadow:14px 0 44px rgba(0,0,0,0.7),
               0 0 0 1px rgba(76,138,255,0.18)!important;
}

/* Invisible hover hot-zone anchored to the viewport's left edge.
   Lives on the app-view container so it stays put when the sidebar moves.
   36px wide × full height. When the user's cursor enters this strip,
   the :has() selector activates the sidebar peek state. */
[data-testid="stAppViewContainer"]::before{
    content:"";
    position:fixed;
    top:0;left:0;
    width:36px;height:100vh;
    background:transparent;
    z-index:1000;
    pointer-events:auto;
    cursor:pointer;
}
/* :has() lets us reach across the DOM: when the hot-zone is hovered,
   force the sidebar to slide in. Supported in all modern browsers (2023+). */
body:has([data-testid="stAppViewContainer"]::before:hover) section[data-testid="stSidebar"][aria-expanded="false"]{
    transform:translateX(0)!important;
    box-shadow:14px 0 44px rgba(0,0,0,0.7),
               0 0 0 1px rgba(76,138,255,0.18)!important;
}

/* Vertical accent ribbon on the viewport's left edge — tells users where
   to hover. Three-stop gradient (cyan → violet → cyan) with a soft glow.
   Fades out when the sidebar opens. */
[data-testid="stAppViewContainer"]::after{
    content:"";
    position:fixed;
    top:50%;left:0;
    transform:translateY(-50%);
    width:3px;height:88px;
    background:linear-gradient(180deg,
        transparent 0%,
        rgba(76,138,255,0.55) 15%,
        rgba(130,84,255,0.85) 50%,
        rgba(76,138,255,0.55) 85%,
        transparent 100%);
    border-radius:0 3px 3px 0;
    pointer-events:none;
    z-index:999;
    box-shadow:0 0 18px rgba(76,138,255,0.55),
               0 0 6px rgba(130,84,255,0.4);
    transition:opacity 280ms ease,height 280ms ease;
    animation:ribbon-pulse 3s ease-in-out infinite;
}
@keyframes ribbon-pulse{
    0%,100%{opacity:0.7;height:88px}
    50%    {opacity:1.0;height:108px}
}
/* Fade ribbon when sidebar is open */
body:has(section[data-testid="stSidebar"][aria-expanded="true"]) [data-testid="stAppViewContainer"]::after,
body:has(section[data-testid="stSidebar"]:hover) [data-testid="stAppViewContainer"]::after{
    opacity:0;
}

/* Collapsed-state chevron — kept as a click toggle, subtle when not focused */
[data-testid="stSidebarCollapsedControl"],
[data-testid="collapsedControl"]{
    background:linear-gradient(135deg,rgba(26,32,53,0.7),rgba(36,44,72,0.7))!important;
    border:1px solid rgba(76,138,255,0.25)!important;
    border-left:none!important;
    border-radius:0 10px 10px 0!important;
    padding:10px 12px!important;
    color:#82b4ff!important;
    z-index:1002!important;
    box-shadow:2px 0 12px rgba(0,0,0,0.4)!important;
    transition:all 220ms ease!important;
    opacity:0.55!important;
}
[data-testid="stSidebarCollapsedControl"]:hover,
[data-testid="collapsedControl"]:hover{
    background:linear-gradient(135deg,#1a2a4a,#243466)!important;
    color:#fff!important;border-color:#4c8aff!important;
    box-shadow:2px 0 18px rgba(76,138,255,0.4)!important;
    opacity:1!important;
}
[data-testid="stSidebarCollapsedControl"] svg,
[data-testid="collapsedControl"] svg{
    width:20px!important;height:20px!important;
    color:#82b4ff!important;fill:#82b4ff!important;
}

section[data-testid="stMain"],.main .block-container{
    transition:padding-left 280ms ease,max-width 280ms ease!important;
    padding-top:2.5rem!important;
}

/* ════════════════════════════════════════════════════════════════════════
   TYPOGRAPHY — hierarchy with accent gradients
   ════════════════════════════════════════════════════════════════════════ */
p,span,label,div,li{color:#e8eaf0!important}

h1{
    color:transparent!important;
    background:linear-gradient(135deg,#82b4ff 0%,#b69cff 100%)!important;
    -webkit-background-clip:text!important;
    background-clip:text!important;
    font-size:2.0rem!important;
    font-weight:800!important;
    letter-spacing:-0.02em!important;
    margin-bottom:6px!important;
}
h2{
    color:#a0c4ff!important;
    font-size:1.35rem!important;
    font-weight:700!important;
    letter-spacing:-0.01em!important;
    margin-top:1.2rem!important;
}
h3{
    color:#b8d4ff!important;
    font-size:1.08rem!important;
    font-weight:600!important;
    letter-spacing:-0.005em!important;
}

/* ════════════════════════════════════════════════════════════════════════
   METRICS — glassmorphic cards with subtle elevation
   ════════════════════════════════════════════════════════════════════════ */
[data-testid="stMetric"]{
    background:linear-gradient(135deg,rgba(30,36,64,0.6) 0%,rgba(20,25,46,0.6) 100%)!important;
    backdrop-filter:blur(10px)!important;
    border:1px solid rgba(76,138,255,0.18)!important;
    border-radius:14px!important;
    padding:18px 22px!important;
    box-shadow:0 4px 20px rgba(0,0,0,0.25),inset 0 1px 0 rgba(255,255,255,0.04)!important;
    transition:all 240ms ease!important;
}
[data-testid="stMetric"]:hover{
    border-color:rgba(76,138,255,0.35)!important;
    transform:translateY(-1px)!important;
    box-shadow:0 6px 28px rgba(76,138,255,0.15),inset 0 1px 0 rgba(255,255,255,0.06)!important;
}
[data-testid="stMetricLabel"]{
    color:#8899bb!important;
    font-size:.78rem!important;
    font-weight:500!important;
    text-transform:uppercase!important;
    letter-spacing:0.06em!important;
}
[data-testid="stMetricValue"]{
    color:transparent!important;
    background:linear-gradient(135deg,#82b4ff 0%,#a89cff 100%)!important;
    -webkit-background-clip:text!important;
    background-clip:text!important;
    font-size:2.0rem!important;
    font-weight:800!important;
    line-height:1.1!important;
}
[data-testid="stMetricDelta"]{font-size:.85rem!important}

/* ════════════════════════════════════════════════════════════════════════
   BUTTONS — gradient primary, subtle secondary, download accent
   ════════════════════════════════════════════════════════════════════════ */
.stButton>button{
    background:linear-gradient(135deg,#1e2a4d 0%,#26345c 100%)!important;
    color:#c8dcff!important;
    border:1px solid rgba(76,138,255,0.3)!important;
    border-radius:10px!important;
    font-weight:600!important;
    padding:10px 22px!important;
    letter-spacing:0.01em!important;
    transition:all 220ms cubic-bezier(.2,.8,.2,1)!important;
    box-shadow:0 2px 8px rgba(0,0,0,0.2)!important;
}
.stButton>button:hover{
    background:linear-gradient(135deg,#2a3a6a 0%,#3a4d80 100%)!important;
    border-color:#4c8aff!important;
    color:#ffffff!important;
    transform:translateY(-1px)!important;
    box-shadow:0 6px 18px rgba(76,138,255,0.25)!important;
}
.stButton>button[kind="primary"]{
    background:linear-gradient(135deg,#1560c0 0%,#3a7fdb 50%,#5a4cd6 100%)!important;
    color:#fff!important;
    border-color:rgba(255,255,255,0.15)!important;
    font-weight:700!important;
    box-shadow:0 4px 16px rgba(76,138,255,0.3)!important;
}
.stButton>button[kind="primary"]:hover{
    background:linear-gradient(135deg,#2070d8 0%,#4a8fec 50%,#6a5ce0 100%)!important;
    box-shadow:0 6px 22px rgba(76,138,255,0.45)!important;
}
[data-testid="stDownloadButton"] button{
    background:linear-gradient(135deg,#0d3520 0%,#1a5a35 100%)!important;
    color:#7fe8a5!important;
    border:1px solid rgba(96,208,128,0.35)!important;
    border-radius:10px!important;
    font-weight:600!important;
    box-shadow:0 2px 10px rgba(46,125,50,0.2)!important;
}
[data-testid="stDownloadButton"] button:hover{
    background:linear-gradient(135deg,#1a5a35 0%,#2a7a4a 100%)!important;
    border-color:#60d080!important;
    box-shadow:0 4px 16px rgba(96,208,128,0.3)!important;
}

/* ════════════════════════════════════════════════════════════════════════
   EXPANDER + INFO / WARNING / ERROR / SUCCESS callouts
   ════════════════════════════════════════════════════════════════════════ */
[data-testid="stExpander"]{
    background:rgba(20,25,46,0.55)!important;
    backdrop-filter:blur(8px)!important;
    border:1px solid rgba(76,138,255,0.15)!important;
    border-radius:12px!important;
    margin-bottom:10px!important;
    transition:border-color 200ms ease!important;
}
[data-testid="stExpander"]:hover{border-color:rgba(76,138,255,0.28)!important}
[data-testid="stExpander"] summary{
    color:#a0bce8!important;font-weight:600!important;
    padding:10px 14px!important;
}

div[data-testid="stInfo"]{
    background:linear-gradient(135deg,rgba(13,35,64,0.7) 0%,rgba(20,55,100,0.5) 100%)!important;
    border:1px solid rgba(76,138,255,0.35)!important;
    color:#9ec6ff!important;
    border-radius:10px!important;
    backdrop-filter:blur(6px)!important;
}
div[data-testid="stWarning"]{
    background:linear-gradient(135deg,rgba(42,30,0,0.7) 0%,rgba(80,60,5,0.5) 100%)!important;
    border:1px solid rgba(255,204,96,0.35)!important;
    color:#ffd47a!important;
    border-radius:10px!important;
    backdrop-filter:blur(6px)!important;
}
div[data-testid="stError"]{
    background:linear-gradient(135deg,rgba(42,13,13,0.7) 0%,rgba(80,20,20,0.5) 100%)!important;
    border:1px solid rgba(255,128,128,0.35)!important;
    color:#ff9a9a!important;
    border-radius:10px!important;
    backdrop-filter:blur(6px)!important;
}
div[data-testid="stSuccess"]{
    background:linear-gradient(135deg,rgba(13,42,20,0.7) 0%,rgba(20,80,35,0.5) 100%)!important;
    border:1px solid rgba(96,208,128,0.35)!important;
    color:#8fe8a8!important;
    border-radius:10px!important;
    backdrop-filter:blur(6px)!important;
}

/* ════════════════════════════════════════════════════════════════════════
   TABLES + DATAFRAMES — modern data-product styling
   ════════════════════════════════════════════════════════════════════════ */
[data-testid="stDataFrame"]{
    background:rgba(20,25,46,0.55)!important;
    backdrop-filter:blur(8px)!important;
    border:1px solid rgba(76,138,255,0.18)!important;
    border-radius:12px!important;
}
table{
    width:100%!important;border-collapse:separate!important;border-spacing:0!important;
    font-size:.88rem!important;border-radius:10px!important;overflow:hidden!important;
}
table th{
    background:linear-gradient(180deg,#1f2a4a 0%,#1a2440 100%)!important;
    color:#a0c0f0!important;
    font-weight:700!important;
    padding:12px 16px!important;
    border-bottom:2px solid rgba(76,138,255,0.25)!important;
    letter-spacing:0.02em!important;
    text-transform:uppercase!important;
    font-size:.78rem!important;
}
table td{
    color:#c8ccd8!important;
    padding:10px 16px!important;
    border-bottom:1px solid rgba(76,138,255,0.08)!important;
    background:rgba(18,23,42,0.5)!important;
    transition:background 150ms ease!important;
}
table tr:hover td{background:rgba(28,38,68,0.65)!important}
table tr:nth-child(even) td{background:rgba(21,28,48,0.5)!important}
table tr:nth-child(even):hover td{background:rgba(30,40,72,0.65)!important}

/* ════════════════════════════════════════════════════════════════════════
   INPUTS — selectbox, text, number, textarea, radio
   ════════════════════════════════════════════════════════════════════════ */
input,textarea,select{
    background:rgba(30,37,64,0.7)!important;
    color:#e8eaf0!important;
    border:1px solid rgba(76,138,255,0.2)!important;
    border-radius:8px!important;
    transition:border-color 180ms ease,box-shadow 180ms ease!important;
}
input:focus,textarea:focus,select:focus{
    border-color:#4c8aff!important;
    box-shadow:0 0 0 3px rgba(76,138,255,0.15)!important;
    outline:none!important;
}
[data-baseweb="select"]>div{
    background:rgba(30,37,64,0.7)!important;
    border:1px solid rgba(76,138,255,0.2)!important;
    border-radius:8px!important;
}
[data-baseweb="select"]>div:hover{border-color:rgba(76,138,255,0.4)!important}

/* Radio buttons (sidebar navigation) — pill style with accent active */
.stRadio>div{gap:4px!important}
.stRadio label{
    color:#c8ccd8!important;
    padding:8px 12px!important;
    border-radius:8px!important;
    transition:background 180ms ease!important;
    width:100%!important;
}
.stRadio label:hover{background:rgba(76,138,255,0.08)!important}
.stRadio label[data-checked="true"],
.stRadio [role="radio"][aria-checked="true"]+div{
    background:linear-gradient(90deg,rgba(76,138,255,0.18) 0%,rgba(130,84,255,0.12) 100%)!important;
    border-left:3px solid #4c8aff!important;
}
.stCheckbox label{color:#c8ccd8!important}

hr{border:none!important;border-top:1px solid rgba(76,138,255,0.15)!important;margin:1.5rem 0!important}

/* ════════════════════════════════════════════════════════════════════════
   CODE BLOCKS + INLINE CODE
   ════════════════════════════════════════════════════════════════════════ */
.stCodeBlock,code,pre{
    background:rgba(8,11,22,0.85)!important;
    color:#7ee8b0!important;
    border:1px solid rgba(76,138,255,0.18)!important;
    border-radius:8px!important;
    font-family:'JetBrains Mono','Menlo','Monaco',monospace!important;
    font-feature-settings:'cv02','cv11'!important;
}
.katex{color:#b0d0ff!important}

/* ════════════════════════════════════════════════════════════════════════
   TABS — modern underlined accent
   ════════════════════════════════════════════════════════════════════════ */
[data-baseweb="tab-list"]{
    background:transparent!important;
    border-bottom:1px solid rgba(76,138,255,0.18)!important;
    gap:4px!important;
}
[data-baseweb="tab"]{
    background:transparent!important;
    color:#8899bb!important;
    font-weight:600!important;
    padding:10px 16px!important;
    transition:all 200ms ease!important;
    border-radius:8px 8px 0 0!important;
}
[data-baseweb="tab"]:hover{color:#c8dcff!important;background:rgba(76,138,255,0.06)!important}
[data-baseweb="tab"][aria-selected="true"]{
    color:#82b4ff!important;
    background:linear-gradient(180deg,rgba(76,138,255,0.12) 0%,transparent 100%)!important;
    border-bottom:2px solid #4c8aff!important;
}

/* Progress bars */
.stProgress>div>div{
    background:linear-gradient(90deg,#4c8aff 0%,#8254ff 100%)!important;
    border-radius:6px!important;
}

/* ════════════════════════════════════════════════════════════════════════
   ST-AI COMPONENT STYLES — tier boxes, cards, section headers
   ════════════════════════════════════════════════════════════════════════ */
.tier-box{
    border-radius:14px;
    padding:20px 26px;
    margin:10px 0;
    border:1px solid;
    backdrop-filter:blur(8px);
    box-shadow:0 4px 24px rgba(0,0,0,0.25);
}

.layer-card{
    background:linear-gradient(135deg,rgba(22,27,49,0.7) 0%,rgba(16,21,40,0.6) 100%);
    backdrop-filter:blur(8px);
    border-radius:12px;
    padding:16px 20px;
    margin-bottom:12px;
    border-left:4px solid #4c8aff;
    border-top:1px solid rgba(76,138,255,0.12);
    border-right:1px solid rgba(76,138,255,0.12);
    border-bottom:1px solid rgba(76,138,255,0.12);
    transition:transform 200ms ease,border-left-color 200ms ease;
}
.layer-card:hover{
    transform:translateX(2px);
    border-left-color:#6ca0ff;
}

.blocker-box{
    background:linear-gradient(135deg,rgba(42,13,13,0.75) 0%,rgba(80,20,20,0.55) 100%);
    border:1px solid rgba(255,80,80,0.4);
    border-left:4px solid #ff5050;
    backdrop-filter:blur(6px);
    border-radius:12px;
    padding:14px 18px;margin:8px 0;
    color:#ffa0a0!important;
    box-shadow:0 2px 12px rgba(180,30,30,0.2);
}
.warning-box{
    background:linear-gradient(135deg,rgba(42,30,0,0.75) 0%,rgba(80,60,5,0.55) 100%);
    border:1px solid rgba(255,204,96,0.4);
    border-left:4px solid #ffcc60;
    backdrop-filter:blur(6px);
    border-radius:12px;
    padding:14px 18px;margin:8px 0;
    color:#ffd47a!important;
    box-shadow:0 2px 12px rgba(180,140,0,0.18);
}
.approved-box{
    background:linear-gradient(135deg,rgba(13,42,20,0.75) 0%,rgba(20,80,35,0.55) 100%);
    border:1px solid rgba(96,208,128,0.4);
    border-left:4px solid #60d080;
    backdrop-filter:blur(6px);
    border-radius:12px;
    padding:14px 18px;margin:8px 0;
    color:#9ee8b5!important;
    box-shadow:0 2px 12px rgba(40,130,60,0.18);
}
.rec-box{
    background:linear-gradient(135deg,rgba(13,32,64,0.75) 0%,rgba(20,55,100,0.55) 100%);
    border:1px solid rgba(122,180,255,0.4);
    border-left:4px solid #4c8aff;
    backdrop-filter:blur(6px);
    border-radius:12px;
    padding:13px 17px;margin:8px 0;
    color:#9ec6ff!important;
    box-shadow:0 2px 12px rgba(40,100,180,0.18);
}

.derive-row{
    background:rgba(14,19,38,0.5);
    border-left:2px solid rgba(76,138,255,0.3);
    border-radius:4px;
    padding:6px 12px;
    margin:3px 0;
    font-size:.82rem;
    color:#9aabc8!important;
    font-family:'JetBrains Mono','Menlo','Monaco',monospace;
}

.section-header{
    background:linear-gradient(90deg,
        rgba(26,42,74,0.85) 0%,
        rgba(36,30,80,0.7) 50%,
        rgba(13,26,48,0.6) 100%);
    backdrop-filter:blur(10px);
    padding:14px 22px;
    border-radius:12px;
    margin:18px 0 16px;
    border-left:4px solid #4c8aff;
    border-top:1px solid rgba(76,138,255,0.15);
    border-right:1px solid rgba(76,138,255,0.1);
    border-bottom:1px solid rgba(76,138,255,0.1);
    box-shadow:0 4px 18px rgba(0,0,0,0.2);
}
.section-header h3{
    color:transparent!important;
    background:linear-gradient(135deg,#82b4ff 0%,#b69cff 100%);
    -webkit-background-clip:text!important;
    background-clip:text!important;
    margin:0!important;
    font-size:1.05rem!important;
    font-weight:700!important;
    letter-spacing:-0.005em!important;
}

.phase-badge{
    display:inline-block;
    padding:4px 12px;
    border-radius:14px;
    font-size:.74rem;
    font-weight:700;
    margin-left:10px;
    letter-spacing:0.03em;
    text-transform:uppercase;
    box-shadow:0 2px 8px rgba(0,0,0,0.25);
    backdrop-filter:blur(4px);
}

/* Tooltips */
[data-baseweb="tooltip"]{
    background:#0f1426!important;
    border:1px solid rgba(76,138,255,0.25)!important;
    color:#e8eaf0!important;
    font-size:.8rem!important;
    border-radius:8px!important;
}

/* ════════════════════════════════════════════════════════════════════════
   TOAST NOTIFICATIONS — top-right pop-up, auto-dismisses after 6s
   Renders via st.markdown(<div class="stai-toast …">…</div>).
   Three flavours: blocked (red), approved (green), review (amber).
   The progress bar at the bottom shrinks over 6s, then the toast fades
   and slides off-screen via pure CSS animation (no JavaScript needed).
   ════════════════════════════════════════════════════════════════════════ */
.stai-toast{
    position:fixed;
    bottom:20px;right:20px;
    width:340px;
    z-index:10000;
    display:flex;
    align-items:flex-start;
    gap:12px;
    padding:14px 16px 16px 18px;
    border-radius:12px;
    backdrop-filter:blur(14px) saturate(140%);
    -webkit-backdrop-filter:blur(14px) saturate(140%);
    box-shadow:
        0 12px 40px rgba(0,0,0,0.55),
        inset 0 1px 0 rgba(255,255,255,0.08);
    border:1px solid;
    overflow:hidden;
    animation:
        toast-slide-in 360ms cubic-bezier(.16,.84,.24,1) 0s 1 both,
        toast-slide-out 480ms cubic-bezier(.4,0,1,1) 5.6s 1 forwards;
}
@keyframes toast-slide-in{
    from{transform:translateX(120%);opacity:0}
    to  {transform:translateX(0);opacity:1}
}
@keyframes toast-slide-out{
    from{transform:translateX(0);opacity:1}
    to  {transform:translateX(120%);opacity:0}
}

.toast-blocked{
    background:linear-gradient(135deg,
        rgba(58,10,10,0.92) 0%,
        rgba(96,20,20,0.85) 60%,
        rgba(120,28,28,0.80) 100%);
    border-color:rgba(255,80,80,0.5);
    color:#ffd0d0;
}
.toast-approved{
    background:linear-gradient(135deg,
        rgba(13,42,20,0.92) 0%,
        rgba(20,76,35,0.85) 60%,
        rgba(28,96,42,0.80) 100%);
    border-color:rgba(96,208,128,0.5);
    color:#d0f0d8;
}
.toast-review{
    background:linear-gradient(135deg,
        rgba(48,32,4,0.92) 0%,
        rgba(86,58,8,0.85) 60%,
        rgba(112,76,12,0.80) 100%);
    border-color:rgba(255,204,96,0.5);
    color:#ffe6b8;
}

.stai-toast-icon{
    font-size:1.4rem;
    line-height:1;
    flex-shrink:0;
    margin-top:1px;
}
.stai-toast-body{flex:1;min-width:0}
.stai-toast-title{
    font-weight:700;
    font-size:.92rem;
    letter-spacing:-0.005em;
    margin-bottom:4px;
    color:#fff;
}
.stai-toast-text{
    font-size:.78rem;
    line-height:1.45;
    opacity:0.88;
}
.stai-toast-bar{
    position:absolute;
    left:0;bottom:0;
    height:3px;
    background:linear-gradient(90deg,rgba(255,255,255,0.5),rgba(255,255,255,0.85));
    border-radius:0 0 12px 0;
    animation:toast-progress 6s linear 0s 1 forwards;
}
@keyframes toast-progress{
    from{width:100%}
    to  {width:0%}
}
.toast-blocked  .stai-toast-bar{background:linear-gradient(90deg,#ff7878,#ffb0b0)}
.toast-approved .stai-toast-bar{background:linear-gradient(90deg,#60d080,#a8eaba)}
.toast-review   .stai-toast-bar{background:linear-gradient(90deg,#ffcc60,#ffe0a0)}
</style>
"""


def inject_css():
    st.markdown(DARK_CSS, unsafe_allow_html=True)
    # Hide Streamlit's auto-generated sidebar page list (the alphabetical
    # link list it builds from pages/*.py). The framework provides its own
    # curated, gate-aware navigation radio in app.py, so the auto-list is
    # redundant and includes utility pages (entry_gate, session_restore)
    # that aren't meant to be user-navigable.
    st.markdown(
        "<style>"
        "[data-testid='stSidebarNav'] {display: none !important;}"
        "div[data-testid='stSidebarNav'] {display: none !important;}"
        "</style>",
        unsafe_allow_html=True,
    )


def tier_banner(tier: ActionTierEnum, pcs_score: float):
    """Full-width tier result banner — modernised with gradient + glassmorphism."""
    colours = {
        ActionTierEnum.CRITICAL: ("#ff6b6b", "#a82828",
                                  "linear-gradient(135deg,rgba(58,10,10,0.85),rgba(120,25,25,0.6))"),
        ActionTierEnum.HIGH:     ("#ffcc60", "#a87000",
                                  "linear-gradient(135deg,rgba(42,32,0,0.85),rgba(120,95,15,0.6))"),
        ActionTierEnum.MODERATE: ("#7fe89a", "#1f7a3a",
                                  "linear-gradient(135deg,rgba(10,32,16,0.85),rgba(25,90,45,0.6))"),
        ActionTierEnum.LOW:      ("#82b4ff", "#2a5fa0",
                                  "linear-gradient(135deg,rgba(10,21,48,0.85),rgba(30,75,160,0.6))"),
    }
    decisions = {
        ActionTierEnum.CRITICAL: "Deployment BLOCKED — remediate all conditions below",
        ActionTierEnum.HIGH:     "Constrained deployment — enhanced monitoring required",
        ActionTierEnum.MODERATE: "Deployment with documented monitoring plan",
        ActionTierEnum.LOW:      "Standard deployment with routine monitoring",
    }
    fg, border, gradient = colours[tier]
    emoji = TIER_EMOJI[tier]
    decision = decisions[tier]
    score_display = "UNDEFINED" if pcs_score == 999.0 else f"{pcs_score:.2f}"

    st.markdown(f"""
    <div style='background:{gradient};border:1px solid {border};border-radius:16px;
                padding:24px 30px;margin:18px 0;backdrop-filter:blur(10px);
                box-shadow:0 8px 32px rgba(0,0,0,0.35),inset 0 1px 0 rgba(255,255,255,0.04);'>
        <div style='display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;'>
            <span style='font-size:1.8rem;'>{emoji}</span>
            <span style='font-size:1.7rem;font-weight:800;color:{fg};
                         letter-spacing:-0.02em;'>{tier.value}</span>
            <span style='font-size:1.1rem;color:#8899bb;font-weight:500;'>·</span>
            <span style='font-size:1.5rem;font-weight:700;color:#e8eaf0;'>
                PCS = <span style='color:{fg};'>{score_display}</span>
            </span>
        </div>
        <div style='color:#c8ccd8;margin-top:8px;font-size:0.98rem;
                    font-weight:400;line-height:1.5;'>{decision}</div>
    </div>
    """, unsafe_allow_html=True)


def section_header(title: str, phase: str = "", icon: str = ""):
    phase_colours = {
        "Design-time": ("linear-gradient(135deg,#3c5a8a,#4a6fa8)", "#fff"),
        "Deployment":  ("linear-gradient(135deg,#2e7d32,#3a9542)", "#fff"),
        "Runtime":     ("linear-gradient(135deg,#1a6a50,#22826a)", "#fff"),
        "Governance":  ("linear-gradient(135deg,#4a148c,#6020a8)", "#fff"),
        "EOL":         ("linear-gradient(135deg,#8a2a2a,#a83838)", "#fff"),
    }
    phase_html = ""
    if phase:
        pgrad, ptext = phase_colours.get(phase, ("linear-gradient(135deg,#3a4560,#4a5878)", "#fff"))
        phase_html = (
            f"<span class='phase-badge' style='background:{pgrad};color:{ptext};'>{phase}</span>"
        )
    icon_html = ""
    if icon:
        icon_html = (
            f"<span style='font-size:1.15rem;margin-right:6px;'>{icon}</span>"
        )
    st.markdown(f"""
    <div class='section-header'>
        <h3>{icon_html}{title} {phase_html}</h3>
    </div>
    """, unsafe_allow_html=True)


def blocker_card(text: str):
    st.markdown(f"<div class='blocker-box'>⛔ {text}</div>", unsafe_allow_html=True)


def warning_card(text: str):
    st.markdown(f"<div class='warning-box'>{text}</div>", unsafe_allow_html=True)


def approved_card(text: str):
    st.markdown(f"<div class='approved-box'>✅ {text}</div>", unsafe_allow_html=True)


def rec_card(text: str):
    st.markdown(f"<div class='rec-box'>{text}</div>", unsafe_allow_html=True)


def derive_row(text: str):
    st.markdown(f"<div class='derive-row'>→ {text}</div>", unsafe_allow_html=True)