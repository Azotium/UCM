"""ui_pages/overview.py — Dashboard overview."""

import streamlit as st
from modules.stats import StatsEngine



def render():
    st.title(":color[🛡️ Detection Engineering Platform]{foreground='#101e87'}")
    st.markdown("##### Azure DevOps · Sigma · Elastic · MITRE ATT&CK")

    if not st.session_state.get("ado_client"):
        st.info("👈 Connect to Azure DevOps in the sidebar to get started.")
        _show_quickstart()
        return

    use_cases = st.session_state.get("use_cases", [])


    if not use_cases:
        st.warning("No use cases loaded. Select a repo and branch in the sidebar, then click **Load Use Cases**.")
        return
    
    # ── Auto-refresh validation, MITRE and stats on every page load ─────────
    from modules.shared import auto_refresh
    auto_refresh()
 
    stats = st.session_state.get("stats")
    if not stats:
        st.info("Computing statistics…")
        return
    
    # # ── Auto-compute stats if missing or stale ────────────────────────────────
    # # Use a fingerprint based on the set of UC names so that loading a different
    # # repo/branch invalidates the cached stats automatically.

    # uc_fingerprint = frozenset(uc.name for uc in use_cases)
    # cached_fp      = st.session_state.get("stats_fingerprint")

    # if st.session_state.get("stats") is None or cached_fp != uc_fingerprint:
    #     engine = StatsEngine()
    #     stats, coverage  = engine.compute(
    #         use_cases=use_cases,
    #         sigma_results=st.session_state.get("sigma_results", {}),
    #         readme_results=st.session_state.get("readme_results", {}),
    #         mitre_coverage=st.session_state.get("mitre_coverage"),
    #     )
    #     st.session_state.stats             = stats
    #     st.session_state.stats_fingerprint = uc_fingerprint
    #     if coverage and not st.session_state.get("mitre_coverage"):
    #         st.session_state.mitre_coverage = coverage
 
    # stats = st.session_state.stats

    # ── Top metrics ───────────────────────────────────────────────────────────
    complete   = sum(1 for uc in use_cases if uc.is_complete)
    mitre      = st.session_state.get("mitre_coverage")
    tech_count = len(mitre.techniques) if mitre else 0
 
    cards = [
        ("Total Rules",      str(len(use_cases)),          None,                          None),
        ("Complete",         str(complete),                 f"{complete/len(use_cases)*100:.0f}%", "✅ Validator"),
        ("Missing Files",    str(len(use_cases)-complete),  None,                          "✅ Validator"),
        ("ATT&CK Techniques",str(tech_count),               None,                          "🛡️ MITRE Coverage"),
        ("Avg Health Score", f"{stats.avg_health:.0f}/100", None,                          "📊 Statistics"),
    ]
 
    # ── Build card HTML pieces (plain string concatenation, no f-string) ──────
    cards_html = ""
    for label, value, delta, target_page in cards:
        delta_span = ('<span style="font-size:12px;font-weight:400;color:#3fb950;'
                      'margin-left:6px;vertical-align:middle">▲ ' + delta + '</span>') if delta else ""
        hint       = ('<span style="display:block;font-size:10px;color:#484f58;'
                      'margin-top:6px">click to navigate →</span>') if target_page else ""
        if target_page:
            onclick = 'onclick="navigate(\'' + target_page.replace("'", "\\'") + '\')"'
            extra_style = "cursor:pointer;"
            hover_id    = "mc-link"
        else:
            onclick     = ""
            extra_style = ""
            hover_id    = ""
 
        cards_html += (
            '<div class="mc ' + hover_id + '" ' + onclick + ' style="' + extra_style + '">'
            '<div style="font-size:11px;color:#8b949e;text-transform:uppercase;'
            'letter-spacing:.06em;margin-bottom:6px">' + label + '</div>'
            '<div style="font-size:28px;font-weight:700;color:#58a6ff;line-height:1.15">'
            + value + ' ' + delta_span + '</div>'
            + hint +
            '</div>'
        )
 
    # CSS for cards + hide nav buttons (built without f-string to avoid brace escaping)
    nav_titles_css = ",".join(
        'button[title="' + tp + '"]'
        for _, _, _, tp in cards if tp
    )
    hide_css = (nav_titles_css + " {display:none!important}") if nav_titles_css else ""
 
    card_css = (
        "<style>"
        ".mc{flex:1;background:#0d1117;border:1px solid #21262d;border-radius:8px;"
        "padding:14px 16px 12px;min-height:88px}"
        ".mc-link{transition:border-color .15s,background .15s}"
        ".mc-link:hover{border-color:#58a6ff;background:#111820}"
        ".mc-link:active{background:#0d2137}"
        + hide_css +
        "</style>"
    )
 
    navigate_js = (
        "<script>"
        "function navigate(page){"
        "var btns=document.querySelectorAll('button[title=\"'+page+'\"]');"
        "if(btns.length)btns[0].click();}"
        "</script>"
    )
 
    row_html = (
        card_css
        + '<div style="display:flex;gap:12px;width:100%;margin-bottom:8px">'
        + cards_html
        + "</div>"
        + navigate_js
    )
 
    st.markdown(row_html, unsafe_allow_html=True)
 
    # ── Hidden trigger buttons (found by JS via title attribute) ─────────────
    for label, _, _, target_page in cards:
        if target_page:
            if st.button("·", key="nav_" + label.replace(" ", "_"),
                         help=target_page):
                st.session_state._navigate_to = target_page
                st.rerun()

    # ── Quick health table ────────────────────────────────────────────────────
    #if stats:
    st.markdown("---")
    st.markdown("#### 🩺 Rule Health")

    # If validator has run, offer a re-compute button so scores reflect new results
    if st.session_state.get("sigma_results") or st.session_state.get("readme_results"):
        if st.button("🔄 Refresh scores", help="Re-compute with latest validation results"):
            st.session_state.stats = None
            st.session_state.stats_fingerprint = None
            st.rerun()
 
    import pandas as pd
    df = stats.to_dataframe(stats)

    df["Health Bar"] = df["score"].apply(_health_bar)
    st.dataframe(
        df[["name", "score", "Health Bar", "folder"]].rename(
            columns={"name": "Use Case", "score": "Score", "folder": "Path"}
        ),
        width="content",
        hide_index=True,
    )


def _health_bar(score: float) -> str:
    filled = int(score / 5)
    return "█" * filled + "░" * (20 - filled) + f"  {score:.0f}"


def _show_quickstart():
    st.markdown("---")
    st.markdown("#### Quick Start")
    st.markdown("""
1. Enter your **Azure DevOps org URL** and a **Personal Access Token** (PAT) in the sidebar
2. Select your **project**, **repository**, and **branch**
3. Click **Load Use Cases** to scan the repo
4. Navigate to **Validator**, **MITRE Coverage**, or **Statistics**

**PAT permissions required:** Code (read), Pull Requests (read/write)
    """)

def _metric_card(label: str, value: str, delta: str | None, target_page: str | None):
    """
    Render a metric card.
    - Clickable cards: st.button with use_container_width, styled with a single
      global CSS block injected once per page load (keyed on session state).
    - Non-clickable cards: plain HTML div.
    """
    delta_html = f"  ▲ {delta}" if delta else ""
 
    if target_page:
        if st.button(
            f"{label}",
            key=f"mc_{label.replace(' ','_')}",
            use_container_width=True,
            help=f"Go to {target_page}",
        ):
            st.session_state._navigate_to = target_page
            st.rerun()
        # Show the value below the button as a styled markdown
        st.markdown(
            f"<div style='margin-top:-12px;padding:0 4px 8px'>"
            f"<span style='font-size:1.7rem;font-weight:700;color:#58a6ff'>{value}</span>"
            f"<span style='font-size:.78rem;color:#3fb950;margin-left:8px'>{delta_html}</span>"
            f"<br><span style='font-size:.68rem;color:#484f58'>click to navigate →</span>"
            f"</div>",
            unsafe_allow_html=True,
        )
    else:
        delta_div = f"<div style='font-size:.78rem;color:#3fb950;margin-top:3px'>▲ {delta}</div>" if delta else ""
        st.markdown(
            f"<div style='background:#0d1117;border:1px solid #21262d;border-radius:8px;"
            f"padding:.9rem 1.1rem;min-height:90px'>"
            f"<div style='font-size:.72rem;color:#8b949e;text-transform:uppercase;"
            f"letter-spacing:.05em;margin-bottom:4px'>{label}</div>"
            f"<div style='font-size:1.9rem;font-weight:700;color:#58a6ff;line-height:1.1'>{value}</div>"
            f"{delta_div}"
            f"</div>",
            unsafe_allow_html=True,
        )

