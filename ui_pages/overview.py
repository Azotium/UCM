"""ui_pages/overview.py — Dashboard overview."""

import streamlit as st
from modules.stats import StatsEngine



def render():
    st.title(":color[🛡️ Detection Engineering Platform]{foreground='#101e87'}")
    st.markdown("##### Azure DevOps · Sigma · Elastic · MITRE ATT&CK")

    # Guard: no ADO connection yet — show onboarding instructions
    if not st.session_state.get("ado_client"):
        st.info("👈 Connect to Azure DevOps in the sidebar to get started.")
        _show_quickstart()
        return

    use_cases = st.session_state.get("use_cases", [])

    # Guard: connected but no use cases loaded yet
    if not use_cases:
        st.warning("No use cases loaded. Select a repo and branch in the sidebar, then click **Load Use Cases**.")
        return
    
    # ── Auto-refresh ──────────────────────────────────────────────────────────
    # Runs the full pipeline (content load → validation → MITRE → stats)
    # if the use case list has changed since the last render.
    # Results are cached in session_state and shared with all other pages.
    from modules.shared import auto_refresh
    auto_refresh()
 
    stats = st.session_state.get("stats")
    if not stats:
        st.info("Computing statistics…")
        return

    # ── Top metrics ───────────────────────────────────────────────────────────
    col1, col2, col3, col4, col5 = st.columns(5)

    # Count UCs that have all required files (README + Sigma + ≥1 SIEM rule)
    complete = sum(1 for uc in use_cases if uc.is_complete)

    # Technique count comes from MITRE coverage (may be None if no Sigma content)
    mitre = st.session_state.get("mitre_coverage")
    tech_count = len(mitre.techniques) if mitre else 0
    avg_health = stats.avg_health if stats else 0

    with col1:
        st.metric("Total Rules", len(use_cases))
    with col2:
        # delta shows the percentage of complete rules
        st.metric("Complete", complete, delta=f"{complete/len(use_cases)*100:.0f}%")
    with col3:
        st.metric("Missing Files", len(use_cases) - complete)
    with col4:
        st.metric("ATT&CK Techniques", tech_count)
    with col5:
        st.metric("Avg Health Score", f"{avg_health:.0f}/100")

    # ── Quick health table ────────────────────────────────────────────────────
    #if stats:
    st.markdown("---")
    st.markdown("#### 🩺 Rule Health")

    # Manual refresh button — only shown after validation has run so that
    # engineers can re-compute health scores after fixing issues
    if st.session_state.get("sigma_results") or st.session_state.get("readme_results"):
        if st.button("🔄 Refresh scores", help="Re-compute with latest validation results"):
            # Clear cached stats so auto_refresh rebuilds them on next render
            st.session_state.stats = None
            st.session_state.stats_fingerprint = None
            st.rerun()
 
    import pandas as pd
    df = stats.to_dataframe(stats) # returns DataFrame sorted by score ascending (worst first)

    # Add a visual health bar column (20-char ASCII bar + numeric score)
    df["Health Bar"] = df["score"].apply(_health_bar)
    st.dataframe(
        df[["name", "score", "Health Bar", "folder"]].rename(
            columns={"name": "Use Case", "score": "Score", "folder": "Path"}
        ),
        width="content",
        hide_index=True,
    )


def _health_bar(score: float) -> str:
    """
    Convert a 0–100 health score to a 20-character ASCII progress bar.
    Each filled block represents 5 points (100 / 20 = 5 pts/block).
    """
    filled = int(score / 5)
    return "█" * filled + "░" * (20 - filled) + f"  {score:.0f}"


def _show_quickstart():
    """Render onboarding instructions for first-time users."""
    st.markdown("---")
    st.markdown("#### Quick Start")
    st.markdown("""
1. Enter your **Azure DevOps org URL** and a **Personal Access Token** (PAT) in the sidebar
2. Select your **project**, **repository**, and **branch**
3. Click **Load Use Cases** to scan the repo
4. Navigate to **Validator**, **MITRE Coverage**, or **Statistics**

**PAT permissions required:** Code (read), Pull Requests (read/write)
    """)
