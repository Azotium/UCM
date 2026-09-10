"""ui_pages/mitre.py — MITRE ATT&CK coverage heatmap and Navigator export."""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import json
from modules.mitre_mapper import MitreMapper


TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

TACTIC_LABELS = {t: t.replace("-", " ").title() for t in TACTIC_ORDER}

TACTIC_COLORS = {
    "reconnaissance":       "#6e40aa",
    "resource-development": "#7c3aed",
    "initial-access":       "#e53e3e",
    "execution":            "#dd6b20",
    "persistence":          "#d69e2e",
    "privilege-escalation": "#ecc94b",
    "defense-evasion":      "#48bb78",
    "credential-access":    "#38b2ac",
    "discovery":            "#4299e1",
    "lateral-movement":     "#667eea",
    "collection":           "#9f7aea",
    "command-and-control":  "#ed64a6",
    "exfiltration":         "#f687b3",
    "impact":               "#fc8181",
}


def render():
    st.title("🛡️ MITRE ATT&CK Coverage")

    use_cases = st.session_state.get("use_cases", [])
    client = st.session_state.get("ado_client")

    if not use_cases:
        st.info("Load use cases from the sidebar first.")
        return

        # ── Auto-refresh ──────────────────────────────────────────────────────────
    from modules.shared import auto_refresh
    auto_refresh()

    coverage = st.session_state.get("mitre_coverage")
 
    col1, col2 = st.columns([4, 1])
    with col2:
        if st.button("🔄 Rebuild Coverage", width="content"):
            _build_coverage(use_cases, client)
            st.rerun()
 
    if not coverage:
        with col1:
            st.info("No coverage data yet — click **Rebuild Coverage**.")
        return

    # ── KPI row ───────────────────────────────────────────────────────────────
    tactic_counts  = coverage.tactic_counts
    covered_tac    = len(tactic_counts)
    uncovered_tac  = len(TACTIC_ORDER) - covered_tac
    total_tech     = len(coverage.techniques)
    most_covered   = max(tactic_counts, key=tactic_counts.get, default="—")
    least_covered  = min(
        (t for t in TACTIC_ORDER if t in tactic_counts),
        key=lambda t: tactic_counts[t],
        default="—"
    )
    coverage_score = round(covered_tac / len(TACTIC_ORDER) * 100)
 
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1: st.metric("Techniques",       total_tech)
    with c2: st.metric("Tactics Covered",  covered_tac)
    with c3: st.metric("Tactics Gaps",     uncovered_tac)
    with c4: st.metric("Coverage Score",   f"{coverage_score}%")
    with c5: st.metric("Most Covered",     TACTIC_LABELS.get(most_covered, most_covered))
    with c6: st.metric("Least Covered",    TACTIC_LABELS.get(least_covered, least_covered))
 
    st.markdown("---")
 
    tabs = st.tabs([
        "📊 Tactic Heatmap",
        "🔬 Technique Breakdown",
        "🕳️ Gap Analysis",
        "🔍 Tactic Drilldown",
        "📋 Coverage Table",
        "🗺️ Navigator Export",
    ])
 
    # ── Tab 1: Tactic heatmap ─────────────────────────────────────────────────
    with tabs[0]:
        tac_df = _build_tactic_df(tactic_counts)
 
        fig = px.bar(
            tac_df, x="Tactic", y="Rules",
            color="Rules",
            color_continuous_scale=[[0, "#1a1f2e"], [0.01, "#0d3b6e"], [1, "#1a73e8"]],
            template="plotly_dark", height=380,
            text="Rules",
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(13,17,23,1)",
            coloraxis_showscale=False, xaxis_tickangle=-35,
            margin=dict(t=20, b=60),
        )
        fig.update_traces(marker_line_width=0, textposition="outside")
        st.plotly_chart(fig, width="content")
 
        gaps = tac_df[tac_df["Rules"] == 0]["Tactic"].tolist()
        if gaps:
            st.warning(f"**{len(gaps)} uncovered tactics:** " + "  ·  ".join(gaps))
        else:
            st.success("All 14 ATT&CK tactics have at least one detection rule 🎉")
 
        # Coverage % progress per tactic
        st.markdown("##### Coverage by tactic")
        max_count = tac_df["Rules"].max() or 1
        for _, row in tac_df.iterrows():
            pct = int(row["Rules"] / max_count * 100)
            tkey = next((k for k, v in TACTIC_LABELS.items() if v == row["Tactic"]), "")
            color = TACTIC_COLORS.get(tkey, "#58a6ff")
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            st.markdown(
                f"`{row['Tactic']:<28}` {bar}  **{int(row['Rules'])}** rule(s)",
                unsafe_allow_html=False,
            )
 
    # ── Tab 2: Technique breakdown (treemap) ──────────────────────────────────
    with tabs[1]:
        mapper = MitreMapper()
        rows   = mapper.heatmap_data(coverage)
 
        if not rows:
            st.info("No technique data available.")
        else:
            df = pd.DataFrame(rows)
            df["tactic_label"] = df["tactic"].apply(lambda t: TACTIC_LABELS.get(t, t.title()))
 
            col_tree, col_bubble = st.columns(2)
 
            with col_tree:
                st.markdown("**Treemap by tactic → technique**")
                fig2 = px.treemap(
                    df, path=["tactic_label", "technique_id"],
                    values="count",
                    color="count",
                    color_continuous_scale=[[0, "#0d3b6e"], [1, "#1a73e8"]],
                    template="plotly_dark", height=460,
                    hover_data={"technique_name": True, "use_cases": True},
                )
                fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", margin=dict(t=20))
                st.plotly_chart(fig2, width="content")
 
            with col_bubble:
                st.markdown("**Bubble chart — rule count per technique**")
                df_sorted = df.sort_values("count", ascending=False).head(30)
                fig3 = px.scatter(
                    df_sorted,
                    x="tactic_label", y="technique_id",
                    size="count", color="count",
                    color_continuous_scale=[[0, "#0d3b6e"], [1, "#1a73e8"]],
                    template="plotly_dark", height=460,
                    hover_data={"technique_name": True, "use_cases": True, "count": True},
                    labels={"tactic_label": "Tactic", "technique_id": "Technique"},
                )
                fig3.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(13,17,23,1)",
                    xaxis_tickangle=-35, margin=dict(t=20, b=60),
                    coloraxis_showscale=False,
                )
                st.plotly_chart(fig3, width="content")
 
            # Sub-technique stats
            sub_techs = [tid for tid in coverage.techniques if "." in tid]
            if sub_techs:
                st.markdown(f"**Sub-techniques covered:** {len(sub_techs)}")
                sub_df = pd.DataFrame([
                    {
                        "Sub-technique": tid,
                        "Name": coverage.techniques[tid]["name"],
                        "Parent": tid.split(".")[0],
                        "Rules": len(coverage.techniques[tid]["use_cases"]),
                        "Use Cases": ", ".join(coverage.techniques[tid]["use_cases"]),
                    }
                    for tid in sorted(sub_techs)
                ])
                st.dataframe(sub_df, width="content", hide_index=True)
 
    # ── Tab 3: Gap analysis ───────────────────────────────────────────────────
    with tabs[2]:
        st.markdown("#### 🕳️ Coverage Gaps")
        st.markdown("Tactics and techniques with **no detection rule** mapped.")
 
        # Uncovered tactics
        uncovered_tactics = [t for t in TACTIC_ORDER if t not in tactic_counts]
        if uncovered_tactics:
            st.error(f"**{len(uncovered_tactics)} tactics with zero coverage:**")
            cols = st.columns(min(len(uncovered_tactics), 4))
            for col, tac in zip(cols * 10, uncovered_tactics):
                col.markdown(
                    f"<div style='background:#3d1f1f;border:1px solid #f8514933;"
                    f"border-radius:6px;padding:8px 12px;text-align:center;"
                    f"color:#f85149;font-size:0.85rem'>{TACTIC_LABELS[tac]}</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.success("All 14 tactics covered ✅")
 
        st.markdown("---")
 
        # Tactics with only 1 rule (thin coverage)
        thin = {t: c for t, c in tactic_counts.items() if c == 1}
        if thin:
            st.warning(f"**{len(thin)} tactics with only 1 rule (thin coverage):**  " +
                       "  ·  ".join(TACTIC_LABELS.get(t, t) for t in thin))
 
        st.markdown("---")
        st.markdown("#### Recommendations")
 
        recs = []
        for tac in uncovered_tactics:
            recs.append({
                "Priority": "🔴 High",
                "Tactic": TACTIC_LABELS[tac],
                "Issue": "No coverage",
                "Suggestion": f"Add at least one detection rule for {TACTIC_LABELS[tac]}",
            })
        for tac, count in thin.items():
            recs.append({
                "Priority": "🟡 Medium",
                "Tactic": TACTIC_LABELS.get(tac, tac),
                "Issue": f"Only {count} rule",
                "Suggestion": f"Consider adding depth to {TACTIC_LABELS.get(tac, tac)} coverage",
            })
 
        if recs:
            st.dataframe(pd.DataFrame(recs), width="content", hide_index=True)
        else:
            st.success("No critical gaps identified 🎉")
 
        # Duplicate-covered techniques
        dupes = {
            tid: info for tid, info in coverage.techniques.items()
            if len(info["use_cases"]) > 1
        }
        if dupes:
            st.markdown("---")
            st.markdown(f"#### ♻️ Overlapping Coverage ({len(dupes)} techniques)")
            st.caption("Techniques covered by more than one rule — potential consolidation opportunities.")
            dupe_rows = [
                {
                    "Technique": tid,
                    "Name": info["name"],
                    "# Rules": len(info["use_cases"]),
                    "Use Cases": ", ".join(info["use_cases"]),
                }
                for tid, info in sorted(dupes.items(), key=lambda x: -len(x[1]["use_cases"]))
            ]
            st.dataframe(pd.DataFrame(dupe_rows), width="content", hide_index=True)
 
    # ── Tab 4: Tactic drilldown ───────────────────────────────────────────────
    with tabs[3]:
        st.markdown("#### 🔍 Tactic Drilldown")
        covered_tactic_list = [t for t in TACTIC_ORDER if t in tactic_counts]
 
        if not covered_tactic_list:
            st.info("No covered tactics to drill into.")
        else:
            selected_tactic = st.selectbox(
                "Select tactic",
                covered_tactic_list,
                format_func=lambda t: TACTIC_LABELS.get(t, t),
            )
 
            # Techniques in this tactic
            tac_techniques = {
                tid: info for tid, info in coverage.techniques.items()
                if selected_tactic in (info.get("tactics") or [])
            }
 
            if not tac_techniques:
                st.info("No technique details available — MITRE ATT&CK data may not be fully loaded.")
            else:
                st.markdown(f"**{len(tac_techniques)} technique(s)** mapped under "
                            f"**{TACTIC_LABELS.get(selected_tactic, selected_tactic)}**")
 
                for tid, info in sorted(tac_techniques.items()):
                    is_sub = "." in tid
                    indent = "  " if is_sub else ""
                    with st.expander(f"{indent}{'↳ ' if is_sub else ''}**{tid}** — {info['name'] or tid}  "
                                     f"({len(info['use_cases'])} rule(s))"):
                        for uc_name in info["use_cases"]:
                            st.markdown(f"- `{uc_name}`")
                        mitre_url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                        st.markdown(f"[🔗 MITRE ATT&CK page]({mitre_url})")
 
            # Rules in this tactic with NO sub-technique
            generic_rules = [
                uc_name
                for tid, info in tac_techniques.items()
                if "." not in tid
                for uc_name in info["use_cases"]
            ]
            st.markdown(f"**Rules covering this tactic (base techniques only):** {len(set(generic_rules))}")
 
    # ── Tab 5: Coverage table ─────────────────────────────────────────────────
    with tabs[4]:
        table_rows = []
        for tid, info in sorted(coverage.techniques.items()):
            table_rows.append({
                "Technique ID": tid,
                "Sub-technique": "✅" if "." in tid else "",
                "Name": info["name"] or tid,
                "Tactics": ", ".join(t.replace("-"," ").title() for t in (info.get("tactics") or [])),
                "# Rules": len(info["use_cases"]),
                "Use Cases": ", ".join(info["use_cases"]),
            })
        df_table = pd.DataFrame(table_rows)
 
        # Filter controls
        c1, c2 = st.columns(2)
        with c1:
            tac_filter = st.multiselect(
                "Filter by tactic",
                options=[TACTIC_LABELS[t] for t in TACTIC_ORDER],
                default=[],
            )
        with c2:
            min_rules = st.slider("Minimum rules", 0, 5, 0)
 
        if tac_filter:
            df_table = df_table[df_table["Tactics"].apply(
                lambda t: any(f.lower() in t.lower() for f in tac_filter)
            )]
        if min_rules > 0:
            df_table = df_table[df_table["# Rules"] >= min_rules]
 
        st.dataframe(df_table, width="content", hide_index=True)
        st.download_button("📥 Download CSV", df_table.to_csv(index=False),
                           "mitre_coverage.csv", "text/csv")
 
    # ── Tab 6: Navigator export ───────────────────────────────────────────────
    with tabs[5]:
        st.markdown(
            "Export a layer file for [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). "
            "Upload the downloaded JSON to visualise your coverage."
        )
        layer_name = st.text_input("Layer name", "Detection Coverage")
        mapper2    = MitreMapper()
        layer      = mapper2.navigator_layer(coverage, layer_name)
        layer_json = json.dumps(layer, indent=2)
 
        c1, c2 = st.columns(2)
        with c1:
            st.download_button("📥 Download Navigator Layer", layer_json,
                               "navigator_layer.json", "application/json",
                               width="content")
        with c2:
            st.markdown("[🔗 Open ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)")
 
        with st.expander("Preview layer JSON"):
            st.code(layer_json[:3000] + ("\n... (truncated)" if len(layer_json) > 3000 else ""),
                    language="json")
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
 
def _build_tactic_df(tactic_counts: dict) -> pd.DataFrame:
    rows = []
    for t in TACTIC_ORDER:
        rows.append({
            "Tactic":     TACTIC_LABELS[t],
            "tactic_key": t,
            "Rules":      tactic_counts.get(t, 0),
            "Covered":    t in tactic_counts,
        })
    return pd.DataFrame(rows)
 
 
def _build_coverage(use_cases, client):
    mapper  = MitreMapper()
    uc_data = []
    progress = st.progress(0, text="Loading Sigma files…")
 
    for i, uc in enumerate(use_cases):
        if uc.sigma:
            if not uc.sigma.content and client:
                try:
                    uc.sigma.content = client.load_file(uc.sigma)
                except Exception:
                    pass
            if uc.sigma.content:
                uc_data.append({"name": uc.name, "sigma_content": uc.sigma.content})
        progress.progress((i + 1) / len(use_cases))
 
    coverage = mapper.build_coverage(uc_data)
    st.session_state.mitre_coverage = coverage
    progress.empty()
    st.success(f"Coverage rebuilt — {len(coverage.techniques)} technique(s) mapped")
