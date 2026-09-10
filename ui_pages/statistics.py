"""ui_pages/statistics.py — Detection repository statistics and health dashboard."""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from modules.stats import StatsEngine


def render():
    st.title("📊 Statistics")

    use_cases = st.session_state.get("use_cases", [])
    if not use_cases:
        st.info("Load use cases from the sidebar first.")
        return

    if st.button("🔄 Compute Statistics"):
        _compute(use_cases)

    stats = st.session_state.get("stats")
    if not stats:
        st.markdown("Click **Compute Statistics** (requires Validator to have run first for best results).")
        return
    
    mitre = st.session_state.get("mitre_coverage")
    tech_count = len(mitre.techniques) if mitre else 0

    # ── Top KPIs ──────────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1: st.metric("Total Rules", stats.total)
    with c2: st.metric("Complete", stats.complete)
    with c3: st.metric("Completeness", f"{stats.completeness_pct:.0f}%")
    with c4: st.metric("Avg Health", f"{stats.avg_health:.0f}/100")
    with c5: st.metric("ATT&CK Techniques", tech_count)
    with c6: st.metric("Missing SIEM Rule", stats.missing_siem)

    st.markdown("---")

    col_left, col_right = st.columns(2)

    # ── Severity distribution ─────────────────────────────────────────────────
    with col_left:
        st.markdown("#### Severity Distribution")
        if stats.by_level:
            level_order = ["critical", "high", "medium", "low", "informational", "unknown"]
            colors = {
                "critical":      "#f85149", 
                "high":          "#e3b341", 
                "medium":        "#58a6ff",
                "low":           "#3fb950", 
                "informational": "#8b949e", 
                "unknown":       "#484f58"
            }
            df_level = pd.DataFrame([
                {"Level": k.title(), "Count": v, "color": colors.get(k, "#58a6ff")}
                for k, v in stats.by_level.items()
            ])
            df_level["order"] = df_level["Level"].apply(
                lambda x: level_order.index(x.lower()) if x.lower() in level_order else 99
            )
            df_level = df_level.sort_values("order")
            fig = px.bar(df_level, x="Level", y="Count", color="Level",
                        color_discrete_map={k.title(): v for k, v in colors.items()},
                        template="plotly_dark", height=300)
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(13,17,23,1)",
                              showlegend=False, margin=dict(t=10, b=10))
            st.plotly_chart(fig, width='stretch')
        else:
            st.info("Run Validator first to get severity data.")

    # ── Status distribution ───────────────────────────────────────────────────
    with col_right:
        st.markdown("#### Rule Status Distribution")
        if stats.by_status:
            df_status = pd.DataFrame([{"Status": k.title(), "Count": v}
                                      for k, v in stats.by_status.items()])
            fig2 = px.pie(df_status, names="Status", values="Count",
                         color_discrete_sequence=px.colors.sequential.Blues_r,
                         template="plotly_dark", height=300)
            fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", margin=dict(t=10, b=10))
            fig2.update_traces(textposition="inside", textinfo="percent+label")
            st.plotly_chart(fig2, width='stretch')
        else:
            st.info("Run Validator first to get status data.")

    
    st.markdown("---")

    # ── Row 2: File completeness + SIEM platform coverage ────────────────────
    col_left2, col_right2 = st.columns(2)

    with col_left2:
        st.markdown("#### File Completeness")
        comp_data = [
            ("✅ Complete",          stats.complete,          "#3fb950"),
            ("📄 Missing README",    stats.missing_readme,    "#e3b341"),
            ("σ  Missing Sigma",     stats.missing_sigma,     "#e3b341"),
            ("⚠️ Missing SIEM Rule", stats.missing_siem,      "#f85149"),
        ]
        fig3 = go.Figure(go.Bar(
                x=[v for _, v, _ in comp_data],
                y=[l for l, _, _ in comp_data],
                orientation="h",
                marker_color=[c for _, _, c in comp_data],
                text=[v for _, v, _ in comp_data],
                textposition="auto",
            ))
        fig3.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(13,17,23,1)", height=240,
            margin=dict(t=10, b=10, l=10),
            xaxis_title="Rules",
        )
        st.plotly_chart(fig3, width="content")

    with col_right2:
        st.markdown("#### SIEM Platform Coverage")
        platform_labels = {
            "elastic":   "⚡ Elastic",
            "defender":  "🛡️ Defender XDR",
            "sentinel":  "☁️ Sentinel",
        }
        platform_colors = {
            "elastic":   "#1a73e8",
            "defender":  "#00a4ef",
            "sentinel":  "#7b83eb",
        }
 
        if stats.by_platform:
            platform_rows = []
            for key, label in platform_labels.items():
                count   = stats.by_platform.get(key, 0)
                missing = stats.total - count
                platform_rows.append({
                    "Platform": label,
                    "With Rule": count,
                    "Without Rule": missing,
                    "color": platform_colors[key],
                })
            df_plat = pd.DataFrame(platform_rows)
 
            fig5 = go.Figure()
            fig5.add_trace(go.Bar(
                name="With Rule",
                x=df_plat["Platform"],
                y=df_plat["With Rule"],
                marker_color=[r["color"] for _, r in df_plat.iterrows()],
                text=df_plat["With Rule"],
                textposition="auto",
            ))
            fig5.add_trace(go.Bar(
                name="Without Rule",
                x=df_plat["Platform"],
                y=df_plat["Without Rule"],
                marker_color="#21262d",
                text=df_plat["Without Rule"],
                textposition="auto",
            ))
            fig5.update_layout(
                barmode="stack",
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(13,17,23,1)",
                height=240,
                margin=dict(t=10, b=10),
                legend=dict(orientation="h", yanchor="bottom", y=1.02),
                yaxis_title="Rules",
            )
            st.plotly_chart(fig5, width="content")
 
            # Coverage percentages as metrics
            mc1, mc2, mc3 = st.columns(3)
            for col, key, label in zip(
                [mc1, mc2, mc3],
                ["elastic", "defender", "sentinel"],
                ["⚡ Elastic", "🛡️ Defender", "☁️ Sentinel"],
            ):
                count = stats.by_platform.get(key, 0)
                pct   = count / stats.total * 100 if stats.total else 0
                col.metric(label, f"{count}/{stats.total}", f"{pct:.0f}%")
        else:
            # No platform data yet — show per-UC breakdown from use_cases directly
            use_cases = st.session_state.get("use_cases", [])
            counts = {
                "⚡ Elastic":    sum(1 for uc in use_cases if uc.elastic_rule),
                "🛡️ Defender":  sum(1 for uc in use_cases if getattr(uc, "defender_rule", None)),
                "☁️ Sentinel":  sum(1 for uc in use_cases if getattr(uc, "sentinel_rule", None)),
            }
            df_counts = pd.DataFrame([
                {"Platform": k, "Count": v, "Missing": stats.total - v}
                for k, v in counts.items()
            ])
            fig6 = go.Figure()
            fig6.add_trace(go.Bar(name="With Rule",    x=df_counts["Platform"], y=df_counts["Count"],
                                  marker_color=["#1a73e8","#00a4ef","#7b83eb"],
                                  text=df_counts["Count"], textposition="auto"))
            fig6.add_trace(go.Bar(name="Without Rule", x=df_counts["Platform"], y=df_counts["Missing"],
                                  marker_color="#21262d", text=df_counts["Missing"], textposition="auto"))
            fig6.update_layout(barmode="stack", template="plotly_dark",
                               paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(13,17,23,1)",
                               height=240, margin=dict(t=10, b=10),
                               legend=dict(orientation="h", yanchor="bottom", y=1.02))
            st.plotly_chart(fig6, width="content")

    st.markdown("---")
 
    # ── Row 3: Multi-SIEM coverage table ─────────────────────────────────────
    st.markdown("#### Per-Rule SIEM Coverage")
    use_cases = st.session_state.get("use_cases", [])
    rows = []
    for uc in use_cases:
        hs = next((h for h in stats.health_scores if h["name"] == uc.name), {})
        rows.append({
            "Use Case":  uc.name,
            "Subcategory": getattr(uc, "subcategory", "") or "—",
            "⚡ Elastic":  "✅" if uc.elastic_rule  else "❌",
            "🛡️ Defender": "✅" if getattr(uc, "defender_rule", None) else "❌",
            "☁️ Sentinel": "✅" if getattr(uc, "sentinel_rule", None) else "❌",
            "σ Sigma":    "✅" if uc.sigma   else "❌",
            "📄 README":  "✅" if uc.readme  else "❌",
            "Health":     hs.get("score", 0),
        })
    df_table = pd.DataFrame(rows)
    st.dataframe(df_table, width="content", hide_index=True)
    csv = df_table.to_csv(index=False)
    st.download_button("📥 Download CSV", csv, "siem_coverage.csv", "text/csv")
    
    # ── Health score distribution ─────────────────────────────────────────────
    st.markdown("---")
    st.markdown("#### Health Score Distribution")
    
    health_scores = getattr(stats, "health_scores", [])
    df_health = pd.DataFrame(health_scores)
    if not df_health.empty:
        fig4 = px.histogram(df_health, x="score", nbins=20,
                           color_discrete_sequence=["#1a73e8"],
                           template="plotly_dark", height=250,
                           labels={"score": "Health Score"})
        fig4.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                           plot_bgcolor="rgba(13,17,23,1)", margin=dict(t=10, b=10))
        st.plotly_chart(fig4, width='stretch')

        st.markdown("#### Lowest Scoring Rules")
        st.dataframe(
            df_health.head(10)[["name", "score", "folder"]].rename(
                columns={"name": "Use Case", "score": "Health Score", "folder": "Path"}
            ),
            width='stretch', hide_index=True
        )


def _compute(use_cases):
    engine = StatsEngine()
    stats, coverage = engine.compute(
        use_cases=use_cases,
        sigma_results=st.session_state.get("sigma_results", {}),
        readme_results=st.session_state.get("readme_results", {}),
        mitre_coverage=st.session_state.get("mitre_coverage"),
    )
    st.session_state.stats = stats
    if coverage:
        st.session_state.mitre_coverage = coverage
    st.success("Statistics computed!")
