"""
ui_pages/validator.py — Bulk Sigma + README validation
=======================================================
Validates all loaded use cases and presents results in four tabs:
  🔴 Sigma Errors    — rules with schema or detection block errors
  🟡 Sigma Warnings  — rules with missing recommended fields
  📄 README Issues   — READMEs with missing sections or metadata
  📋 Full Report     — tabular summary with CSV export
 
Results are stored in st.session_state.sigma_results and
st.session_state.readme_results so other pages (Overview, Statistics)
can read them without re-running validation.
"""

import streamlit as st
from modules.sigma_validator import SigmaValidator
from modules.readme_validator import ReadmeValidator


def render():
    st.title("✅ Validator")

    use_cases = st.session_state.get("use_cases", [])
    client = st.session_state.get("ado_client")

    if not use_cases:
        st.info("Load use cases from the sidebar first.")
        return

    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown(f"**{len(use_cases)}** use cases loaded · Ready for bulk validation")
    with col2:
        # Manual "Validate All" button — useful after editing rules
        if st.button("🚀 Validate All", width='stretch'):
            _run_bulk_validation(use_cases, client)

    sigma_results = st.session_state.get("sigma_results", {})
    readme_results = st.session_state.get("readme_results", {})

    # If neither result set has been populated (first visit before auto_refresh),
    # show a prompt rather than empty tabs
    if not sigma_results and not readme_results:
        st.markdown("---")
        st.markdown("Click **Validate All** to run validation across every use case.")
        return

    # ── Summary ───────────────────────────────────────────────────────────────
    st.markdown("---")
    sigma_pass = sum(1 for r in sigma_results.values() if r.valid)
    sigma_fail = len(sigma_results) - sigma_pass
    # Average README completeness as a percentage
    readme_avg = (sum(r.score for r in readme_results.values()) / len(readme_results) * 100) if readme_results else 0

    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("Sigma Valid", sigma_pass)
    with c2: st.metric("Sigma Invalid", sigma_fail)
    with c3: st.metric("Avg README Score", f"{readme_avg:.0f}%")
    with c4: st.metric("Rules Validated", len(sigma_results))

    # ── Detailed results ──────────────────────────────────────────────────────
    st.markdown("---")
    tabs = st.tabs(["🔴 Sigma Errors", "🟡 Sigma Warnings", "📄 README Issues", "📋 Full Report"])

    # Tab 1: Sigma errors — rules that fail schema validation
    with tabs[0]:
        shown = 0
        for name, result in sigma_results.items():
            errors = result.errors
            if errors:
                shown += 1
                with st.expander(f"❌ {name} ({len(errors)} error(s))"):
                    for e in errors:
                        st.markdown(f"🔴 `{e.code}` {f'[{e.field}]' if e.field else ''} — {e.message}")
        if not shown:
            st.success("No Sigma errors found 🎉")

    # Tab 2: Sigma warnings — rules that pass but have recommended improvements
    with tabs[1]:
        shown = 0
        for name, result in sigma_results.items():
            warnings = result.warnings
            if warnings:
                shown += 1
                with st.expander(f"⚠️ {name} ({len(warnings)} warning(s))"):
                    for w in warnings:
                        st.markdown(f"🟡 `{w.code}` {f'[{w.field}]' if w.field else ''} — {w.message}")
        if not shown:
            st.success("No Sigma warnings found 🎉")

    # Tab 3: README issues — missing sections or metadata fields
    with tabs[2]:
        shown = 0
        for name, result in readme_results.items():
            issues = result.missing_sections + result.missing_fields + result.warnings
            if issues:
                shown += 1
                with st.expander(f"📄 {name} — score {result.score*100:.0f}%"):
                    for s in result.missing_sections:
                        st.markdown(f"🔴 Missing required section: `{s}`")
                    for f in result.missing_fields:
                        st.markdown(f"🟡 Missing metadata field: `{f}`")
                    for w in result.warnings:
                        st.markdown(f"🟡 {w}")
        if not shown:
            st.success("All READMEs look great 🎉")

    # Tab 4: Full tabular report + CSV export
    with tabs[3]:
        import pandas as pd
        rows = []
        for uc in use_cases:
            sv = sigma_results.get(uc.name)
            rv = readme_results.get(uc.name)
            rows.append({
                "Use Case": uc.name,
                "Sigma Valid": "✅" if sv and sv.valid else ("❌" if sv else "—"),
                "Sigma Errors": len(sv.errors) if sv else 0,
                "Sigma Warnings": len(sv.warnings) if sv else 0,
                "Elastic Query": "✅" if sv and sv.elastic_query else ("⚠️" if sv else "—"),
                "README Score": f"{rv.score*100:.0f}%" if rv else "—",
            })
        st.dataframe(pd.DataFrame(rows), width='stretch', hide_index=True)

        # Export
        csv = pd.DataFrame(rows).to_csv(index=False)
        st.download_button("📥 Download CSV", csv, "validation_report.csv", "text/csv")


def _run_bulk_validation(use_cases, client):
    """
    Validate all use cases and store results in session_state.
 
    Loads file content from ADO on demand (if not already in memory).
    Shows a progress bar during the loop for large repositories.
    """
    sv = SigmaValidator()
    rv = ReadmeValidator()
    sigma_results = {}
    readme_results = {}

    progress = st.progress(0, text="Validating…")

    for i, uc in enumerate(use_cases):
        # Load content if needed
        if client:
            try:
                if uc.sigma and not uc.sigma.content:
                    uc.sigma.content = client.load_file(uc.sigma)
                if uc.readme and not uc.readme.content:
                    uc.readme.content = client.load_file(uc.readme)
            except Exception:
                pass

        if uc.sigma and uc.sigma.content:
            sigma_results[uc.name] = sv.validate(uc.sigma.content)
        if uc.readme and uc.readme.content:
            readme_results[uc.name] = rv.validate(uc.readme.content)

        progress.progress((i + 1) / len(use_cases), text=f"Validated {uc.name}…")

    # Store results in session_state for access by Overview and Statistics pages
    st.session_state.sigma_results = sigma_results
    st.session_state.readme_results = readme_results
    progress.empty()
    st.success(f"Validation complete — {len(sigma_results)} Sigma, {len(readme_results)} README")
