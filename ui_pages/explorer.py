"""ui_pages/explorer.py — Browse and inspect individual detection use cases."""

import streamlit as st
import yaml


def render():
    st.title("🔍 Use Case Explorer")

    use_cases = st.session_state.get("use_cases", [])
    if not use_cases:
        st.info("Load use cases from the sidebar first.")
        return

    client = st.session_state.get("ado_client")

    # ── Search & filter ───────────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
    with col1:
        search = st.text_input("🔎 Search", placeholder="UC name, category, technique…")
    with col2:
        cats = sorted({
            cat for uc in use_cases
            if (cat := getattr(uc, "category", None))
        })
        cat_options = ["All"] + [s if s else "(none)" for s in cats]
        cat_filter = st.selectbox("Category", cat_options)
    with col3:
        filter_complete = st.selectbox("Completeness", ["All", "Complete", "Incomplete"])
    with col4:
        sort_by = st.selectbox("Sort", ["Name", "Category", "Health Score"])

    filtered = list(use_cases)
    if search:
        q = search.lower()
        filtered = [uc for uc in filtered if q in uc.name.lower()
                    or q in uc.folder.lower() or q in uc.category.lower() or q in uc.readme.content.lower() or q in uc.sigma.content.lower() or q in uc.elastic_rule.content.lower()]
    if cat_filter not in ("All",):
        wanted = "" if cat_filter == "(none)" else cat_filter
        filtered = [uc for uc in filtered if uc.category == wanted]
    if filter_complete == "Complete":
        filtered = [uc for uc in filtered if uc.is_complete]
    elif filter_complete == "Incomplete":
        filtered = [uc for uc in filtered if not uc.is_complete]

    if sort_by == "Category":
        filtered.sort(key=lambda uc: (uc.category, uc.name))
    elif sort_by == "Health Score":
        hs_map = {h["name"]: h["score"] for h in (st.session_state["stats"].health_scores
                  if st.session_state.get("stats") else [])}
        filtered.sort(key=lambda uc: hs_map.get(uc.name, 0))
    else:
        filtered.sort(key=lambda uc: uc.name)

    st.markdown(f"Showing **{len(filtered)}** of **{len(use_cases)}** use cases")
    st.markdown("---")

    for uc in filtered:
        sigma_result = st.session_state.get("sigma_results", {}).get(uc.name)
        health_score = None
        if st.session_state.get("stats"):
            hs = next((h for h in st.session_state["stats"].health_scores if h["name"] == uc.name), None)
            health_score = hs["score"] if hs else None

        completeness = _completeness_icons(uc)
        cat_tag = f"`{cat}`  " if (cat := getattr(uc, "category", None)) else ""
        score_str = f"  ·  🩺 **{health_score:.0f}/100**" if health_score is not None else ""
        sigma_badge = ("  ✅" if sigma_result and sigma_result.valid
                       else "  ❌" if sigma_result else "")
        header = f"{completeness}  {cat_tag}**{uc.name}**{score_str}{sigma_badge}"

        with st.expander(header):
            #print("UseCases: ", uc, "\n")
            _render_use_case(uc, client)


def _completeness_icons(uc) -> str:
    return "".join([
        "📄" if uc.readme else "⬜",
        "σ" if uc.sigma else "⬜",
        "⚡" if uc.elastic_rule else "⬜",
    ])


def _render_use_case(uc, client):
    cols = st.columns(6)
    extra = uc.extra_files or []
    items = [
        ("📄 README",     bool(uc.readme)),
        ("σ Sigma",       bool(uc.sigma)),
        ("⚡ Elastic",    bool(uc.elastic_rule)),
        ("🔧 Pipelines",  any("pipeline" in f.path.lower() for f in extra)),
        ("🧪 Tests",      any("test" in f.path.lower() for f in extra)),
        ("📊 Dashboards", any("dashboard" in f.path.lower() for f in extra)),
    ]
    for col, (label, present) in zip(cols, items):
        col.markdown(f"{'✅' if present else '❌'} {label}")

    st.markdown(f"**Path:** `{uc.folder}`")
    if getattr(uc, "category", None):
        st.markdown(f"**Category:** `{getattr(uc, 'category')}`")
    st.markdown("---")

    tab_labels = []
    if uc.readme:                    tab_labels.append("📄 README")
    if uc.sigma:                     tab_labels.append("σ Sigma")
    if uc.elastic_rule:              tab_labels.append("⚡ Elastic Rule")
    if any("pipeline" in f.path.lower() for f in extra):       tab_labels.append("🔧 Pipelines")
    if any("test" in f.path.lower() for f in extra):           tab_labels.append("🧪 Tests")
    if any("dashboard" in f.path.lower() for f in extra):      tab_labels.append("📊 Dashboards")
    tab_labels.append("✅ Validate")

    tabs = st.tabs(tab_labels)
    idx = 0

    if uc.readme:
        with tabs[idx]:
            _ensure_content(uc.readme, client)
            st.markdown(uc.readme.content or "_Empty_")
        idx += 1

    if uc.sigma:
        with tabs[idx]:
            _ensure_content(uc.sigma, client)
            st.code(uc.sigma.content or "_Empty_", language="yaml")
            _show_sigma_tags(uc.sigma.content)
        idx += 1

    if uc.elastic_rule:
        with tabs[idx]:
            _ensure_content(uc.elastic_rule, client)
            ext = uc.elastic_rule.path.split(".")[-1].lower()
            lang = {"toml": "toml", "json": "json"}.get(ext, "yaml")
            st.code(uc.elastic_rule.content or "_Empty_", language=lang)
        idx += 1

    for cat in ("pipelines", "tests", "dashboards"):
        files = [f for f in extra if cat in f.path.lower()]
        if not files:
            continue
        with tabs[idx]:
            for f in files:
                _ensure_content(f, client)
                fname = f.path.split("/")[-1]
                ext = fname.split(".")[-1].lower()
                lang = {"yml": "yaml", "yaml": "yaml", "json": "json",
                        "toml": "toml", "ndjson": "json"}.get(ext, "text")
                st.markdown(f"**{fname}**  `{f.path}`")
                st.code(f.content or "_Empty_", language=lang)
        idx += 1

    with tabs[idx]:
        _inline_validate(uc, client)


def _ensure_content(df, client):
    if not df.content and client:
        try:
            df.content = client.load_file(df)
        except Exception as e:
            df.content = f"[Error loading file: {e}]"


def _show_sigma_tags(content: str):
    if not content:
        return
    try:
        doc = yaml.safe_load(content)
        if not isinstance(doc, dict):
            return
        tags = [t for t in doc.get("tags", []) if isinstance(t, str) and "attack." in t.lower()]
        if tags:
            st.markdown("**ATT&CK Tags:** " + "  ".join(f"`{t}`" for t in tags))
        level = doc.get("level", "")
        status = doc.get("status", "")
        if level or status:
            st.markdown(f"**Level:** `{level}`  **Status:** `{status}`")
    except Exception:
        pass


def _inline_validate(uc, client):
    from modules.sigma_validator import SigmaValidator
    from modules.readme_validator import ReadmeValidator

    if st.button("▶ Run Validation", key=f"val_{uc.name}"):
        if uc.sigma:
            _ensure_content(uc.sigma, client)
            sv = SigmaValidator()
            result = sv.validate(uc.sigma.content)
            st.session_state.setdefault("sigma_results", {})[uc.name] = result

            if result.valid:
                st.success("✅ Sigma validation passed")
            else:
                st.error("❌ Sigma validation failed")

            for issue in result.issues:
                icon = {"error": "🔴", "warning": "🟡", "info": "🔵"}.get(issue.level, "⚪")
                st.markdown(f"{icon} `{issue.code}` {f'[{issue.field}]' if issue.field else ''} — {issue.message}")

            if result.elastic_query:
                st.markdown("**Elastic Lucene Query:**")
                st.code(result.elastic_query, language="text")
            elif result.conversion_error:
                st.warning(f"Elastic conversion: {result.conversion_error}")
        else:
            st.warning("No Sigma file found in `detection/` folder.")

        if uc.readme:
            _ensure_content(uc.readme, client)
            rv = ReadmeValidator()
            rr = rv.validate(uc.readme.content)
            st.session_state.setdefault("readme_results", {})[uc.name] = rr
            st.markdown(f"**README completeness:** {rr.score*100:.0f}%")
            if rr.missing_sections:
                st.warning("Missing required sections: " + ", ".join(rr.missing_sections))
            for w in rr.warnings:
                st.markdown(f"🟡 {w}")
        else:
            st.warning("No README.md found at UC root.")