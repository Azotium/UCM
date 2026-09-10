"""
pages/editor.py
Create new use cases or edit existing ones, push to a branch, and open a PR.
"""

from __future__ import annotations
from importlib.resources import files
import re
import json
import streamlit as st
import yaml
from typing import Tuple, List

from modules.templates import (
    sigma_template, elastic_template,
    defender_template, sentinel_template,
    readme_template,
)
from modules.sigma_validator import SigmaValidator
from modules.converters import (
    sigma_to_elastic, elastic_to_sigma,
    sigma_to_defender_rule, sigma_to_sentinel,
)
from modules.ado_client import _cached_list_branches


# ── Constants ─────────────────────────────────────────────────────────────────
SEVERITIES = ["critical", "high", "medium", "low", "informational"]
STATUSES   = ["experimental", "test", "stable", "deprecated"]
LOGSOURCE_CATEGORIES = ["network", "process_creation", "file_event", "registry_event",
                        "dns", "authentication", "web", "firewall", "proxy", ""]
COVERAGE_DEPTHS = ["Level 1 - Basic (atomic detection)", "Level 2 - Contextual detection (enrichment)", "Level 3 - Correlational detection", "Level 4 - Behavioral or risk-based detection"]
PROTECTED_BRANCHES = {"main", "dev"}


def render():
    st.title("✏️ Use Case Editor")

    client   = st.session_state.get("ado_client")
    project  = st.session_state.get("project", "")
    repo     = st.session_state.get("repo", "")
    uc_root  = st.session_state.get("uc_root", "/UseCases")

    if not client or not project or not repo:
        st.info("Connect to Azure DevOps and load a repository first.")
        return

    # ── Mode selector ─────────────────────────────────────────────────────────
    mode = st.radio(
        "Mode",
        ["➕ Create new use case", "✏️ Edit existing use case"],
        horizontal=True,
        label_visibility="collapsed",
    )
    st.markdown("---")

    if mode == "➕ Create new use case":
        _create_mode(client, project, repo, uc_root)
    else:
        _edit_mode(client, project, repo, uc_root)


# ═══════════════════════════════════════════════════════════════════════════════
# CREATE MODE
# ═══════════════════════════════════════════════════════════════════════════════

def _create_mode(client, project, repo, uc_root):
    # ── Step tracker ──────────────────────────────────────────────────────────
    step = st.session_state.get("editor_step", 1)
    steps = ["1 · Branch", "2 · Metadata", "3 · Sigma", "4 · SIEM Rules", "5 · Review & Push"]
    cols = st.columns(len(steps))
    for i, (col, label) in enumerate(zip(cols, steps), 1):
        with col:
            if i < step:
                st.markdown(f"<div style='text-align:center;color:#3fb950'>✅ {label}</div>", unsafe_allow_html=True)
            elif i == step:
                st.markdown(f"<div style='text-align:center;color:#58a6ff;font-weight:600'>▶ {label}</div>", unsafe_allow_html=True)
            else:
                st.markdown(f"<div style='text-align:center;color:#484f58'>{label}</div>", unsafe_allow_html=True)
    st.markdown("---")

    if step == 1: _step_branch(client, project, repo)
    elif step == 2: _step_metadata()
    elif step == 3: _step_sigma()
    elif step == 4: _step_siem_rules()
    elif step == 5: _step_review_push(client, project, repo, uc_root)


# ── Step 1: Branch ────────────────────────────────────────────────────────────

def _step_branch(client, project, repo):
    st.subheader("1 · Create or select a branch")

    existing_branches = client.list_branches(project, repo)
    feature_branches  = [b for b in existing_branches if b not in ("main", "master", "dev")]

    branch_mode = st.radio("Branch", ["Create new branch", "Use existing branch"], horizontal=True)

    if branch_mode == "Create new branch":
        col1, col2 = st.columns(2)
        with col1:
            uc_id_hint = st.text_input("UC ID (used in branch name)", placeholder="UC-024",
                                       value=st.session_state.get("new_uc_id", ""))
        with col2:
            base = st.selectbox("Base branch", ["dev", "main"] + [b for b in existing_branches if b not in ("dev","main")])

        # Auto-suggest branch name
        slug = re.sub(r"[^a-z0-9-]", "-", uc_id_hint.lower()).strip("-")
        suggested = f"feat/{slug}-detection" if slug else "feat/new-detection"
        branch_name = st.text_input("New branch name", value=suggested)

        if st.button("🌿 Create Branch", disabled=not branch_name):
            if client.branch_exists(project, repo, branch_name):
                st.warning(f"Branch `{branch_name}` already exists — selecting it.")
                st.session_state.editor_branch = branch_name
                st.session_state.new_uc_id = uc_id_hint
                st.session_state.editor_step = 2
                st.rerun()
            else:
                with st.spinner(f"Creating branch `{branch_name}` from `{base}`…"):
                    try:
                        result = client.create_branch(project, repo, branch_name, base)
                        st.session_state.editor_branch = branch_name
                        st.session_state.new_uc_id = uc_id_hint
                        st.session_state.editor_step = 2
                        st.success(f"✅ Branch `{branch_name}` created")
                        _cached_list_branches.clear()
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to create branch: {e}")
    else:
        chosen = st.selectbox("Select branch", feature_branches or existing_branches)
        uc_id_hint = st.text_input("UC ID", placeholder="UC-024",
                                   value=st.session_state.get("new_uc_id", ""))
        if st.button("Use this branch →"):
            st.session_state.editor_branch = chosen
            st.session_state.new_uc_id = uc_id_hint
            st.session_state.editor_step = 2
            st.rerun()


# ── Step 2: Metadata ──────────────────────────────────────────────────────────

def _step_metadata():
    branch = st.session_state.get("editor_branch", "")
    uc_id  = st.session_state.get("new_uc_id", "")
    st.subheader(f"2 · Use case metadata  ·  branch `{branch}`")

    prev = st.session_state.get("editor_meta", {})

    col1, col2 = st.columns(2)
    with col1:
        uc_id   = st.text_input("UC ID *", value=prev.get("uc_id", uc_id), placeholder="UC-024")
        title   = st.text_input("Title *", value=prev.get("title", ""), placeholder="VPN Anomaly Detection")
        author  = st.text_input("Author", value=prev.get("author", ""), placeholder="Security Team")
        cat  = st.text_input("Category (optional)", value=prev.get("Category", ""),
                                placeholder="checkpoint, vendor-agnostic…")
    with col2:
        severity = st.selectbox("Severity", SEVERITIES,
                                index=SEVERITIES.index(prev.get("severity", "medium")))
        status   = st.selectbox("Status", STATUSES,
                                index=STATUSES.index(prev.get("status", "experimental")))
        logsource_cat  = st.selectbox("Log source category", LOGSOURCE_CATEGORIES,
                                      index=LOGSOURCE_CATEGORIES.index(prev.get("logsource_cat", "network")))
        logsource_prod = st.text_input("Log source product", value=prev.get("logsource_prod", ""),
                                       placeholder="windows, cisco, palo-alto…")
        logsource_svc  = st.text_input("Log source service", value=prev.get("logsource_svc", ""),
                                       placeholder="syslog, winlogbeat…")

    description = st.text_area("Description *", value=prev.get("description", ""),
                               placeholder="Detects anomalous VPN logins from unusual geolocations…", height=100)
    mitre_raw   = st.text_input("MITRE ATT&CK tags (comma-separated)",
                                value=prev.get("mitre_raw", ""),
                                placeholder="attack.t1078, attack.initial-access")
    
    col1, col2 = st.columns(2)
    st.markdown("Perimeter & Coverage")
    with col1:
        coverage_assets = st.text_input("Assets in scope", value=prev.get("coverage_assets", ""), placeholder="All, Critical assets, Specific groups…")
        coverage_width = st.slider("Estimated coverage (%)", min_value=0.0, max_value=1.0, value=prev.get("coverage", 0.8), format="percent", step=0.1)
        coverage_depth = st.selectbox("Detection depth", COVERAGE_DEPTHS, index=COVERAGE_DEPTHS.index(prev.get("coverage_depth", "Level 1 - Basic (atomic detection)")))

    with col2:
        datasources = st.text_area("Data sources (one per line)", value=prev.get("datasources", ""), placeholder="Windows Security Events, Zeek conn logs, AWS CloudTrail…", height=80)
        datasets = st.text_area("Datasets used (one per line)", value=prev.get("datasets", ""), placeholder="a1000-application_logs-prd, etc.", height=80)

    detection_method = st.text_area("Detection method",
                                   value=prev.get("detection_method", ""), height=80, placeholder="Describe the detection logic here — what event sources are used, what conditions trigger the rule, and why.")


    false_positives = st.text_area("False positives (one per line)",
                                   value=prev.get("false_positives", ""), height=80)
    

    triage = st.text_area("Triage steps", value=prev.get("triage", ""), height=80, placeholder="1. Identify the source host and user account\n2. Review recent activity for the involved entities\n3. Correlate with other alerts or indicators")
    response = st.text_area("Response steps", value=prev.get("response", ""), height=80, placeholder="1. If confirmed malicious: escalate to IR team\n2. If benign: document as exception and tune rule")
    playbooks = st.text_input("Associated playbooks (one per line)", value=prev.get("playbooks", ""), placeholder="PB-00X, PB-00Y\n…")

    mttd = st.text_input("Target MTTD (e.g. < 5 min)", value=prev.get("mttd", ""), placeholder="e.g. < 5 min")
    fp_rate = st.text_input("Target FP rate (e.g. < 10%)", value=prev.get("fp_rate", ""), placeholder="e.g. < 10%") 

    pipelines = st.text_area("Detection pipeline (optional)", value=prev.get("pipelines", ""), height=80, placeholder="Describe the technical implementation here — which SIEM or detection platform is used, how is the rule structured, etc.")

    references  = st.text_area("References (one per line)",
                                value=prev.get("references", ""), height=80)
    

    # Platform selection
    st.markdown("**SIEM platforms to generate rules for:**")
    pc1, pc2, pc3 = st.columns(3)
    with pc1: gen_elastic  = st.checkbox("⚡ Elastic",          value=prev.get("gen_elastic", True))
    with pc2: gen_defender = st.checkbox("🛡️ Defender XDR",    value=prev.get("gen_defender", True))
    with pc3: gen_sentinel = st.checkbox("☁️ Sentinel",        value=prev.get("gen_sentinel", True))
    

    col_back, col_next = st.columns([1, 4])
    with col_back:
        if st.button("← Back"):
            st.session_state.editor_step = 1
            st.rerun()
    with col_next:
        if st.button("Next: Sigma →", type="primary"):
            if not uc_id or not title or not description:
                st.error("UC ID, Title, and Description are required.")
                return

            mitre_tags = [t.strip() for t in mitre_raw.split(",") if t.strip()]
            meta = {
                "uc_id": uc_id, "title": title, "author": author,
                "category": cat, "severity": severity, "status": status,
                "logsource_cat": logsource_cat, "logsource_prod": logsource_prod,
                "logsource_svc": logsource_svc, "description": description,
                "mitre_raw": mitre_raw, "mitre_tags": mitre_tags,
                "false_positives": false_positives, "references": references,
                "coverage_assets": coverage_assets, "coverage_width": coverage_width, "coverage_depth": coverage_depth,
                "datasources": datasources, "datasets": datasets,
                "detection_method": detection_method,
                "triage": triage, "response": response, "playbooks": playbooks,
                "mttd": mttd, "fp_rate": fp_rate, pipelines: pipelines,
                "gen_elastic": gen_elastic, "gen_defender": gen_defender, "gen_sentinel": gen_sentinel
            }
            st.session_state.editor_meta = meta
            st.session_state.new_uc_id = uc_id

            # Always regenerate templates from the latest metadata
            # (only skip if user has explicitly customised AND metadata hasn't changed)
            meta_changed = (meta != st.session_state.get("editor_meta_prev", {}))
            st.session_state.editor_meta_prev = meta

            tech_ids = _extract_techniques(mitre_tags)
            tactics  = _extract_tactics(mitre_tags)

            # Auto-generate Sigma if not customised yet
            if not st.session_state.get("editor_sigma_customised") or meta_changed:
                st.session_state.editor_sigma = sigma_template(
                    uc_id=uc_id, title=title, description=description, author=author,
                    severity=severity, status=status, mitre_tags=mitre_tags,
                    logsource_category=logsource_cat, logsource_product=logsource_prod,
                    logsource_service=logsource_svc,
                )

            # Auto-generate Elastic if not customised yet
            # if not st.session_state.get("editor_elastic_customised") or meta_changed:
            #     tech_ids = [t.split(".")[-1].upper() for t in mitre_tags
            #                 if re.match(r"(?i)attack\.t\d{4}", t.split(".")[-1] if "." in t else t)]
            #     tactics  = [t.split(".")[-1] for t in mitre_tags
            #                 if "attack." in t.lower() and not re.match(r"(?i)t\d{4}", t.split(".")[-1])]
            #     st.session_state.editor_elastic = elastic_template(
            #         uc_id=uc_id, title=title, description=description, author=author,
            #         severity=severity, mitre_tactics=tactics, mitre_techniques=tech_ids,
            #     )
            
            if gen_elastic and (not st.session_state.get("editor_elastic_customised") or meta_changed):
                st.session_state.editor_elastic = elastic_template(
                    uc_id=uc_id, title=title, description=description, author=author,
                    severity=severity, mitre_tactics=tactics, mitre_techniques=tech_ids,
                )
            if gen_defender and (not st.session_state.get("editor_defender_customised") or meta_changed):
                st.session_state.editor_defender = defender_template(
                    uc_id=uc_id, title=title, description=description, author=author,
                    severity=severity, mitre_tags=mitre_tags, logsource_category=logsource_cat,
                )
            if gen_sentinel and (not st.session_state.get("editor_sentinel_customised") or meta_changed):
                st.session_state.editor_sentinel = sentinel_template(
                    uc_id=uc_id, title=title, description=description, author=author,
                    severity=severity, mitre_tactics=tactics, mitre_techniques=tech_ids,
                )

            st.session_state.editor_step = 3
            st.rerun()


# ── Step 3: Sigma editor ──────────────────────────────────────────────────────

def _step_sigma():
    meta   = st.session_state.get("editor_meta", {})
    uc_id  = meta.get("uc_id", "UC-XXX")
    branch = st.session_state.get("editor_branch", "")
    st.subheader(f"3 · Sigma rule  ·  `{uc_id}`  ·  branch `{branch}`")

    sigma_content = st.session_state.get("editor_sigma", "")

    col_editor, col_validation = st.columns([3, 2])

    with col_editor:
        st.markdown("**Edit Sigma YAML**")
        new_content = st.text_area(
            "sigma_editor",
            value=sigma_content,
            height=480,
            label_visibility="collapsed",
            key="sigma_text_area",
        )
        if new_content != sigma_content:
            st.session_state.editor_sigma = new_content
            st.session_state.editor_sigma_customised = True

        col_reset, col_convert, c3, c4 = st.columns([1,1,1,3])
        with col_reset:
            if st.button("↺ Reset to template", key="sigma_reset"):
                st.session_state.editor_sigma = sigma_template(
                    uc_id=meta.get("uc_id",""), title=meta.get("title",""),
                    description=meta.get("description",""), author=meta.get("author",""),
                    severity=meta.get("severity","medium"), status=meta.get("status","experimental"),
                    mitre_tags=meta.get("mitre_tags",[]),
                    logsource_category=meta.get("logsource_cat",""),
                    logsource_product=meta.get("logsource_prod",""),
                    logsource_service=meta.get("logsource_svc",""),
                )
                st.session_state.editor_sigma_customised = False
                st.rerun()

        with col_convert:
            if st.button("⚡ Convert → Elastic", key="sigma_to_elastic", type="primary"):
                toml_str, errs = sigma_to_elastic(st.session_state.get("editor_sigma",""))
                if toml_str:
                    st.session_state.editor_elastic = toml_str
                    st.session_state.editor_elastic_customised = True
                    st.session_state.editor_sigma_converted = errs
                    st.success("✅ Converted to Elastic — review in Step 4")
                else:
                    st.error("Conversion failed: " + "; ".join(errs))

        with c3:
            if st.button("⚡ Convert → All SIEMs", type="primary"):
                sigma_content = st.session_state.get("editor_sigma","")
                convert_all, errs = _convert_sigma_to_all_siems(sigma_content, meta)
                if convert_all: 
                    st.success("✅ Converted to all SIEMs — review in Step 4")
                else:
                    st.error("Conversion failed: " + "; ".join(errs))

        if st.session_state.get("editor_sigma_converted"):
            for w in st.session_state.editor_sigma_converted:
                st.caption(f"⚠️ {w}")

    with col_validation:
        st.markdown("**Live Validation**")
        _live_sigma_validation(st.session_state.get("editor_sigma", ""))

    col_back, col_next = st.columns([1,4])
    with col_back:
        if st.button("← Back", key="sigma_back"):
            st.session_state.editor_step = 2
            st.rerun()
    with col_next:
        if st.button("Next: SIEM Rules →", type="primary", key="sigma_next"):
            st.session_state.editor_step = 4
            st.rerun()


def _live_sigma_validation(content: str):
    if not content.strip():
        st.info("Start typing to validate…")
        return
    sv = SigmaValidator()
    result = sv.validate(content)

    if result.valid:
        st.success("✅ Valid Sigma rule")
    else:
        st.error(f"❌ {len(result.errors)} error(s)")

    for issue in result.issues:
        icon = {"error": "🔴", "warning": "🟡", "info": "🔵"}.get(issue.level, "⚪")
        field = f" `{issue.field}`" if issue.field else ""
        st.markdown(f"{icon} **{issue.code}**{field}  \n{issue.message}")

    if result.elastic_query:
        st.markdown("**→ Elastic Lucene query:**")
        st.code(result.elastic_query, language="text")
    elif result.conversion_error:
        st.caption(f"Elastic conversion: {result.conversion_error}")

    # Show parsed metadata
    if result.parsed:
        doc = result.parsed
        with st.expander("Parsed fields"):
            for field in ("title","status","level","author","date"):
                if field in doc:
                    st.markdown(f"**{field}:** {doc[field]}")
            tags = doc.get("tags", [])
            if tags:
                st.markdown("**tags:** " + ", ".join(f"`{t}`" for t in tags))


# ── Step 4: Elastic rule editor ───────────────────────────────────────────────

# def _step_elastic():
#     meta   = st.session_state.get("editor_meta", {})
#     uc_id  = meta.get("uc_id", "UC-XXX")
#     branch = st.session_state.get("editor_branch", "")
#     st.subheader(f"4 · Elastic rule  ·  `{uc_id}`  ·  branch `{branch}`")

#     elastic_content = st.session_state.get("editor_elastic", "")

#     col_editor, col_preview = st.columns([3, 2])

#     with col_editor:
#         st.markdown("**Edit Elastic rule (TOML)**")
#         new_content = st.text_area(
#             "elastic_editor",
#             value=elastic_content,
#             height=500,
#             label_visibility="collapsed",
#             key="elastic_text_area",
#         )
#         if new_content != elastic_content:
#             st.session_state.editor_elastic = new_content
#             st.session_state.editor_elastic_customised = True

#         col_reset, col_convert = st.columns(2)

#         with col_reset:
#             if st.button("↺ Reset to template"):
#                 tech_ids = [t.split(".")[-1].upper() for t in meta.get("mitre_tags", [])
#                             if re.match(r"(?i)t\d{4}", t.split(".")[-1] if "." in t else t)]
#                 tactics  = [t.split(".")[-1] for t in meta.get("mitre_tags", [])
#                             if "attack." in t.lower() and not re.match(r"(?i)t\d{4}", t.split(".")[-1])]
#                 st.session_state.editor_elastic = elastic_template(
#                     uc_id=meta.get("uc_id",""), title=meta.get("title",""),
#                     description=meta.get("description",""), author=meta.get("author",""),
#                     severity=meta.get("severity","medium"),
#                     mitre_tactics=tactics, mitre_techniques=tech_ids,
#                 )
#                 st.session_state.editor_elastic_customised = False
#                 st.rerun()

#         with col_convert:
#             if st.button("σ Convert → Sigma", key="elastic_to_sigma", type="primary"):
#                 yaml_str, errs = elastic_to_sigma(st.session_state.get("editor_elastic",""))
#                 if yaml_str:
#                     st.session_state.editor_sigma = yaml_str
#                     st.session_state.editor_sigma_customised = True
#                     st.session_state.editor_elastic_converted = errs
#                     st.success("✅ Converted to Sigma — review in Step 3")
#                 else:
#                     st.error("Conversion failed: " + "; ".join(errs))
 
#         if st.session_state.get("editor_elastic_converted"):
#             for w in st.session_state.editor_elastic_converted:
#                 st.caption(f"⚠️ {w}")

#     with col_preview:
#         st.markdown("**TOML syntax check**")
#         _toml_check(st.session_state.get("editor_elastic", ""))

#     col_back, col_next = st.columns([1, 4])
#     with col_back:
#         if st.button("← Back"):
#             st.session_state.editor_step = 3
#             st.rerun()
#     with col_next:
#         if st.button("Next: Review & Push →", type="primary"):
#             st.session_state.editor_step = 5
#             st.rerun()


def _step_siem_rules():
    meta   = st.session_state.get("editor_meta",{})
    uc_id  = meta.get("uc_id","UC-XXX")
    branch = st.session_state.get("editor_branch","")
    st.subheader(f"4 · SIEM Rules  ·  `{uc_id}`  ·  branch `{branch}`")
 
    gen_elastic  = meta.get("gen_elastic", True)
    gen_defender = meta.get("gen_defender", True)
    gen_sentinel = meta.get("gen_sentinel", True)
 
    # Convert from Sigma in one click
    if st.button("🔄 Re-generate all from Sigma", type="primary"):
        _convert_sigma_to_all_siems(st.session_state.get("editor_sigma",""), meta)
        st.rerun()
 
    sigma_content = st.session_state.get("editor_sigma","")
 
    tab_labels = []
    if gen_elastic:  tab_labels.append("⚡ Elastic")
    if gen_defender: tab_labels.append("🛡️ Defender XDR")
    if gen_sentinel: tab_labels.append("☁️ Sentinel")
    if not tab_labels:
        st.warning("No SIEM platforms selected. Go back to Step 2 and enable at least one.")
        if st.button("← Back", key="s4_back_none"): st.session_state.editor_step=2; st.rerun()
        return
 
    tabs = st.tabs(tab_labels)
    tab_idx = 0
 
    if gen_elastic:
        with tabs[tab_idx]:
            _siem_editor_panel(
                key="editor_elastic", customised_key="editor_elastic_customised",
                label="Elastic TOML", lang="toml",
                validation_fn=_toml_check,
                convert_label="σ ← From Sigma",
                convert_fn=lambda: _apply_conversion("editor_elastic","editor_elastic_customised",
                                                      *sigma_to_elastic(sigma_content)),
                reset_fn=lambda: elastic_template(
                    uc_id=meta.get("uc_id",""), title=meta.get("title",""),
                    description=meta.get("description",""), author=meta.get("author",""),
                    severity=meta.get("severity","medium"),
                    mitre_tactics=_extract_tactics(meta.get("mitre_tags",[])),
                    mitre_techniques=_extract_techniques(meta.get("mitre_tags",[])),
                ),
            )
        tab_idx += 1
 
    if gen_defender:
        with tabs[tab_idx]:
            _siem_editor_panel(
                key="editor_defender", customised_key="editor_defender_customised",
                label="Defender XDR KQL", lang="text",
                validation_fn=_kql_check,
                convert_label="σ ← From Sigma",
                convert_fn=lambda: _apply_conversion("editor_defender","editor_defender_customised",
                                                      *sigma_to_defender_rule(sigma_content)),
                reset_fn=lambda: defender_template(
                    uc_id=meta.get("uc_id",""), title=meta.get("title",""),
                    description=meta.get("description",""), author=meta.get("author",""),
                    severity=meta.get("severity","medium"), mitre_tags=meta.get("mitre_tags",[]),
                    logsource_category=meta.get("logsource_cat",""),
                ),
            )
        tab_idx += 1
 
    if gen_sentinel:
        with tabs[tab_idx]:
            _siem_editor_panel(
                key="editor_sentinel", customised_key="editor_sentinel_customised",
                label="Sentinel ARM JSON", lang="json",
                validation_fn=_json_check,
                convert_label="σ ← From Sigma",
                convert_fn=lambda: _apply_conversion("editor_sentinel","editor_sentinel_customised",
                                                      *sigma_to_sentinel(sigma_content)),
                reset_fn=lambda: sentinel_template(
                    uc_id=meta.get("uc_id",""), title=meta.get("title",""),
                    description=meta.get("description",""), author=meta.get("author",""),
                    severity=meta.get("severity","medium"),
                    mitre_tactics=_extract_tactics(meta.get("mitre_tags",[])),
                    mitre_techniques=_extract_techniques(meta.get("mitre_tags",[])),
                ),
            )
 
    col_back, col_next = st.columns([1,4])
    with col_back:
        if st.button("← Back", key="s4_back"): st.session_state.editor_step=3; st.rerun()
    with col_next:
        if st.button("Next: Review & Push →", type="primary"): st.session_state.editor_step=5; st.rerun()
 
 
def _siem_editor_panel(key, customised_key, label, lang, validation_fn,
                       convert_label, convert_fn, reset_fn):
    """Reusable two-column SIEM rule editor."""
    col_ed, col_val = st.columns([3,2])
    with col_ed:
        st.markdown(f"**{label}**")
        current = st.session_state.get(key,"")
        new_content = st.text_area(key, value=current, height=420,
                                   label_visibility="collapsed", key=f"ta_{key}")
        if new_content != current:
            st.session_state[key] = new_content
            st.session_state[customised_key] = True
 
        c1, c2 = st.columns(2)
        with c1:
            if st.button(f"↺ Reset", key=f"reset_{key}"):
                st.session_state[key] = reset_fn()
                st.session_state[customised_key] = False
                st.rerun()
        with c2:
            if st.button(convert_label, key=f"conv_{key}", type="primary"):
                convert_fn()
                st.rerun()
    with col_val:
        st.markdown("**Validation**")
        validation_fn(st.session_state.get(key,""))


def _toml_check(content: str):
    if not content.strip():
        st.info("Waiting for content…")
        return
    try:
        import tomllib
        tomllib.loads(content)
        st.success("✅ Valid TOML")
    except ImportError:
        try:
            import tomli
            tomli.loads(content)
            st.success("✅ Valid TOML")
        except ImportError:
            st.info("Install `tomli` for TOML validation")
        except Exception as e:
            st.error(f"❌ TOML error: {e}")
    except Exception as e:
        st.error(f"❌ TOML error: {e}")


# ── Step 5: Review & Push ─────────────────────────────────────────────────────

def _step_review_push(client, project, repo, uc_root):
    meta         = st.session_state.get("editor_meta", {})
    branch       = st.session_state.get("editor_branch", "")
    uc_id        = meta.get("uc_id", "UC-XXX")
    category  = meta.get("category", "")
    sigma_content   = st.session_state.get("editor_sigma", "")
    elastic_content = st.session_state.get("editor_elastic", "")

    st.subheader(f"5 · Review & Push  ·  `{uc_id}`  ·  branch `{branch}`")

    # ── Generate README ───────────────────────────────────────────────────────
    readme_content = readme_template(
        uc_id=uc_id,
        title=meta.get("title",""),
        description=meta.get("description",""),
        author=meta.get("author",""),
        severity=meta.get("severity","medium"),
        status=meta.get("status","experimental"),
        mitre_tags=meta.get("mitre_tags",[]),
        false_positives=meta.get("false_positives",""),
        references=meta.get("references",""),
        category=category,
        coverage_assets=meta.get("coverage_assets",""),
        coverage_width=meta.get("coverage_width",0.0),
        coverage_depth=meta.get("coverage_depth",""),
        datasources=meta.get("datasources",""),
        datasets=meta.get("datasets",""),
        detection_method=meta.get("detection_method",""),
        triage=meta.get("triage",""),
        response=meta.get("response",""),
        playbooks=meta.get("playbooks",""),
        mttd=meta.get("mttd",""),
        fp_rate=meta.get("fp_rate",""),
        pipelines=meta.get("pipelines",""),
    )

    # ── Build file paths ──────────────────────────────────────────────────────
    uc_slug = re.sub(r"[^a-z0-9_]", "_", uc_id.lower())
    cat_part = f"/{category}" if category else ""
    uc_folder = f"{uc_root.rstrip('/')}{cat_part}/{uc_id}"

    files_to_push = [
        {
            "path": f"{uc_folder}/README.md",
            "content": readme_content,
            "label": "📄 README.md",
        },
        {
            "path": f"{uc_folder}/detection/{uc_slug}_sigma.yml",
            "content": sigma_content,
            "label": "σ Sigma YAML",
        },
        # {
        #     "path": f"{uc_folder}/implementation/{uc_slug}_elastic_rule.toml",
        #     "content": elastic_content,
        #     "label": "⚡ Elastic Rule TOML",
        # },
    ]

    if meta.get("gen_elastic") and st.session_state.get("editor_elastic"):
        files_to_push.append({"path": f"{uc_folder}/implementation/elastic/{uc_slug}_elastic_rule.toml",
                      "content": st.session_state["editor_elastic"], "label": "⚡ Elastic"})
    if meta.get("gen_defender") and st.session_state.get("editor_defender"):
        files_to_push.append({"path": f"{uc_folder}/implementation/defender/{uc_slug}_defender.kql",
                      "content": st.session_state["editor_defender"], "label": "🛡️ Defender"})
    if meta.get("gen_sentinel") and st.session_state.get("editor_sentinel"):
        files_to_push.append({"path": f"{uc_folder}/implementation/sentinel/{uc_slug}_sentinel.json",
                      "content": st.session_state["editor_sentinel"], "label": "☁️ Sentinel"})

    # ── File previews ─────────────────────────────────────────────────────────
    tabs = st.tabs([f["label"] for f in files_to_push])
    for tab, f in zip(tabs, files_to_push):
        with tab:
            st.caption(f"`{f['path']}`")
            ext = f["path"].split(".")[-1]
            lang = {"md":"markdown","yml":"yaml","toml":"toml","json":"json","kql":"text"}.get(ext, "text")
            st.code(f["content"], language=lang)

    st.markdown("---")

    # ── Validation summary ────────────────────────────────────────────────────
    sv = SigmaValidator()
    sigma_result = sv.validate(sigma_content)
    if sigma_result.valid:
        st.success("✅ Sigma validation passed")
    else:
        st.error(f"❌ Sigma has {len(sigma_result.errors)} error(s) — you can still push but review recommended")

    st.markdown(f"**{len(files_to_push)} files** will be pushed to `{branch}`")

    # ── Commit message ────────────────────────────────────────────────────────
    commit_msg = st.text_input(
        "Commit message",
        value=f"feat({uc_id}): add detection use case — {meta.get('title','')}",
    )

    col_back, _, col_push = st.columns([1, 2, 2])
    with col_back:
        if st.button("← Back"):
            st.session_state.editor_step = 4
            st.rerun()

    with col_push:
        if st.button("🚀 Push to branch", type="primary"):
            with st.spinner(f"Pushing {len(files_to_push)} files to `{branch}`…"):
                try:
                    result = client.push_files(
                        project=project, repo=repo, branch=branch,
                        files=[{"path": f["path"], "content": f["content"]} for f in files_to_push],
                        commit_message=commit_msg,
                    )
                    st.success(f"✅ Pushed! Commit `{result['commit_id'][:8]}`")
                    st.session_state.editor_pushed = True
                    st.session_state.editor_push_branch = branch
                    st.session_state.editor_push_meta   = meta
                except Exception as e:
                    st.error(f"Push failed: {e}")

    # ── PR creation (shown after push) ───────────────────────────────────────
    if st.session_state.get("editor_pushed"):
        st.markdown("---")
        st.markdown("### 🔀 Create Pull Request")

        target = st.selectbox("Merge into", ["dev", "main"])
        pr_title = st.text_input(
            "PR title",
            value=f"[{uc_id}] {meta.get('title','')}",
        )
        pr_body = st.text_area(
            "PR description",
            value=_pr_body(meta),
            height=220,
        )

        if st.button("🔀 Create PR", type="primary"):
            with st.spinner("Creating PR…"):
                try:
                    pr = client.create_pull_request(
                        project=project, repo=repo,
                        title=pr_title, description=pr_body,
                        source_branch=branch, target_branch=target,
                    )
                    org_url  = st.session_state.get("org_url","")
                    pr_url   = f"{org_url}/{project}/_git/{repo}/pullrequest/{pr['id']}"
                    st.success(f"✅ PR #{pr['id']} created!")
                    st.markdown(f"[🔗 Open PR in Azure DevOps]({pr_url})")
                    # Reset editor state
                    for key in ("editor_step","editor_branch","editor_meta","editor_meta_prev",
                          "editor_sigma","editor_elastic","editor_defender","editor_sentinel",
                          "editor_pushed","editor_sigma_customised","editor_elastic_customised",
                          "editor_defender_customised","editor_sentinel_customised","new_uc_id"):
                        st.session_state.pop(key, None)
                except Exception as e:
                    st.error(f"PR creation failed: {e}")



# ═══════════════════════════════════════════════════════════════════════════════
# EDIT MODE
# ═══════════════════════════════════════════════════════════════════════════════

def _edit_mode(client, project, repo, uc_root):
    use_cases = st.session_state.get("use_cases", [])
    if not use_cases:
        st.warning("No use cases loaded — go to the sidebar and click **Load Use Cases** first.")
        return

    # ── Select use case ───────────────────────────────────────────────────────
    uc_names  = [uc.name for uc in use_cases]
    #branch    = st.session_state.get("branch", "dev")

    col1, col2 = st.columns([2, 1])
    with col1:
        selected_name = st.selectbox("Select use case to edit", uc_names)
    with col2:
        branches = client.list_branches(project, repo)
        feat_branches = [b for b in branches if b not in ("main", "dev")]
        feat_branches.append("Create a new branch")
        edit_branch = st.selectbox(
            "Target branch",
            feat_branches or branches,
            help="Branch to commit edits to. Create a new feature branch first if needed.",
        )

        if edit_branch == "Create a new branch":
            edit_branch = st.text_input("New branch name", value="", placeholder="feat/uc-024-edit", key="edit_branch_name")

    uc = next((u for u in use_cases if u.name == selected_name), None)
    if not uc:
        return

    # ── Load files on demand ──────────────────────────────────────────────────
    edit_key = f"edit_{uc.name}"
    if edit_key not in st.session_state:
        with st.spinner(f"Loading files for {uc.name}…"):
            # if uc.readme and not uc.readme.content:
            #     try:    uc.readme.content = client.load_file(uc.readme)
            #     except: pass
            # if uc.sigma and not uc.sigma.content:
            #     try:    uc.sigma.content = client.load_file(uc.sigma)
            #     except: pass
            # if uc.elastic_rule and not uc.elastic_rule.content:
            #     try:    uc.elastic_rule.content = client.load_file(uc.elastic_rule)
            #     except: pass
            for attr in ("readme","sigma","elastic_rule","defender_rule","sentinel_rule"):
                df = getattr(uc, attr, None)
                if df and not df.content:
                    try: df.content = client.load_file(df)
                    except: pass
        st.session_state[edit_key] = {
            "readme":  uc.readme.content  if uc.readme  else "",
            "sigma":   uc.sigma.content   if uc.sigma   else "",
            "elastic": uc.elastic_rule.content if uc.elastic_rule else "",
            "defender":  uc.defender_rule.content if uc.defender_rule else "",
            "sentinel":  uc.sentinel_rule.content if uc.sentinel_rule else "",
        }

    state = st.session_state[edit_key]

    st.markdown("---")

    # ── Tabbed editors ────────────────────────────────────────────────────────
    cols = st.columns(5)
    for col, (label, present) in zip(cols, [
        ("📄 README", bool(uc.readme)),
        ("σ Sigma",   bool(uc.sigma)),
        ("⚡ Elastic", bool(uc.elastic_rule)),
        ("🛡️ Defender", bool(uc.defender_rule)),
        ("☁️ Sentinel", bool(uc.sentinel_rule)),
    ]):
        col.markdown(f"{'✅' if present else '❌'} {label}")

    tab_labels = ["📄 README","σ Sigma","⚡ Elastic","🛡️ Defender XDR","☁️ Sentinel"]
    tabs = st.tabs(tab_labels)

    # README
    with tabs[0]:
        new_readme = st.text_area("README content", value=state["readme"],
                                  height=500, label_visibility="collapsed")
        if new_readme != state["readme"]:
            st.session_state[edit_key]["readme"] = new_readme

    # Sigma
    with tabs[1]:
        col_ed, col_val = st.columns([3, 2])
        with col_ed:
            st.markdown("**Edit Sigma YAML**")

            new_sigma = st.text_area("Sigma content", value=state["sigma"],
                                     height=480, label_visibility="collapsed")
            if new_sigma != state["sigma"]:
                st.session_state[edit_key]["sigma"] = new_sigma

            c1, c2, c3 = st.columns(3)
            with c1:
                if st.button("⚡ → Elastic", key=f"s2e_{uc.name}"):
                    toml, errs = sigma_to_elastic(st.session_state[edit_key]["sigma"])
                    if toml: st.session_state[edit_key]["elastic"] = toml; st.success("Elastic updated"); st.rerun()
                    else:    st.error("; ".join(errs))
            with c2:
                if st.button("🛡️ → Defender", key=f"s2d_{uc.name}"):
                    kql, errs = sigma_to_defender_rule(st.session_state[edit_key]["sigma"])
                    if kql: st.session_state[edit_key]["defender"] = kql; st.success("Defender updated"); st.rerun()
                    else:   st.error("; ".join(errs))
            with c3:
                if st.button("☁️ → Sentinel", key=f"s2s_{uc.name}"):
                    jsn, errs = sigma_to_sentinel(st.session_state[edit_key]["sigma"])
                    if jsn: st.session_state[edit_key]["sentinel"] = jsn; st.success("Sentinel updated"); st.rerun()
                    else:   st.error("; ".join(errs))

            # if st.button("⚡ Convert Sigma → Elastic", key=f"conv_s2e_{uc.name}", type="primary"):
            #     toml_str, errs = sigma_to_elastic(st.session_state[edit_key]["sigma"])
            #     if toml_str:
            #         st.session_state[edit_key]["elastic"] = toml_str
            #         st.success("✅ Elastic rule updated from Sigma — review the Elastic tab")
            #         for w in errs:
            #             st.caption(f"⚠️ {w}")
            #         st.rerun()
            #     else:
            #         st.error("Conversion failed: " + "; ".join(errs))

        with col_val:
            st.markdown("**Live validation**")
            _live_sigma_validation(st.session_state[edit_key]["sigma"])

    # Elastic
    with tabs[2]:
        col_ed2, col_chk = st.columns([3, 2])
        with col_ed2:
            st.markdown("**Edit Elastic TOML**")
            new_elastic = st.text_area("Elastic content", value=state["elastic"],
                                       height=480, label_visibility="collapsed")
            if new_elastic != state["elastic"]:
                st.session_state[edit_key]["elastic"] = new_elastic

            if st.button("σ Convert Sigma → Elastic", key=f"sig2e_{uc.name}", type="primary"):
                toml, errs = sigma_to_elastic(st.session_state[edit_key]["sigma"])
                if toml: 
                    st.session_state[edit_key]["elastic"] = toml
                    st.success("✅ Elastic rule updated from Sigma — review the Elastic tab")
                    for w in errs:
                        st.caption(f"⚠️ {w}")
                    st.rerun()
                else:    st.error("; ".join(errs))
            if st.button("σ Convert Elastic → Sigma", key=f"e2sig_{uc.name}"):
                yml, errs = elastic_to_sigma(st.session_state[edit_key]["elastic"])
                if yml: 
                    st.session_state[edit_key]["sigma"] = yml
                    st.success("✅ Sigma rule updated from Elastic — review the Sigma tab")
                    for w in errs:
                        st.caption(f"⚠️ {w}")
                    st.rerun()
                else:   st.error("; ".join(errs))

            # if st.button("σ Convert Elastic → Sigma", key=f"conv_e2s_{uc.name}", type="primary"):
            #     toml_str, errs = elastic_to_sigma(st.session_state[edit_key]["elastic"])
            #     if toml_str:
            #         st.session_state[edit_key]["sigma"] = toml_str
            #         st.success("✅ Sigma rule updated from Elastic — review the Sigma tab")
            #         for w in errs:
            #             st.caption(f"⚠️ {w}")
            #         st.rerun()
            #     else:
            #         st.error("Conversion failed: " + "; ".join(errs))

        with col_chk:
            st.markdown("**TOML syntax check**")
            _toml_check(st.session_state[edit_key]["elastic"])

    # Defender
    with tabs[3]:
        col_ed, col_val = st.columns([3,2])
        with col_ed:
            st.markdown("**Edit Defender KQL**")

            new_def = st.text_area("Defender", value=state["defender"], height=420,
                                   label_visibility="collapsed")
            if new_def != state["defender"]: st.session_state[edit_key]["defender"] = new_def
            if st.button("σ Convert Sigma → Defender", key=f"sig2d_{uc.name}", type="primary"):
                kql, errs = sigma_to_defender_rule(st.session_state[edit_key]["sigma"])
                if kql: 
                    st.session_state[edit_key]["defender"] = kql
                    st.success("✅ Defender rule updated from Sigma")
                    for w in errs:
                        st.caption(f"⚠️ {w}")
                    st.rerun()
                else:   st.error("; ".join(errs))
        with col_val:
            st.markdown("**KQL Check**")
            kql_valid, kql_errors = _validate_defender_schema(st.session_state[edit_key]["defender"])
            syntax_valid, syntax_errors = _validate_kql(st.session_state[edit_key]["defender"])
            if kql_valid:
                st.success("✅ Valid Defender rule schema")
            else:
                st.error(f"❌ Defender schema error: {kql_errors}")
            if syntax_valid:
                st.success("✅ Valid Defender KQL syntax")
            else:
                st.error(f"❌ Defender KQL syntax error: {syntax_errors}")      

 
    # Sentinel
    with tabs[4]:
        col_ed, col_val = st.columns([3,2])
        with col_ed:
            st.markdown("**Edit Sentinel JSON**")
            new_sen = st.text_area("Sentinel", value=state["sentinel"], height=420,
                                   label_visibility="collapsed")
            if new_sen != state["sentinel"]: st.session_state[edit_key]["sentinel"] = new_sen
            if st.button("σ Convert Sigma → Sentinel", key=f"sig2sen_{uc.name}", type="primary"):
                jsn, errs = sigma_to_sentinel(st.session_state[edit_key]["sigma"])
                if jsn: 
                    st.session_state[edit_key]["sentinel"] = jsn
                    st.success("✅ Sigma rule updated from Sentinel — review the Sigma tab")
                    for w in errs:
                        st.caption(f"⚠️ {w}")
                    st.rerun()
                else:   st.error("; ".join(errs))
        with col_val:
            st.markdown("**JSON Check**")
            _json_check(st.session_state[edit_key]["sentinel"])


    # ── Push ──────────────────────────────────────────────────────────────────
    st.markdown("---")
    commit_msg = st.text_input(
        "Commit message",
        value=f"fix({uc.name}): update detection files",
    )

    files_to_push = []
    if uc.readme:        files_to_push.append({"path": uc.readme.path,       "content": state["readme"]})
    if uc.sigma:         files_to_push.append({"path": uc.sigma.path,        "content": state["sigma"]})
    if uc.elastic_rule:  files_to_push.append({"path": uc.elastic_rule.path, "content": state["elastic"]})
    if uc.defender_rule: files_to_push.append({"path": uc.defender_rule.path,"content": state["defender"]})
    if uc.sentinel_rule: files_to_push.append({"path": uc.sentinel_rule.path,"content": state["sentinel"]})

    col_push, col_pr = st.columns(2)
    with col_push:
        if st.button("🚀 Push edits to branch", type="primary", disabled=not edit_branch):
            with st.spinner(f"Pushing to `{edit_branch}`…"):
                try:
                    if not client.branch_exists(project, repo, edit_branch):
                        new_branch_result = client.create_branch(project, repo, edit_branch, "dev")
                        if new_branch_result:
                            st.success(f"✅ Branch `{edit_branch}` created for PR")
                            _cached_list_branches.clear()

                    result = client.push_files(
                        project=project, repo=repo, branch=edit_branch,
                        files=files_to_push,
                        commit_message=commit_msg,
                    )
                    st.success(f"✅ Pushed! Commit `{result['commit_id'][:8]}`")
                    st.session_state[f"{edit_key}_pushed"] = True
                    st.session_state[f"{edit_key}_push_branch"] = edit_branch
                except Exception as e:
                    st.error(f"Push failed: {e}")

    with col_pr:
        if st.session_state.get(f"{edit_key}_pushed"):
            if st.button("🔀 Create PR from this branch"):
                try:
                    pr = client.create_pull_request(
                        project=project, repo=repo,
                        title=f"[{uc.name}] Update detection files",
                        description=f"Updated detection files for {uc.name} from the Detection Engineering Platform.\n\n**Branch:** `{edit_branch}`",
                        source_branch=st.session_state[f"{edit_key}_push_branch"],
                        target_branch="dev",
                    )
                    org_url = st.session_state.get("org_url","")
                    pr_url  = f"{org_url}/{project}/_git/{repo}/pullrequest/{pr['id']}"
                    st.success(f"✅ PR #{pr['id']} created!")
                    st.markdown(f"[🔗 Open in Azure DevOps]({pr_url})")
                except Exception as e:
                    st.error(f"PR creation failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Shared helpers
# ═══════════════════════════════════════════════════════════════════════════════
 
def _convert_sigma_to_all_siems(sigma_content: str, meta: dict):
    if meta.get("gen_elastic"):
        toml, _ = sigma_to_elastic(sigma_content)
        if toml: st.session_state.editor_elastic = toml; st.session_state.editor_elastic_customised = True
    if meta.get("gen_defender"):
        kql, _ = sigma_to_defender_rule(sigma_content)
        if kql: st.session_state.editor_defender = kql; st.session_state.editor_defender_customised = True
    if meta.get("gen_sentinel"):
        jsn, _ = sigma_to_sentinel(sigma_content)
        if jsn: st.session_state.editor_sentinel = jsn; st.session_state.editor_sentinel_customised = True
    if st.session_state.editor_elastic_customised and st.session_state.editor_defender_customised and st.session_state.editor_sentinel_customised:
        return True, []
    return False, _ #["Conversion failed for one or more SIEMs"]

def _apply_conversion(content_key, customised_key, content, errors):
    if content:
        st.session_state[content_key] = content
        st.session_state[customised_key] = True
        for e in errors: st.caption(f"⚠️ {e}")
    else:
        st.error("; ".join(errors))
 
 
def _live_sigma_validation(content: str):
    if not content.strip(): st.info("Start typing…"); return
    sv     = SigmaValidator()
    result = sv.validate(content)
    if result.valid: st.success("✅ Valid Sigma")
    else:            st.error(f"❌ {len(result.errors)} error(s)")
    for issue in result.issues:
        icon  = {"error":"🔴","warning":"🟡","info":"🔵"}.get(issue.level,"⚪")
        field = f" `{issue.field}`" if issue.field else ""
        st.markdown(f"{icon} **{issue.code}**{field}  \n{issue.message}")
    if result.elastic_query:
        with st.expander("Elastic Lucene query"):
            st.code(result.elastic_query, language="text")
 
def _validate_defender_schema(rule_json: str) -> Tuple[bool, List[str]]:
    errors = []

    try:
        rule = json.loads(rule_json)
    except Exception as e:
        return False, [f"Invalid JSON: {e}"]

    # Required top-level fields
    required_fields = ["displayName", "queryCondition", "schedule", "detectionAction"]
    for field in required_fields:
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    # Query
    query = rule.get("queryCondition", {}).get("queryText")
    if not query:
        errors.append("queryCondition.queryText is required")

    # Schedule
    if "period" not in rule.get("schedule", {}):
        errors.append("schedule.period is required")

    # Alert template
    alert = rule.get("detectionAction", {}).get("alertTemplate", {})
    if not alert.get("title"):
        errors.append("alertTemplate.title is required")
    if not alert.get("severity"):
        errors.append("alertTemplate.severity is required")

    # Severity enum
    valid_sev = ["low", "medium", "high", "informational"]
    if alert.get("severity") not in valid_sev:
        errors.append(f"Invalid severity: {alert.get('severity')}")

    return len(errors) == 0, errors

def _validate_kql(query: str) -> Tuple[bool, List[str]]:
    errors = []

    if not query.strip():
        return False, ["Query is empty"]

    # Basic sanity checks
    if "|" not in query:
        errors.append("Query missing pipe operator '|'")

    if "where" not in query.lower():
        errors.append("Query has no filters (where clause)")

    # Defender tables check
    valid_tables = [
        "DeviceProcessEvents",
        "DeviceNetworkEvents",
        "DeviceFileEvents",
        "DeviceRegistryEvents",
        "DeviceLogonEvents",
        "EmailEvents",
        "CloudAppEvents"
    ]

    if not any(tbl in query for tbl in valid_tables):
        errors.append("Query does not reference a known Defender table")

    return len(errors) == 0, errors

def _toml_check(content: str):
    if not content.strip(): st.info("No content."); return
    try:
        import tomllib; tomllib.loads(content); st.success("✅ Valid TOML")
    except ImportError:
        try:
            import tomli; tomli.loads(content); st.success("✅ Valid TOML")
        except ImportError: st.info("Install `tomli` for TOML validation")
        except Exception as e: st.error(f"❌ {e}")
    except Exception as e: st.error(f"❌ {e}")
 
 
def _kql_check(content: str):
    if not content.strip(): st.info("No content."); return
    lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("//")]
    if lines: st.success(f"✅ {len(lines)} non-comment line(s)")
    else:     st.warning("Only comments — add your KQL query")
    # Check for table reference
    tables = ["DeviceProcessEvents","DeviceNetworkEvents","DeviceFileEvents",
              "DeviceRegistryEvents","DeviceLogonEvents","EmailEvents","CloudAppEvents",
              "SecurityEvent","SigninLogs","AzureActivity","CommonSecurityLog",
              "DnsEvents","OfficeActivity","IdentityLogonEvents"]
    found = [t for t in tables if t in content]
    if found: st.markdown("**Table:** " + ", ".join(f"`{t}`" for t in found))
    else:     st.warning("No known Defender/Sentinel table found in query")
 
 
def _json_check(content: str):
    if not content.strip(): st.info("No content."); return
    try:
        doc = json.loads(content)
        st.success("✅ Valid JSON")
        # Check for ARM structure
        resources = doc.get("resources", [])
        if resources:
            kind = resources[0].get("kind","")
            name = resources[0].get("properties",{}).get("displayName","")
            sev  = resources[0].get("properties",{}).get("severity","")
            st.markdown(f"**Rule:** `{name}`  **Kind:** `{kind}`  **Severity:** `{sev}`")
    except json.JSONDecodeError as e:
        st.error(f"❌ JSON error: {e}")


def _extract_techniques(mitre_tags: list[str]) -> list[str]:
    return [t.split(".")[-1].upper() for t in mitre_tags
            if re.search(r"(?i)t\d{4}", t.split(".")[-1] if "." in t else t)]
 
 
def _extract_tactics(mitre_tags: list[str]) -> list[str]:
    return [t.split(".")[-1] for t in mitre_tags
            if "attack." in t.lower() and not re.search(r"(?i)t\d{4}", t.split(".")[-1])]
 
 
def _pr_body(meta: dict) -> str:
    tags = ", ".join(f"`{t}`" for t in meta.get("mitre_tags",[]))
    platforms = [p for p, k in [("Elastic","gen_elastic"),("Defender XDR","gen_defender"),("Sentinel","gen_sentinel")]
                 if meta.get(k)]
    return f"""## {meta.get('uc_id','')} — {meta.get('title','')}
 
**Severity:** {meta.get('severity','').title()} | **Status:** {meta.get('status','').title()} | **Author:** {meta.get('author','')}
**Platforms:** {', '.join(platforms) or 'N/A'}
 
### Description
{meta.get('description','')}
 
### MITRE ATT&CK
{tags or '_Not specified_'}
 
### False Positives
{meta.get('false_positives','_None identified_')}
 
### Checklist
- [ ] Sigma validates without errors
- [ ] Elastic query verified in dev environment
- [ ] Defender XDR query tested in Advanced Hunting
- [ ] Sentinel rule deployed and tested in dev workspace
- [ ] README complete
- [ ] Test cases added
"""