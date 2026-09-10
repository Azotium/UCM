"""
app.py — Detection Engineering Platform
========================================
Main entry point for the Streamlit application.
Run with:  streamlit run app.py
 
Architecture overview
---------------------
- All pages live in ui_pages/ and are dynamically loaded via importlib.
- All shared business logic lives in modules/.
- Session state acts as the in-memory data store between page navigations.
- Credentials and repo settings are persisted to ~/.dep_session.json via
  modules/local_storage.py (PAT is encrypted with a keyring-stored key).
- ADO API calls are cached with @st.cache_data (TTL 5–10 min) to avoid
  hammering the API on every Streamlit rerun.
"""

import streamlit as st
import sys, os

# Ensure modules/ and ui_pages/ are importable from any working directory
sys.path.insert(0, os.path.dirname(__file__))

st.set_page_config(
    page_title="Detection Engineering Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Global CSS ────────────────────────────────────────────────────────────────
# Injected once at startup so all pages share the same visual theme.
# Uses Google Fonts for typography and overrides Streamlit's default
# metric, tab, and expander styles to match the dark security-tool aesthetic.
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600&display=swap');

  html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
  code, pre, .stCode { font-family: 'JetBrains Mono', monospace; }

  /* Sidebar */
  [data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #21262d;
  }
  [data-testid="stSidebar"] * { color: #c9d1d9 !important; }
  [data-testid="stSidebar"] .stSelectbox label,
  [data-testid="stSidebar"] .stTextInput label { color: #8b949e !important; font-size: 0.75rem; }

  /* Main background */
  .main { background: #010409; }
  .block-container { padding-top: 1.5rem; }

  /* Metric cards */
  [data-testid="stMetric"] {
    background: #a0c7f2;
    border: 1px solid #a0c7f2;
    border-radius: 8px;
    padding: 1rem;
  }
  [data-testid="stMetricValue"] { color: #2187fc; font-weight: 600; }

  /* Status badges */
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.72rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
  }
  .badge-error   { background: #3d1f1f; color: #f85149; border: 1px solid #f8514933; }
  .badge-warning { background: #2d2208; color: #e3b341; border: 1px solid #e3b34133; }
  .badge-ok      { background: #0f2d1a; color: #3fb950; border: 1px solid #3fb95033; }
  .badge-info    { background: #0d2137; color: #58a6ff; border: 1px solid #58a6ff33; }

  /* Section headers */
  h1, h2, h3 { color: black !important; }
  h1 { font-size: 1.6rem !important; font-weight: 600 !important; }
  h3 { font-size: 1rem !important; color: black !important; font-weight: 400 !important; }

  /* Tab styling */
  .stTabs [data-baseweb="tab-list"] { background: white; border-radius: 8px; gap: 10px;  }
  .stTabs [data-baseweb="tab"] { color: #8b949e; background: transparent; border-radius: 6px; padding: 5px 10px; }
  .stTabs [aria-selected="true"] { background: #1f6feb22 !important; color: #58a6ff !important; }

  /* Expander */
  .streamlit-expanderHeader { background: #0d1117 !important; color: #c9d1d9 !important; }
  .streamlit-expanderContent { background: #010409 !important; border: 1px solid #21262d; }

    .st-key-styled_button button{
            border-radius:8px;
            box-shadow: 3px 5px 10px 0px rgba(128, 128, 128, 0.245);
            border-color:black;
            background-color:darkslategrey;
        }
    .st-key-styled_button:hover button{
            border-color:black;
            background-color:white;
            color:black;
        }
    .st-key-styled_button :focus:not(:active) {
            border-color:black;
        }
    .st-key-styled_button p{
            color:darkslategrey;
            font-weight: bold;
        }
    .st-key-styled_button :active p {
            color:white;
            font-weight: bold;
        }
    .st-key-styled_button span[data-testid="stIconMaterial"]{
            color:orange;
        }
    .st-key-styled_button :active span[data-testid="stIconMaterial"]{
            color:white;
        }
</style>
""", unsafe_allow_html=True)

# ── Persistent session bridge ─────────────────────────────────────────────────
# load_from_storage() reads ~/.dep_session.json and pushes org_url, PAT,
# project, repo, branch, uc_root back into st.session_state.
# The PAT is decrypted using a key stored in the OS keyring (modules/local_storage.py).
from modules.local_storage import load_from_storage, save_to_storage, clear_storage
load_from_storage()   # reads localStorage → session_state on first render after refresh

# ── Session state defaults ────────────────────────────────────────────────────
# Any key not already set (e.g. on first run) gets its default value here.
# Keys already populated by load_from_storage() are intentionally NOT overwritten.
_defaults = {
    "ado_client":        None,   # ADOClient instance (not serialisable — rebuilt on each session)
    "use_cases":         [],     # list[DetectionUseCase] loaded from the repo
    "sigma_results":     {},     # {uc.name: SigmaValidationResult} — populated by validator/auto_refresh
    "readme_results":    {},     # {uc.name: ReadmeValidationResult}
    "mitre_coverage":    None,   # MitreCoverage — populated by mitre_mapper/auto_refresh
    "stats":             None,   # DetectionStats — populated by stats engine/auto_refresh
    "org_url":           "",     # Azure DevOps organization URL
    "pat":               "",     # Personal Access Token (decrypted at runtime)
    "project":           None,   # Selected ADO project name
    "repo":              None,   # Selected repository name
    "branch":            "dev",  # Active branch (default: dev)
    "uc_root":           "/UseCases",  # Repo path to the use-cases root folder
    "projects":          [],     # Cached list of ADO projects for the selectbox
    "_storage_loaded":   False,  # Internal flag: local_storage bridge has fired
    "_auto_connect_done": False, # Internal flag: auto-reconnect attempt has been made
}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

 
# ── Auto-reconnect after browser refresh ─────────────────────────────────────
# After a hard refresh, Streamlit loses all Python objects (including the
# ADOClient instance) but session_state is also cleared. local_storage.py
# restores the primitive values (org_url, PAT, etc.) from disk. This block
# then rebuilds the ADOClient and reloads use cases silently.
# The _auto_connect_done flag prevents this from running on every render.
if (
    not st.session_state._auto_connect_done
    and not st.session_state.ado_client
    and st.session_state.org_url
    and st.session_state.pat
):
    try:
        from modules.ado_client import ADOClient
        client = ADOClient(
            org_url=st.session_state.org_url,
            pat=st.session_state.pat,
        )
        # list_projects is cached — essentially free after first call
        projects = client.list_projects()
        st.session_state.ado_client = client
        st.session_state.projects = projects
 
        # Also restore use cases if we have enough context
        if (
            st.session_state.project
            and st.session_state.repo
            and st.session_state.branch
        ):
            use_cases = client.list_use_cases(
                st.session_state.project,
                st.session_state.repo,
                st.session_state.branch,
                use_cases_root=st.session_state.uc_root,
            )
            st.session_state.use_cases = use_cases
    except Exception as e:
        # Silent failure — user will see the "Not connected" indicator and
        # can reconnect manually. Don't crash the app.
        st.sidebar.warning(f"Auto-reconnect failed: {e}")
        st.session_state._auto_connect_done = False  # allow retry on next manual connect


# ── Sidebar ───────────────────────────────────────────────────────────────────
# Connection status indicator

with st.sidebar:
    st.markdown("## 🛡️ Detection Platform")

    # Connection status indicator — green when ADOClient is live
    if st.session_state.ado_client:
        st.markdown("🟢 **Connected**")
    else:
        st.markdown("🔴 **Not connected**")
 
    # ── Azure DevOps connection section ───────────────────────────────────────
    # Collapsed in a st.expander so it doesn't dominate the sidebar once connected
    with st.expander("Azure DevOps", expanded=not st.session_state.ado_client):
        org_url = st.text_input(
            "Organization URL",
            placeholder="https://dev.azure.com/myorg",
            value=st.session_state.org_url,
        )
        pat = st.text_input(
            "Personal Access Token",
            type="password",
            value=st.session_state.pat,
        )
 
        col_conn, col_disc = st.columns([3, 1])
        with col_conn:
            if st.button("🔌 Connect", width="stretch"):
                if org_url and pat:
                    try:
                        from modules.ado_client import ADOClient
                        client = ADOClient(org_url=org_url, pat=pat)
                        projects = client.list_projects()

                        # Store client and metadata in session state
                        st.session_state.ado_client = client
                        st.session_state.projects = projects
                        st.session_state.org_url = org_url
                        st.session_state.pat = pat
                        st.session_state._auto_connect_done = True

                        # Persist to disk so the next refresh auto-reconnects
                        save_to_storage({
                            "org_url": org_url,
                            "pat": pat,
                            "project": st.session_state.get("project", ""),
                            "repo": st.session_state.get("repo", ""),
                            "branch": st.session_state.get("branch", "dev"),
                            "uc_root": st.session_state.get("uc_root", "/UseCases"),
                        })
                        st.success(f"Connected — {len(projects)} project(s)")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Connection failed: {e}")
                else:
                    st.warning("Enter org URL and PAT")
        with col_disc:
            if st.button("✕", help="Disconnect & clear saved session", width='stretch'):
                clear_storage()
                for k, v in _defaults.items():
                    st.session_state[k] = v
                st.rerun()
 
    # ── Repository selector ─────────────────────────────
    # Only shown when connected. Dropdowns are populated from cached ADO API calls.

    if st.session_state.ado_client:
        with st.expander("Repository", expanded=True):
            client = st.session_state.ado_client
    
            projects = st.session_state.get("projects", [])
            saved_project = st.session_state.get("project")
            project_idx = projects.index(saved_project) if saved_project in projects else 0
            project = st.selectbox("Project", projects, index=project_idx)
    
            if project:
                # list_repos is @st.cache_data — won't hit the API on every render
                repos = client.list_repos(project)   # cached
                saved_repo = st.session_state.get("repo")
                repo_idx = repos.index(saved_repo) if saved_repo in repos else 0
                repo = st.selectbox("Repository", repos, index=repo_idx)
    
                if repo:
                    # list_branches is @st.cache_data
                    branches = client.list_branches(project, repo)   # cached
                    saved_branch = st.session_state.get("branch", "dev")
                    branch_idx = branches.index(saved_branch) if saved_branch in branches else 0
                    branch = st.selectbox("Branch", branches, index=branch_idx)
    
                    # Root path within the repo where UC folders live
                    # Supports an optional category level: /UseCases/[category]/UC-NNN
                    uc_root = st.text_input(
                        "Use Cases root path",
                        value=st.session_state.get("uc_root", "/UseCases"),
                        help="Root folder containing UC-NNN folders (optional category level supported)",
                    )
    
                    if st.button("📥 Load Use Cases", width='stretch'):
                        with st.spinner("Loading…"):
                            # list_use_cases is @st.cache_data (TTL 5 min)
                            use_cases = client.list_use_cases(
                                project, repo, branch, use_cases_root=uc_root
                            )
                            st.session_state.use_cases = use_cases
                            st.session_state.project = project
                            st.session_state.repo = repo
                            st.session_state.branch = branch
                            st.session_state.uc_root = uc_root
                            # Persist updated repo settings
                            save_to_storage({
                                "org_url": st.session_state.org_url,
                                "pat": st.session_state.pat,
                                "project": project,
                                "repo": repo,
                                "branch": branch,
                                "uc_root": uc_root,
                            })
                        # Show discovered categories in the success message
                        cats = sorted({
                            cat for uc in use_cases
                            if (cat := getattr(uc, "category", None))
                        })
                        msg = f"Loaded {len(use_cases)} use case(s)"
                        if cats:
                            msg += f" · categories: {', '.join(cats)}"
                        st.success(msg)
    
                    # Show cached status
                    if st.session_state.use_cases:
                        st.caption(f"📦 {len(st.session_state.use_cases)} use cases in memory")
                        if st.button("🗑️ Clear cache", width='stretch', help="Force reload from ADO on next load"):
                            from modules.ado_client import (
                                _cached_list_use_cases, _cached_list_projects,
                                _cached_list_repos, _cached_list_branches
                            )
                            _cached_list_use_cases.clear()
                            _cached_list_projects.clear()
                            _cached_list_repos.clear()
                            _cached_list_branches.clear()
                            st.session_state.use_cases = []
                            st.rerun()


# ── Navigation ────────────────────────────────────────────────────────────────
# Each page is a Python file with a render() function.
# Pages are dynamically loaded with importlib so adding a new page only
# requires adding an entry here — no Streamlit multipage boilerplate needed
pages = {
    "🏠 Overview":          "ui_pages/overview.py",
    "🔍 Use Case Explorer": "ui_pages/explorer.py",
    "✏️ Editor":            "ui_pages/editor.py",
    "✅ Validator":         "ui_pages/validator.py",
    "🛡️ MITRE Coverage":    "ui_pages/mitre.py",
    "📊 Statistics":        "ui_pages/statistics.py",
    "🔀 Pull Requests":     "ui_pages/pull_requests.py",
}

page = st.sidebar.radio("Navigate", list(pages.keys()), label_visibility="collapsed")

# Dynamically load and execute the selected page module
import importlib.util
page_file = os.path.join(os.path.dirname(__file__), pages[page])

if os.path.exists(page_file):
    spec = importlib.util.spec_from_file_location("page", page_file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if hasattr(mod, "render"):
        mod.render()
else:
    st.info("This page is not yet available.")