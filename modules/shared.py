"""
modules/shared.py — Auto-refresh orchestration
================================================
Provides auto_refresh(), a single function called at the top of the
Overview, Validator, and Statistics pages.
 
Why this exists
---------------
Streamlit re-renders the entire page on every interaction (button click,
selectbox change, etc.). Without a staleness guard, expensive operations
(ADO file fetches, Sigma parsing, MITRE mapping, stats computation) would
re-run on every render, making the UI sluggish.
 
auto_refresh() uses a fingerprint — a frozenset of UC names — to detect
when the loaded use cases have changed (e.g. after "Load Use Cases" or
switching branches). It only re-runs the pipeline when:
  - the fingerprint has changed (new use cases loaded), OR
  - force=True is passed (user clicked "Force Refresh")
 
Pipeline order
--------------
1. _ensure_content_loaded  — fetch Sigma + README text from ADO (lazy, skips already-loaded)
2. _run_validation         — Sigma schema + README completeness checks
3. _build_mitre            — extract ATT&CK tags and build MitreCoverage
4. _compute_stats          — health scores, severity/status/platform distributions
 
All results are written into st.session_state so every page can read them
without re-computing.
"""
 
from __future__ import annotations
import streamlit as st
 
 
def auto_refresh(force: bool = False):
    """
    Orchestrate the full validation + MITRE + stats pipeline if results
    are stale or missing.
 
    Parameters
    ----------
    force : bool
        If True, skip the fingerprint check and re-run unconditionally.
        Used by the "Force Refresh" / "Force Recompute" buttons.
    """
    use_cases = st.session_state.get("use_cases", [])
    if not use_cases:
        return  # nothing to do — no use cases loaded yet
 
    # Fingerprint is a frozenset of UC names; changes when the UC list changes
    uc_fingerprint = frozenset(uc.name for uc in use_cases)
    cached_fp      = st.session_state.get("_refresh_fingerprint")
    is_stale       = force or (cached_fp != uc_fingerprint)
 
    if not is_stale:
        return  # results are still valid — skip the expensive pipeline
 
    client = st.session_state.get("ado_client")
 
    # ── Step 1: Load Sigma + README content if not already in memory ──────────
    _ensure_content_loaded(use_cases, client)
 
    # ── Step 2: Validate all use cases ───────────────────────────────────────
    _run_validation(use_cases)
 
    # ── Step 3: Build MITRE coverage ─────────────────────────────────────────
    _build_mitre(use_cases)
 
    # ── Step 4: Compute statistics ────────────────────────────────────────────
    _compute_stats(use_cases)
 
    # Update fingerprint so subsequent renders skip the pipeline
    st.session_state._refresh_fingerprint = uc_fingerprint
 
 
def _ensure_content_loaded(use_cases, client):
    """
    Lazily fetch Sigma and README file contents from ADO.
 
    Only downloads files whose `content` field is still empty ("").
    This avoids re-fetching files already loaded by the Explorer or Editor.
    Silently skips files that fail to load (e.g. 404, permissions).
    """
    if not client:
        return  # no ADO connection — can't fetch anything
    for uc in use_cases:
        for df in [uc.sigma, uc.readme]:
            if df and not df.content:
                try:
                    df.content = client.load_file(df)
                except Exception:
                    pass  # leave content as "" — downstream steps handle missing content
 
 
def _run_validation(use_cases):
    """
    Run Sigma YAML and README completeness validation for all use cases.
 
    Results are stored as dicts keyed by uc.name:
        st.session_state.sigma_results  : {name: SigmaValidationResult}
        st.session_state.readme_results : {name: ReadmeValidationResult}
 
    SigmaValidator also attempts a pySigma → Elastic Lucene conversion
    and stores the result on the SigmaValidationResult object.
    """
    from modules.sigma_validator import SigmaValidator
    from modules.readme_validator import ReadmeValidator
    sv = SigmaValidator()
    rv = ReadmeValidator()
    sigma_results  = {}
    readme_results = {}
 
    for uc in use_cases:
        if uc.sigma and uc.sigma.content:
            sigma_results[uc.name] = sv.validate(uc.sigma.content)
        if uc.readme and uc.readme.content:
            readme_results[uc.name] = rv.validate(uc.readme.content)
 
    st.session_state.sigma_results  = sigma_results
    st.session_state.readme_results = readme_results
 
 
def _build_mitre(use_cases):
    """
    Extract MITRE ATT&CK technique tags from each Sigma file and build
    a MitreCoverage object.
 
    MitreCoverage holds a dict of {technique_id: {name, tactics, use_cases}}
    and a tactic_counts property for the statistics/MITRE pages.
 
    If no Sigma files have content (e.g. ADO fetch failed), this is a no-op.
    """
    from modules.mitre_mapper import MitreMapper
    mapper  = MitreMapper()
    uc_data = [
        {"name": uc.name, "sigma_content": uc.sigma.content}
        for uc in use_cases
        if uc.sigma and uc.sigma.content
    ]
    if uc_data:
        st.session_state.mitre_coverage = mapper.build_coverage(uc_data)
 
 
def _compute_stats(use_cases):
    """
    Compute health scores, completeness counters, severity/status/platform
    distributions, and tactic coverage counts.
 
    StatsEngine.compute() also builds MITRE coverage internally if
    st.session_state.mitre_coverage is None (e.g. on first load before
    _build_mitre has run). The returned coverage is written to session state.
 
    Results stored:
        st.session_state.stats           : DetectionStats
        st.session_state.mitre_coverage  : MitreCoverage (may be updated)
        st.session_state.stats_fingerprint : frozenset (for statistics.py's own guard)
    """
    from modules.stats import StatsEngine
    engine = StatsEngine()
    stats, coverage = engine.compute(
        use_cases=use_cases,
        sigma_results=st.session_state.get("sigma_results", {}),
        readme_results=st.session_state.get("readme_results", {}),
        mitre_coverage=st.session_state.get("mitre_coverage"),
    )
    st.session_state.stats = stats
    st.session_state.stats_fingerprint = frozenset(uc.name for uc in use_cases)
    if coverage:
        st.session_state.mitre_coverage = coverage