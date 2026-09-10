"""
ui_pages/pull_requests.py — Pull Request management
=====================================================
Two tabs:
  📋 Active PRs  — lists all PRs for the current repo with status + ADO link
  ➕ Create PR   — form to open a PR from a feature branch with a pre-flight checklist
 
The PR list is cached in st.session_state.pr_list and invalidated by
the "Refresh PRs" button or after a new PR is created.
"""

import streamlit as st


def render():
    st.title("🔀 Pull Requests")

    client = st.session_state.get("ado_client")
    if not client:
        st.info("Connect to Azure DevOps in the sidebar first.")
        return

    project = st.session_state.get("project")
    repo = st.session_state.get("repo")

    if not project or not repo:
        st.warning("Load a repository first.")
        return

    tabs = st.tabs(["📋 Active PRs", "➕ Create PR"])

    # ── Tab 1: Active PRs ─────────────────────────────────────────────────────
    with tabs[0]:
        # Refresh button clears the cached PR list so the next render re-fetches
        if st.button("🔄 Refresh PRs"):
            st.session_state.pop("pr_list", None)

        # Lazy-load the PR list on first render or after refresh
        if "pr_list" not in st.session_state:
            with st.spinner("Loading PRs…"):
                try:
                    prs = client.list_pull_requests(project, repo)
                    st.session_state.pr_list = prs
                except Exception as e:
                    st.error(f"Failed to load PRs: {e}")
                    return

        prs = st.session_state.get("pr_list", [])
        if not prs:
            st.info("No active pull requests.")
        else:
            for pr in prs:
                # Map ADO PR status to an emoji indicator
                status_icon = {"active": "🟢", "completed": "✅", "abandoned": "🔴"}.get(pr["status"], "⚪")
                with st.expander(f"{status_icon} PR #{pr['id']} — {pr['title']}"):
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown(f"**Source branch:** `{pr['source']}`")
                        st.markdown(f"**Target branch:** `{pr['target']}`")
                    with c2:
                        st.markdown(f"**Created by:** {pr['created_by']}")
                        st.markdown(f"**Status:** {pr['status']}")
                    if pr.get("created_date"):
                        st.caption(f"Created: {pr['created_date']}")

                    # Deep link to the PR in Azure DevOps
                    url = f"{st.session_state.get('org_url')}/{project}/_git/{repo}/pullrequest/{pr['id']}"
                    st.markdown(f"[🔗 Open in Azure DevOps]({url})")

    # ── Tab 2: Create PR ──────────────────────────────────────────────────────
    with tabs[1]:
        st.markdown("Create a PR from a feature branch to `dev`.")

        try:
            branches = client.list_branches(project, repo)
        except Exception as e:
            st.error(f"Could not list branches: {e}")
            return

        # Filter out protected branches — engineers should only PR from feature branches
        feature_branches = [b for b in branches if b not in ("main", "master", "dev")]

        source = st.selectbox("Source branch (feature)", feature_branches or branches)
        target = st.selectbox("Target branch", ["dev", "main"])
        title = st.text_input("PR Title", placeholder="feat: add detection for …")
        description = st.text_area("Description", placeholder="## Summary\n\n## Testing\n\n## MITRE ATT&CK\n\n")

        # Pre-flight checklist — the Create button is disabled until all boxes are ticked.
        # This enforces a minimum quality bar before code reaches dev.
        st.markdown("**Pre-PR checklist:**")
        checks = {
            "Sigma file validated":         st.checkbox("Sigma file validates without errors"),
            "Elastic query generated":      st.checkbox("Elastic query successfully generated"),
            "README complete":              st.checkbox("README includes description, MITRE tags, false positives"),
            "Tested in dev environment":    st.checkbox("Rule tested in dev SIEM environment"),
        }
        all_checked = all(checks.values())

        if not all_checked:
            st.warning("Complete the checklist before creating a PR.")

        if st.button("🚀 Create Pull Request", disabled=not (title and all_checked)):
            try:
                result = client.create_pull_request(
                    project=project, repo=repo,
                    title=title, description=description,
                    source_branch=source, target_branch=target,
                )
                st.success(f"✅ PR #{result['id']} created!")
                # Invalidate cached PR list so it refreshes on next tab visit
                st.session_state.pop("pr_list", None)  
            except Exception as e:
                st.error(f"Failed to create PR: {e}")
