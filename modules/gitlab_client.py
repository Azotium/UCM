"""
gitlab_client.py — GitLab integration layer
=============================================
Implements the exact same public interface as ADOClient so every UI page
and module works without any changes.

Public interface (mirrors ADOClient exactly)
--------------------------------------------
    GitLabClient(url, token)
    .list_projects()                              → list[str]
    .list_repos(project)                          → list[str]
    .list_branches(project, repo)                 → list[str]
    .list_use_cases(project, repo, branch, root)  → list[DetectionUseCase]
    .load_file(DetectionFile)                     → str
    .load_use_case(DetectionUseCase)              → DetectionUseCase
    .push_files(project, repo, branch, files, msg)→ {"push_id", "commit_id"}
    .create_branch(project, repo, new, base)      → {"branch", "sha", "result"}
    .branch_exists(project, repo, branch)         → bool
    .list_pull_requests(project, repo)            → list[dict]
    .create_pull_request(project, repo, ...)      → {"id", "url"}

Naming conventions
------------------
GitLab terminology differs from Azure DevOps in a few places:

    ADO term        GitLab term     Notes
    ─────────────── ─────────────── ──────────────────────────────────────
    Organization    Instance URL    e.g. https://gitlab.com or self-hosted
    Project         Group           top-level namespace (org/team)
    Repository      Project         the actual Git repo
    Pull Request    Merge Request   same concept, different name
    PAT             Private token   same concept (also supports OAuth tokens)

In this module, `project` means the GitLab **group** (or user namespace),
and `repo` means the GitLab **project** (the actual repository).
The `project` parameter is a namespace path, e.g. "mygroup" or "mygroup/subgroup".

The GitLab REST API v4 is used directly via the `python-gitlab` library.
Fallback to raw `requests` calls where python-gitlab doesn't expose an endpoint.

Authentication
--------------
Pass a Personal Access Token with at least:
  - api scope (needed for MRs, file writes)
  - read_repository scope (needed for file reads and tree listing)

For self-hosted GitLab, pass the instance URL as `url`
(e.g. https://gitlab.example.com).  gitlab.com is the default.

Dependencies
------------
    pip install python-gitlab
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import base64

import streamlit as st

# python-gitlab is the official GitLab Python client
try:
    import gitlab
except ImportError:
    raise ImportError(
        "python-gitlab is required for GitLab support.\n"
        "Install it with:  pip install python-gitlab"
    )

# Re-use the shared data models from ado_client so session_state contents
# are identical regardless of which backend is connected.
from modules.ado_client import DetectionFile, DetectionUseCase


# ---------------------------------------------------------------------------
# GitLab client
# ---------------------------------------------------------------------------

class GitLabClient:
    """
    GitLab integration layer with the same public interface as ADOClient.

    `project` throughout this module refers to a GitLab **namespace**
    (group or username).  `repo` refers to a GitLab **project** (repository).

    Usage
    -----
        client = GitLabClient(url="https://gitlab.com", token="glpat-xxx")
        namespaces = client.list_projects()      # groups/namespaces
        repos      = client.list_repos("mygroup")
        branches   = client.list_branches("mygroup", "detections")
        use_cases  = client.list_use_cases("mygroup", "detections", "dev")
    """

    def __init__(self, url: str, token: str):
        """
        Parameters
        ----------
        url   : GitLab instance URL, e.g. "https://gitlab.com"
        token : Personal Access Token (scope: api + read_repository)
        """
        self._url   = url.rstrip("/")
        self._token = token

        # Initialise the python-gitlab connection.
        # ssl_verify=True is the default; set to False for self-signed certs.
        ###self._gl = gitlab.Gitlab(url=self._url, private_token=self._token)
        ###self._gl.auth()   # validates the token immediately; raises on failure
        
        self._gl = gitlab.Gitlab(
            url=self._url,
            private_token=self._token,
        )

        # Cache of resolved GitLab project objects keyed by "namespace/repo_name"
        # to avoid repeated API lookups within a session.
        self._project_cache: dict[str, object] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_gl_project(self, namespace: str, repo: str):
        """
        Resolve a GitLab Project object from namespace + repo name.

        Tries the full path "namespace/repo" first (most common case),
        then falls back to searching by name within the namespace.
        Result is cached for the lifetime of this client instance.
        """
        key = f"{namespace}/{repo}"
        if key not in self._project_cache:
            try:
                # get() accepts a full path like "mygroup/myrepo"
                self._project_cache[key] = self._gl.projects.get(key)
            except gitlab.exceptions.GitlabGetError:
                # Search within namespace — handles subgroups and forks
                results = self._gl.projects.list(search=repo, namespace=namespace)
                match   = next((p for p in results if p.path == repo or p.name == repo), None)
                if match is None:
                    raise ValueError(f"Repository '{repo}' not found in namespace '{namespace}'")
                self._project_cache[key] = match
        return self._project_cache[key]

    # ------------------------------------------------------------------
    # Project / namespace discovery
    # ------------------------------------------------------------------

    def list_projects(self) -> list[str]:
        """
        Return the list of GitLab groups/namespaces the token has access to.

        Mirrors ADOClient.list_projects() which returns ADO project names.
        In GitLab terms these are top-level groups (or the user's own namespace).
        """
        return _cached_gl_list_namespaces(self._url, self._token)

    def list_repos(self, namespace: str) -> list[str]:
        """
        Return the list of GitLab project names (repositories) within a namespace.

        Mirrors ADOClient.list_repos(project).
        """
        return _cached_gl_list_repos(self._url, self._token, namespace)

    def list_branches(self, namespace: str, repo: str) -> list[str]:
        """Return all branch names for a GitLab repository."""
        return _cached_gl_list_branches(self._url, self._token, namespace, repo)

    # ------------------------------------------------------------------
    # Use-case discovery — same logic as ADOClient._list_use_cases_impl
    # ------------------------------------------------------------------

    def list_use_cases(
        self,
        namespace: str,
        repo: str,
        branch: str = "dev",
        use_cases_root: str = "/UseCases",
    ) -> list[DetectionUseCase]:
        """
        Discover all DetectionUseCase objects under use_cases_root.
        Cached for 5 minutes (same TTL as ADOClient).
        """
        return _cached_gl_list_use_cases(
            self._url, self._token, namespace, repo, branch, use_cases_root
        )

    def _list_use_cases_impl(
        self,
        namespace: str,
        repo: str,
        branch: str,
        use_cases_root: str,
    ) -> list[DetectionUseCase]:
        """
        Internal implementation.  Fetches the repository tree recursively and
        applies the same folder-structure heuristics as ADOClient.
        Called by _cached_gl_list_use_cases to avoid re-entrancy.
        """
        gl_project = self._get_gl_project(namespace, repo)
        root_clean  = use_cases_root.rstrip("/")

        # GitLab tree API: get all items under use_cases_root recursively.
        # path must omit the leading slash for the GitLab API.
        api_path = root_clean.lstrip("/")
        try:
            items = gl_project.repository_tree(
                path=api_path,
                ref=branch,
                recursive=True,
                get_all=True,   # paginate automatically
            )
        except gitlab.exceptions.GitlabGetError as e:
            raise ValueError(
                f"Could not list tree at '{use_cases_root}' on branch '{branch}': {e}"
            )

        # Index files and folders from the flat tree response.
        # GitLab tree items have: {"id", "name", "type": "blob"|"tree", "path", "mode"}
        # Paths from GitLab do NOT have a leading slash — we normalise to add one.
        all_files:   dict[str, object] = {}
        all_folders: set[str]          = set()
        for item in items:
            # Normalise to absolute paths (matching ADOClient convention)
            abs_path = "/" + item["path"].lstrip("/")
            if item["type"] == "tree":
                all_folders.add(abs_path.rstrip("/"))
            else:
                all_files[abs_path] = item

        # Identify UC root folders using the same depth heuristic as ADOClient.
        uc_roots: list[str] = []
        for folder in sorted(all_folders):
            if folder.rstrip("/") == root_clean:
                continue   # skip the root itself

            rel   = folder[len(root_clean):].strip("/")
            depth = len(rel.split("/"))

            # UCs are at depth 1 (flat) or depth 2 (category/UC-NNN)
            if depth not in (1, 2):
                continue

            has_detection = any(p.startswith(f"{folder}/detection/") for p in all_files)
            has_readme    = f"{folder}/README.md" in all_files

            if has_detection or has_readme:
                uc_roots.append(folder)

        use_cases = []
        for uc_root in uc_roots:
            uc = DetectionUseCase(
                folder=uc_root,
                branch=branch,
                repo=repo,
                project=namespace,   # "project" field holds the namespace in GitLab mode
            )

            # README.md at UC root (case-insensitive candidates)
            for candidate in [f"{uc_root}/README.md", f"{uc_root}/readme.md", f"{uc_root}/Readme.md"]:
                if candidate in all_files:
                    uc.readme = DetectionFile(candidate, "", branch, repo, namespace)
                    break

            # Sigma: first .yml in detection/
            for path in sorted(all_files):
                if path.startswith(f"{uc_root}/detection/") and path.endswith(".yml"):
                    uc.sigma = DetectionFile(path, "", branch, repo, namespace)
                    break

            # Elastic: first .toml in implementation/elastic/
            for path in sorted(all_files):
                if path.startswith(f"{uc_root}/implementation/elastic/") and path.endswith(".toml"):
                    uc.elastic_rule = DetectionFile(path, "", branch, repo, namespace)
                    break

            # Defender: first .kql in implementation/defender/
            for path in sorted(all_files):
                if path.startswith(f"{uc_root}/implementation/defender/") and path.endswith(".kql"):
                    uc.defender_rule = DetectionFile(path, "", branch, repo, namespace)
                    break

            # Sentinel: first .json in implementation/sentinel/
            for path in sorted(all_files):
                if path.startswith(f"{uc_root}/implementation/sentinel/") and path.endswith(".json"):
                    uc.sentinel_rule = DetectionFile(path, "", branch, repo, namespace)
                    break

            # Extra files: pipelines, tests, dashboards
            for path in sorted(all_files):
                if not path.startswith(uc_root + "/"):
                    continue
                rel        = path[len(uc_root) + 1:]
                top_folder = rel.split("/")[0]
                if top_folder in ("pipelines", "tests", "dashboards"):
                    uc.extra_files.append(DetectionFile(path, "", branch, repo, namespace))

            use_cases.append(uc)

        return use_cases

    # ------------------------------------------------------------------
    # Content loading
    # ------------------------------------------------------------------

    def load_file(self, df: DetectionFile) -> str:
        """
        Fetch the raw UTF-8 content of a single file from GitLab.

        Uses the repository files API (GET /projects/:id/repository/files/:path).
        The path must NOT have a leading slash for this API endpoint.
        Content is returned base64-encoded by GitLab and decoded here.
        """
        gl_project = self._get_gl_project(df.project, df.repo)
        api_path   = df.path.lstrip("/")   # GitLab files API requires no leading slash

        file_info = gl_project.files.get(file_path=api_path, ref=df.branch)
        # GitLab returns content as base64-encoded bytes
        raw = base64.b64decode(file_info.content)
        return raw.decode("utf-8", errors="replace")

    def load_use_case(self, uc: DetectionUseCase) -> DetectionUseCase:
        """Eagerly load content for README, Sigma, and all SIEM rule files."""
        for attr in ("readme", "sigma", "elastic_rule", "defender_rule", "sentinel_rule"):
            df: Optional[DetectionFile] = getattr(uc, attr)
            if df:
                df.content = self.load_file(df)
        for ef in uc.extra_files:
            ef.content = self.load_file(ef)
        return uc

    # ------------------------------------------------------------------
    # Branch management
    # ------------------------------------------------------------------

    def branch_exists(self, namespace: str, repo: str, branch: str) -> bool:
        """Return True if `branch` exists in the repository."""
        gl_project = self._get_gl_project(namespace, repo)
        try:
            gl_project.branches.get(branch)
            return True
        except gitlab.exceptions.GitlabGetError:
            return False

    def create_branch(
        self,
        namespace: str,
        repo: str,
        new_branch: str,
        base_branch: str = "dev",
    ) -> dict:
        """
        Create `new_branch` from the HEAD of `base_branch`.

        Returns {"branch": str, "sha": str, "result": bool}
        to match the ADOClient interface.
        """
        gl_project = self._get_gl_project(namespace, repo)

        # Get the SHA of the base branch HEAD
        try:
            base_ref = gl_project.branches.get(base_branch)
            base_sha = base_ref.commit["id"]
        except gitlab.exceptions.GitlabGetError:
            raise ValueError(f"Base branch '{base_branch}' not found")

        # Create the new branch pointing at base_sha
        gl_project.branches.create({"branch": new_branch, "ref": base_branch})

        return {"branch": new_branch, "sha": base_sha, "result": True}

    # ------------------------------------------------------------------
    # File push — commit multiple files in a single GitLab commit
    # ------------------------------------------------------------------

    def push_files(
        self,
        project: str,
        repo: str,
        branch: str,
        files: list[dict],      # [{"path": str, "content": str}, ...]
        commit_message: str,
    ) -> dict:
        """
        Commit one or more files to branch in a single GitLab commit.

        Uses the Commits API (POST /projects/:id/repository/commits) with
        multiple actions in one request — equivalent to ADOClient.push_files().

        Returns {"push_id": None, "commit_id": str}.
        GitLab commits don't have a separate push_id concept, so push_id is
        set to None (callers only display commit_id[:8]).
        """
        gl_project = self._get_gl_project(project, repo)

        # Build the actions list: each file is either "create" or "update"
        actions = []
        for f in files:
            file_exists = self._file_exists_gl(gl_project, branch, f["path"])
            action_type = "update" if file_exists else "create"

            actions.append({
                "action":    action_type,
                "file_path": f["path"].lstrip("/"),   # GitLab API: no leading slash
                "content":   f["content"],            # plain UTF-8 text
                "encoding":  "text",
            })

        # Create the commit with all actions in one request
        commit = gl_project.commits.create({
            "branch":         branch,
            "commit_message": commit_message,
            "actions":        actions,
        })

        return {
            "push_id":   None,              # not a GitLab concept
            "commit_id": commit.id,         # full SHA
        }

    def _file_exists_gl(self, gl_project, branch: str, path: str) -> bool:
        """Check if a file exists without downloading its content."""
        try:
            gl_project.files.get(file_path=path.lstrip("/"), ref=branch)
            return True
        except gitlab.exceptions.GitlabGetError:
            return False

    # ------------------------------------------------------------------
    # Merge Request (≡ Pull Request) management
    # ------------------------------------------------------------------

    def list_pull_requests(self, namespace: str, repo: str) -> list[dict]:
        """
        Return open (and recently merged) Merge Requests as plain dicts.

        Dict keys match ADOClient.list_pull_requests() exactly so
        ui_pages/pull_requests.py works without changes.

        GitLab MR states: "opened" → "active", "merged" → "completed",
        "closed" → "abandoned"  (mapped to ADO equivalents).
        """
        gl_project = self._get_gl_project(namespace, repo)

        # Fetch open + merged MRs (the PR page shows both)
        mrs = gl_project.mergerequests.list(
            state="all",
            order_by="updated_at",
            per_page=50,
            get_all=False,
        )

        STATE_MAP = {
            "opened": "active",
            "merged": "completed",
            "closed": "abandoned",
            "locked": "active",
        }

        return [
            {
                "id":           mr.iid,          # internal project MR number (not global id)
                "title":        mr.title,
                "source":       mr.source_branch,
                "target":       mr.target_branch,
                "status":       STATE_MAP.get(mr.state, mr.state),
                "created_by":   mr.author.get("name", mr.author.get("username", "unknown")),
                "created_date": mr.created_at,
                # Extra GitLab-specific fields (ignored by pull_requests.py but available)
                "web_url":      mr.web_url,
                "description":  mr.description or "",
            }
            for mr in mrs
        ]

    def create_pull_request(
        self,
        namespace: str,
        repo: str,
        title: str,
        description: str,
        source_branch: str,
        target_branch: str = "dev",
    ) -> dict:
        """
        Open a Merge Request from source_branch into target_branch.

        Returns {"id": int, "url": str} matching ADOClient.create_pull_request().
        """
        gl_project = self._get_gl_project(namespace, repo)

        mr = gl_project.mergerequests.create({
            "source_branch": source_branch,
            "target_branch": target_branch,
            "title":         title,
            "description":   description,
            # Remove the source branch automatically after merge (optional)
            "remove_source_branch": False,
        })

        return {"id": mr.iid, "url": mr.web_url}


# ---------------------------------------------------------------------------
# Cached module-level functions (TTL matches ado_client.py)
# ---------------------------------------------------------------------------
# Module-level so Streamlit can cache them by primitive arguments.
# Each creates a lightweight GitLabClient without going through __init__'s
# full auth cycle (auth() is called once per session when the client is first
# constructed in app.py).

@st.cache_data(ttl=600, show_spinner=False)
# def _cached_gl_list_namespaces(url: str, token: str) -> list[str]:
#     """
#     Return accessible top-level group paths + the authenticated user's namespace.
#     Cached 10 minutes.
#     """
#     gl = gitlab.Gitlab(url=url, private_token=token)

#     namespaces = []

#     # Top-level groups the token has at least Reporter access to
#     try:
#         groups     = gl.groups.list(top_level_only=True, min_access_level=10, get_all=True)
#         namespaces = [g.full_path for g in groups]
#     except Exception:
#         pass

#     # Also include the authenticated user's personal namespace
#     try:
#         # user = gl.auth()
#         # if hasattr(gl, "user") and gl.user:
#         #     personal = gl.user.username
#         #     if personal not in namespaces:
#         #         namespaces.insert(0, personal)
#         user = gl.http_get("/user")
#         personal = user["username"]
#         if personal not in namespaces:
#             namespaces.insert(0, personal)
        
#     except Exception:
#         pass

#     return sorted(namespaces) if namespaces else ["(no groups found)"]

def _cached_gl_list_namespaces(url: str, token: str) -> list[str]:
    """
    Return accessible top-level GitLab groups.
    """
    gl = gitlab.Gitlab(
        url=url.rstrip("/"),
        private_token=token,
    )

    try:
        groups = gl.groups.list(get_all=True)

        return sorted(g.full_path for g in groups)

    except Exception as e:
        raise RuntimeError(f"Could not retrieve GitLab groups: {e}")

@st.cache_data(ttl=600, show_spinner=False)
def _cached_gl_list_repos(url: str, token: str, namespace: str) -> list[str]:
    """
    Return project (repository) names within a namespace.
    Cached 10 minutes.
    """
    gl = gitlab.Gitlab(url=url, private_token=token)

    try:
        # Try as a group first
        group    = gl.groups.get(namespace)
        projects = group.projects.list(get_all=True, include_subgroups=False)
        return sorted(p.path for p in projects)
    except gitlab.exceptions.GitlabGetError:
        pass

    # Fall back to user projects
    try:
        user_projects = gl.projects.list(
            namespace=namespace,
            owned=True,
            get_all=True,
        )
        return sorted(p.path for p in user_projects)
    except Exception:
        return []


@st.cache_data(ttl=600, show_spinner=False)
def _cached_gl_list_branches(url: str, token: str, namespace: str, repo: str) -> list[str]:
    """Return all branch names for a repository. Cached 10 minutes."""
    gl         = gitlab.Gitlab(url=url, private_token=token)
    gl_project = gl.projects.get(f"{namespace}/{repo}")
    branches   = gl_project.branches.list(get_all=True)
    return sorted(b.name for b in branches)


@st.cache_data(ttl=300, show_spinner=False)
def _cached_gl_list_use_cases(
    url: str,
    token: str,
    namespace: str,
    repo: str,
    branch: str,
    use_cases_root: str,
) -> list:
    """
    Scan the repository tree and return DetectionUseCase objects.
    Cached 5 minutes — same TTL as ADOClient.
    """
    # Build a minimal client instance without triggering the full __init__
    # auth cycle (which would re-validate the token on every cache miss).
    client         = GitLabClient.__new__(GitLabClient)
    client._url    = url
    client._token  = token
    client._gl     = gitlab.Gitlab(url=url, private_token=token)
    client._project_cache = {}
    return client._list_use_cases_impl(namespace, repo, branch, use_cases_root)