"""
ado_client.py — Azure DevOps integration layer
================================================
Provides:
  - DetectionFile    : lightweight dataclass holding a single file's path + content
  - DetectionUseCase : dataclass grouping all files for one UC folder
  - ADOClient        : thin SDK wrapper with cached list/discovery methods
  - Module-level @st.cache_data functions that survive Streamlit reruns
 
Design decisions
----------------
- ADOClient.__init__ builds the SDK connection eagerly (the git client is needed
  by almost every method). Heavy operations (list, fetch) are delegated to
  module-level cached functions so the cache key is a plain tuple of primitives
  (org_url, pat, project, …) — Streamlit cannot cache methods whose `self` is
  a non-hashable object.
- _make_connection() creates a raw SDK Connection without going through
  ADOClient.__init__, which prevents circular re-entrancy when cached functions
  need to bootstrap a fresh git client.
- push_files() uses the REST-level dict format for changes (changeType="add"/"edit",
  contentType="rawtext") rather than the SDK's GitChange model, which requires
  base64 encoding. The REST approach is simpler and avoids an extra encode/decode.
"""

from __future__ import annotations
import fnmatch
from dataclasses import dataclass, field
from typing import Optional

from azure.devops.connection import Connection
from azure.devops.v7_1.git.models import GitVersionDescriptor, ItemContent
from msrest.authentication import BasicAuthentication
import streamlit as st


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DetectionFile:
    """
    A single file inside a detection use case.
 
    `content` starts as an empty string and is lazily populated by
    ADOClient.load_file() or modules/shared.py's _ensure_content_loaded().
    Lazy loading avoids fetching every file on startup — only open files
    are fetched.
    """
    path: str       # full repo path, e.g. /UseCases/checkpoint/UC-023/README.md
    content: str    # raw UTF-8 text; "" until loaded
    branch: str     # branch this file was read from
    repo: str       # repository name
    project: str    # ADO project name


@dataclass
class DetectionUseCase:
    """
    All files belonging to a single detection use case.
 
    Canonical folder structure expected in the repo:
        UseCases/
        [category/]          ← optional subcategory level
        └── UC-NNN/
            ├── README.md                          ← metadata & documentation
            ├── detection/       *.yml             ← Sigma generic detection rule
            ├── implementation/
            │   ├── elastic/     *.toml            ← Elastic Security rule
            │   ├── defender/    *.kql             ← Defender XDR Advanced Hunting
            │   └── sentinel/    *.json            ← Sentinel ARM analytics rule
            ├── pipelines/       *.yml             ← ingest/enrichment pipelines
            ├── tests/           *.json            ← positive/negative test cases
            └── dashboards/      *.ndjson          ← Kibana/Grafana dashboards
 
    Fields are Optional because not every UC will have every file.
    `is_complete` defines the minimum viable set: README + Sigma + ≥1 SIEM rule.
    """
    folder: str          # full repo path to the UC root, e.g. /UseCases/checkpoint/UC-023
    branch: str
    repo: str
    project: str
    readme:        Optional[DetectionFile] = None
    sigma:         Optional[DetectionFile] = None
    elastic_rule:  Optional[DetectionFile] = None   # implementation/elastic/*.toml
    defender_rule: Optional[DetectionFile] = None   # implementation/defender/*.kql
    sentinel_rule: Optional[DetectionFile] = None   # implementation/sentinel/*.json
    extra_files:   list[DetectionFile] = field(default_factory=list)

    
    @property
    def name(self) -> str:
        """
        Return the UC identifier (e.g. 'UC-023').
 
        Walks the path segments after 'UseCases/', skipping known
        subfolder names (detection, implementation, etc.) to handle
        both flat (UseCases/UC-NNN) and categorised
        (UseCases/category/UC-NNN) layouts.
        """

        parts = self.folder.rstrip("/").split("/")

        if "UseCases" not in parts:
            return parts[-1]

        idx = parts.index("UseCases")
        tail = parts[idx + 1:]
        # Skip the category segment if it matches
        if tail[0] == self.category:
            tail = parts[idx+2:]

        # folders that are NOT UC identifiers
        skip = {"detection", "pipelines", "tests", "dashboards", "implementation"}

        for part in tail:
            if part not in skip:
                return part

        return tail[-1]

    @property
    def category(self) -> str:
        """
        The category folder if present, else empty string.
        e.g. /UseCases/checkpoint/UC-023  ->  'checkpoint'
             /UseCases/UC-023             ->  ''
        """
        parts = self.folder.rstrip("/").split("/")
        use_cases_idx = next((i for i, p in enumerate(parts) if p.lower() == "usecases"), None)
        # A category exists only if there are ≥2 segments after 'UseCases'
        if use_cases_idx is not None and len(parts) - use_cases_idx > 2:
            return parts[use_cases_idx + 1]
        return ""

    @property
    def is_complete(self) -> bool:
        """True when the minimum viable set of files is present."""
        return bool(self.readme and self.sigma and
                    (self.elastic_rule or self.defender_rule or self.sentinel_rule))
    
    @property
    def siem_rules(self) -> dict:
        """Return a dict of present SIEM rules: {label: DetectionFile}."""
        rules = {}
        if self.elastic_rule:   rules["Elastic"]   = self.elastic_rule
        if self.defender_rule:  rules["Defender"]  = self.defender_rule
        if self.sentinel_rule:  rules["Sentinel"]  = self.sentinel_rule
        return rules

    @property
    def extra_by_folder(self) -> dict:
        """Group extra_files by their immediate subfolder (pipelines/tests/dashboards)."""
        groups: dict = {}
        for ef in self.extra_files:
            rel = ef.path[len(self.folder) + 1:]
            sub = rel.split("/")[0]
            groups.setdefault(sub, []).append(ef)
        return groups


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class ADOClient:
    """
    Thin wrapper around the Azure DevOps Python SDK for detection engineering.

    Usage
    -----
    client = ADOClient(org_url="https://dev.azure.com/myorg", pat="xxx")
    use_cases = client.list_use_cases(project="MyProject", repo="detections", branch="dev")
    uc = client.load_use_case(use_cases[0])
    """

    def __init__(self, org_url: str, pat: str):
        self.org_url = org_url.rstrip("/")
        self._pat = pat
        credentials = BasicAuthentication("", pat)
        self.connection = Connection(base_url=self.org_url, creds=credentials)
        # git client is used by almost every operation — build it once here
        self._git = self.connection.clients.get_git_client()

    # ------------------------------------------------------------------
    # Read-only list operations (all delegated to @st.cache_data functions)
    # ------------------------------------------------------------------

    def list_projects(self) -> list[str]:
        """Return all ADO project names the PAT has access to."""
        return _cached_list_projects(self.org_url, self._pat)
 
    def list_repos(self, project: str) -> list[str]:
        """Return all repository names in a project."""
        return _cached_list_repos(self.org_url, self._pat, project)
 
    def list_branches(self, project: str, repo: str) -> list[str]:
        """Return all branch names (without refs/heads/ prefix) for a repo."""
        return _cached_list_branches(self.org_url, self._pat, project, repo)

    # ------------------------------------------------------------------
    # Use-case discovery
    # ------------------------------------------------------------------

    def list_use_cases(
        self,
        project: str,
        repo: str,
        branch: str = "dev",
        use_cases_root: str = "/UseCases",
    ) -> list[DetectionUseCase]: 
        """
        Discover and return all DetectionUseCase objects under use_cases_root.
        Result is cached for 5 minutes. Use Clear Cache in the sidebar to force
        a fresh scan.
        """
        return _cached_list_use_cases(self.org_url, self._pat, project, repo, branch, use_cases_root)

    def _list_use_cases_impl(
        self,
        project: str,
        repo: str,
        branch: str = "dev",
        use_cases_root: str = "/UseCases",
    ) -> list[DetectionUseCase]:
        """
        Internal implementation called by _cached_list_use_cases.
 
        Strategy:
        1. Fetch the full recursive file tree under use_cases_root in one API call.
        2. Identify UC root folders at depth 1 (flat layout) or depth 2
           (category/UC layout) by checking for a README or detection/ subfolder.
        3. For each UC root, assign the canonical files by path prefix matching.
        4. Collect non-canonical files (pipelines, tests, dashboards) as extras.
        """

        items = self._git.get_items(
            repository_id=repo,
            project=project,
            scope_path=use_cases_root,
            version_descriptor=GitVersionDescriptor(version=branch, version_type="branch"),
            recursion_level="full", # fetch the entire subtree in one request
        )

        # Separate folders from files for efficient lookups
        all_files: dict[str, object] = {}
        all_folders: set[str] = set()
        for item in items:
            if item.is_folder:
                all_folders.add(item.path.rstrip("/"))
            else:
                all_files[item.path] = item

        # Identify UC root folders: direct children of use_cases_root,
        # OR direct children of a category (one level deeper).
        # A UC root is a folder whose name matches UC-* (case-insensitive),
        # or simply any folder that contains a README.md at its root.
        
        uc_roots: list[str] = []
        root_clean = use_cases_root.rstrip("/")

        for folder in sorted(all_folders):
            if folder.rstrip("/") == use_cases_root.rstrip("/"):
                continue
            # rel is the path relative to use_cases_root; depth 1 = flat, depth 2 = categorised
            rel = folder[len(root_clean):].strip("/")
            depth = len(rel.split("/"))

            # UC must always be at depth 1 or 2:
            # UseCases/UC-001
            # UseCases/category/UC-001
            if depth not in (1, 2):
                continue # skip deeper subfolders (implementation, detection, etc.)

            # must contain detection OR readme somewhere below
            has_detection = any(p.startswith(f"{folder}/detection/") for p in all_files)
            has_readme = f"{folder}/README.md" in all_files

            if has_detection or has_readme:
                uc_roots.append(folder)

        use_cases = []
        for uc_root in uc_roots:
            uc = DetectionUseCase(
                folder=uc_root,
                branch=branch,
                repo=repo,
                project=project,
            )

            # README.md — case-insensitive candidates
            for candidate in [f"{uc_root}/README.md", f"{uc_root}/readme.md", f"{uc_root}/Readme.md"]:
                if candidate in all_files:
                    uc.readme = DetectionFile(candidate, "", branch, repo, project)
                    break

            # Sigma: first .yml in detection/
            for path in sorted(all_files):
                if path.startswith(f"{uc_root}/detection/") and path.endswith(".yml"):
                    uc.sigma = DetectionFile(path, "", branch, repo, project)
                    break

            # Elastic rule: first .toml in implementation/elastic/
            for path in sorted(all_files):
                if path.startswith(f"{uc_root}/implementation/elastic/") and path.endswith(".toml"):
                    uc.elastic_rule = DetectionFile(path, "", branch, repo, project)
                    break

            # Defender rule: first .kql in implementation/defender/
            for path in sorted(all_files):
                if path.startswith(f"{uc_root}/implementation/defender/") and path.endswith(".kql"):
                    uc.defender_rule = DetectionFile(path, "", branch, repo, project)
                    break
 
            # Sentinel rule: first .json in implementation/sentinel/
            for path in sorted(all_files):
                if path.startswith(f"{uc_root}/implementation/sentinel/") and path.endswith(".json"):
                    uc.sentinel_rule = DetectionFile(path, "", branch, repo, project)
                    break

            # Extra files: pipelines, tests, dashboards
            for path in sorted(all_files):
                if not path.startswith(uc_root + "/"):
                    continue
                rel = path[len(uc_root) + 1:]
                top_folder = rel.split("/")[0]
                if top_folder in ("pipelines", "tests", "dashboards"):
                    uc.extra_files.append(DetectionFile(path, "", branch, repo, project))

            use_cases.append(uc)

        return use_cases

    # ------------------------------------------------------------------
    # Content loading (not cached — content is stored on the DetectionFile object)
    # ------------------------------------------------------------------

    def load_file(self, df: DetectionFile) -> str:
        """
        Fetch the raw UTF-8 content of a single file from ADO.
        The returned string is stored on df.content by the caller.
        """
        stream = self._git.get_item_content(
            repository_id=df.repo,
            project=df.project,
            path=df.path,
            version_descriptor=GitVersionDescriptor(
                version=df.branch, version_type="branch"
            ),
            download=True,
        )
        # get_item_content returns a generator of bytes chunks
        raw = b"".join(stream)
        return raw.decode("utf-8", errors="replace")

    def load_use_case(self, uc: DetectionUseCase) -> DetectionUseCase:
        """Populate content for all files in a use case."""
        for attr in ("readme", "sigma", "elastic_rule"):
            df: Optional[DetectionFile] = getattr(uc, attr)
            if df:
                df.content = self.load_file(df)
        for ef in uc.extra_files:
            ef.content = self.load_file(ef)
        return uc

    # ------------------------------------------------------------------
    # PR management
    # ------------------------------------------------------------------

    def list_pull_requests(self, project: str, repo: str) -> list[dict]:
        """Return all active (and recently closed) PRs as plain dicts."""
        prs = self._git.get_pull_requests(repo, None, project=project)
        return [
            {
                "id": pr.pull_request_id,
                "title": pr.title,
                "source": pr.source_ref_name.replace("refs/heads/", ""),
                "target": pr.target_ref_name.replace("refs/heads/", ""),
                "status": pr.status,
                "created_by": pr.created_by.display_name,
                "created_date": pr.creation_date,
            }
            for pr in prs
        ]

    def create_pull_request(
        self,
        project: str,
        repo: str,
        title: str,
        description: str,
        source_branch: str,
        target_branch: str = "dev",
    ) -> dict:
        """
        Open a PR from source_branch into target_branch.
        Returns {"id": int, "url": str}.
        """
        from azure.devops.v7_1.git.models import GitPullRequest

        pr = self._git.create_pull_request(
            GitPullRequest(
                title=title,
                description=description,
                source_ref_name=f"refs/heads/{source_branch}",
                target_ref_name=f"refs/heads/{target_branch}",
            ),
            repository_id=repo,
            project=project,
        )
        return {"id": pr.pull_request_id, "url": pr.url}
    
    
    # ------------------------------------------------------------------
    # Branch management
    # ------------------------------------------------------------------

    def create_branch(
        self,
        project: str,
        repo: str,
        new_branch: str,
        base_branch: str = "dev",
    ) -> dict:
        """
        Create new_branch pointing at the current HEAD of base_branch.
        The old_object_id of all-zeros signals "this ref does not exist yet".
        """
        from azure.devops.v7_1.git.models import GitRefUpdate

        # Get current HEAD of base branch
        refs = self._git.get_refs(
            repository_id=repo,
            project=project,
            filter=f"heads/{base_branch}",
        )
        if not refs:
            raise ValueError(f"Base branch '{base_branch}' not found")

        base_sha = refs[0].object_id

        result = self._git.update_refs(
            ref_updates=[GitRefUpdate(
                name=f"refs/heads/{new_branch}",
                old_object_id="0000000000000000000000000000000000000000",
                new_object_id=base_sha,
            )],
            repository_id=repo,
            project=project,
        )
        return {"branch": new_branch, "sha": base_sha, "result": result[0].success if result else False}

    def branch_exists(self, project: str, repo: str, branch: str) -> bool:
        """Return True if the branch already exists in the repo."""
        refs = self._git.get_refs(
            repository_id=repo,
            project=project,
            filter=f"heads/{branch}",
        )
        return bool(refs)

    # ------------------------------------------------------------------
    # File push (create or update, multiple files in one commit)
    # ------------------------------------------------------------------

    def push_files(
        self,
        project: str,
        repo: str,
        branch: str,
        files: list[dict],      # [{"path": "/UseCases/UC-024/README.md", "content": "..."}]
        commit_message: str,
    ) -> dict:
        """
        Commit one or more files to branch in a single push.
 
        Each file is created (changeType="add") if it doesn't exist yet,
        or updated (changeType="edit") if it does. Existence is checked with
        a lightweight get_item call.
 
        Uses the REST dict format for changes rather than the SDK's GitChange
        model, which requires base64 encoding. "rawtext" avoids the extra step.
 
        Returns {"push_id": int, "commit_id": str}.
        """
        from azure.devops.v7_1.git.models import (
            GitPush, GitCommit, GitCommitRef,
            GitRefUpdate,
        )
        import base64

        # Get current branch HEAD
        refs = self._git.get_refs(
            repository_id=repo,
            project=project,
            filter=f"heads/{branch}",
        )
        if not refs:
            raise ValueError(f"Branch '{branch}' not found")
        old_sha = refs[0].object_id

        # Determine add vs edit per file
        changes = []
        for f in files:
            exists = self._file_exists(project, repo, branch, f["path"])
            change_type = "edit" if exists else "add"

            changes.append({
            "changeType": change_type,
            "item": {"path": f["path"]},
            "newContent": {
                "content": f["content"],   # ← plain text, no base64 needed
                "contentType": "rawtext"
            }
        })

        # A single push with a single commit containing all changes
        push = self._git.create_push(
            push=GitPush(
                ref_updates=[GitRefUpdate(
                    name=f"refs/heads/{branch}",
                    old_object_id=old_sha,
                )],
                commits=[GitCommit(
                    comment=commit_message,
                    changes=changes,
                )],
            ),
            repository_id=repo,
            project=project,
        )
        return {"push_id": push.push_id, "commit_id": push.commits[0].commit_id}

    def _file_exists(self, project: str, repo: str, branch: str, path: str) -> bool:
        """
        Check if a file exists on branch without downloading its content.
        Returns False on any exception (including 404 Not Found).
        """
        try:
            self._git.get_item(
                repository_id=repo,
                project=project,
                path=path,
                version_descriptor=GitVersionDescriptor(version=branch, version_type="branch"),
            )
            return True
        except Exception:
            return False

    # ---------------------------------------------------------------------------
    # Helpers — build raw SDK connection without going through ADOClient.__init__
    # (avoids re-entrancy when cached functions are called during __init__)
    # ---------------------------------------------------------------------------
    
def _make_connection(org_url: str, pat: str) -> Connection:
    """
    Build an ADO SDK Connection directly, bypassing ADOClient.__init__.
 
    Used by the module-level @st.cache_data functions to avoid circular
    re-entrancy: cached functions must not call ADOClient() because ADOClient
    methods call the cached functions, creating infinite recursion.
    """
    return Connection(
        base_url=org_url.rstrip("/"),
        creds=BasicAuthentication("", pat),
    )

# ---------------------------------------------------------------------------
# Cached module-level functions
# ---------------------------------------------------------------------------
# These are module-level (not methods) so Streamlit can cache them by their
# primitive arguments. TTL of 600s for metadata lists, 300s for use cases.
    

@st.cache_data(ttl=600, show_spinner=False)
def _cached_list_projects(org_url: str, pat: str) -> list[str]:
    """Fetch all ADO project names; cached 10 minutes."""
    conn = _make_connection(org_url, pat)
    core = conn.clients.get_core_client()
    return [p.name for p in core.get_projects()]


@st.cache_data(ttl=600, show_spinner=False)
def _cached_list_repos(org_url: str, pat: str, project: str) -> list[str]:
    """Fetch all repository names in a project; cached 10 minutes."""
    conn = _make_connection(org_url, pat)
    git = conn.clients.get_git_client()
    return [r.name for r in git.get_repositories(project)]


@st.cache_data(ttl=600, show_spinner=False)
def _cached_list_branches(org_url: str, pat: str, project: str, repo: str) -> list[str]:
    """Fetch all branch names for a repo; cached 10 minutes."""
    conn = _make_connection(org_url, pat)
    git = conn.clients.get_git_client()
    refs = git.get_refs(repository_id=repo, project=project, filter="heads/")
    return [r.name.replace("refs/heads/", "") for r in refs]

@st.cache_data(ttl=300, show_spinner=False)
def _cached_list_use_cases(
    org_url: str,
    pat: str,
    project: str,
    repo: str,
    branch: str,
    use_cases_root: str,
) -> list:
    """
    Scan the repo tree and return DetectionUseCase objects; cached 5 minutes.
 
    Uses ADOClient.__new__() to construct a minimal client instance without
    triggering __init__ (which would call list_projects → this function again).
    """
    conn = _make_connection(org_url, pat)
    client = ADOClient.__new__(ADOClient)
    client.org_url = org_url.rstrip("/")
    client._pat = pat
    client.connection = conn
    client._git = conn.clients.get_git_client()
    return client._list_use_cases_impl(project, repo, branch, use_cases_root)


# ------------------------------------------------------------------
# File push (create or update, multiple files in one commit)
# ------------------------------------------------------------------

# def push_files(
#     self,
#     project: str,
#     repo: str,
#     branch: str,
#     files: list[dict],      # [{"path": "/UseCases/UC-024/README.md", "content": "..."}]
#     commit_message: str,
# ) -> dict:
#     """
#     Commit one or more files to branch in a single push.
#     Each file is created if it doesn't exist, updated otherwise.
#     files: list of {"path": str, "content": str}
#     """
#     from azure.devops.v7_1.git.models import (
#         GitPush, GitCommit, GitChange, ItemContent,
#         GitRefUpdate,
#     )
#     import base64

#     # Get current branch HEAD
#     refs = self._git.get_refs(
#         repository_id=repo,
#         project=project,
#         filter=f"heads/{branch}",
#     )
#     if not refs:
#         raise ValueError(f"Branch '{branch}' not found")
#     old_sha = refs[0].object_id

#     # Determine add vs edit per file
#     changes = []
#     for f in files:
#         exists = self._file_exists(project, repo, branch, f["path"])
#         change_type = 2 if exists else 1   # 1=add, 2=edit

#         content_bytes = f["content"].encode("utf-8")
#         b64 = base64.b64encode(content_bytes).decode("ascii")

#         changes.append(GitChange(
#             change_type=change_type,
#             item={"path": f["path"]},
#             new_content=ItemContent(
#                 content=b64,
#                 content_type=0,   # base64encoded = 0 in the enum
#             ),
#         ))

#     push = self._git.create_push(
#         push=GitPush(
#             ref_updates=[GitRefUpdate(
#                 name=f"refs/heads/{branch}",
#                 old_object_id=old_sha,
#             )],
#             commits=[GitCommit(
#                 comment=commit_message,
#                 changes=changes,
#             )],
#         ),
#         repository_id=repo,
#         project=project,
#     )
#     return {"push_id": push.push_id, "commit_id": push.commits[0].commit_id}

# def _file_exists(self, project: str, repo: str, branch: str, path: str) -> bool:
#     try:
#         self._git.get_item(
#             repository_id=repo,
#             project=project,
#             path=path,
#             version_descriptor=GitVersionDescriptor(version=branch, version_type="branch"),
#         )
#         return True
#     except Exception:
#         return False