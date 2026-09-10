"""
mitre_mapper.py — MITRE ATT&CK technique/tactic coverage
=========================================================
Provides:
  - MitreCoverage  : dataclass holding per-technique coverage data
  - MitreMapper    : extracts ATT&CK tags from Sigma files and builds coverage
 
Data sources
------------
Technique metadata (name, tactics) is loaded from the MITRE ATT&CK STIX JSON
via mitreattack-python if installed. On first use it downloads the JSON from
the MITRE GitHub repo and caches it in the OS temp directory. Subsequent calls
use the local cache.
 
If mitreattack-python is not installed, MitreMapper still works but technique
names and tactic mappings will be empty — only the raw T-IDs are returned.
The converters.py module provides a parallel MITRE data loader via direct JSON
parsing (no mitreattack-python dependency).
 
Tag extraction
--------------
Tags are extracted from two sources in each Sigma file:
  1. The `tags:` list — ATT&CK tags follow the format `attack.tXXXX` or
     `attack.tXXXX.XXX` (sub-technique). These are the canonical source.
  2. Bare T-numbers in the full file text (e.g. in comments or description)
     — extracted as a fallback to catch informally documented techniques.
"""

from __future__ import annotations
import re
import yaml
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique database (embedded subset — no network required)
# Extended at runtime if mitreattack-python is installed.
# ---------------------------------------------------------------------------

# Maps technique ID -> {name, tactics}
TECHNIQUE_DB: dict[str, dict] = {}

def _load_mitre_db():
    """
    Populate TECHNIQUE_DB from the MITRE ATT&CK STIX JSON.
 
    Called once per process via the global guard `if TECHNIQUE_DB: return`.
    Uses mitreattack-python for robust STIX parsing; silently degrades to
    an empty DB if the library is missing or the download fails.
    """
    global TECHNIQUE_DB
    if TECHNIQUE_DB:
        return # already loaded — no-op
    try:
        from mitreattack.stix20 import MitreAttackData
        import os, tempfile, urllib.request

        # Cache the JSON in the OS temp dir to avoid re-downloading every run
        cache = os.path.join(tempfile.gettempdir(), "enterprise-attack.json")
        if not os.path.exists(cache):
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            urllib.request.urlretrieve(url, cache)

        data = MitreAttackData(cache)
        for t in data.get_techniques(remove_revoked_deprecated=True):
            ext_refs = t.get("external_references", [])
            tid = next((r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"), None)
            if not tid:
                continue
            tactics = [p["phase_name"] for p in t.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
            TECHNIQUE_DB[tid.upper()] = {
                "name": t.get("name", ""),
                "tactics": tactics,
            }
    except Exception:
        pass   # graceful degradation — coverage mapping still works, just without names


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class MitreCoverage:
    """
    Coverage data for all techniques found across the loaded use cases.
 
    Structure of `techniques` dict:
        {
          "T1059": {
            "name":      "Command and Scripting Interpreter",
            "tactics":   ["execution"],
            "use_cases": ["UC-001", "UC-007"],
          },
          "T1059.001": { ... },
          ...
        }
    """
    techniques: dict[str, dict] = field(default_factory=dict)
    # technique_id -> {name, tactics, use_cases: [str]}

    @property
    def tactic_counts(self) -> dict[str, int]:
        """
        Return a dict of {tactic_name: rule_count}.
        A technique mapped to multiple tactics is counted once per tactic.
        Used by the statistics page for the tactic distribution chart.
        """
        counts: dict[str, int] = {}
        for tech in self.techniques.values():
            for tac in tech.get("tactics", []):
                counts[tac] = counts.get(tac, 0) + 1
        return counts

    @property
    def technique_ids(self) -> list[str]:
        """Return a list of all covered technique IDs."""
        return list(self.techniques.keys())


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


class MitreMapper:

    def __init__(self):
        _load_mitre_db()

    def extract_tags(self, sigma_content: str) -> list[str]:
        """
        Extract MITRE technique IDs from a Sigma YAML file.
 
        Primary source: the `tags:` list (attack.tXXXX format).
        Fallback:       bare T-numbers anywhere in the file text.
        Returns a deduplicated list of uppercase technique IDs.
        """
        techniques = []
        try:
            doc = yaml.safe_load(sigma_content)
            tags = doc.get("tags", []) if isinstance(doc, dict) else []
            for tag in tags:
                if not isinstance(tag, str):
                    continue
                # Match attack.tXXXX or attack.tXXXX.XXX (sub-techniques)
                m = re.match(r"(?i)attack\.(t\d{4}(?:\.\d{3})?)", tag)
                if m:
                    techniques.append(m.group(1).upper())
        except Exception:
            pass

        # Also scan raw content for loose T-numbers
        for m in re.finditer(r"\b(T\d{4}(?:\.\d{3})?)\b", sigma_content):
            tid = m.group(1).upper()
            if tid not in techniques:
                techniques.append(tid)

        return techniques

    def build_coverage(self, use_cases: list[dict]) -> MitreCoverage:
        """
        Build a MitreCoverage object from a list of use case dicts.
 
        Each dict must have {"name": str, "sigma_content": str}.
        Technique metadata (name, tactics) is looked up from TECHNIQUE_DB;
        unknown IDs get empty name and tactics (still counted in coverage).
        """
        coverage = MitreCoverage()

        for uc in use_cases:
            name = uc.get("name", "unknown")
            sigma = uc.get("sigma_content", "")
            if not sigma:
                continue

            for tid in self.extract_tags(sigma):
                if tid not in coverage.techniques:
                    # Initialise entry with data from the global TECHNIQUE_DB
                    db_entry = TECHNIQUE_DB.get(tid, {})
                    coverage.techniques[tid] = {
                        "name": db_entry.get("name", tid),
                        "tactics": db_entry.get("tactics", []),
                        "use_cases": [],
                    }
                # Track which UCs cover each technique (for the drilldown view)
                coverage.techniques[tid]["use_cases"].append(name)

        return coverage

    def heatmap_data(self, coverage: MitreCoverage) -> list[dict]:
        """
        Flatten coverage into a list of records for Plotly charts.
 
        A technique mapped to N tactics produces N rows (one per tactic)
        so the treemap and bubble chart can group by tactic correctly.
 
        Each row: {technique_id, technique_name, tactic, count, use_cases}
        """
        rows = []
        for tid, info in coverage.techniques.items():
            # Default to "unknown" tactic if the technique isn't in TECHNIQUE_DB
            tactics = info["tactics"] or ["unknown"]
            for tac in tactics:
                rows.append({
                    "technique_id":   tid,
                    "technique_name": info["name"],
                    "tactic":         tac,
                    "count":          len(info["use_cases"]),
                    "use_cases":      ", ".join(info["use_cases"]),
                })
        return rows

    def navigator_layer(self, coverage: MitreCoverage, layer_name: str = "Detection Coverage") -> dict:
        """
        Export coverage as an ATT&CK Navigator JSON layer.
 
        The layer can be uploaded to https://mitre-attack.github.io/attack-navigator/
        for a visual heatmap. `score` is the number of rules covering each technique;
        the gradient scales from white (0) to blue (max coverage).
        """
        techniques = []
        for tid, info in coverage.techniques.items():
            techniques.append({
                "techniqueID":  tid,
                "score":        len(info["use_cases"]),
                "comment":      f"Covered by: {', '.join(info['use_cases'])}",
                "enabled":      True,
            })
        return {
            "name":         layer_name,
            "versions":     {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain":       "enterprise-attack",
            "techniques":   techniques,
            "gradient": {
                "colors":   ["#ffffff", "#1a73e8"],
                "minValue": 0,
                "maxValue": max((len(v["use_cases"]) for v in coverage.techniques.values()), default=1),
            },
        }
