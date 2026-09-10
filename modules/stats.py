"""
stats.py — Detection health scoring and repository statistics
=============================================================
Provides:
  - DetectionStats  : dataclass holding all computed statistics
  - StatsEngine     : computes stats from loaded use cases + validation results
 
Health score model (0–100)
--------------------------
Each use case receives a health score composed of weighted sub-scores:
  15 pts  — has a README
  20 pts  — has a Sigma file
  20 pts  — has at least one SIEM rule (Elastic, Defender, or Sentinel)
  20 pts  — Sigma validates without errors (requires validator to have run)
  10 pts  — Sigma has zero errors (vs. just passing overall)
  15 pts  — README completeness score (0–1 float, scaled to 0–15)
  -----
 100 pts  total
 
The first three sub-scores are always computed from the UC file inventory.
The last three require validation results — if the validator hasn't run,
those components contribute 0 and the score reflects structural completeness only.
 
MITRE auto-build
----------------
If mitre_coverage=None is passed to compute(), StatsEngine builds it
from the Sigma file contents already in memory. This means overview.py
gets tactic counts even before the user visits the MITRE Coverage page.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import pandas as pd


@dataclass
class DetectionStats:
    """
    Aggregated statistics for the entire detection use case repository.
 
    Counters
    --------
    total           — total number of DetectionUseCase objects
    complete        — UCs with README + Sigma + ≥1 SIEM rule
    missing_readme  — UCs without a README
    missing_sigma   — UCs without a Sigma file
    missing_siem    — UCs without any SIEM rule (Elastic, Defender, or Sentinel)
 
    Distributions
    -------------
    by_status    — {status_value: count}  e.g. {"experimental": 5, "stable": 2}
    by_level     — {level_value: count}   e.g. {"high": 3, "medium": 4}
    by_tactic    — {tactic_name: count}   from MITRE coverage
    by_platform  — {platform: count}      e.g. {"elastic": 7, "defender": 3}
 
    Health
    ------
    health_scores — list of {"name": str, "score": float, "folder": str}
    """
    total: int = 0
    complete: int = 0           # has readme + sigma + elastic rule
    missing_readme: int = 0
    missing_sigma: int = 0
    missing_siem: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    by_level: dict[str, int] = field(default_factory=dict)
    by_tactic: dict[str, int] = field(default_factory=dict)
    by_platform: dict[str, int] = field(default_factory=dict)  # elastic/defender/sentinel counts
    health_scores: list[dict] = field(default_factory=list)  # per use-case

    @property
    def completeness_pct(self) -> float:
        """Percentage of UCs that are complete (have all required files)."""
        return (self.complete / self.total * 100) if self.total else 0.0

    @property
    def avg_health(self) -> float:
        """Mean health score across all UCs (0–100)."""
        if not self.health_scores:
            return 0.0
        return sum(h["score"] for h in self.health_scores) / len(self.health_scores)
    
    def to_dataframe(self, stats: DetectionStats) -> pd.DataFrame:
        """
        Return health scores as a DataFrame sorted ascending by score
        (worst-scoring rules first), suitable for the health table in the UI.
        """
        return pd.DataFrame(stats.health_scores).sort_values("score", ascending=True)


LEVEL_ORDER = ["critical", "high", "medium", "low", "informational"]
STATUS_ORDER = ["stable", "test", "experimental", "deprecated", "unsupported"]


class StatsEngine:
    """Computes DetectionStats from a list of DetectionUseCase objects."""

    def compute(
        self,
        use_cases: list[Any],              # list of DetectionUseCase (loaded)
        sigma_results: dict[str, Any],     # uc.name -> SigmaValidationResult
        readme_results: dict[str, Any],    # uc.name -> ReadmeValidationResult
        mitre_coverage: Any = None,        # MitreCoverage
    ) -> DetectionStats:
        """
        Compute statistics for all use cases.
 
        Returns (DetectionStats, MitreCoverage) — both are written to
        session state by the caller (shared.py / statistics.py).
 
        If mitre_coverage is None, it is built from Sigma file contents
        already in memory. If no Sigma files have content, coverage is None.
        """
        # Auto-build MITRE coverage if not already available
        
        if mitre_coverage is None:
            mitre_coverage = self._build_mitre_coverage(use_cases)

        stats = DetectionStats(total=len(use_cases))

        for uc in use_cases:
            name = uc.name

            # Completeness
            if uc.is_complete:
                stats.complete += 1
            if not uc.readme:
                stats.missing_readme += 1
            if not uc.sigma:
                stats.missing_sigma += 1
            # Check all three SIEM platforms via getattr for forward compatibility
            if not (uc.elastic_rule or getattr(uc, "defender_rule", None)
                    or getattr(uc, "sentinel_rule", None)):
                stats.missing_siem += 1

            # ── Platform coverage counters ────────────────────────────────────
            if uc.elastic_rule:
                stats.by_platform["elastic"] = stats.by_platform.get("elastic", 0) + 1
            if getattr(uc, "defender_rule", None):
                stats.by_platform["defender"] = stats.by_platform.get("defender", 0) + 1
            if getattr(uc, "sentinel_rule", None):
                stats.by_platform["sentinel"] = stats.by_platform.get("sentinel", 0) + 1
        

            # ── Health score ──────────────────────────────────────────────────
            score = self._health_score(uc, sigma_results.get(name), readme_results.get(name))
            stats.health_scores.append({"name": name, "score": score, "folder": uc.folder})

            # ── Severity / status distribution ────────────────────────────────
            sv = sigma_results.get(name)
            if sv and sv.parsed:
                status = sv.parsed.get("status", "unknown")
                stats.by_status[status] = stats.by_status.get(status, 0) + 1

                level = sv.parsed.get("level", "unknown")
                stats.by_level[level] = stats.by_level.get(level, 0) + 1
            elif uc.sigma and uc.sigma.content:
                # Parse level/status directly from Sigma if validator hasn't run
                import yaml
                try:
                    doc = yaml.safe_load(uc.sigma.content)
                    if isinstance(doc, dict):
                        status = doc.get("status", "unknown")
                        stats.by_status[status] = stats.by_status.get(status, 0) + 1
                        level = doc.get("level", "unknown")
                        stats.by_level[level] = stats.by_level.get(level, 0) + 1
                except Exception:
                    pass

        # Tactic distribution from MITRE coverage
        if mitre_coverage:
            stats.by_tactic = mitre_coverage.tactic_counts

        return stats, mitre_coverage
    
    def _build_mitre_coverage(self, use_cases: list[Any]) -> Any:
        """
        Build a MitreCoverage object from Sigma files already in memory.
        Returns None if no Sigma content is available yet.
        """
        try:
            from modules.mitre_mapper import MitreMapper
        except ImportError:
            from .mitre_mapper import MitreMapper
 
        mapper   = MitreMapper()
        uc_data  = []
        for uc in use_cases:
            if uc.sigma and uc.sigma.content:
                uc_data.append({"name": uc.name, "sigma_content": uc.sigma.content})
 
        if not uc_data:
            return None
 
        return mapper.build_coverage(uc_data)

    def _health_score(self, uc, sigma_result, readme_result) -> float:
        """
        Compute the health score for a single use case (0–100).
 
        Sub-scores and their weights are defined inline.
        Structural sub-scores (readme, sigma, siem) are always computed.
        Validation sub-scores (sigma_valid, no_errors, readme_completeness)
        are only added if the corresponding result object is present.
        """
        score = 0.0
        weights = {
            "has_readme":       15,  # structural: README file exists
            "has_sigma":        20,  # structural: Sigma file exists
            "has_siem_rule":    20,  # structural: at least one SIEM rule exists
            "sigma_valid":      20,  # validation: Sigma passes schema check
            "no_sigma_errors":  10,  # validation: Sigma has zero errors (vs. just valid)
            "readme_score":     15,  # validation: README section completeness (scaled 0–15)
        }

        # ── Structural sub-scores (always available) ──────────────────────────
        if uc.readme:
            score += weights["has_readme"]
        if uc.sigma:
            score += weights["has_sigma"]
        if (uc.elastic_rule or getattr(uc, "defender_rule", None)
                or getattr(uc, "sentinel_rule", None)):
            score += weights["has_siem_rule"]

        # ── Validation sub-scores (only if validator has run) ────────────────
        if sigma_result:
            if sigma_result.valid:
                score += weights["sigma_valid"]
            if not sigma_result.errors: # valid AND no errors = full score
                score += weights["no_sigma_errors"]

        if readme_result:
            # readme_result.score is 0.0–1.0; scale to 0–15
            score += readme_result.score * weights["readme_score"]

        return round(score, 1)


