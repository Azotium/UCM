"""
readme_validator.py — README metadata completeness validation
=============================================================
Checks that a detection use case README.md contains the required
documentation sections and key metadata fields.
 
Scoring model (0.0 – 1.0)
--------------------------
  found_required_sections / total_required  ×  0.5
+ found_metadata_fields   / total_metadata  ×  0.5
 
A score of 1.0 means all required sections AND all metadata fields are present.
Recommended (but not required) sections produce warnings only and don't lower the score.
 
Detection strategy
------------------
Sections are matched case-insensitively against:
  - Markdown headings:  ## Section Name
  - Bold keywords:      **Section Name**
  - Bare keyword:       anywhere in the document (fallback)
 
This is intentionally permissive — engineers don't all format READMEs identically.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field


@dataclass
class ReadmeValidationResult:
    """
    Outcome of validating one README.md file.
 
    `valid` is True only when all required sections are present.
    `score` is always computed (0.0–1.0) regardless of validity.
    """
    valid:            bool
    found_sections:   list[str] = field(default_factory=list)   # required sections found
    missing_sections: list[str] = field(default_factory=list)   # required sections absent
    missing_fields:   list[str] = field(default_factory=list)   # metadata keys absent
    warnings:         list[str] = field(default_factory=list)   # recommended section gaps
    score:            float = 0.0   # completeness score, 0.0–1.0


# Sections that MUST be present for the README to be considered valid
REQUIRED_SECTIONS = [
    "description",
    "mitre",
    "false positives",
    "references",
]

# Sections that SHOULD be present — absence produces a warning but not an error
RECOMMENDED_SECTIONS = [
    "triage",
    "response",
    "author",
    "version",
    "severity",
]

# Regex patterns that look for inline metadata (e.g. **Severity:** High)
# Each key maps to a pattern; a match means the field is present.
METADATA_PATTERNS = {
    "severity":   r"(?i)(severity|level)\s*[:\|]\s*\S+",
    "author":     r"(?i)author\s*[:\|]\s*\S+",
    "date":       r"(?i)(date|created)\s*[:\|]\s*\S+",
    "mitre_tag":  r"(?i)(T\d{4}(\.\d{3})?|attack\.\w+)",
}


class ReadmeValidator:

    def validate(self, content: str) -> ReadmeValidationResult:
        """Run all README completeness checks and return a result object."""
        result = ReadmeValidationResult(valid=True)
        lower = content.lower()

        # ── Required sections ─────────────────────────────────────────────────
        for section in REQUIRED_SECTIONS:
            if self._section_present(section, lower):
                result.found_sections.append(section)
            else:
                result.missing_sections.append(section)
                result.valid = False

        # ── Recommended sections (warnings only) ──────────────────────────────
        for section in RECOMMENDED_SECTIONS:
            if not self._section_present(section, lower):
                result.warnings.append(f"Recommended section missing: '{section}'")

        # ── Metadata field patterns ───────────────────────────────────────────
        for key, pattern in METADATA_PATTERNS.items():
            if not re.search(pattern, content):
                result.missing_fields.append(key)

        # ── Completeness score ────────────────────────────────────────────────
        # Combines required-section coverage and metadata field coverage equally.
        total = len(REQUIRED_SECTIONS) + len(METADATA_PATTERNS)
        found = len(result.found_sections) + (len(METADATA_PATTERNS) - len(result.missing_fields))
        result.score = found / total if total > 0 else 0.0

        return result

    def _section_present(self, section: str, content_lower: str) -> bool:
        """
        Check if a section name is present in the README using three patterns:
          1. Markdown heading (## Section Name)
          2. Bold markdown (** Section Name **)
          3. Bare word boundary match (loose fallback)
        """
        patterns = [
            rf"#+\s+{re.escape(section)}",           # ## Section
            rf"\*\*{re.escape(section)}\*\*",        # **Section**
            rf"\b{re.escape(section)}\b",            # bare word
        ]
        return any(re.search(p, content_lower) for p in patterns)
