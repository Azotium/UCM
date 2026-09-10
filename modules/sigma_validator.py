"""
sigma_validator.py — Sigma YAML schema validation + Elastic conversion
=======================================================================
Validates a Sigma rule file against:
  1. YAML syntax (must be parseable and a top-level dict)
  2. Required fields (title, status, description, logsource, detection)
  3. Recommended fields (id, date, author, tags, level, falsepositives, references)
  4. Value constraints (status and level must be from allowed sets)
  5. MITRE ATT&CK tag format (attack.tXXXX or attack.<tactic>)
  6. Detection block structure (must have condition + at least one selector)
  7. Logsource completeness (at least one of category/product/service)
 
After structural validation, it attempts to convert the Sigma rule to
an Elastic Lucene query using pySigma + the Elasticsearch backend.
The query is stored on the result object so the validator page and
the editor's live-validation panel can display it.
"""

from __future__ import annotations
import yaml
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ValidationIssue:
    level: str          # "error" | "warning" | "info"
    code: str
    message: str
    field: str = ""


@dataclass
class SigmaValidationResult:
    """
    Outcome of validating one Sigma YAML file.
 
    `valid` is True only when there are no error-level issues.
    Warnings and info issues do not affect validity.
    `elastic_query` is populated if pySigma conversion succeeds;
    `conversion_error` explains why it failed otherwise.
    """
    valid:            bool
    issues:           list[ValidationIssue] = field(default_factory=list)
    parsed:           dict = field(default_factory=dict)   # the parsed YAML doc
    elastic_query:    str  = ""    # Lucene query string if conversion succeeded
    conversion_error: str  = ""    # human-readable reason if conversion failed

    @property
    def errors(self):
        """Filter issues to error level only."""
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self):
        """Filter issues to warning level only."""
        return [i for i in self.issues if i.level == "warning"]


# ---------------------------------------------------------------------------
# Required / recommended Sigma fields
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = ["title", "status", "description", "logsource", "detection"]
RECOMMENDED_FIELDS = ["id", "date", "author", "tags", "level", "falsepositives", "references"]
VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
VALID_LEVELS = {"critical", "high", "medium", "low", "informational"}


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class SigmaValidator:

    def validate(self, content: str) -> SigmaValidationResult:
        """
        Run all validation checks against a Sigma YAML string.
        Returns a SigmaValidationResult regardless of outcome.
        """

        result = SigmaValidationResult(valid=True)

        # 1. Parse YAML
        try:
            doc = yaml.safe_load(content)
        except yaml.YAMLError as e:
            result.valid = False
            result.issues.append(ValidationIssue("error", "YAML_PARSE", str(e)))
            return result

        if not isinstance(doc, dict):
            result.valid = False
            result.issues.append(ValidationIssue("error", "YAML_NOT_DICT", "Top-level YAML must be a mapping"))
            return result

        result.parsed = doc

        # 2. Required fields
        for f in REQUIRED_FIELDS:
            if f not in doc:
                result.valid = False
                result.issues.append(ValidationIssue("error", "MISSING_REQUIRED", f"Missing required field: {f}", field=f))

        # 3. Recommended fields
        for f in RECOMMENDED_FIELDS:
            if f not in doc:
                result.issues.append(ValidationIssue("warning", "MISSING_RECOMMENDED", f"Missing recommended field: {f}", field=f))

        # 4. Status value
        status = doc.get("status", "")
        if status and status not in VALID_STATUSES:
            result.issues.append(ValidationIssue("warning", "INVALID_STATUS",
                f"status '{status}' not in {VALID_STATUSES}", field="status"))

        # 5. Level value
        level = doc.get("level", "")
        if level and level not in VALID_LEVELS:
            result.issues.append(ValidationIssue("warning", "INVALID_LEVEL",
                f"level '{level}' not in {VALID_LEVELS}", field="level"))

        # 6. Tags — check MITRE format
        tags = doc.get("tags", [])
        if tags:
            for tag in tags:
                if not isinstance(tag, str):
                    result.issues.append(ValidationIssue("warning", "TAG_NOT_STRING", f"Tag is not a string: {tag}", field="tags"))
                elif tag.startswith("attack.") and len(tag.split(".")) < 2:
                    result.issues.append(ValidationIssue("warning", "TAG_FORMAT", f"Possibly malformed ATT&CK tag: {tag}", field="tags"))

        # 7. Detection block
        detection = doc.get("detection", {})
        if isinstance(detection, dict):
            if "condition" not in detection:
                result.valid = False
                result.issues.append(ValidationIssue("error", "MISSING_CONDITION",
                    "detection block is missing 'condition'", field="detection.condition"))
            if len(detection) < 2:
                result.issues.append(ValidationIssue("warning", "THIN_DETECTION",
                    "detection block has only condition and no selectors", field="detection"))

        # 8. Logsource
        logsource = doc.get("logsource", {})
        if isinstance(logsource, dict):
            if not any(k in logsource for k in ["category", "product", "service"]):
                result.issues.append(ValidationIssue("warning", "LOGSOURCE_INCOMPLETE",
                    "logsource should have at least one of: category, product, service", field="logsource"))

        # 9. Try Elastic conversion via pySigma
        result.elastic_query, result.conversion_error = self._convert_to_elastic(content)

        return result

    def _convert_to_elastic(self, sigma_content: str) -> tuple[str, str]:
        """
        Attempt pySigma → Elastic Lucene conversion.
 
        Returns (query_string, error_string).
        One of the two will always be empty.
        Requires: pip install pySigma pySigma-backend-elasticsearch pySigma-pipeline-ecs
        """
        try:
            from sigma.collection import SigmaCollection
            from sigma.backends.elasticsearch import LuceneBackend
            from sigma.processing.resolver import ProcessingPipelineResolver

            try:
                from sigma.pipelines.elasticsearch import ecs_windows
                pipeline = ecs_windows()
            except Exception:
                pipeline = None

            rules = SigmaCollection.from_yaml(sigma_content)
            backend = LuceneBackend(processing_pipeline=pipeline)
            queries = backend.convert(rules)
            return "\n\n".join(queries) if queries else "", ""
        except ImportError:
            return "", "pySigma or Elastic backend not installed"
        except Exception as e:
            return "", str(e)
