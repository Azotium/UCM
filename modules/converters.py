"""
converters.py
Bidirectional conversion between Sigma YAML and Elastic TOML rule format.

sigma_to_elastic(sigma_content)  → (toml_str, errors)
elastic_to_sigma(toml_content)   → (yaml_str, errors)
"""

from __future__ import annotations
import re
import yaml
from datetime import date, datetime, timedelta
from typing import Optional
import os, requests, json
import streamlit as st


ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def download_enterprise_attack_json(
    output_path: str = "enterprise-attack.json",
    force: bool = False,
    max_age_days: int = 7,
) -> str:
    """
    Download MITRE ATT&CK Enterprise JSON and store it on disk.

    Args:
        output_path: local file path
        force: force re-download even if file exists
        max_age_days: refresh file if older than this

    Returns:
        Path to the local JSON file
    """

    # Check if file exists and is still fresh
    if os.path.exists(output_path) and not force:
        file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(output_path))
        if file_age < timedelta(days=max_age_days):
            return output_path

    # Download
    response = requests.get(ATTACK_URL, timeout=60)
    response.raise_for_status()

    # Write to disk
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(response.text)

    return output_path

@st.cache_resource
def get_attack_file(): return download_enterprise_attack_json()

@st.cache_resource
def load_attack_data():
    path = get_attack_file()
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
    
@st.cache_resource
def build_attack_indexes():
    data = load_attack_data()

    tactic_lookup = {}      # name/shortname → TA id
    technique_lookup = {}   # T id → name

    for obj in data["objects"]:

        # -------------------------
        # TACTICS
        # -------------------------
        if obj.get("type") == "x-mitre-tactic":
            tactic_id = None

            for ref in obj.get("external_references", []):
                if ref.get("external_id"):
                    tactic_id = ref["external_id"]

            if tactic_id:
                name = obj.get("name", "").lower()
                short = obj.get("x_mitre_shortname", "").lower()

                tactic_lookup[name] = tactic_id
                tactic_lookup[short] = tactic_id

        # -------------------------
        # TECHNIQUES
        # -------------------------
        elif obj.get("type") == "attack-pattern":
            tech_id = None

            for ref in obj.get("external_references", []):
                if ref.get("external_id"):
                    tech_id = ref["external_id"]

            if tech_id:
                technique_lookup[tech_id.upper()] = obj.get("name")

    return tactic_lookup, technique_lookup


def get_tactic_id(tactic_input: str):
    tactic_lookup, _ = build_attack_indexes()
    return tactic_lookup.get(tactic_input.lower())

def get_technique_name(tech_id: str):
    _, technique_lookup = build_attack_indexes()
    return technique_lookup.get(tech_id.upper())


# ---------------------------------------------------------------------------
# Sigma → Elastic
# ---------------------------------------------------------------------------

def sigma_to_elastic(sigma_content: str) -> tuple[str, list[str]]:
    """
    Convert a Sigma YAML rule to an Elastic TOML rule.
    Returns (toml_string, list_of_warnings).
    Uses pySigma for the query conversion if available,
    falls back to embedding the raw Sigma detection as a comment.
    """
    errors: list[str] = []

    try:
        doc = yaml.safe_load(sigma_content)
    except yaml.YAMLError as e:
        return "", [f"YAML parse error: {e}"]

    if not isinstance(doc, dict):
        return "", ["Sigma file is not a valid YAML mapping"]

    title       = doc.get("title", "Untitled")
    description = doc.get("description", "")
    author      = doc.get("author", "")
    status      = doc.get("status", "experimental")
    level       = doc.get("level", "medium")
    sigma_id    = doc.get("id", re.sub(r"[^a-z0-9_]", "_", title.lower()))
    tags        = doc.get("tags", [])
    date_str    = str(doc.get("date", date.today().isoformat()))

    # Parse MITRE tags
    techniques = []
    tactics    = []
    for tag in tags:
        tag = str(tag)
        m = re.match(r"(?i)attack\.(t\d{4}(?:\.\d{3})?)", tag)
        if m:
            techniques.append(m.group(1).upper())
        elif re.match(r"(?i)attack\.\w+", tag):
            tac = tag.split(".")[-1].replace("-", " ").title()
            tactics.append(tac)

    risk_score = {"critical": 99, "high": 73, "medium": 47,
                  "low": 21, "informational": 5}.get(level.lower(), 47)

    # Try pySigma conversion for the query
    lucene_query, conv_error = _sigma_to_lucene(sigma_content)
    if conv_error:
        errors.append(f"Query conversion: {conv_error}")
        # Embed a placeholder that engineers can fill in
        lucene_query = "* /* TODO: translate Sigma detection manually */"

    # Build MITRE threat blocks
    threat_blocks = _build_threat_blocks(tactics, techniques)

    # Tags list
    tag_lines = [f'    "Detection: {sigma_id}",']
    for tac in tactics:
        tag_lines.append(f'    "{tac}",')
    for tid in techniques:
        tag_lines.append(f'    "{tid}",')

    toml = f'''[metadata]
creation_date = "{date_str}"
maturity = "{status}"
updated_date = "{date.today().isoformat()}"

[rule]
author = ["{author}"]
description = """{description}"""
from = "now-9m"
index = ["logs-*", "filebeat-*", "winlogbeat-*"]
language = "kuery"
license = "Elastic License v2"
name = "{title}"
risk_score = {risk_score}
rule_id = "{sigma_id}"
severity = "{level}"
tags = [
{chr(10).join(tag_lines)}
]
timestamp_override = "event.ingested"
type = "query"

query = \'\'\'
{lucene_query}
\'\'\'

{threat_blocks}
'''
    return toml, errors


# ---------------------------------------------------------------------------
# Elastic → Sigma
# ---------------------------------------------------------------------------

def elastic_to_sigma(toml_content: str) -> tuple[str, list[str]]:
    """
    Convert an Elastic TOML rule to a Sigma YAML rule.
    Returns (yaml_string, list_of_warnings).
    """
    errors: list[str] = []

    try:
        doc = _parse_toml(toml_content)
    except Exception as e:
        return "", [f"TOML parse error: {e}"]

    rule = doc.get("rule", {})
    if not rule:
        return "", ["No [rule] section found in TOML"]

    title       = rule.get("name", "Untitled")
    description = rule.get("description", "")
    author      = rule.get("author", [])
    author_str  = author[0] if isinstance(author, list) and author else str(author)
    severity    = rule.get("severity", "medium")
    rule_id     = rule.get("rule_id", re.sub(r"[^a-z0-9_]", "_", title.lower()))
    query       = rule.get("query", "").strip()
    meta        = doc.get("metadata", {})
    created     = meta.get("creation_date", str(date.today().isoformat()))

    # Extract MITRE tags from threat blocks
    sigma_tags: list[str] = []
    threats = rule.get("threat", [])
    if isinstance(threats, list):
        for threat in threats:
            if not isinstance(threat, dict):
                continue
            tactic = threat.get("tactic", {})
            if isinstance(tactic, dict):
                tac_name = tactic.get("name", "")
                if tac_name:
                    sigma_tags.append(f"attack.{tac_name.lower().replace(' ', '-')}")
            for tech in threat.get("technique", []):
                if isinstance(tech, dict):
                    tid = tech.get("id", "")
                    if tid:
                        sigma_tags.append(f"attack.{tid.lower()}")

    # Also pull tags list
    for tag in rule.get("tags", []):
        m = re.match(r"(?i)T\d{4}", str(tag))
        if m and f"attack.{tag.lower()}" not in sigma_tags:
            sigma_tags.append(f"attack.{tag.lower()}")

    # Build logsource from index hints
    index = rule.get("index", [])
    logsource = _guess_logsource(index, query)

    # Build detection block — embed the KQL as a comment, add a stub
    detection_comment = query.replace("\n", "\n        # ") if query else "# TODO"
    detection = {
        "selection": {"EventID": 1},  # placeholder
        "condition": "selection",
    }

    sigma_doc = {
        "title": title,
        "id": rule_id,
        "status": "experimental",
        "description": description,
        "author": author_str,
        "date": str(created)[:10],
        "tags": sigma_tags or ["attack.tXXXX"],
        "logsource": logsource,
        "detection": detection,
        "falsepositives": ["Legitimate administrative activity"],
        "level": severity,
    }

    # Dump with a header comment showing the original KQL
    yaml_str = "# Converted from Elastic rule — review detection block\n"
    if query:
        yaml_str += f"# Original KQL query:\n"
        for line in query.splitlines():
            yaml_str += f"#   {line}\n"
        yaml_str += "#\n"
    yaml_str += yaml.dump(sigma_doc, default_flow_style=False, sort_keys=False, allow_unicode=True)

    errors.append("Detection block contains a placeholder — update with correct Sigma selection criteria")
    return yaml_str, errors


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sigma_to_lucene(sigma_content: str) -> tuple[str, str]:
    """Try pySigma → Elastic Lucene conversion."""
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.elasticsearch import LuceneBackend
        try:
            from sigma.pipelines.elasticsearch import ecs_windows
            pipeline = ecs_windows()
        except Exception:
            pipeline = None
        rules = SigmaCollection.from_yaml(sigma_content)
        backend = LuceneBackend(processing_pipeline=pipeline)
        queries = backend.convert(rules)
        return "\n".join(queries) if queries else "", ""
    except ImportError:
        return "", "pySigma not installed"
    except Exception as e:
        return "", str(e)


def _parse_toml(content: str) -> dict:
    """Parse TOML, trying tomllib (3.11+), then tomli, then manual fallback."""
    try:
        import tomllib
        return tomllib.loads(content)
    except ImportError:
        pass
    try:
        import tomli
        return tomli.loads(content)
    except ImportError:
        pass
    # Minimal fallback: extract key = value pairs from [rule] section
    return _minimal_toml_parse(content)


def _minimal_toml_parse(content: str) -> dict:
    """Very basic TOML parser for key = value and [sections]."""
    result: dict = {}
    current_section: list[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            current_section = section.split(".")
            obj = result
            for part in current_section:
                obj = obj.setdefault(part, {})
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            # Strip quotes and triple quotes
            for quote in ('"""', "'''", '"', "'"):
                if val.startswith(quote) and val.endswith(quote) and len(val) > len(quote):
                    val = val[len(quote):-len(quote)]
                    break
            obj = result
            for part in current_section:
                obj = obj.setdefault(part, {})
            obj[key] = val
    return result


def _guess_logsource(index: list[str], query: str) -> dict:
    src: dict = {}
    index_str = " ".join(str(i) for i in index).lower()
    query_lower = query.lower()
    if "winlogbeat" in index_str or "windows" in index_str:
        src["product"] = "windows"
    elif "filebeat" in index_str:
        src["product"] = "linux"
    if "process" in query_lower:
        src["category"] = "process_creation"
    elif "network" in query_lower or "dns" in query_lower:
        src["category"] = "network"
    elif "authentication" in query_lower or "login" in query_lower:
        src["category"] = "authentication"
    else:
        src["category"] = "network"
    return src or {"category": "network"}


def _build_threat_blocks(tactics: list[str], techniques: list[str]) -> str:
    if not tactics and not techniques:
        return ""
    lines = ["[[rule.threat]]", 'framework = "MITRE ATT&CK"']
    if tactics:
        for tac in tactics:
            tac_id = get_tactic_id(tac)
            lines += [
                "",
                "[[rule.threat.tactic]]",
                f'id = "{tac_id}"',
                f'name = "{tac}"',
                f'reference = "https://attack.mitre.org/tactics/{tac_id}/"',
            ]
    for tid in techniques:
        lines += [
            "",
            "[[rule.threat.technique]]",
            f'id = "{tid}"',
            f'name = "{get_technique_name(tid)}"',
            f'reference = "https://attack.mitre.org/techniques/{tid}/"',
        ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Query-level conversions  (detection block only, not full rule files)
# ---------------------------------------------------------------------------
 
def sigma_detection_to_kql(sigma_content: str) -> tuple[str, str, list[str]]:
    """
    Extract the detection block from a Sigma YAML rule and convert it to a
    KQL (Kibana Query Language) string suitable for Elastic.
 
    Returns (kql_query, lucene_query, warnings).
    kql_query   — human-readable KQL  (best-effort, always produced)
    lucene_query — pySigma output if available, else empty
    """
    warnings: list[str] = []
 
    try:
        doc = yaml.safe_load(sigma_content)
    except yaml.YAMLError as e:
        return "", "", [f"YAML parse error: {e}"]
 
    if not isinstance(doc, dict):
        return "", "", ["Not a valid Sigma YAML mapping"]
 
    detection = doc.get("detection", {})
    if not detection:
        return "", "", ["No detection block found"]
 
    # ── pySigma path (Lucene) ─────────────────────────────────────────────────
    lucene_query = ""
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.elasticsearch import LuceneBackend
        try:
            from sigma.pipelines.elasticsearch import ecs_windows
            pipeline = ecs_windows()
        except Exception:
            pipeline = None
        collection = SigmaCollection.from_yaml(sigma_content)
        backend = LuceneBackend(processing_pipeline=pipeline)
        results = backend.convert(collection)
        lucene_query = "\n".join(results) if results else ""
    except ImportError:
        warnings.append("pySigma not installed — Lucene output unavailable")
    except Exception as e:
        warnings.append(f"pySigma conversion: {e}")
 
    # ── Built-in KQL translation ──────────────────────────────────────────────
    logsource  = doc.get("logsource", {})
    kql_parts  = _logsource_to_kql_filters(logsource)
    condition  = detection.get("condition", "")
    selectors  = {k: v for k, v in detection.items() if k != "condition"}
 
    kql_parts += _selectors_to_kql(selectors, condition)
    kql_query  = "\n  and ".join(kql_parts) if kql_parts else "* /* could not translate */"
 
    if not lucene_query and not warnings:
        warnings.append("Lucene output requires pySigma — showing KQL approximation only")
 
    return kql_query, lucene_query, warnings
 
 
def kql_to_sigma_detection(kql_query: str, logsource_hints: dict | None = None) -> tuple[str, list[str]]:
    """
    Parse a KQL or Lucene query string and produce a Sigma detection block YAML snippet.
 
    Returns (sigma_detection_yaml, warnings).
    The result is a partial YAML string (detection + logsource only) that can be
    pasted into a full Sigma rule.
    """
    warnings: list[str] = []
    query = kql_query.strip()
 
    if not query:
        return "", ["Empty query"]
 
    # Detect language
    is_eql   = _looks_like_eql(query)
    is_lucene = _looks_like_lucene(query) and not is_eql
 
    if is_eql:
        warnings.append("EQL detected — converting to Sigma is approximate, review carefully")
        selectors, condition = _eql_to_selectors(query)
    else:
        selectors, condition = _kql_lucene_to_selectors(query)
 
    if not selectors:
        warnings.append("Could not parse query into structured selectors — using raw keyword fallback")
        selectors  = {"keywords": [query]}
        condition  = "keywords"
 
    # Guess logsource
    logsource = logsource_hints or _guess_logsource_from_kql(query)
 
    sigma_fragment = {
        "logsource": logsource,
        "detection": {**selectors, "condition": condition},
    }
 
    yaml_out = (
        "# --- Sigma detection fragment (converted from KQL/Lucene) ---\n"
        "# Paste into your Sigma rule and review all field names.\n"
        + yaml.dump(sigma_fragment, default_flow_style=False, sort_keys=False, allow_unicode=True)
    )
 
    warnings.append("Field names are guesses — verify against your Sigma pipelines/field mapping")
    return yaml_out, warnings
 
 
# ---------------------------------------------------------------------------
# KQL builder helpers  (Sigma detection → KQL)
# ---------------------------------------------------------------------------
 
def _logsource_to_kql_filters(logsource: dict) -> list[str]:
    parts = []
    product  = logsource.get("product", "")
    category = logsource.get("category", "")
    service  = logsource.get("service", "")
 
    CATEGORY_MAP = {
        "process_creation":  'event.category: "process" and event.type: "start"',
        "network":           'event.category: "network"',
        "file_event":        'event.category: "file"',
        "registry_event":    'event.category: "registry"',
        "dns":               'event.category: "network" and network.protocol: "dns"',
        "authentication":    'event.category: "authentication"',
        "web":               'event.category: "web"',
        "firewall":          'event.category: "network" and event.dataset: "firewall"',
    }
    PRODUCT_MAP = {
        "windows": 'agent.type: "winlogbeat" or data_stream.dataset: "windows.*"',
        "linux":   'agent.type: "filebeat" and host.os.type: "linux"',
        "aws":     'event.dataset: "aws.*"',
        "azure":   'event.dataset: "azure.*"',
    }
 
    if category in CATEGORY_MAP:
        parts.append(f"({CATEGORY_MAP[category]})")
    if product in PRODUCT_MAP:
        parts.append(f"({PRODUCT_MAP[product]})")
    if service:
        parts.append(f'event.dataset: "{service}"')
    return parts
 
 
def _selectors_to_kql(selectors: dict, condition: str) -> list[str]:
    """Convert Sigma selectors dict to KQL clauses."""
    selector_kql: dict[str, str] = {}
 
    for name, body in selectors.items():
        if isinstance(body, dict):
            clauses = []
            for field, value in body.items():
                field_kql = _sigma_field_to_kql(field)
                clauses.append(_sigma_value_to_kql(field_kql, value))
            selector_kql[name] = " and ".join(clauses) if clauses else "*"
        elif isinstance(body, list):
            # keyword list
            kws = [f'"{_esc(str(v))}"' for v in body]
            selector_kql[name] = " or ".join(kws)
        else:
            selector_kql[name] = f'"{_esc(str(body))}"'
 
    return _apply_condition(selector_kql, condition)
 
 
def _sigma_field_to_kql(field: str) -> str:
    """Map common Sigma field names to ECS field names."""
    FIELD_MAP = {
        "CommandLine":       "process.command_line",
        "Image":             "process.executable",
        "ParentImage":       "process.parent.executable",
        "ProcessName":       "process.name",
        "DestinationIp":     "destination.ip",
        "DestinationPort":   "destination.port",
        "SourceIp":          "source.ip",
        "SourcePort":        "source.port",
        "EventID":           "event.code",
        "User":              "user.name",
        "TargetUserName":    "user.name",
        "SubjectUserName":   "user.name",
        "FileName":          "file.name",
        "FilePath":          "file.path",
        "RegistryKey":       "registry.key",
        "RegistryValue":     "registry.value",
        "dns.question.name": "dns.question.name",
        "url.path":          "url.path",
        "http.request.method": "http.request.method",
    }
    return FIELD_MAP.get(field, field.lower().replace(".", "."))
 
 
def _sigma_value_to_kql(field: str, value) -> str:
    if isinstance(value, list):
        parts = [_single_value_kql(field, v) for v in value]
        return f"({' or '.join(parts)})"
    return _single_value_kql(field, value)
 
 
def _single_value_kql(field: str, value) -> str:
    v = str(value)
    # Wildcard
    if "*" in v or "?" in v:
        return f"{field}: {v}"
    # Null
    if v.lower() in ("null", "none"):
        return f"not {field}: *"
    return f'{field}: "{_esc(v)}"'
 
 
def _apply_condition(selector_kql: dict, condition: str) -> list[str]:
    if not condition or not selector_kql:
        return list(selector_kql.values())
    cond = condition.strip()
 
    # Simple: "selection"  or  "selection and not filter"
    # Replace selector names with their KQL
    for name, kql in sorted(selector_kql.items(), key=lambda x: -len(x[0])):
        cond = re.sub(rf"\b{re.escape(name)}\b", f"({kql})", cond)
 
    # Map Sigma operators
    cond = re.sub(r"\bnot\b", "not", cond)
    cond = re.sub(r"\band\b", "and", cond)
    cond = re.sub(r"\bor\b",  "or",  cond)
 
    return [cond]
 
 
def _esc(v: str) -> str:
    return v.replace('"', '\\"')
 
 
# ---------------------------------------------------------------------------
# KQL/Lucene → Sigma detection  (reverse)
# ---------------------------------------------------------------------------
 
def _kql_lucene_to_selectors(query: str) -> tuple[dict, str]:
    """
    Parse a KQL/Lucene query into Sigma selectors.
    Handles:  field: "value"  field: value  field: (v1 or v2)  wildcards  AND/OR/NOT
    Returns (selectors_dict, condition_str).
    """
    # Strip outer parens
    query = query.strip()
 
    # Split on top-level AND into sub-selectors
    parts = _split_top_level(query, r"\band\b")
 
    if len(parts) == 1:
        selectors = {"selection": _parse_kql_block(query)}
        condition  = "selection"
    else:
        selectors = {}
        cond_parts = []
        for i, part in enumerate(parts):
            part = part.strip()
            negate = False
            if part.lower().startswith("not "):
                negate = True
                part = part[4:].strip()
            key = f"selection_{i+1}" if not negate else f"filter_{i+1}"
            selectors[key] = _parse_kql_block(part)
            cond_parts.append(f"not {key}" if negate else key)
        condition = " and ".join(cond_parts)
 
    return selectors, condition
 
 
def _parse_kql_block(block: str) -> dict | list:
    """Parse a KQL clause like  field: "value"  or  field: (v1 or v2)."""
    block = block.strip().strip("()")
 
    # field: (v1 or v2 ...)
    m = re.match(r'^([\w.]+)\s*:\s*\((.+)\)$', block, re.DOTALL)
    if m:
        field = _kql_field_to_sigma(m.group(1))
        values = [v.strip().strip('"\'') for v in re.split(r'\s+or\s+', m.group(2), flags=re.IGNORECASE)]
        return {field: values}
 
    # field: "value" or field: value
    m = re.match(r'^([\w.]+)\s*:\s*["\']?(.+?)["\']?$', block)
    if m:
        field = _kql_field_to_sigma(m.group(1))
        val   = m.group(2).strip().strip('"\'')
        return {field: val}
 
    # Bare keyword
    return {"keywords": [block.strip('"\'')]}
 
 
def _kql_field_to_sigma(field: str) -> str:
    """Map ECS field names back to common Sigma field names."""
    REVERSE_MAP = {
        "process.command_line":     "CommandLine",
        "process.executable":       "Image",
        "process.parent.executable":"ParentImage",
        "process.name":             "ProcessName",
        "destination.ip":           "DestinationIp",
        "destination.port":         "DestinationPort",
        "source.ip":                "SourceIp",
        "source.port":              "SourcePort",
        "event.code":               "EventID",
        "user.name":                "User",
        "file.name":                "FileName",
        "file.path":                "FilePath",
        "registry.key":             "RegistryKey",
        "registry.value":           "RegistryValue",
    }
    return REVERSE_MAP.get(field.lower(), field)
 
 
def _split_top_level(text: str, pattern: str) -> list[str]:
    """Split text on a regex pattern but only at depth-0 parentheses."""
    parts, depth, start = [], 0, 0
    tokens = list(re.finditer(r'[()]|' + pattern, text, re.IGNORECASE))
    prev = 0
    for m in tokens:
        if m.group() == "(":
            depth += 1
        elif m.group() == ")":
            depth -= 1
        elif depth == 0:
            parts.append(text[prev:m.start()])
            prev = m.end()
    parts.append(text[prev:])
    return [p.strip() for p in parts if p.strip()]
 
 
def _guess_logsource_from_kql(query: str) -> dict:
    q = query.lower()
    logsource: dict[str, str] = {}
    if "event.category: \"process\"" in q or "process.executable" in q:
        logsource = {"category": "process_creation"}
    elif "event.category: \"network\"" in q or "destination.ip" in q:
        logsource = {"category": "network"}
    elif "event.category: \"authentication\"" in q or "user.name" in q:
        logsource = {"category": "authentication"}
    elif "event.category: \"file\"" in q or "file.path" in q:
        logsource = {"category": "file_event"}
    elif "event.category: \"registry\"" in q or "registry.key" in q:
        logsource = {"category": "registry_event"}
    elif "dns.question.name" in q:
        logsource = {"category": "dns"}
    else:
        logsource = {"category": "network"}
 
    if "winlogbeat" in q or "windows" in q:
        logsource["product"] = "windows"
    elif "linux" in q or "filebeat" in q:
        logsource["product"] = "linux"
 
    return logsource
 
 
# ---------------------------------------------------------------------------
# EQL helpers
# ---------------------------------------------------------------------------
 
def _looks_like_eql(query: str) -> bool:
    return bool(re.match(r"^\s*(sequence|process where|network where|file where|"
                         r"registry where|authentication where|any where)", query, re.IGNORECASE))
 
 
def _looks_like_lucene(query: str) -> bool:
    return ":" in query or bool(re.search(r"\bAND\b|\bOR\b|\bNOT\b", query))
 
 
def _eql_to_selectors(query: str) -> tuple[dict, str]:
    """Very basic EQL → Sigma selectors (event_type where conditions)."""
    # Strip event type prefix:  "process where ..."
    m = re.match(r"^\s*\w+\s+where\s+(.+)$", query, re.IGNORECASE | re.DOTALL)
    body = m.group(1).strip() if m else query
 
    # Replace EQL == with KQL : for reuse
    body = re.sub(r'(\w[\w.]*)\s*==\s*"([^"]+)"', r'\1: "\2"', body)
    body = re.sub(r'(\w[\w.]*)\s*==\s*(\S+)', r'\1: \2', body)
    body = re.sub(r"\blike~?\s*", ": ", body)
 
    return _kql_lucene_to_selectors(body)
 
 
# ---------------------------------------------------------------------------
# Sigma → Defender XDR Advanced Hunting KQL
# ---------------------------------------------------------------------------
 
def sigma_to_defender(sigma_content: str) -> tuple[str, list[str]]:
    """
    Convert a Sigma rule to a Defender XDR Advanced Hunting KQL query.
    Returns (kql_string, warnings).
    """
    warnings: list[str] = []
 
    try:
        doc = yaml.safe_load(sigma_content)
    except yaml.YAMLError as e:
        return "", [f"YAML parse error: {e}"]
    if not isinstance(doc, dict):
        return "", ["Not a valid Sigma YAML mapping"]
 
    title       = doc.get("title", "Untitled")
    description = doc.get("description", "")
    author      = doc.get("author", "")
    level       = doc.get("level", "medium")
    tags        = doc.get("tags", [])
    logsource   = doc.get("logsource", {})
    detection   = doc.get("detection", {})
 
    mitre_str = ", ".join(str(t) for t in tags if "attack." in str(t).lower())
    sev_map   = {"critical": "High", "high": "High", "medium": "Medium",
                 "low": "Low", "informational": "Informational"}
    sev_label = sev_map.get(level.lower(), "Medium")
 
    # Map logsource to Defender table
    table, table_warn = _logsource_to_defender_table(logsource)
    if table_warn:
        warnings.append(table_warn)
 
    # Convert detection block to KQL filters
    kql_filters, det_warnings = _detection_to_defender_kql(detection, logsource)
    warnings.extend(det_warnings)
 
    # Build projection based on table
    projection = _defender_projection(table)
 
    header = f"""// =============================================================================
// Title       : {title}
// Author      : {author}
// Severity    : {sev_label}
// MITRE       : {mitre_str or "N/A"}
// Description : {description}
// Converted from Sigma — review field mappings carefully
// =============================================================================
 
"""
    query = header
    query += f"{table}\n"
    query += "| where Timestamp > ago(1d)\n"
    for f in kql_filters:
        query += f"| where {f}\n"
    query += f"// TODO: add additional filters as needed\n"
    query += f"{projection}\n"
    query += "| order by Timestamp desc\n"
 
    return query, warnings

def sigma_to_defender_rule(sigma_content: str) -> tuple[str, list[str]]:
    """
    Sigma → Microsoft Defender Detection Rule (Graph API JSON via template)
    """
    from modules.templates import defender_template

    warnings: list[str] = []

    try:
        doc = yaml.safe_load(sigma_content)
    except yaml.YAMLError as e:
        return "", [f"YAML parse error: {e}"]

    if not isinstance(doc, dict):
        return "", ["Invalid Sigma YAML"]

    title       = doc.get("title", "Untitled")
    description = doc.get("description", "")
    level       = doc.get("level", "medium")
    tags        = doc.get("tags", [])
    logsource_category     = doc.get("logsource", {}).get("category", "General").title().replace("_", " ")

    # ✅ Reuse your existing KQL converter
    kql_query, kql_warnings = sigma_to_defender(sigma_content)
    warnings.extend(kql_warnings)

    # 🔥 Strip header comments (Graph API doesn't need them)
    query_clean = "\n".join(
        line for line in kql_query.splitlines()
        if not line.strip().startswith("//")
    ).strip()

    # ✅ Extract MITRE techniques
    mitre_techniques = []
    for tag in tags:
        if isinstance(tag, str) and tag.lower().startswith("attack.t"):
            mitre_techniques.append(tag.split(".")[-1].upper())

    # ✅ Use template (THIS is the key change)
    json_payload = defender_template(
        title=title,
        description=description,
        query=query_clean,
        severity=level,
        mitre_techniques=mitre_techniques,
        logsource_category=logsource_category
    )

    return json_payload, warnings
 
 
def _logsource_to_defender_table(logsource: dict) -> tuple[str, str]:
    if logsource.get("category"):
        category = logsource.get("category", "").lower()
    if logsource.get("product"):
        product  = logsource.get("product", "").lower()
    if logsource.get("service"):
        service  = logsource.get("service", "").lower()
 
    TABLE_MAP = {
        "process_creation":  "DeviceProcessEvents",
        "network":           "DeviceNetworkEvents",
        "file_event":        "DeviceFileEvents",
        "file_creation":     "DeviceFileEvents",
        "registry_event":    "DeviceRegistryEvents",
        "registry_add":      "DeviceRegistryEvents",
        "registry_set":      "DeviceRegistryEvents",
        "dns":               "DeviceNetworkEvents",
        "authentication":    "DeviceLogonEvents",
        "webserver":         "DeviceNetworkEvents",
    }
    if category in TABLE_MAP:
        return TABLE_MAP[category], ""
 
    if "email" in service or "exchange" in service:
        return "EmailEvents", ""
    if "azure" in product or "azure" in service:
        return "CloudAppEvents", ""
    if "aws" in product:
        return "CloudAppEvents", "AWS events map to CloudAppEvents — verify field names"
    if "windows" in product:
        return "DeviceEvents", ""
 
    return "DeviceEvents", f"Could not map logsource category '{category}' to a Defender table — defaulted to DeviceEvents"
 
 
def _detection_to_defender_kql(detection: dict, logsource: dict) -> tuple[list[str], list[str]]:
    filters  = []
    warnings = []
    if logsource.get("category"):
        category = logsource.get("category", "").lower()
 
    for name, body in detection.items():
        if name == "condition":
            continue
        if not isinstance(body, dict):
            continue
        for sigma_field, value in body.items():
            # Strip Sigma modifiers (e.g. CommandLine|contains → CommandLine)
            base_field, *modifiers = sigma_field.split("|")
            modifier = modifiers[0].lower() if modifiers else "exact"
 
            defender_field = _sigma_to_defender_field(base_field, category)
 
            if isinstance(value, list):
                kql_vals = ", ".join(f'"{_esc(str(v))}"' for v in value)
                if modifier in ("contains", "contains|all"):
                    clauses = [f'{defender_field} contains "{_esc(str(v))}"' for v in value]
                    filters.append("(" + " or ".join(clauses) + ")")
                elif modifier in ("endswith",):
                    clauses = [f'{defender_field} endswith "{_esc(str(v))}"' for v in value]
                    filters.append("(" + " or ".join(clauses) + ")")
                elif modifier in ("startswith",):
                    clauses = [f'{defender_field} startswith "{_esc(str(v))}"' for v in value]
                    filters.append("(" + " or ".join(clauses) + ")")
                else:
                    filters.append(f"{defender_field} in~ ({kql_vals})")
            else:
                v = str(value)
                if "*" in v:
                    filters.append(f'{defender_field} matches regex "{_glob_to_regex(v)}"')
                elif modifier == "contains":
                    filters.append(f'{defender_field} contains "{_esc(v)}"')
                elif modifier == "endswith":
                    filters.append(f'{defender_field} endswith "{_esc(v)}"')
                elif modifier == "startswith":
                    filters.append(f'{defender_field} startswith "{_esc(v)}"')
                else:
                    filters.append(f'{defender_field} == "{_esc(v)}"')
 
    return filters, warnings
 
 
def _sigma_to_defender_field(sigma_field: str, category: str) -> str:
    FIELD_MAP = {
        "CommandLine":       "ProcessCommandLine",
        "Image":             "FolderPath",
        "ParentImage":       "InitiatingProcessFolderPath",
        "ProcessName":       "FileName",
        "ParentProcessName": "InitiatingProcessFileName",
        "User":              "AccountName",
        "TargetUserName":    "AccountName",
        "SubjectUserName":   "AccountName",
        "DestinationIp":     "RemoteIP",
        "DestinationPort":   "RemotePort",
        "SourceIp":          "LocalIP",
        "SourcePort":        "LocalPort",
        "FileName":          "FileName",
        "FilePath":          "FolderPath",
        "RegistryKey":       "RegistryKey",
        "RegistryValue":     "RegistryValueName",
        "EventID":           "ActionType",
        "md5":               "MD5",
        "sha256":            "SHA256",
        "sha1":              "SHA1",
    }
    return FIELD_MAP.get(sigma_field, sigma_field)
 
 
def _defender_projection(table: str) -> str:
    PROJECTIONS = {
        "DeviceProcessEvents":  "| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256",
        "DeviceNetworkEvents":  "| project Timestamp, DeviceName, AccountName, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, RemoteUrl",
        "DeviceFileEvents":     "| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName",
        "DeviceRegistryEvents": "| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, ActionType",
        "DeviceLogonEvents":    "| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, IsLocalAdmin",
        "EmailEvents":          "| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes, DetectionMethods",
        "CloudAppEvents":       "| project Timestamp, AccountId, AccountDisplayName, IPAddress, ActionType, Application, ActivityType",
    }
    return PROJECTIONS.get(table, "| project Timestamp, DeviceName, AccountName, ActionType")
 
 
def _glob_to_regex(glob: str) -> str:
    return glob.replace(".", "\\.").replace("*", ".*").replace("?", ".")
 
 
# ---------------------------------------------------------------------------
# Sigma → Sentinel Analytics Rule JSON
# ---------------------------------------------------------------------------
 
def sigma_to_sentinel(sigma_content: str) -> tuple[str, list[str]]:
    """
    Convert a Sigma rule to a Microsoft Sentinel Analytics Rule (ARM JSON).
    Returns (json_string, warnings).
    """
    import json as _json
    warnings: list[str] = []
 
    try:
        doc = yaml.safe_load(sigma_content)
    except yaml.YAMLError as e:
        return "", [f"YAML parse error: {e}"]
    if not isinstance(doc, dict):
        return "", ["Not a valid Sigma YAML mapping"]
 
    title       = doc.get("title", "Untitled")
    description = doc.get("description", "")
    author      = doc.get("author", "")
    level       = doc.get("level", "medium")
    tags        = doc.get("tags", [])
    logsource   = doc.get("logsource", {})
    detection   = doc.get("detection", {})
    sigma_id    = doc.get("id", re.sub(r"[^a-z0-9_]", "_", title.lower()))
 
    sev_map   = {"critical": "High", "high": "High", "medium": "Medium",
                 "low": "Low", "informational": "Informational"}
    sev_label = sev_map.get(level.lower(), "Medium")
 
    # Parse MITRE
    tactics    = []
    techniques = []
    for tag in tags:
        tag = str(tag)
        m = re.match(r"(?i)attack\.(t\d{4}(?:\.\d{3})?)", tag)
        if m:
            techniques.append(m.group(1).upper())
        elif re.match(r"(?i)attack\.\w+", tag):
            tac = tag.split(".")[-1].replace("_", " ").title()
            tactics.append(tac)
 
    # Build Sentinel KQL query
    sentinel_kql, kql_warnings = _detection_to_sentinel_kql(detection, logsource)
    warnings.extend(kql_warnings)
 
    rule = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {},
        "resources": [
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                "apiVersion": "2022-11-01-preview",
                "name": f"[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/{sigma_id}')]",
                "kind": "Scheduled",
                "properties": {
                    "displayName": title,
                    "description": description,
                    "severity": sev_label,
                    "enabled": True,
                    "query": sentinel_kql,
                    "queryFrequency": "PT1H",
                    "queryPeriod": "PT1H",
                    "triggerOperator": "GreaterThan",
                    "triggerThreshold": 0,
                    "suppressionDuration": "PT1H",
                    "suppressionEnabled": False,
                    "tactics": tactics,
                    "techniques": techniques,
                    "alertRuleTemplateName": None,
                    "incidentConfiguration": {
                        "createIncident": True,
                        "groupingConfiguration": {
                            "enabled": False,
                            "reopenClosedIncident": False,
                            "lookbackDuration": "PT5M",
                            "matchingMethod": "AllEntities",
                            "groupByEntities": [],
                            "groupByAlertDetails": [],
                            "groupByCustomDetails": []
                        }
                    },
                    "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
                    "metadata": {
                        "author": {"name": author},
                        "dateAdded": date.today().isoformat(),
                    },
                    "entityMappings": _sentinel_entity_mappings(logsource),
                }
            }
        ]
    }
 
    return _json.dumps(rule, indent=2), warnings
 
 
def _detection_to_sentinel_kql(detection: dict, logsource: dict) -> tuple[str, list[str]]:
    warnings  = []
    category  = logsource.get("category", "").lower() if logsource.get("category") else ""
    product   = logsource.get("product", "").lower() if logsource.get("product") else ""
    service   = logsource.get("service", "").lower() if logsource.get("service") else ""
 
    # Map to Sentinel table
    TABLE_MAP = {
        "process_creation": ("SecurityEvent", "EventID == 4688"),
        "authentication":   ("SigninLogs",    None),
        "network":          ("CommonSecurityLog", None),
        "dns":              ("DnsEvents",     None),
        "file_event":       ("DeviceFileEvents", None),
        "registry_event":   ("DeviceRegistryEvents", None),
    }
    table, base_filter = TABLE_MAP.get(category, ("SecurityEvent", None))
 
    if "azure" in product or "azure" in service:
        table = "AzureActivity"
        base_filter = None
    elif "aws" in product:
        table = "AWSCloudTrail"
        base_filter = None
        warnings.append("AWS logsource — verify AWSCloudTrail connector and field names")
    elif "office" in product or "m365" in product:
        table = "OfficeActivity"
        base_filter = None
 
    filters = []
    if base_filter:
        filters.append(base_filter)
 
    SENTINEL_FIELD_MAP = {
        "CommandLine":       "CommandLine",
        "Image":             "NewProcessName",
        "ParentImage":       "ParentProcessName",
        "ProcessName":       "Process",
        "User":              "Account",
        "TargetUserName":    "TargetAccount",
        "SubjectUserName":   "SubjectAccount",
        "DestinationIp":     "DestinationIP",
        "DestinationPort":   "DestinationPort",
        "SourceIp":          "SourceIP",
        "EventID":           "EventID",
    }
 
    for name, body in detection.items():
        if name == "condition" or not isinstance(body, dict):
            continue
        for sigma_field, value in body.items():
            base_field, *mods = sigma_field.split("|")
            modifier = mods[0].lower() if mods else "exact"
            sent_field = SENTINEL_FIELD_MAP.get(base_field, base_field)
 
            if isinstance(value, list):
                if modifier in ("contains",):
                    clauses = [f'{sent_field} contains "{_esc(str(v))}"' for v in value]
                    filters.append("(" + " or ".join(clauses) + ")")
                elif modifier in ("endswith",):
                    clauses = [f'{sent_field} endswith "{_esc(str(v))}"' for v in value]
                    filters.append("(" + " or ".join(clauses) + ")")
                else:
                    vals = ", ".join(f'"{_esc(str(v))}"' for v in value)
                    filters.append(f"{sent_field} in ({vals})")
            else:
                v = str(value)
                if modifier == "contains":
                    filters.append(f'{sent_field} contains "{_esc(v)}"')
                elif modifier == "endswith":
                    filters.append(f'{sent_field} endswith "{_esc(v)}"')
                elif modifier == "startswith":
                    filters.append(f'{sent_field} startswith "{_esc(v)}"')
                elif "*" in v:
                    filters.append(f'{sent_field} matches regex "{_glob_to_regex(v)}"')
                else:
                    filters.append(f'{sent_field} == "{_esc(v)}"')
 
    kql = table + "\n"
    for f in filters:
        kql += f"| where {f}\n"
    kql += "// TODO: refine query and add projections\n"
    kql += f"| project TimeGenerated, Computer, Account, CommandLine\n"
    kql += "| order by TimeGenerated desc"
 
    if not filters:
        warnings.append("Detection block produced no filters — query is a bare table scan")
 
    return kql, warnings
 
 
def _sentinel_entity_mappings(logsource: dict) -> list:
    category = logsource.get("category", "").lower()
    base = [
        {"entityType": "Account", "fieldMappings": [{"identifier": "FullName", "columnName": "Account"}]},
        {"entityType": "Host",    "fieldMappings": [{"identifier": "FullName", "columnName": "Computer"}]},
    ]
    if "network" in category:
        base.append({"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "DestinationIP"}]})
    return base