"""
templates.py
Generate file content templates for new detection use cases.
"""
from __future__ import annotations
from datetime import date


def sigma_template(
    uc_id: str,
    title: str,
    description: str,
    author: str,
    severity: str,
    status: str,
    mitre_tags: list[str],
    logsource_category: str,
    logsource_product: str,
    logsource_service: str,
) -> str:
    tags_yaml = "\n".join(f"    - {t}" for t in mitre_tags) if mitre_tags else "    - attack.tXXXX"
    return f"""title: {title}
id: {uc_id.lower().replace("-", "_")}
status: {status}
description: {description}
author: {author}
date: {date.today().isoformat()}
tags:
{tags_yaml}
logsource:
    category: {logsource_category or ""}
    product: {logsource_product or ""}
    service: {logsource_service or ""}
detection:
    selection:
        EventID: 1   # TODO: define your selection criteria
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: {severity}
"""


def elastic_template(
    uc_id: str,
    title: str,
    description: str,
    author: str,
    severity: str,
    mitre_tactics: list[str],
    mitre_techniques: list[str],
) -> str:
    tactics_toml = "\n".join(f'        "{t}",' for t in mitre_tactics)
    techniques_toml = "\n".join(f'        "{t}",' for t in mitre_techniques)
    uc_lower = uc_id.lower().replace("-", "_")
    return f'''[metadata]
creation_date = "{date.today().isoformat()}"
integration = ["system"]
maturity = "development"
updated_date = "{date.today().isoformat()}"

[rule]
author = ["{author}"]
description = """{description}"""
from = "now-9m"
index = ["logs-*", "filebeat-*"]
language = "kuery"
license = "Elastic License v2"
name = "{title}"
risk_score = {_severity_to_risk(severity)}
rule_id = "{uc_lower}"
severity = "{severity}"
tags = [
    "Detection: {uc_id}",
{tactics_toml}
{techniques_toml}
]
timestamp_override = "event.ingested"
type = "query"

query = \'\'\'
event.category: "network"
  and event.type: "connection"
  and event.outcome: "success"
  /* TODO: refine your KQL query */
\'\'\'

[[rule.threat]]
framework = "MITRE ATT&CK"

{_threat_blocks(mitre_tactics, mitre_techniques)}
'''


def readme_template(
    uc_id: str,
    title: str,
    description: str,
    author: str,
    severity: str,
    status: str,
    mitre_tags: list[str],
    false_positives: str,
    references: str,
    category: str,
    coverage_assets: str,
    coverage_width: int,
    coverage_depth: str,
    datasources: str,
    datasets: str,
    detection_method: str,
    triage: str,
    response: str,
    playbooks: str,
    mttd: str,
    fp_rate: str,
    pipelines: str,
) -> str:
    tags_md = " ".join(f"`{t}`" for t in mitre_tags) if mitre_tags else "`attack.tXXXX`"
    refs_md = "\n".join(f"- {r.strip()}" for r in references.splitlines() if r.strip()) or "- N/A"
    fps_md = "\n".join(f"- {f.strip()}" for f in false_positives.splitlines() if f.strip()) or "- None identified"
    cat_line = f"\n**Category:** {category}" if category else ""
    return f"""# {uc_id} — {title}

| Field | Value |
|-------|-------|
| **ID** | {uc_id} |
| **Severity** | {severity.title()} |
| **Status** | {status.title()} |
| **Author** | {author} |
| **Date** | {date.today().isoformat()} |{cat_line}

## Description

{description}

## MITRE ATT&CK

**Tags:** {tags_md}

| Tactic | Technique |
|--------|-----------|
| TODO   | TODO      |

## Risks

| Risk ID | Description |
|---------|-------------|
| TODO    | TODO        |


## Perimeter & Coverage
- Assets : {coverage_assets}
- Width : {coverage_width}
- Depth : {coverage_depth}

## Data Sources
{datasources}

## Datasets Elastic
{datasets}

## Detection Logic

{detection_method}

## False Positives

{fps_md}

## 7. Technical pipelines
{pipelines}


## KPI & SLA
- MTTD: {mttd}
- FP rate: {fp_rate}

## Triage
{triage}

## Response
{response}

## Associated playbooks
{playbooks}

## References

{refs_md}

## Versioning & History
- v1.0 – Production launch (2026-03)

"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_to_risk(severity: str) -> int:
    return {"critical": 99, "high": 73, "medium": 47, "low": 21, "informational": 5}.get(severity.lower(), 47)


def _threat_blocks(tactics: list[str], techniques: list[str]) -> str:
    if not tactics:
        return ""
    lines = []
    for tactic in tactics:
        lines.append(f'[[rule.threat.tactic]]\nid = "TODO"\nname = "{tactic}"\nreference = "https://attack.mitre.org/tactics/TODO/"')
    for tech in techniques:
        tid = tech.upper()
        lines.append(f'\n[[rule.threat.technique]]\nid = "{tid}"\nname = "TODO"\nreference = "https://attack.mitre.org/techniques/{tid}/"')
    return "\n".join(lines)


# def defender_template(
#     uc_id: str,
#     title: str,
#     description: str,
#     author: str,
#     severity: str,
#     mitre_tags: list[str],
# ) -> str:
#     """
#     Microsoft Defender XDR Advanced Hunting query (.kql).
#     Structured as a commented header + KQL query block.
#     """
#     tags_comment = ", ".join(mitre_tags) if mitre_tags else "attack.tXXXX"
#     sev_map = {"critical": "High", "high": "High", "medium": "Medium",
#                "low": "Low", "informational": "Informational"}
#     sev_label = sev_map.get(severity.lower(), "Medium")
#     return f"""// =============================================================================
# // Title       : {title}
# // ID          : {uc_id}
# // Author      : {author}
# // Date        : {date.today().isoformat()}
# // Severity    : {sev_label}
# // MITRE       : {tags_comment}
# // Description : {description}
# // Platform    : Microsoft Defender XDR — Advanced Hunting
# // =============================================================================
 
# // TODO: Replace the query below with your detection logic.
# // Defender XDR Advanced Hunting uses KQL against the Microsoft 365 Defender schema.
# // Common tables: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents,
# //                DeviceRegistryEvents, DeviceLogonEvents, EmailEvents,
# //                CloudAppEvents, IdentityLogonEvents
 
# DeviceProcessEvents
# | where Timestamp > ago(1d)
# | where FileName in~ ("powershell.exe", "cmd.exe")
#     and ProcessCommandLine has_any ("-EncodedCommand", "-enc", "-exec bypass")
# // TODO: refine filters
# | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
#           InitiatingProcessFileName, InitiatingProcessCommandLine
# | order by Timestamp desc
# """
 
def defender_template(
    title: str,
    description: str,
    query: str,
    severity: str,
    mitre_techniques: list[str],
    logsource_category: str,
) -> str:
    """
    Microsoft Defender Detection Rule (Graph API JSON template)
    """

    import json

    CATEGORY_MAP = {
      "process_creation": "Execution",
      "network": "Command and control",
      "authentication": "Credential access",
      "file_event": "Persistence",
      "registry": "Persistence",
      "scheduled_task": "Persistence",    
      "code_injection": "Defense evasion",
      "lateral_movement": "Lateral movement",
      "data_exfiltration": "Exfiltration",
      "other": "Suspicious activity"
    }

    sev_map = {
        "critical": "high",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "informational"
    }

    sev_label = sev_map.get(severity.lower(), "medium")

    payload = {
        "displayName": title,
        "isEnabled": False,

        "queryCondition": {
            "queryText": query
        },

        "schedule": {
            "period": "12H"
        },

        "detectionAction": {
            "alertTemplate": {
                "title": title,
                "description": description,
                "severity": sev_label,
                "category": CATEGORY_MAP.get(logsource_category, "Suspicious Activity"),
                "recommendedActions": None,
                "mitreTechniques": mitre_techniques or [],
                "impactedAssets": [
                    {
                        "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                        "identifier": "deviceId"
                    }
                ]
            },
            "organizationalScope": None,
            "responseActions": [
                {
                    "@odata.type": "#microsoft.graph.security.isolateDeviceResponseAction",
                    "identifier": "deviceId",
                    "isolationType": "full"
                }
            ]
        }
    }

    return json.dumps(payload, indent=2)
 
def sentinel_template(
    uc_id: str,
    title: str,
    description: str,
    author: str,
    severity: str,
    mitre_tactics: list[str],
    mitre_techniques: list[str],
) -> str:
    """
    Microsoft Sentinel Analytics Rule in ARM JSON format.
    Compatible with the Sentinel GitHub community rule format.
    """
    import json
    sev_map = {"critical": "High", "high": "High", "medium": "Medium",
               "low": "Low", "informational": "Informational"}
    sev_label = sev_map.get(severity.lower(), "Medium")
 
    tactic_list   = json.dumps(mitre_tactics)
    technique_list = json.dumps(mitre_techniques)
 
    return f"""{{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {{}},
  "resources": [
    {{
      "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
      "apiVersion": "2022-11-01-preview",
      "name": "[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/{uc_id.lower().replace("-", "_")}')]",
      "kind": "Scheduled",
      "properties": {{
        "displayName": "{title}",
        "description": "{description}",
        "severity": "{sev_label}",
        "enabled": true,
        "query": "// TODO: Replace with your KQL detection logic\\n// Common Sentinel tables: SecurityEvent, Syslog, SigninLogs,\\n//   AzureActivity, OfficeActivity, DeviceProcessEvents (via MDE connector)\\n\\nSecurityEvent\\n| where EventID == 4688\\n| where CommandLine has_any ('-EncodedCommand', '-enc')\\n// TODO: refine\\n| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName",
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT1H",
        "suppressionEnabled": false,
        "tactics": {tactic_list},
        "techniques": {technique_list},
        "alertRuleTemplateName": null,
        "incidentConfiguration": {{
          "createIncident": true,
          "groupingConfiguration": {{
            "enabled": false,
            "reopenClosedIncident": false,
            "lookbackDuration": "PT5M",
            "matchingMethod": "AllEntities",
            "groupByEntities": [],
            "groupByAlertDetails": [],
            "groupByCustomDetails": []
          }}
        }},
        "eventGroupingSettings": {{
          "aggregationKind": "SingleAlert"
        }},
        "metadata": {{
          "author": {{
            "name": "{author}"
          }},
          "dateAdded": "{date.today().isoformat()}",
          "categories": {{
            "domains": ["Security - Threat Protection"]
          }}
        }},
        "entityMappings": [
          {{
            "entityType": "Account",
            "fieldMappings": [
              {{
                "identifier": "FullName",
                "columnName": "Account"
              }}
            ]
          }},
          {{
            "entityType": "Host",
            "fieldMappings": [
              {{
                "identifier": "FullName",
                "columnName": "Computer"
              }}
            ]
          }}
        ]
      }}
    }}
  ]
}}
"""