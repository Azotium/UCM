# 🛡️ Detection Engineering Platform

A Streamlit-based web application for managing, validating, and analysing detection use cases stored in Azure DevOps repositories.

---

## Features

| Feature | Description |
|---|---|
| 🔌 **ADO Integration** | Connect to any Azure DevOps org, browse projects/repos/branches |
| 🔍 **Use Case Explorer** | Browse detection folders, view README / Sigma / Elastic rule files |
| ✅ **Bulk Validator** | Validate Sigma YAML schema, completeness, and convert to Elastic Lucene queries |
| 📄 **README Validator** | Check metadata completeness (description, MITRE tags, false positives, etc.) |
| 🛡️ **MITRE ATT&CK** | Coverage heatmap, treemap, and ATT&CK Navigator layer export |
| 📊 **Statistics** | Health scores, severity/status distributions, completeness metrics |
| 🔀 **PR Manager** | View active PRs and create new ones with a pre-PR checklist |

---

## Folder structure per use case

Each detection use case should be a folder containing:

```
detections/
└── T1059_command_scripting/
    ├── README.md          ← Use case description, MITRE tags, FPs, references
    ├── sigma.yml          ← Sigma rule (generic)
    └── elastic_rule.toml  ← SIEM-specific rule (Elastic)
```

---

## Installation

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Requirements

- Python 3.10+
- Azure DevOps Personal Access Token with **Code (Read)** and **Pull Requests (Read & Write)** scopes

---

## Workflow

```
Feature branch  →  PR to dev  →  Validate in platform  →  PR to main
```

1. Connect to ADO in the sidebar
2. Select project, repository, and branch
3. Click **Load Use Cases**
4. Run **Validator** to check all rules
5. Build **MITRE Coverage** map
6. Compute **Statistics**
7. Create or review **Pull Requests**
