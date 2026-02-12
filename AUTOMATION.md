# Automation & Dashboard — Technical Manual

This document describes the **Automation** and **Dashboard** capabilities added to AttackRuleMap. It is intended for Security Engineers and Detection Engineers who want to run Atomic Red Team tests, validate detections against Splunk and Sigma rules, and consume the resulting mapping via an HTML dashboard and MITRE ATT&CK® Navigator layers.

---

## 1. Overview

The automation module:

- **Executes** [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests (optionally on a Windows VM or Proxmox-managed lab).
- **Queries** Splunk for detection events using SPL derived from **Sigma** and **Splunk Security Content (ESCU)** rules.
- **Maps** each atomic test to which rules detected it, with time-bounded search to avoid cross-contamination between sequential tests.
- **Generates** a consolidated report (`attack_rule_map.json`) and an **HTML Dashboard** (`dist/index.html`) plus **MITRE ATT&CK® Navigator** layers for heatmap-style coverage visualization.

The focus is **validation**: confirming that your detection rules (Sigma/ESCU → Splunk) actually fire when the corresponding adversary techniques are executed, rather than relying on static mapping alone.

---

## 2. Architecture

| Phase | Component | Description |
|-------|-----------|-------------|
| **Execution** | Atomic Red Team | Runs atomic tests (e.g. PowerShell, registry, file operations) on a target—local or remote VM. Test IDs and atomics are discovered from the Atomic Red Team repo. |
| **Detection** | Splunk + Sigma / ESCU | Sigma rules are converted to SPL (pySigma); ESCU provides native SPL. The pipeline runs time-bounded Splunk searches to determine which rules detected each test. |
| **Mapping** | Deep Merge Logic | New results are merged into the existing report by `atomic_attack_guid`. Existing entries are not overwritten; their `sigma_rules` and `splunk_rules` lists are extended with new detections (no duplicate rule names). |
| **Visualization** | HTML Dashboard & MITRE Heatmap | `dist/index.html` loads `attack_rule_map.json` via AJAX and displays technique ↔ rule ↔ atomic test mappings. Navigator layers (`mitre_layer_sigma.json`, `mitre_layer_splunk.json`, `mitre_layer_combined.json`) show detection coverage per technique. |

Data flow: **Atomic execution** → **Splunk search (time window)** → **Detection result per rule** → **Report merge** → **JSON + MITRE layers** → **Dashboard**.

---

## 3. Setup & Installation

### 3.1 Python Dependencies

From the project root:

```bash
pip install -r requirements.txt
```

This installs (among others): `paramiko`, `PyYAML`, `python-dotenv`, `pySigma`, `pySigma-backend-splunk`, `splunk-sdk`.

### 3.2 Environment Configuration

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` with your values. At minimum, configure:
   - **Splunk**: `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD` (or `SPLUNK_TOKEN`), and optionally `SPLUNK_SEARCH_INDEX`.
   - **Execution** (if using a VM): `VM_HOST`, `VM_USERNAME`, `VM_PASSWORD`, `VM_SAFE_DIR`; or Proxmox-related variables if using snapshot-based VMs.

See `.env.example` for all variables and inline comments. Do not commit `.env` to version control.

### 3.3 Repositories (Sigma, ESCU, Atomic Red Team)

On first run with `--all` or when technique discovery is needed, the pipeline will clone (if missing) into `data/repos/` by default:

- Sigma (SigmaHQ/sigma)
- Splunk Security Content (splunk/security_content)
- Atomic Red Team (redcanaryco/atomic-red-team)

Paths can be overridden via `REPOS_BASE_PATH`, `SIGMA_REPO_PATH`, `ESCU_REPO_PATH`, `ATOMIC_RED_TEAM_REPO`, etc. in `.env`.

---

## 4. Usage

### 4.1 Main Automation

From the project root:

```bash
# Run all techniques defined in ATTACK_TIDS (config / .env)
python -m automation.main --all

# Run specific technique(s)
python -m automation.main --tid T1059.001 --tid T1087.001

# Verbose (DEBUG) logging
python -m automation.main -v --tid T1059.001
```

The pipeline will: run atomics, wait for indexing, query Splunk for each test’s time window, merge results into `dist/attack_rule_map.json`, and regenerate the MITRE Navigator layers.

### 4.2 Regenerating MITRE Layers Only

To regenerate only the MITRE ATT&CK Navigator layer files from an existing `attack_rule_map.json` (no test execution):

```bash
python -m automation.main --mitre-only
```

Use this after editing the report manually or when you only need updated heatmaps.

### 4.3 Report Merge (No Separate Script)

The pipeline does **not** ship a separate “recovery merge” script. Report updates are **incremental** and **deep-merged** on every run:

- If `dist/attack_rule_map.json` exists, new results are merged by `atomic_attack_guid`.
- For matching GUIDs, existing `sigma_rules` and `splunk_rules` are preserved and extended (by rule name, no duplicates).
- New tests are appended. Output is “ultra-lite” (detected rules with `rule_name` and `rule_link` only).

So each run both adds new data and preserves prior validations.

---

## 5. Dashboard Features

### 5.1 HTML Report (`dist/index.html`)

- **Location**: Open `dist/index.html` in a browser (or serve `dist/` with any static file server).
- **Data**: The page loads `attack_rule_map.json` via AJAX and optionally `metadata.json` for “Last updated” information.
- **Content**: Table and filters for MITRE technique, atomic test name, Sigma rules, and Splunk/ESCU rules that detected each test. Supports export and search typical of a DataTables-based UI.

### 5.2 MITRE ATT&CK® Navigator Integration

Three layer files are written under `dist/`:

| File | Description |
|------|-------------|
| `mitre_layer_sigma.json` | Coverage based on Sigma rule detections only. |
| `mitre_layer_splunk.json` | Coverage based on Splunk/ESCU rule detections only. |
| `mitre_layer_combined.json` | Coverage where either Sigma or Splunk detected the technique. |

Import these into [MITRE ATT&CK® Navigator](https://mitre-attack.github.io/attack-navigator/) to view heatmaps (e.g. by detection rate per technique). Scores and comments in the layer reflect test counts and detected counts.

### 5.3 Deep Merge Logic

- **Preserves history**: Existing report entries are never overwritten by a new run; rule lists are merged by `atomic_attack_guid` and by rule name.
- **Validation-centric**: The dashboard and layers reflect which rules have **actually** detected which tests in your environment, not just static rule–technique mappings.

---

## 6. Directory Structure

| Path | Purpose |
|------|---------|
| `automation/` | Python package: config, atomic discovery, Sigma/ESCU handling, Splunk queries, VM/execution, report merge, MITRE layer generation. |
| `dist/` | Output directory: `attack_rule_map.json`, `index.html`, `metadata.json`, MITRE layer JSONs, and static assets (CSS, JS, images) for the dashboard. |
| `data/repos/` | Default location for cloned Sigma, ESCU, and Atomic Red Team repositories (created on first run if using default `REPOS_BASE_PATH`). |

The project root also contains `requirements.txt`, `.env.example`, and the main `README.md`; the latter is unchanged and describes the original AttackRuleMap project.

---

## Summary

This automation provides an end-to-end **detection validation** workflow: run Atomic Red Team tests, verify which Sigma and Splunk rules fire in your environment, and consume the results via a JSON report, HTML dashboard, and MITRE ATT&CK Navigator layers. Configuration is driven by `.env`; see `.env.example` for all options.
