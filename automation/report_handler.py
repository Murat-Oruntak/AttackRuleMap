import json
import os
import logging
import csv
from datetime import datetime

from automation import config


class ReportHandler:
    """Handles report generation, MITRE Navigator layer, and coverage statistics."""

    def generate_mitre_layer(self, data: list) -> str:
        """
        Generate MITRE ATT&CK Navigator layer from report data.
        Args:
            data: List of report entries (tech_id, sigma_rules, escu_rules, etc.)
        Returns:
            Path to the generated mitre_layer.json file.
        """
        output_file = os.path.join(config.DIST_PATH, "mitre_layer.json")
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        layer = {
            "name": "Detection Lab Coverage (Sigma)",
            "versions": {
                "attack": "18",
                "navigator": "5.3.0",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": "Detection Lab Results - Coverage Map",
            "filters": {
                "platforms": ["Windows"]
            },
            "sorting": 3,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": False,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False
            },
            "hideDisabled": False,
            "techniques": []
        }

        technique_stats = {}
        for test in data:
            tid = test.get("tech_id", "")
            if not tid:
                continue
            if tid not in technique_stats:
                technique_stats[tid] = {"total": 0, "detected": 0}
            technique_stats[tid]["total"] += 1

            sigma_rules = test.get("sigma_rules", [])
            is_detected = any(r.get("detected") for r in sigma_rules)
            if is_detected:
                technique_stats[tid]["detected"] += 1

        for tid, stats in technique_stats.items():
            total = stats["total"]
            detected = stats["detected"]
            score = (detected / total * 100) if total > 0 else 0
            technique_data = {
                "techniqueID": tid,
                "score": score,
                "color": "",
                "comment": f"Tests: {total} | Detected: {detected} | Coverage: %{score:.1f}",
                "enabled": True,
                "metadata": []
            }
            layer["techniques"].append(technique_data)

        layer["gradient"] = {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(layer, f, indent=4)

        logging.info("MITRE Layer file created: %s", output_file)
        logging.info("Total %s techniques mapped to layer.", len(layer["techniques"]))
        return output_file

    def save_report_json(self, new_results: list) -> str:
        """
        Smart Merge: Save report to root, preserving existing data from other contributors
        (e.g., Linux/macOS tests) that were not run in this session.
        - If attack_rule_map.json exists: merge (keep untouched, overwrite session, append new)
        - If not: save new data as usual.
        - Normalizes technique_id -> tech_id so output schema matches attack_rule_map.json.
        """
        path = config.REPORT_JSON_PATH

        def _normalize_entry(e: dict) -> dict:
            """Map technique_id -> tech_id for schema consistency; remove technique_id."""
            entry = dict(e)
            tid = entry.get("tech_id") or entry.get("technique_id")
            if tid:
                entry["tech_id"] = str(tid).upper() if isinstance(tid, str) else tid
            if "technique_id" in entry:
                del entry["technique_id"]
            return entry

        def _key(e: dict) -> tuple:
            tid = e.get("tech_id") or e.get("technique_id") or ""
            return (
                (str(tid) if tid else "").upper(),
                e.get("test_number"),
                str(e.get("platform", "")).strip().lower(),
            )

        normalized = [_normalize_entry(e) for e in new_results]
        new_map = {_key(e): e for e in normalized}
        session_keys = set(new_map.keys())

        existing: list = []
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    existing = data if isinstance(data, list) else []
            except (json.JSONDecodeError, OSError) as e:
                logging.warning("Could not load existing report, starting fresh: %s", e)
                existing = []

        merged: list = []
        for e in existing:
            k = _key(e)
            if k in session_keys:
                merged.append(new_map[k])
                del new_map[k]
            else:
                merged.append(e)
        for e in new_map.values():
            merged.append(e)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=4, ensure_ascii=False)
        logging.info("Report saved (smart merge): %s", path)
        return path

    def print_coverage_stats(self, data: list) -> None:
        """
        Calculate and print coverage statistics to the console using logging.
        Args:
            data: List of report entries (tech_id, sigma_rules, escu_rules, etc.)
        """
        if not data:
            logging.warning("No report data to compute coverage stats.")
            return

        total_tests = len(data)
        detected_tests = sum(
            1 for t in data
            if any(r.get("detected") for r in t.get("sigma_rules", []))
        )
        coverage_pct = (detected_tests / total_tests * 100) if total_tests > 0 else 0.0

        logging.info("Total Atomic Tests: %s", total_tests)
        logging.info("Tests Detected: %s", detected_tests)
        logging.info("Coverage Rate: %.2f%%", coverage_pct)


def generate_json_output(new_results, output_path):
    """
    Reads an existing map file, intelligently updates or appends new results,
    and handles NOT_DETECTED statuses for existing entries.
    """
    logging.info("Generating final JSON report with advanced 'update/append/audit' strategy...")
    
    today_str = datetime.now().strftime("%Y-%m-%d")
    existing_map = {}
    if os.path.exists(output_path):
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                existing_map = json.load(f)
        except json.JSONDecodeError:
            logging.warning(f"Could not decode existing JSON file at {output_path}.")
    
    # --- Process new results ---
    for res in new_results:
        technique = res['attack_technique'].upper()
        if technique not in existing_map:
            existing_map[technique] = []
            
        # Define the unique identifiers for a mapping
        rule_title = res['sigma_rule_title']
        test_name = res['atomic_test_name']
        
        # --- Find if an entry already exists ---
        entry_index_to_update = -1
        for i, existing_rule in enumerate(existing_map[technique]):
            is_match = (existing_rule.get('sigma_rule') == rule_title or existing_rule.get('splunk_rule') == rule_title) and \
                       existing_rule.get('atomic_test_name') == test_name
            if is_match:
                entry_index_to_update = i
                break

        # --- Update, Append or Audit Logic ---
        if res['result'] == 'DETECTED':
            new_entry = {
                "atomic_test_name": test_name,
                "atomic_attack_guid": res.get('atomic_test_guid', 'N/A'),
                "platform": res.get('platform', 'N/A'),
                "sigma_rule": rule_title if "ESCU" not in rule_title else "",
                "splunk_rule": rule_title if "ESCU" in rule_title else "",
                "rule_link": res.get('sigma_rule_link', '#'),
                "last_validated_date": today_str # Add validation date
            }
            if entry_index_to_update != -1:
                # UPDATE existing entry
                existing_map[technique][entry_index_to_update] = new_entry
            else:
                # APPEND new entry
                existing_map[technique].append(new_entry)
        
        elif res['result'] == 'NOT_DETECTED':
            if entry_index_to_update != -1:
                # AUDIT: Mark the existing entry as not detected in this run
                logging.info(f"Auditing existing entry: '{rule_title}' for test '{test_name}' is now NOT DETECTED.")
                existing_map[technique][entry_index_to_update]['last_test_status'] = 'NOT_DETECTED'
                existing_map[technique][entry_index_to_update]['last_tested_date'] = today_str

    # --- Write the combined map back to the file ---
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(existing_map, f, indent=4)
        logging.info(f"Successfully created final combined report: {output_path}")
    except Exception as e:
        logging.error(f"Failed to write JSON report. Error: {e}")

def generate_csv_summary(results, output_path):
    logging.info(f"Generating detailed CSV summary report to: {output_path}")
    header = ['sigma_rule_title', 'attack_technique', 'atomic_test_name', 'result', 'details']
    try:
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header)
            writer.writeheader()
            for res in results:
                csv_row = {'sigma_rule_title': res.get('sigma_rule_title', 'N/A'),'attack_technique': res.get('attack_technique', 'N/A'),'atomic_test_name': res.get('atomic_test_name', 'N/A'),'result': res.get('result', 'UNKNOWN'),'details': res.get('details', '')}
                writer.writerow(csv_row)
        logging.info("Successfully created CSV summary report.")
    except Exception as e:
        logging.error(f"Failed to write CSV summary report. Error: {e}")