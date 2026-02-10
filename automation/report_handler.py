import json
import os
import logging
import csv
from datetime import datetime

from automation import config


class ReportHandler:
    """Handles report generation, ATT&CK Navigator layer, and coverage statistics."""

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

    def _log_rule_details(self, entry: dict, rule_list: list, rule_type: str) -> None:
        """Log full rule details (event_count, SPL) before filtering. DEBUG level = file only, not terminal."""
        tid = entry.get("tech_id", "")
        test_num = entry.get("test_number", "")
        atomic_name = entry.get("atomic_attack_name", "")
        for r in rule_list:
            name = r.get("rule_name", "")
            detected = r.get("detected", False)
            event_count = r.get("log_count", r.get("event_count", 0))
            spl = r.get("generated_spl") or r.get("original_spl") or r.get("sanitized_spl") or ""
            logging.debug(
                "[RULE_DETAIL] tech_id=%s test=%s atomic=%s type=%s rule=%s detected=%s event_count=%s spl=%s",
                tid, test_num, atomic_name, rule_type, name, detected, event_count,
                spl[:200] + "..." if len(spl) > 200 else spl,
            )

    def _build_ultra_lite(self, merged: list) -> list:
        """
        Build Ultra-Lite JSON: filter detected-only rules, strip to rule_name+rule_link.
        Does NOT modify the original merged list.
        """
        lite = []
        for entry in merged:
            e = dict(entry)
            # Filter sigma_rules: keep only detected=True (or legacy entries without detected field)
            sigma = e.get("sigma_rules", [])
            sigma_lite = [
                {"rule_name": r.get("rule_name", ""), "rule_link": r.get("rule_link", "")}
                for r in sigma
                if r.get("detected", True)  # Legacy: no 'detected' -> include
            ]
            e["sigma_rules"] = sigma_lite

            # escu_rules and splunk_rules: normalize to splunk_rules for dashboard
            escu = e.get("escu_rules", e.get("splunk_rules", []))
            escu_lite = [
                {"rule_name": r.get("rule_name", ""), "rule_link": r.get("rule_link", "")}
                for r in escu
                if r.get("detected", True)  # Legacy: no 'detected' -> include
            ]
            e["splunk_rules"] = escu_lite
            if "escu_rules" in e:
                del e["escu_rules"]
            lite.append(e)
        return lite

    def _merge_rule_lists(self, existing_rules: list, new_rules: list) -> list:
        """
        Merge two rule lists by rule_name. No duplicate rule names.
        Order: existing first, then new rules whose rule_name is not already present.
        """
        seen_names = {r.get("rule_name") for r in existing_rules if r.get("rule_name")}
        out = list(existing_rules)
        for r in new_rules:
            name = r.get("rule_name")
            if name and name not in seen_names:
                seen_names.add(name)
                out.append(r)
        return out

    def save_report_json(self, new_results: list) -> str:
        """
        Deep Merge by attack GUID: Save report preserving existing data and extending
        rule lists when the same atomic test (same GUID) exists in both existing and new.
        - If attack_rule_map.json exists: merge by atomic_attack_guid.
        - If GUID exists: do NOT overwrite; merge sigma_rules and splunk_rules (no duplicate rule names).
        - If GUID does not exist: append new entry as is.
        - Normalizes technique_id -> tech_id so output schema matches attack_rule_map.json.
        - Produces Ultra-Lite JSON: detected-only rules, rule_name+rule_link, minified.
        - Full details (event_count, SPL) are logged before filtering.
        """
        path = config.REPORT_JSON_PATH
        os.makedirs(os.path.dirname(path), exist_ok=True)

        def _normalize_entry(e: dict) -> dict:
            """Map technique_id -> tech_id for schema consistency; remove technique_id."""
            entry = dict(e)
            tid = entry.get("tech_id") or entry.get("technique_id")
            if tid:
                entry["tech_id"] = str(tid).upper() if isinstance(tid, str) else tid
            if "technique_id" in entry:
                del entry["technique_id"]
            return entry

        normalized = [_normalize_entry(e) for e in new_results]
        new_by_guid: dict = {}
        for e in normalized:
            guid = (e.get("atomic_attack_guid") or "").strip()
            if not guid:
                continue
            if guid not in new_by_guid:
                new_by_guid[guid] = dict(e)
                new_by_guid[guid]["sigma_rules"] = list(e.get("sigma_rules", []))
                new_by_guid[guid]["splunk_rules"] = list(
                    e.get("escu_rules") or e.get("splunk_rules", [])
                )
                if "escu_rules" in new_by_guid[guid]:
                    del new_by_guid[guid]["escu_rules"]
            else:
                new_by_guid[guid]["sigma_rules"] = self._merge_rule_lists(
                    new_by_guid[guid]["sigma_rules"], e.get("sigma_rules", [])
                )
                new_by_guid[guid]["splunk_rules"] = self._merge_rule_lists(
                    new_by_guid[guid]["splunk_rules"],
                    e.get("escu_rules") or e.get("splunk_rules", []),
                )

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
            guid = (e.get("atomic_attack_guid") or "").strip()
            if guid and guid in new_by_guid:
                new_entry = new_by_guid.pop(guid)
                merged_entry = dict(e)
                merged_entry["sigma_rules"] = self._merge_rule_lists(
                    e.get("sigma_rules", []), new_entry.get("sigma_rules", [])
                )
                merged_entry["splunk_rules"] = self._merge_rule_lists(
                    e.get("splunk_rules", []), new_entry.get("splunk_rules", [])
                )
                if "escu_rules" in merged_entry:
                    del merged_entry["escu_rules"]
                merged.append(merged_entry)
            else:
                merged.append(e)

        for e in new_by_guid.values():
            merged.append(e)

        # Log full details BEFORE filtering (log file is source of truth)
        for entry in merged:
            for rule_type, key in [("sigma", "sigma_rules"), ("escu", "escu_rules"), ("splunk", "splunk_rules")]:
                rules = entry.get(key, [])
                if rules:
                    self._log_rule_details(entry, rules, rule_type)

        # Build Ultra-Lite version (filter detected, strip to rule_name+rule_link)
        lite = self._build_ultra_lite(merged)

        # Save minified Ultra-Lite JSON
        with open(path, "w", encoding="utf-8") as f:
            json.dump(lite, f, separators=(",", ":"), ensure_ascii=False)
        logging.info("Report saved (smart merge, ultra-lite): %s", path)

        # Write metadata.json in same directory (dist/) for dashboard "Last Updated"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        metadata = {"last_updated": timestamp}
        metadata_path = os.path.join(os.path.dirname(path), "metadata.json")
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        logging.info("Metadata saved: %s", metadata_path)

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