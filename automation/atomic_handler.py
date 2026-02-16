# automation/atomic_handler.py

import os
import re
import yaml
import logging

# ATT&CK technique ID pattern: T followed by digits, optional .digits
_TID_PATTERN = re.compile(r"^T\d+(\.\d+)?$", re.I)


def get_all_technique_ids(atomics_path: str | None = None) -> list[str]:
    """
    Discovers all technique IDs from the Atomic Red Team atomics folder.
    Returns sorted list of technique IDs (e.g. T1059.001, T1087.001, ...).
    """
    from automation import config
    path = atomics_path or config.ATOMIC_TESTS_PATH
    if not os.path.isdir(path):
        return []
    result = []
    for name in os.listdir(path):
        if _TID_PATTERN.match(name):
            yaml_path = os.path.join(path, name, f"{name}.yaml")
            md_path = os.path.join(path, name, f"{name}.md")
            if os.path.isfile(yaml_path) or os.path.isfile(md_path):
                result.append(name.upper())
    return sorted(result)


class AtomicParser:
    """
    Parses Atomic Red Team YAML files and returns structured test lists.
    Supports Attack Mapping: one report entry per Atomic Test.
    """

    def __init__(self, atomics_path: str | None = None):
        from automation import config
        self.atomics_path = atomics_path or config.ATOMIC_TESTS_PATH

    def get_tests_for_technique(
        self, technique_id: str, platform_filter: str | None = "windows"
    ) -> list[dict]:
        """
        Returns list of atomic tests for a technique.
        Each dict: test_number, name, guid, supported_platforms, ...
        """
        test_data, _ = find_atomic_for_technique(technique_id, self.atomics_path)
        if not test_data or "atomic_tests" not in test_data:
            return []
        result = []
        for i, t in enumerate(test_data["atomic_tests"], start=1):
            platforms = t.get("supported_platforms") or []
            if isinstance(platforms, str):
                platforms = [platforms]
            platforms = [str(p).lower() for p in platforms if p]
            if platform_filter and platforms and platform_filter.lower() not in platforms:
                continue
            guid = t.get("auto_generated_guid") or t.get("guid") or ""
            result.append({
                "test_number": i,
                "name": t.get("name", f"Test {i}"),
                "guid": guid,
                "supported_platforms": platforms,
            })
        return result


def find_atomic_for_technique(technique_id, atomics_path):
    """
    Finds the Atomic Red Team test file and its path for a given ATT&CK technique ID.
    """
    formatted_id = technique_id.upper()
    test_file_path = os.path.join(atomics_path, formatted_id, f"{formatted_id}.yaml")
    
    if not os.path.exists(test_file_path):
        test_file_path = os.path.join(atomics_path, formatted_id, f"{formatted_id}.md")
        if not os.path.exists(test_file_path):
            return None, None 

    try:
        with open(test_file_path, 'r', encoding='utf-8') as f:
            if test_file_path.endswith('.md'):
                content = f.read()
                parts = content.split('---')
                if len(parts) >= 3:
                    yaml_content = parts[1]
                    test_data = yaml.safe_load(yaml_content)
                else:
                    logging.warning(f"    -> Malformed markdown atomic file (no YAML front matter): {test_file_path}")
                    return None, None
            else:
                test_data = yaml.safe_load(f)
        
        if test_data and 'atomic_tests' in test_data:
            for atomic in test_data['atomic_tests']:
                if 'auto_generated_guid' in atomic:
                    atomic['guid'] = atomic['auto_generated_guid']
        
        return test_data, test_file_path
    except Exception as e:
        logging.warning(f"    -> Could not parse atomic test file: {test_file_path}. Error: {e}")
        return None, None

def prepare_command(atomic_test):
    """
    Takes a single atomic test object and substitutes its input arguments
    to create a final, executable command.
    
    :param atomic_test: A dictionary representing a single test from the YAML.
    :return: A final, executable command string, or None.
    """
    raw_command = atomic_test.get('executor', {}).get('command')
    if not raw_command:
        return None
        
    final_command = raw_command
    if atomic_test.get('input_arguments'):
        for arg_name, arg_details in atomic_test['input_arguments'].items():
            placeholder = f"#{{{arg_name}}}"
            default_value = arg_details.get('default')
            
            if default_value is not None:
                final_command = final_command.replace(placeholder, str(default_value))

    return final_command