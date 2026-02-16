import os
import glob
import logging
from automation import utils


def _normalize_status(raw: str | None) -> str:
    """Map ESCU statuses to our pipeline statuses.

    production -> stable
    experimental -> experimental
    deprecated/other -> as-is (likely filtered later)
    """
    if not raw:
        return 'stable'
    val = str(raw).strip().lower()
    if val == 'production':
        return 'stable'
    if val == 'experimental':
        return 'experimental'
    return val


def load_and_parse_rules(path: str):
    """
    Scans for ESCU YAML detection files and extracts key rule info.

    Expected fields (Security Content format):
    - name: rule title
    - status: production/experimental/deprecated
    - search: SPL query string
    - tags.mitre_attack_id: list of MITRE technique IDs (e.g., ["T1003.001"]) 
    - tags.asset_type: e.g., "Windows" (used to infer platform)
    """
    logging.info(f"Scanning for ESCU rules in: {path}")
    yml_files = glob.glob(os.path.join(path, '**', '*.yml'), recursive=True)
    logging.info(f"    -> Found {len(yml_files)} YAML detection files.")

    loaded_rules: list[dict] = []

    for file_path in yml_files:
        doc = utils.load_yaml_file(file_path)
        if not isinstance(doc, dict):
            continue

        title = doc.get('name') or doc.get('title')
        spl = doc.get('search')
        tags = (doc.get('tags') or {})
        attack_ids = tags.get('mitre_attack_id') or []
        # Normalize attack tags as uppercase technique IDs
        attack_tags = []
        if isinstance(attack_ids, list):
            attack_tags = [str(t).upper() for t in attack_ids if isinstance(t, (str, int))]
        elif isinstance(attack_ids, (str, int)):
            attack_tags = [str(attack_ids).upper()]

        if not title or not spl or not attack_tags:
            # Skip documents that don't have essential bits
            continue

        asset_type = (tags.get('asset_type') or '')
        platform = str(asset_type).strip().lower() if asset_type else ''

        loaded_rules.append({
            'filepath': file_path,
            'title': title,
            'status': _normalize_status(doc.get('status')),
            'platform': platform or 'windows' if str(asset_type).lower() == 'windows' else platform,
            'is_escu': True,
            'query': spl,
            'attack_tags': list(set(attack_tags)),
        })

    logging.info(f"    -> Successfully loaded and parsed {len(loaded_rules)} valid ESCU rules with ATT&CK tags.")
    return loaded_rules