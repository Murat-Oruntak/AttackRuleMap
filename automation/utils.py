import yaml
import logging

def load_yaml_file(filepath):
    """
    Safely loads a YAML file and returns its content.
    Returns None if the file cannot be read or parsed.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.warning(f"Could not read or parse YAML file: {filepath}. Error: {e}")
        return None