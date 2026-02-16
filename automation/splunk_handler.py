import os
import time
import logging
from datetime import datetime, timezone
import splunklib.client as client
from automation import config
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.exceptions import SigmaError

def connect_to_splunk():
    """
    Establishes and returns a connection object to the Splunk service.
    """
    try:
        connect_kwargs = {
            "host": config.SPLUNK_HOST,
            "port": config.SPLUNK_PORT,
            "scheme": config.SPLUNK_SCHEME,
            "verify": config.SPLUNK_VERIFY_CERT,
        }

        token = config.SPLUNK_TOKEN
        if token:
            # For Splunk Cloud or token-based auth
            connect_kwargs["token"] = f"Splunk {token}"
            if (config.SPLUNK_USERNAME or config.SPLUNK_PASSWORD):
                logging.debug("Both token and username/password configured; using token authentication and ignoring username/password.")
        else:
            connect_kwargs["username"] = config.SPLUNK_USERNAME
            connect_kwargs["password"] = config.SPLUNK_PASSWORD

        service = client.connect(**connect_kwargs)
        if not (config.SPLUNK_SEARCH_INDEX or "").strip():
            logging.debug("SPLUNK_SEARCH_INDEX is empty. Searches will not be scoped to an index; consider setting it in .env for better performance/precision.")
        logging.debug(
            "Connected to Splunk at %s://%s:%s (verify_cert=%s)",
            connect_kwargs['scheme'], config.SPLUNK_HOST, connect_kwargs['port'], str(connect_kwargs.get('verify'))
        )
        return service
    except Exception as e:
        logging.error(f"Failed to connect to Splunk at {config.SPLUNK_HOST}:{config.SPLUNK_PORT}. Details: {e}")
        return None

def convert_sigma_to_spl(sigma_filepath: str) -> str | None:
    """
    Converts a single Sigma rule file to a Splunk SPL query using the pySigma library.

    Returns the first SPL string if conversion succeeds, otherwise None.
    Handles both list and string return types from pySigma backends for compatibility.
    """
    logging.debug("    -> Converting Sigma rule using pySigma: %s", os.path.basename(sigma_filepath))
    try:
        with open(sigma_filepath, "r", encoding="utf-8") as f:
            rule_text = f.read()
        
        rules = SigmaCollection.from_yaml(rule_text)
        backend = SplunkBackend()
        result = backend.convert(rules)

        # pySigma may return a list/tuple or a single string depending on version
        if isinstance(result, (list, tuple)):
            if result and isinstance(result[0], str) and result[0].strip():
                return result[0]
        elif isinstance(result, str):
            if result.strip():
                return result
        logging.warning("    -> pySigma conversion resulted in an empty query.")
        return None
    except (SigmaError, Exception) as e:
        logging.error(f"    -> pySigma conversion failed for {os.path.basename(sigma_filepath)}. Error: {e}")
        return None

def _iso_to_epoch_seconds(iso_str: str) -> int:
    """Converts ISO 8601 string to epoch seconds (UTC)."""
    try:
        # Handle potential trailing 'Z'
        if iso_str.endswith('Z'):
            iso_str = iso_str.replace('Z', '+00:00')
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        # Fallback: try parsing as integer epoch already
        try:
            return int(float(iso_str))
        except Exception:
            return int(time.time())

def _with_index_prefix(query: str) -> str:
    """Attach index scoping for classic searches but do not break tstats/datamodel pipelines.

    Rules:
    - If query starts with a pipe '|' or startswith 'tstats', return as-is (SDK earliest/latest still applied).
    - If query already starts with 'search', inject index token right after 'search' when configured.
    - Otherwise, prepend 'search [index=...]' + query.
    """
    q = (query or '').lstrip()
    idx = (config.SPLUNK_SEARCH_INDEX or '').strip()
    if not q:
        return 'search'
    # Don't alter tstats/datamodel or pre-piped queries
    if q.startswith('|') or q.lower().startswith('tstats'):
        return q
    # If already a search command
    if q.lower().startswith('search '):
        if idx:
            # insert index token after 'search'
            return 'search index="{}" {}'.format(idx, q[len('search '):])
        return q
    # Default: prefix with search (and index if set)
    if idx:
        return f'search index="{idx}" {q}'
    return f'search {q}'

def check_for_detection(service, search_query: str, earliest_time: str, latest_time: str) -> bool:
    """
    Searches Splunk for events matching a specific SPL query within a specific time window.
    """
    if not search_query:
        logging.warning("    -> SPL query is empty. Skipping detection check.")
        return False
        
    padded_earliest = _iso_to_epoch_seconds(earliest_time) - config.SPLUNK_TIME_PAD_SECONDS
    padded_latest = _iso_to_epoch_seconds(latest_time) + config.SPLUNK_TIME_PAD_SECONDS

    # Build final query with optional index scoping
    full_query = _with_index_prefix(search_query)
    logging.debug("    -> Querying Splunk: %s earliest=%s latest=%s", full_query, padded_earliest, padded_latest)

    try:
        kwargs = {
            "exec_mode": "blocking",
            "earliest_time": str(padded_earliest),
            "latest_time": str(padded_latest),
        }
        job = service.jobs.create(full_query, **kwargs)
        # Ensure job content is populated
        try:
            job.refresh()
        except Exception:
            pass
        result_count = int((job.content or {}).get("resultCount", 0))
        logging.debug(
            "    -> Found %s result(s) in Splunk. sid=%s",
            result_count, getattr(job, 'sid', None)
        )
        return result_count > 0
    except Exception as e:
        logging.error(
            "    -> An error occurred while searching Splunk. query='%s' earliest=%s latest=%s error=%s",
            full_query, padded_earliest, padded_latest, e
        )
        return False

def sanity_check_ingestion(service, host: str, earliest_time: str, latest_time: str) -> bool:
    """Quick check to see if any events from the VM host are reaching Splunk in the time window."""
    if not host:
        return True  # Can't check; don't block
    padded_earliest = _iso_to_epoch_seconds(earliest_time) - config.SPLUNK_TIME_PAD_SECONDS
    padded_latest = _iso_to_epoch_seconds(latest_time) + config.SPLUNK_TIME_PAD_SECONDS
    base = f'host="{host}"'
    full_query = _with_index_prefix(base)
    logging.debug("Running ingestion sanity check: %s earliest=%s latest=%s", full_query, padded_earliest, padded_latest)
    try:
        job = service.jobs.create(full_query, exec_mode="blocking", earliest_time=str(padded_earliest), latest_time=str(padded_latest))
        try:
            job.refresh()
        except Exception:
            pass
        cnt = int((job.content or {}).get("resultCount", 0))
        logging.debug("Ingestion sanity check events from host='%s': %s (sid=%s)", host, cnt, getattr(job, 'sid', None))
        return cnt > 0
    except Exception as e:
        logging.warning(
            "Sanity check failed for query='%s' earliest=%s latest=%s: %s",
            full_query, padded_earliest, padded_latest, e
        )
        return True  # don't block verification on check failure