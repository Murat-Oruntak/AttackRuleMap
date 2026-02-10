import os
import sys
import argparse
import logging
from datetime import datetime

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from automation import config
from automation import atomic_handler
from automation import dynamic_generator
from automation import report_handler

CYAN = "\033[36m"
GREEN = "\033[32m"
BOLD = "\033[1m"
RESET = "\033[0m"


def banner():
    print()
    print(f"{CYAN}{BOLD}[*] Starting Detection Lab Pipeline...{RESET}")
    print(f"{CYAN}    Rule-Based Verification (Sigma + ESCU -> SPL){RESET}")
    print(f"{CYAN}    Output: {config.REPORT_JSON_PATH}{RESET}")
    print()


def setup_logging(verbose: bool = False):
    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(config.PROJECT_ROOT, f"automation_run_{run_ts}.log")
    fh = logging.FileHandler(log_path, mode="w")
    fh.setLevel(logging.DEBUG)
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG if verbose else logging.INFO)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
        handlers=[fh, sh],
    )
    for _logger in ("splunklib", "urllib3", "paramiko"):
        logging.getLogger(_logger).setLevel(logging.WARNING)


def main():
    parser = argparse.ArgumentParser(
        description="AttackRuleMap Detection Lab — run atomic tests and verify with Sigma/ESCU rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m automation.main --all
  python -m automation.main --tid T1059.001
  python -m automation.main --tid T1059.001 --tid T1087.001
  python -m automation.main -v --tid T1059.001
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--all",
        action="store_true",
        help="Run all techniques from config (ATTACK_LIST / ATTACK_TIDS).",
    )
    group.add_argument(
        "--tid",
        dest="tids",
        action="append",
        metavar="TID",
        help="Run only the given technique ID (e.g. T1059.001). Can be repeated.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging (SPL queries, operational details).",
    )
    args = parser.parse_args()

    setup_logging(verbose=args.verbose)
    banner()

    if args.all:
        from automation import repo_manager
        mgr = repo_manager.RepoManager()
        if not mgr.ensure_repos():
            logging.error("Repo setup failed. Cannot discover techniques.")
            technique_ids = config.ATTACK_LIST
        else:
            technique_ids = atomic_handler.get_all_technique_ids()
        if not technique_ids:
            logging.warning("No techniques found in Atomic Red Team repo. Using ATTACK_TIDS from config.")
            technique_ids = config.ATTACK_LIST
        logging.info("%s[*] Mode: --all (%s techniques)%s", GREEN, len(technique_ids), RESET)
    else:
        technique_ids = [t.strip().upper() for t in args.tids if t]
        logging.info("%s[*] Mode: --tid %s%s", GREEN, ", ".join(technique_ids), RESET)

    # Time-boxing: DynamicDetectionLab captures test_start_time before each atomic test,
    # test_end_time after the 30s indexing buffer, and passes them to Splunk verification
    # to prevent cross-contamination between sequential tests (no relative -2m/now).
    lab = dynamic_generator.DynamicDetectionLab(technique_ids=technique_ids)
    report = lab.run()

    if report:
        handler = report_handler.ReportHandler()
        handler.generate_mitre_layer(report)
        handler.print_coverage_stats(report)

    print()
    logging.info("%s[*] Detection Lab Pipeline finished.%s", CYAN + BOLD, RESET)
    logging.info("%s    Techniques run: %s%s", GREEN, len(report), RESET)
    out_path = config.REPORT_JSON_PATH
    logging.info("%s    Report: %s%s", GREEN, out_path, RESET)
    print()


if __name__ == "__main__":
    main()
