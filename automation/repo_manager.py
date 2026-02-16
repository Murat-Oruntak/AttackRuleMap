import os
import sys
import subprocess
import logging

from automation import config

REPOS = [
    ("sigma", "https://github.com/SigmaHQ/sigma.git"),
    ("security_content", "https://github.com/splunk/security_content.git"),
    ("atomic-red-team", "https://github.com/redcanaryco/atomic-red-team.git"),
]


class RepoManager:
    def __init__(self, base_path: str | None = None):
        self.base_path = base_path or config.REPOS_BASE_PATH

    def _run_git(self, cmd: list[str], cwd: str | None = None) -> tuple[bool, str]:
        try:
            r = subprocess.run(
                cmd,
                cwd=cwd or self.base_path,
                capture_output=True,
                text=True,
                timeout=300,
            )
            out = (r.stdout or "").strip() + (r.stderr or "").strip()
            return r.returncode == 0, out
        except subprocess.TimeoutExpired:
            return False, "Timeout"
        except Exception as e:
            return False, str(e)

    def _clone(self, name: str, url: str) -> bool:
        target = os.path.join(self.base_path, name)
        logging.debug("[*] Cloning %s...", name)
        ok, out = self._run_git(["git", "clone", "--depth", "1", url, target], cwd=self.base_path)
        if ok:
            logging.debug("[*] Cloned %s into %s", name, target)
        else:
            logging.warning("[*] Clone failed for %s: %s", name, out)
        return ok

    def _pull(self, name: str) -> bool:
        target = os.path.join(self.base_path, name)
        logging.debug("[*] Updating %s...", name)
        ok, out = self._run_git(["git", "pull", "--rebase"], cwd=target)
        if ok:
            logging.debug("[*] Updated %s", name)
        else:
            logging.warning("[*] Pull failed for %s (using existing): %s", name, out)
        return ok

    def ensure_repos(self) -> bool:
        os.makedirs(self.base_path, exist_ok=True)
        any_failed = False
        for name, url in REPOS:
            target = os.path.join(self.base_path, name)
            if not os.path.isdir(target):
                if not self._clone(name, url):
                    any_failed = True
                    if not os.path.isdir(target):
                        logging.error("[*] Repo %s missing and clone failed. Cannot continue.", name)
                        return False
            else:
                self._pull(name)
        return True
