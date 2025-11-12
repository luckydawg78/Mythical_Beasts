import subprocess
from pathlib import Path

from utils.config import HYDRA_PASSWORD_WORDLIST, HYDRA_USER_WORDLIST
from utils.logger import log


def _resolve_wordlist(candidate: Path, fallback: str) -> str:
    """
    Return the seclists wordlist if available; otherwise fall back to the local file.
    """
    if candidate and Path(candidate).exists():
        return str(candidate)
    log(f"Wordlist {candidate} not found. Falling back to {fallback}")
    return fallback


def brute_force(target, service):
    user_list = _resolve_wordlist(HYDRA_USER_WORDLIST, "usernames.txt")
    pass_list = _resolve_wordlist(HYDRA_PASSWORD_WORDLIST, "passwords.txt")

    log(
        f"Launching Hydra on {target['ip']} for {service} service "
        f"(users: {user_list}, passwords: {pass_list})"
    )

    cmd = [
        "hydra",
        "-L",
        user_list,
        "-P",
        pass_list,
        f"{target['ip']}",
        service,
    ]
    subprocess.run(cmd, check=False)
