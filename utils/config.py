import os
from pathlib import Path


def _expand_path(value: str) -> Path:
    """Return an expanded Path for the provided value."""
    return Path(value).expanduser()


# Base Seclists directory on Kali (can be overridden via SECLISTS_DIR env var)
SECLISTS_DIR = _expand_path(os.environ.get("SECLISTS_DIR", "/usr/share/seclists"))

# Default wordlists for Hydra within Seclists; override with env vars if needed.
HYDRA_USER_WORDLIST = _expand_path(
    os.environ.get(
        "HYDRA_USER_WORDLIST",
        str(SECLISTS_DIR / "Usernames" / "top-usernames-shortlist.txt"),
    )
)

HYDRA_PASSWORD_WORDLIST = _expand_path(
    os.environ.get(
        "HYDRA_PASSWORD_WORDLIST",
        str(SECLISTS_DIR / "Passwords" / "Common-Credentials" / "10k-most-common.txt"),
    )
)
