import subprocess
import os
from pathlib import Path
from utils.logger import log


def run_scan(
    target_file: str,
    scancannon_path: str = None,
    output_file: str = "scan_results.html",
    auto_confirm_network: bool = True,
    use_sudo: bool | None = None,
    results_dir_choice: str | None = "D",
) -> str | None:
    log(f"Running scan on targets listed in {target_file}")

    # Resolve scan cannon path: parameter -> env -> default
    sc = scancannon_path or os.environ.get("SCANCANNON_PATH") or "/home/vmuser/Desktop/ScanCannon/scancannon.sh"
    sc_path = Path(sc)

    if not sc_path.exists():
        log("error", f"ScanCannon not found at {sc_path}. Set SCANCANNON_PATH or install ScanCannon.")
        return None

    # If the script isn't executable, try to run it via sh
    if not os.access(sc_path, os.X_OK):
        log("warning", f"ScanCannon at {sc_path} is not executable. Attempting to invoke with sh.")
        cmd = ["sh", str(sc_path), target_file]
    else:
        cmd = [str(sc_path), target_file]

    # Allow sudo elevation either via parameter or SCANCANNON_USE_SUDO env flag.
    if use_sudo is None:
        env_flag = os.environ.get("SCANCANNON_USE_SUDO", "").strip().lower()
        use_sudo = env_flag in {"1", "true", "yes", "on"}
    if use_sudo:
        cmd = ["sudo"] + cmd
        log("info", f"Executing ScanCannon with sudo: {' '.join(cmd)}")

    try:
        # Build scripted answers for ScanCannon prompts (NIC config + results folder action).
        answers: list[str] = []
        if auto_confirm_network:
            answers.append("y\n")

        # Allow overriding the results-folder prompt via env var or argument.
        env_choice = os.environ.get("SCANCANNON_RESULTS_CHOICE")
        effective_choice = env_choice.strip().upper() if env_choice else (results_dir_choice or "").upper()
        if effective_choice:
            answers.append(f"{effective_choice}\n")

        stdin_data = "".join(answers) if answers else None

        # Capture output for better diagnostics
        res = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            input=stdin_data,
        )
        if res.returncode != 0:
            # Provide stderr/stdout to help diagnose failures (e.g., git errors inside ScanCannon)
            stderr = (res.stderr or "").strip()
            stdout = (res.stdout or "").strip()
            details = stderr if stderr else stdout
            log("error", f"Scan failed (rc={res.returncode}). Details: {details}")
            return None

        log("info", "Scan completed successfully.")
        return output_file

    except FileNotFoundError as e:
        log("error", f"ScanCannon executable not found: {e}")
        return None
    except Exception as e:
        log("error", f"Unexpected error running ScanCannon: {e}")
        return None
     
