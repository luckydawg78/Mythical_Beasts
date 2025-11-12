import subprocess
import os
from pathlib import Path
from utils.logger import log


def run_scan(target_file: str, scancannon_path: str = None, output_file: str = "scan_results.html") -> str | None:
    """Run ScanCannon against targets listed in `target_file`.

    - scancannon_path: optional path to the scancannon.sh script. If not provided,
      the function will try SCANCANNON_PATH environment variable, then a sensible
      default used in development images.
    - Returns path to generated output_file on success, or None on failure.
    """
    log(f"Running scan on targets listed in {target_file}")

    # Resolve scan cannon path: parameter -> env -> default
    sc = scancannon_path or os.environ.get("SCANCANNON_PATH") or "scancannon.sh"
    sc_path = Path(sc)

    if not sc_path.exists():
        log("error", f"ScanCannon not found at {sc_path}. Set SCANCANNON_PATH or install ScanCannon.")
        return None

    # If the script isn't executable, try to run it via sh
    if not os.access(sc_path, os.X_OK):
        log("warning", f"ScanCannon at {sc_path} is not executable. Attempting to invoke with sh.")
        cmd = ["sh", str(sc_path), "-i", target_file, "-o", output_file]
    else:
        cmd = [str(sc_path), "-i", target_file, "-o", output_file]

    try:
        # Capture output for better diagnostics
        res = subprocess.run(cmd, check=False, capture_output=True, text=True)
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
     