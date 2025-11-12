import subprocess
from utils.logger import log

def run_scan(target_file):
    log(f"Running scan on targets listed in {target_file}")
    try:
        cmd = ["scancannon", "-i", target_file, "-o", "scan_results.html"]
        subprocess.run(cmd, check=True)
        log("Scan completed successfully.")
        return "scan_results.html"
    except subprocess.CalledProcessError:
        log("error", "Scan failed.")
        return None
    