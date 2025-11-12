import json
from recon.scan_cannon import run_scan
from recon.parser import parse_html
from attack.hydra_attack import brute_force
from attack.metasploit_trigger import MsfrpcTrigger
from utils.logger import log

def main():
    log("Starting Automated Red Team")
    # Run scancannon via recon.scan_cannon.run_scan which returns an output HTML file
    scan_output = run_scan("targets.txt")
    log("Scan completed. Parsing results.")

    # parse scan output into structured targets
    targets = []
    if scan_output:
        try:
            targets = parse_html(scan_output)
        except Exception as e:
            log(f"Failed to parse scan output {scan_output}: {e}")
            targets = []
    else:
        log("No scan output produced; skipping parsing and attack steps.")

    # Create a Metasploit RPC trigger helper. Use dry_run=True by default to avoid
    # requiring an actual msfrpcd connection while developing. Replace rpc_password
    # with a real password or load from config when ready.
    msf = MsfrpcTrigger(rpc_password="changeme", rpc_port=55552, ssl=False, dry_run=True)
    if not msf.dry_run:
        connected = msf.connect()
        if not connected:
            log("Warning: could not connect to msfrpcd; continuing in degraded mode")
    else:
        log("msfrpc trigger running in dry_run mode; not connecting to RPC server")

    for target in targets:
        services = target.get("services", []) if isinstance(target, dict) else []
        if "ssh" in services:
            brute_force(target, "ssh")
        if "ftp" in services:
            brute_force(target, "ftp")
        if "http" in services:
            # Attempt to find an IP/host and port; fall back to sensible defaults
            host = target.get("ip") or target.get("host") or target.get("hostname")
            port = int(target.get("port") or 80)
            if host:
                # call the MsfrpcTrigger method to orchestrate an exploit attempt
                msf.exploit_target(host, port, "http")
            else:
                log("No host information for target; skipping http exploit")

    log("Automated Red Team operations completed.")
    log("workflow finished")

if __name__ == "__main__":
    main()
