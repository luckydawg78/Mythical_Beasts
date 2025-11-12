import json;
from recon.scan_cannon import run_scan
from recon.parser import parse_scan_results
from attack.hydra_attack import brute_force
from attack.metasploit_trigger import exploit_targets
from utils.logger import log

def main():
    log("Starting Automated Red Team")
    scan_output = run_scan("targets.txt")
    log("Scan completed. Parsing results.")


    targets = run_scan("targets.txt")
    log("Scan Complete")

    for target in targets:
        if "ssh" in target["services"]:
            brute_force(target,"ssh")
        if "ftp" in target["services"]:
            brute_force(target,"ftp")
        if "http" in target["services"]:
            exploit_targets(target,"http")

    log("Automated Red Team operations completed.")
    log("workflow finished")

if __name__ == "__main__":
    main()
