# Mythical Beasts — Automated Red Team Pipeline

Mythical Beasts is a small, educational red‑team automation pipeline that chains reconnaissance, parsing, credential attacks, and Metasploit RPC exploitation. It is intended for lab and authorized environments only.

Key stages:
- Reconnaissance: Runs `scancannon` against a list of targets, producing an HTML report.
- Parsing: Extracts potential targets and services from the scan report.
- Credential Attacks: Uses `hydra` for basic SSH/FTP brute force with local wordlists.
- Exploitation: Integrates with Metasploit via RPC to search, check, and (optionally) launch exploits.


**Ethical Use Only**
- Use strictly on systems you own or have explicit written authorization to test.
- You are responsible for complying with all laws and policies.


**Repository Structure**
- `main.py`: Orchestrates the end‑to‑end workflow.
- `recon/scan_cannon.py`: Wrapper for running `scancannon` and producing `scan_results.html`.
- `recon/parser.py`: Parses the HTML report into target records for subsequent stages.
- `attack/hydra_attack.py`: Launches `hydra` for SSH/FTP brute forcing using `usernames.txt` and `passwords.txt`.
- `attack/metasploit_trigger.py`: `MsfrpcTrigger` class for Metasploit RPC search/check/exploit and post‑exploitation.
- `utils/logger.py`: Minimal timestamped logger.
- `utils/config.py`: Placeholder for future configuration.


## Requirements

Python
- Python 3.9+ recommended
- Packages: `beautifulsoup4`, `pymetasploit3`

External tools
- `scancannon` in `PATH`
- `hydra` in `PATH`
- Metasploit Framework with `msfrpcd` available and running (for RPC features)

Example setup on a fresh Python environment:
```
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install beautifulsoup4 pymetasploit3
```


## Quickstart

1) Prepare targets
- Create a `targets.txt` file with one IP/CIDR/host per line.

2) Provide wordlists (for Hydra)
- Place `usernames.txt` and `passwords.txt` in the project root (or adjust the code if stored elsewhere).

3) Start Metasploit RPC (optional, for exploitation stage)
- Choose SSL or non‑SSL to match your environment and `MsfrpcTrigger` parameters.
```
# Example (adjust user, password, port, SSL to match your setup)
msfrpcd -U msf -P <rpc_password> -a 127.0.0.1 -p 55553 -S   # SSL
# or
msfrpcd -U msf -P <rpc_password> -a 127.0.0.1 -p 55552      # No SSL
```

4) Run the pipeline
```
python main.py
```

Outputs
- `scan_results.html` created by `scancannon` in the project directory.
- Console logs for progress and results.


## How It Works (Intended Flow)

1) Reconnaissance
- `recon/scan_cannon.py` runs `scancannon -i targets.txt -o scan_results.html`.

2) Parsing
- `recon/parser.py` reads the HTML report and produces target dicts like `{ "ip": "1.2.3.4", "services": ["ssh", ...] }`.

3) Credential Attacks
- `attack/hydra_attack.py` runs Hydra for services like `ssh` and `ftp` using the provided wordlists.

4) Metasploit RPC Exploitation
- `attack/metasploit_trigger.py` contains `MsfrpcTrigger` to:
  - Search for candidate exploit modules
  - Run `check` to validate likely vulnerability
  - Launch exploit jobs (optional) and then run safe post‑exploitation modules


## Example: Using MsfrpcTrigger Directly

```
from attack.metasploit_trigger import MsfrpcTrigger

mt = MsfrpcTrigger(rpc_password="<rpc_password>", rpc_user="msf", rpc_host="127.0.0.1", rpc_port=55553, ssl=True)
if mt.connect():
    result = mt.exploit_target(host="10.0.0.10", port=80, service="http")
    print(result)
```


## Notes and Known Issues

- `main.py` currently demonstrates the intended flow but contains inconsistencies (e.g., duplicated scan call, function name mismatches). You may need to wire `parse_html` into the workflow and adapt calls to `MsfrpcTrigger` for exploitation.
- `recon/parser.py` is a minimal parser and may require fixes and tailoring to your `scancannon` HTML format.
- `utils/config.py` is a placeholder; consider centralizing paths and settings there.
- Wordlists (`usernames.txt`, `passwords.txt`) must be supplied by you.


## Safety and Legal

- This project is for authorized security testing and education only.
- Always obtain explicit written permission before scanning or attacking any system.
- The authors and maintainers are not responsible for misuse or damages.


## Contributing

Contributions that improve safety, correctness, and modularity are welcome. Please open an issue describing your change and any validation steps.


## Disclaimer

This software is provided “as is,” without warranty of any kind, express or implied. Use at your own risk and only in environments where you have clear authorization.
