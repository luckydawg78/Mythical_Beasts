from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from pathlib import Path

from utils.logger import log


DEFAULT_RESULTS_ROOT = Path("reports") / "results"
FALLBACK_RESULTS_ROOT = Path("results")


def parse_scancannon_results(results_hint: str | Path | None = None) -> list[dict]:
    """
    Walk the ScanCannon results tree and extract hosts/services from every Nmap XML file.

    `results_hint` may point to the HTML report, the results directory itself,
    or be omitted (in which case we fall back to SCANCANNON_RESULTS_DIR or defaults).
    """
    root = _resolve_results_root(results_hint)
    if root is None:
        return []

    xml_files = _find_nmap_xml_files(root)
    if not xml_files:
        log("warning", f"No Nmap XML files found under {root}")
        return []

    aggregated: dict[str, dict] = {}
    for xml_file in xml_files:
        for host in _parse_nmap_xml_file(xml_file):
            ip_addr = host["ip"]
            record = aggregated.setdefault(
                ip_addr,
                {
                    "ip": ip_addr,
                    "hostnames": set(),
                    "services": set(),
                    "ports": [],
                    "sources": set(),
                },
            )
            record["hostnames"].update(host["hostnames"])
            record["services"].update(host["services"])
            record["ports"].extend(host["ports"])
            record["sources"].add(host["source"])

    normalized = [
        {
            "ip": info["ip"],
            "hostnames": sorted(info["hostnames"]),
            "services": sorted(info["services"]),
            "ports": info["ports"],
            "sources": sorted(info["sources"]),
        }
        for info in aggregated.values()
    ]

    log(
        "info",
        f"Extracted {len(normalized)} target(s) from {len(xml_files)} Nmap XML "
        f"file(s) under {root}",
    )
    return normalized


def parse_html(scan_output: str | Path | None = None) -> list[dict]:
    """
    Backwards-compatible entry point used by main.py.

    Delegates to parse_scancannon_results so existing imports continue working.
    """
    return parse_scancannon_results(scan_output)


def _resolve_results_root(results_hint: str | Path | None) -> Path | None:
    """
    Determine which on-disk directory holds the ScanCannon results tree.
    """
    search_candidates: list[Path] = []

    env_dir = os.environ.get("SCANCANNON_RESULTS_DIR")
    if env_dir:
        search_candidates.append(Path(env_dir).expanduser())

    if results_hint:
        hint_path = Path(results_hint).expanduser()
        if hint_path.is_dir():
            search_candidates.append(hint_path)
        elif hint_path.is_file():
            search_candidates.append(hint_path.parent / "results")
            search_candidates.append(hint_path.parent / "reports" / "results")

    search_candidates.append(DEFAULT_RESULTS_ROOT)
    search_candidates.append(FALLBACK_RESULTS_ROOT)

    seen: set[Path] = set()
    tried: list[str] = []
    for candidate in search_candidates:
        candidate = candidate.resolve()
        if candidate in seen:
            continue
        seen.add(candidate)
        tried.append(str(candidate))
        if candidate.exists() and candidate.is_dir():
            log("info", f"Using ScanCannon results directory: {candidate}")
            return candidate

    log(
        "warning",
        "Unable to locate a ScanCannon results directory. "
        f"Tried: {', '.join(tried)}",
    )
    return None


def _find_nmap_xml_files(results_root: Path) -> list[Path]:
    """
    Collect every XML file inside any nmap_xml_files directory.
    """
    xml_files = sorted(results_root.rglob("nmap_xml_files/*.xml"))
    if not xml_files:
        # Fallback: pick up any XML in case the directory structure differs slightly.
        xml_files = sorted(results_root.rglob("*.xml"))
    return xml_files


def _parse_nmap_xml_file(xml_file: Path) -> list[dict]:
    hosts: list[dict] = []
    try:
        tree = ET.parse(xml_file)
    except ET.ParseError as exc:
        log("warning", f"Could not parse {xml_file}: {exc}")
        return hosts

    root = tree.getroot()
    for host in root.findall("host"):
        status_el = host.find("status")
        state = status_el.get("state") if status_el is not None else "up"
        if state and state.lower() != "up":
            continue

        ip_addr = _extract_host_ip(host)
        if not ip_addr:
            continue

        hostnames = _extract_hostnames(host)
        services, ports = _extract_services(host)
        if not ports:
            continue

        hosts.append(
            {
                "ip": ip_addr,
                "hostnames": hostnames,
                "services": services,
                "ports": ports,
                "source": str(xml_file),
            }
        )
    return hosts


def _extract_host_ip(host_el: ET.Element) -> str | None:
    address_elements = host_el.findall("address")
    ipv4 = next(
        (addr.get("addr") for addr in address_elements if addr.get("addrtype") == "ipv4"),
        None,
    )
    if ipv4:
        return ipv4
    return next(
        (addr.get("addr") for addr in address_elements if addr.get("addrtype") == "ipv6"),
        None,
    )


def _extract_hostnames(host_el: ET.Element) -> list[str]:
    hostnames = []
    for hostname in host_el.findall("./hostnames/hostname"):
        name = hostname.get("name")
        if name:
            hostnames.append(name)
    return hostnames


def _extract_services(host_el: ET.Element) -> tuple[list[str], list[dict]]:
    services = []
    ports: list[dict] = []

    for port_el in host_el.findall("./ports/port"):
        port_state_el = port_el.find("state")
        port_state = port_state_el.get("state") if port_state_el is not None else "open"
        if port_state.lower() != "open":
            continue

        port_id = port_el.get("portid")
        protocol = port_el.get("protocol", "tcp")
        if not port_id:
            continue

        service_el = port_el.find("service")
        service_name = (service_el.get("name") if service_el is not None else None) or ""
        normalized_service = service_name.lower() if service_name else f"{protocol}/{port_id}"

        services.append(normalized_service)

        product = service_el.get("product") if service_el is not None else None
        version = service_el.get("version") if service_el is not None else None
        extrainfo = service_el.get("extrainfo") if service_el is not None else None

        try:
            port_number: int | str = int(port_id)
        except ValueError:
            port_number = port_id

        ports.append(
            {
                "port": port_number,
                "protocol": protocol,
                "state": port_state,
                "service": normalized_service,
                "service_name": service_name or None,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
            }
        )

    return services, ports
