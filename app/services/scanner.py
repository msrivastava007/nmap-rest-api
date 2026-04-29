from __future__ import annotations
import subprocess
import logging
import xml.etree.ElementTree as ET
from app.config import settings
from app.errors import (
    NmapNotFoundError,
    ScanTimeoutError,
    ScanExecutionError,
    ScanParseError,
)

logger = logging.getLogger(__name__)


def run_scan(target: str) -> dict:
    """
    Execute nmap against target and parse the XML output.

    Returns:
        {
            "resolved_ip": str | None,
            "ports": list[dict],
            "raw_xml": str,
        }

    Raises:
        NmapNotFoundError, ScanTimeoutError, ScanExecutionError, ScanParseError
    """
    flags = settings.NMAP_FLAGS_DEMO if settings.DEMO_MODE else settings.NMAP_FLAGS_PRODUCTION
    cmd = [settings.NMAP_PATH] + flags.split() + [target]
    logger.info("Running nmap: %s", " ".join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        raise NmapNotFoundError()

    try:
        stdout, stderr = proc.communicate(timeout=settings.NMAP_TIMEOUT_SECS)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()  # drain pipes to prevent hang
        raise ScanTimeoutError(f"Scan timed out after {settings.NMAP_TIMEOUT_SECS} seconds")
    except Exception:
        proc.kill()
        proc.communicate()
        raise

    if stderr:
        logger.info("nmap stderr: %s", stderr.strip())

    if proc.returncode != 0:
        raise ScanExecutionError(
            f"nmap exited with code {proc.returncode}: {stderr.strip()}"
        )

    return _parse_xml(stdout)


def _parse_xml(xml_str: str) -> dict:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        raise ScanParseError(f"Failed to parse nmap XML output: {e}")

    host_el = root.find("host")
    if host_el is None:
        return {"resolved_ip": None, "ports": [], "raw_xml": xml_str}

    status_el = host_el.find("status")
    if status_el is not None and status_el.get("state") != "up":
        return {"resolved_ip": None, "ports": [], "raw_xml": xml_str}

    resolved_ip = None
    for addr_el in host_el.findall("address"):
        if addr_el.get("addrtype") == "ipv4":
            resolved_ip = addr_el.get("addr")
            break
    if resolved_ip is None:
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv6":
                resolved_ip = addr_el.get("addr")
                break

    ports = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            service_name = ""
            version_str = ""
            if service_el is not None:
                service_name = service_el.get("name", "")
                product = service_el.get("product", "")
                version = service_el.get("version", "")
                parts = [p for p in (product, version) if p]
                version_str = " ".join(parts)

            ports.append({
                "port": int(port_el.get("portid")),
                "protocol": port_el.get("protocol", "tcp"),
                "state": "open",
                "service": service_name,
                "version": version_str,
            })

    return {"resolved_ip": resolved_ip, "ports": ports, "raw_xml": xml_str}
