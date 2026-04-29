import subprocess
import pytest
from unittest.mock import patch, MagicMock
from app.services.scanner import run_scan
from app.errors import (
    NmapNotFoundError, ScanTimeoutError, ScanExecutionError, ScanParseError
)

VALID_XML_WITH_PORTS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.7"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

XML_HOST_DOWN = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
  </host>
</nmaprun>"""

XML_NO_HOST = """<?xml version="1.0"?>
<nmaprun>
</nmaprun>"""

MALFORMED_XML = "not xml at all <<<"


def _mock_popen(stdout="", stderr="", returncode=0, raise_on_communicate=None):
    proc = MagicMock()
    proc.returncode = returncode
    if raise_on_communicate:
        proc.communicate.side_effect = raise_on_communicate
    else:
        proc.communicate.return_value = (stdout, stderr)
    return proc


def test_successful_scan_returns_ports():
    proc = _mock_popen(stdout=VALID_XML_WITH_PORTS)
    with patch("subprocess.Popen", return_value=proc):
        result = run_scan("scanme.nmap.org")

    assert result["resolved_ip"] == "45.33.32.156"
    assert len(result["ports"]) == 2
    assert result["ports"][0]["port"] == 22
    assert result["ports"][0]["service"] == "ssh"
    assert result["ports"][0]["version"] == "OpenSSH 8.9p1"
    assert result["ports"][1]["port"] == 80


def test_nonzero_returncode_raises_execution_error():
    proc = _mock_popen(stdout="", stderr="Permission denied", returncode=1)
    with patch("subprocess.Popen", return_value=proc):
        with pytest.raises(ScanExecutionError) as exc_info:
            run_scan("example.com")
    assert "Permission denied" in exc_info.value.message


def test_timeout_kills_process_and_raises():
    proc = MagicMock()
    # First communicate() raises TimeoutExpired; second (drain after kill) succeeds
    proc.communicate.side_effect = [
        subprocess.TimeoutExpired(cmd="nmap", timeout=60),
        ("", ""),
    ]
    with patch("subprocess.Popen", return_value=proc):
        with pytest.raises(ScanTimeoutError):
            run_scan("example.com")
    proc.kill.assert_called_once()
    assert proc.communicate.call_count == 2  # first call + drain after kill


def test_file_not_found_raises_nmap_not_found():
    with patch("subprocess.Popen", side_effect=FileNotFoundError):
        with pytest.raises(NmapNotFoundError):
            run_scan("example.com")


def test_malformed_xml_raises_parse_error():
    proc = _mock_popen(stdout=MALFORMED_XML, returncode=0)
    with patch("subprocess.Popen", return_value=proc):
        with pytest.raises(ScanParseError):
            run_scan("example.com")


def test_host_down_returns_empty_ports_not_error():
    proc = _mock_popen(stdout=XML_HOST_DOWN, returncode=0)
    with patch("subprocess.Popen", return_value=proc):
        result = run_scan("example.com")
    assert result["ports"] == []
    assert result["resolved_ip"] is None


def test_no_host_element_returns_empty_ports():
    proc = _mock_popen(stdout=XML_NO_HOST, returncode=0)
    with patch("subprocess.Popen", return_value=proc):
        result = run_scan("example.com")
    assert result["ports"] == []
    assert result["resolved_ip"] is None


def test_port_with_no_service_info():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="9999">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    proc = _mock_popen(stdout=xml, returncode=0)
    with patch("subprocess.Popen", return_value=proc):
        result = run_scan("1.2.3.4")
    assert len(result["ports"]) == 1
    assert result["ports"][0]["service"] == ""
    assert result["ports"][0]["version"] == ""
