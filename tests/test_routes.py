"""
Integration tests — require nmap installed and network access to scanme.nmap.org.
Run with: pytest tests/test_routes.py -v

Unit-style route tests (mocked scanner) are included to allow CI without nmap.
"""
import json
import pytest
from unittest.mock import patch
from app.models import Scan
from datetime import datetime, timezone


MOCK_RESULT = {
    "resolved_ip": "45.33.32.156",
    "ports": [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9p1"},
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4"},
    ],
    "raw_xml": "<nmaprun/>",
}

MOCK_RESULT_2 = {
    "resolved_ip": "45.33.32.156",
    "ports": [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 9.0"},
        {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.18"},
    ],
    "raw_xml": "<nmaprun/>",
}


# --- POST /scans ---

def test_post_valid_target_returns_200(client):
    with patch("app.routes.scans.run_scan", return_value=MOCK_RESULT):
        resp = client.post("/scans", json={"target": "scanme.nmap.org"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["host"] == "scanme.nmap.org"
    assert len(body["ports"]) == 2
    assert body["resolved_ip"] == "45.33.32.156"
    assert body["scan_id"]


def test_post_invalid_target_hyphen(client):
    resp = client.post("/scans", json={"target": "--script=evil"})
    assert resp.status_code == 400
    body = resp.json()
    assert body["code"] == "INVALID_TARGET"


def test_post_invalid_target_url_scheme(client):
    resp = client.post("/scans", json={"target": "http://example.com"})
    assert resp.status_code == 400
    assert resp.json()["code"] == "INVALID_TARGET"


def test_post_localhost_disallowed(client):
    resp = client.post("/scans", json={"target": "127.0.0.1"})
    assert resp.status_code == 400
    assert resp.json()["code"] == "DISALLOWED_TARGET"


def test_post_loopback_string_disallowed(client):
    resp = client.post("/scans", json={"target": "localhost"})
    assert resp.status_code == 400
    assert resp.json()["code"] == "DISALLOWED_TARGET"


def test_post_ipv6_loopback_disallowed(client):
    resp = client.post("/scans", json={"target": "::1"})
    assert resp.status_code == 400
    assert resp.json()["code"] == "DISALLOWED_TARGET"


def test_post_result_has_z_suffix_in_timestamps(client):
    with patch("app.routes.scans.run_scan", return_value=MOCK_RESULT):
        resp = client.post("/scans", json={"target": "scanme.nmap.org"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["started_at"].endswith("Z") or "+" in body["started_at"]


def test_post_missing_body_returns_uniform_error(client):
    resp = client.post("/scans", json={})
    assert resp.status_code == 422
    body = resp.json()
    assert "code" in body
    assert body["code"] == "VALIDATION_ERROR"
    assert "error" in body


def test_post_wrong_content_type_returns_uniform_error(client):
    resp = client.post("/scans", content="not json", headers={"Content-Type": "text/plain"})
    assert resp.status_code in (422, 400)
    body = resp.json()
    assert "code" in body


# --- GET /scans/{host} ---

def test_get_history_returns_scans_newest_first(client):
    host = "history-test.example.com"
    with patch("app.routes.scans.run_scan", return_value=MOCK_RESULT):
        client.post("/scans", json={"target": host})
    with patch("app.routes.scans.run_scan", return_value=MOCK_RESULT_2):
        client.post("/scans", json={"target": host})

    resp = client.get(f"/scans/{host}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["host"] == host
    assert body["total"] == 2
    assert len(body["scans"]) == 2
    # newest first — second POST happened after first, so results[0] is newer
    assert body["scans"][0]["started_at"] >= body["scans"][1]["started_at"]


def test_get_history_unknown_host_returns_404(client):
    resp = client.get("/scans/no-such-host-xyz.example.com")
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"


def test_get_history_invalid_host_returns_400(client):
    resp = client.get("/scans/--badhost")
    assert resp.status_code == 400
    assert resp.json()["code"] == "INVALID_TARGET"


# --- GET /scans/{host}/diff ---

def test_diff_two_completed_scans(client):
    host = "diff-test.example.com"
    with patch("app.routes.scans.run_scan", return_value=MOCK_RESULT):
        client.post("/scans", json={"target": host})
    with patch("app.routes.scans.run_scan", return_value=MOCK_RESULT_2):
        client.post("/scans", json={"target": host})

    resp = client.get(f"/scans/{host}/diff")
    assert resp.status_code == 200
    body = resp.json()
    assert body["host"] == host
    assert "diff" in body
    diff = body["diff"]
    assert "opened" in diff
    assert "closed" in diff
    assert "changed" in diff
    assert "unchanged" in diff
    # port 443 opened, port 80 closed, port 22 changed (version bump)
    opened_ports = [p["port"] for p in diff["opened"]]
    closed_ports = [p["port"] for p in diff["closed"]]
    assert 443 in opened_ports
    assert 80 in closed_ports


def test_diff_insufficient_scans_returns_404(client):
    host = "single-scan.example.com"
    with patch("app.routes.scans.run_scan", return_value=MOCK_RESULT):
        client.post("/scans", json={"target": host})

    resp = client.get(f"/scans/{host}/diff")
    assert resp.status_code == 404
    assert resp.json()["code"] == "INSUFFICIENT_SCANS"


def test_diff_unknown_host_returns_404(client):
    resp = client.get("/scans/nonexistent-diff-host.example.com/diff")
    assert resp.status_code == 404
    assert resp.json()["code"] == "INSUFFICIENT_SCANS"


def test_failed_scan_not_used_as_diff_candidate(client, db_session):
    """
    Critical: a failed scan with empty ports must NOT be used as a diff candidate.
    If it were, it would incorrectly report all previously open ports as closed.
    """
    from app.errors import ScanExecutionError

    host = "diff-failure-test.example.com"

    # First scan succeeds
    with patch("app.routes.scans.run_scan", return_value=MOCK_RESULT):
        r1 = client.post("/scans", json={"target": host})
    assert r1.status_code == 200

    # Second scan fails
    with patch("app.routes.scans.run_scan", side_effect=ScanExecutionError("nmap failed")):
        r2 = client.post("/scans", json={"target": host})
    assert r2.status_code == 500

    # Diff should return 404 INSUFFICIENT_SCANS, not use the failed scan
    resp = client.get(f"/scans/{host}/diff")
    assert resp.status_code == 404
    assert resp.json()["code"] == "INSUFFICIENT_SCANS"
