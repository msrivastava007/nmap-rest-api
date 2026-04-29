from app.services.diff import compute_diff


def _port(port, protocol="tcp", service="ssh", version="1.0"):
    return {"port": port, "protocol": protocol, "state": "open",
            "service": service, "version": version}


def test_both_empty():
    result = compute_diff([], [])
    assert result["opened"] == []
    assert result["closed"] == []
    assert result["changed"] == []
    assert result["unchanged"] == []


def test_identical_scans():
    ports = [_port(22), _port(80, service="http", version="2.0")]
    result = compute_diff(ports, ports)
    assert len(result["unchanged"]) == 2
    assert result["opened"] == []
    assert result["closed"] == []
    assert result["changed"] == []


def test_port_only_in_newer_scan():
    result = compute_diff([], [_port(443)])
    assert len(result["opened"]) == 1
    assert result["opened"][0]["port"] == 443
    assert result["closed"] == []


def test_port_only_in_older_scan():
    result = compute_diff([_port(8080)], [])
    assert len(result["closed"]) == 1
    assert result["closed"][0]["port"] == 8080
    assert result["opened"] == []


def test_version_change_triggers_changed():
    old = [_port(22, version="OpenSSH 6.6.1p1")]
    new = [_port(22, version="OpenSSH 8.9p1")]
    result = compute_diff(old, new)
    assert len(result["changed"]) == 1
    assert result["changed"][0]["previous"]["version"] == "OpenSSH 6.6.1p1"
    assert result["changed"][0]["current"]["version"] == "OpenSSH 8.9p1"
    assert result["unchanged"] == []


def test_service_change_triggers_changed():
    old = [_port(80, service="http")]
    new = [_port(80, service="https")]
    result = compute_diff(old, new)
    assert len(result["changed"]) == 1
    assert result["changed"][0]["previous"]["service"] == "http"
    assert result["changed"][0]["current"]["service"] == "https"


def test_identical_port_is_unchanged():
    p = _port(22, version="OpenSSH 8.9p1")
    result = compute_diff([p], [p])
    assert len(result["unchanged"]) == 1
    assert result["changed"] == []


def test_scan_a_empty_scan_b_populated():
    ports = [_port(22), _port(80, service="http")]
    result = compute_diff([], ports)
    assert len(result["opened"]) == 2
    assert result["closed"] == []
    assert result["unchanged"] == []


def test_scan_a_populated_scan_b_empty():
    ports = [_port(22), _port(80, service="http")]
    result = compute_diff(ports, [])
    assert len(result["closed"]) == 2
    assert result["opened"] == []
    assert result["unchanged"] == []


def test_tcp_and_udp_same_port_are_distinct():
    old = [_port(80, protocol="tcp"), _port(80, protocol="udp")]
    new = [_port(80, protocol="tcp")]
    result = compute_diff(old, new)
    assert len(result["closed"]) == 1
    assert result["closed"][0]["protocol"] == "udp"
    assert len(result["unchanged"]) == 1
    assert result["unchanged"][0]["protocol"] == "tcp"


def test_empty_version_vs_non_empty_triggers_changed():
    old = [_port(22, version="")]
    new = [_port(22, version="1.0")]
    result = compute_diff(old, new)
    assert len(result["changed"]) == 1


def test_changed_entry_has_correct_port_and_protocol():
    old = [_port(443, protocol="tcp", version="old")]
    new = [_port(443, protocol="tcp", version="new")]
    result = compute_diff(old, new)
    assert result["changed"][0]["port"] == 443
    assert result["changed"][0]["protocol"] == "tcp"
