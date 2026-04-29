from __future__ import annotations


def compute_diff(scan_a_ports: list[dict], scan_b_ports: list[dict]) -> dict:
    """
    Compute the diff between two port lists.

    scan_a = older scan (from_scan)
    scan_b = newer scan (to_scan)
    Key = (port, protocol) — 80/tcp and 80/udp are treated as distinct entries.
    """
    prev = {(p["port"], p["protocol"]): p for p in scan_a_ports}
    curr = {(p["port"], p["protocol"]): p for p in scan_b_ports}

    prev_keys = set(prev)
    curr_keys = set(curr)

    opened_keys   = curr_keys - prev_keys
    closed_keys   = prev_keys - curr_keys
    shared_keys   = prev_keys & curr_keys

    changed_keys = {
        k for k in shared_keys
        if prev[k]["version"] != curr[k]["version"]
        or prev[k]["service"] != curr[k]["service"]
    }
    unchanged_keys = shared_keys - changed_keys

    return {
        "opened": [curr[k] for k in opened_keys],
        "closed": [prev[k] for k in closed_keys],
        "changed": [
            {
                "port": k[0],
                "protocol": k[1],
                "previous": {"service": prev[k]["service"], "version": prev[k]["version"]},
                "current":  {"service": curr[k]["service"], "version": curr[k]["version"]},
            }
            for k in changed_keys
        ],
        "unchanged": [curr[k] for k in unchanged_keys],
    }
