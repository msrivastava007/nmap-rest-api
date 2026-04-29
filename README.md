# Nmap REST API

A REST API that wraps the Nmap CLI tool to initiate port scans, retrieve scan history, and diff consecutive scans to detect firewall rule changes.

---

## Requirements

- Python 3.11+
- nmap installed and available on PATH
  - macOS: `brew install nmap`
  - Ubuntu/Debian: `sudo apt install nmap`
  - Windows: https://nmap.org/download.html

---

## Setup and Run (Development)

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The service starts on http://localhost:8000.

> **Note:** uvicorn has no request-duration timeout in dev mode. `NMAP_TIMEOUT_SECS` is the only guard. This is acceptable for development only.

---

## Running in Production

```bash
pip install gunicorn
gunicorn app.main:app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers 4 \
  --timeout 70
```

Set gunicorn `--timeout` to `NMAP_TIMEOUT_SECS + 10`.

If using nginx as a reverse proxy:
```
proxy_read_timeout 75s;
```
Set to `NMAP_TIMEOUT_SECS + 15`.

> `uvicorn --timeout-keep-alive` controls idle keep-alive connections between requests. It has nothing to do with request duration — do not use it for this purpose.

---

## Docker

```bash
docker compose up
```

The API is available at http://localhost:8000. The SQLite database is persisted via a volume mount at `./nmap.db`.

---

## Environment Variables

| Variable                | Default                  | Description                                        |
|-------------------------|--------------------------|----------------------------------------------------|
| `NMAP_PATH`             | `nmap`                   | Path to nmap binary                                |
| `NMAP_FLAGS_DEMO`       | `-F --open -oX -`        | Flags used when DEMO_MODE=true (top 100 ports)     |
| `NMAP_FLAGS_PRODUCTION` | `-sV -T4 --open -oX -`   | Flags used when DEMO_MODE=false (full + version)   |
| `NMAP_TIMEOUT_SECS`     | `60`                     | Hard kill timeout for nmap subprocess              |
| `DATABASE_URL`          | `sqlite:///./nmap.db`    | SQLAlchemy database URL                            |
| `LOG_LEVEL`             | `INFO`                   | Python logging level                               |
| `MAX_HISTORY`           | `50`                     | Max scans returned per GET /scans/{host}           |
| `BLOCK_LOCALHOST`       | `true`                   | Always block loopback addresses                    |
| `BLOCK_PRIVATE_RANGES`  | `false`                  | Block RFC 1918 ranges (set true for public deploy) |
| `RAW_XML_RETENTION_DAYS`| `30`                     | Days to retain raw XML inline (demo only)          |
| `DEMO_MODE`             | `true`                   | Use fast flags; false = version detection          |

---

## API Reference

### POST /scans — Initiate a scan

```bash
curl -X POST http://localhost:8000/scans \
  -H 'Content-Type: application/json' \
  -d '{"target": "scanme.nmap.org"}'
```

**Response 200:**
```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "host": "scanme.nmap.org",
  "resolved_ip": "45.33.32.156",
  "status": "completed",
  "started_at": "2026-04-29T10:00:00Z",
  "finished_at": "2026-04-29T10:00:08Z",
  "duration_secs": 8.2,
  "ports": [
    { "port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9p1" }
  ]
}
```

**Error 400 — invalid target:**
```json
{ "error": "Target starts with a hyphen, which is not permitted", "code": "INVALID_TARGET", "detail": "--script=evil" }
```

**Error 400 — disallowed target:**
```json
{ "error": "Scanning loopback addresses is not permitted", "code": "DISALLOWED_TARGET", "detail": "127.0.0.1" }
```

---

### GET /scans/{host} — Retrieve scan history

```bash
curl http://localhost:8000/scans/scanme.nmap.org
```

**Response 200:**
```json
{
  "host": "scanme.nmap.org",
  "total": 3,
  "scans": [
    {
      "scan_id": "...",
      "status": "completed",
      "started_at": "2026-04-29T10:00:00Z",
      "finished_at": "2026-04-29T10:00:08Z",
      "duration_secs": 8.2,
      "ports": [...]
    }
  ]
}
```

`total` is the count of scans returned in this response, bounded by `MAX_HISTORY`. Results are ordered newest first.

**Error 404:**
```json
{ "error": "No scans found for host: scanme.nmap.org", "code": "NOT_FOUND", "detail": null }
```

---

### GET /scans/{host}/diff — Diff between the two most recent scans

```bash
curl http://localhost:8000/scans/scanme.nmap.org/diff
```

**Response 200:**
```json
{
  "host": "scanme.nmap.org",
  "from_scan": { "scan_id": "abc...", "scanned_at": "2026-04-28T09:00:00Z", "resolved_ip": "45.33.32.156" },
  "to_scan":   { "scan_id": "def...", "scanned_at": "2026-04-29T10:00:00Z", "resolved_ip": "45.33.32.156" },
  "ip_changed": false,
  "diff": {
    "opened":    [{ "port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.18" }],
    "closed":    [{ "port": 8080, "protocol": "tcp", "state": "open", "service": "http-proxy", "version": "" }],
    "changed":   [{ "port": 22, "protocol": "tcp", "previous": { "service": "ssh", "version": "OpenSSH 6.6.1p1" }, "current": { "service": "ssh", "version": "OpenSSH 8.9p1" } }],
    "unchanged": [{ "port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4.7" }]
  }
}
```

Only `completed` scans are used as diff candidates. A failed scan is never compared.

**Error 404:**
```json
{ "error": "Need at least 2 completed scans to diff. Found: 1", "code": "INSUFFICIENT_SCANS", "detail": null }
```

---

## Running Tests

Unit tests (no nmap required):
```bash
pytest tests/test_validator.py tests/test_diff.py tests/test_scanner.py -v
```

All tests including route tests (mocked scanner, no network required):
```bash
pytest tests/ -v
```

---

## Nmap Permissions

The service should not run as root. Without root, nmap defaults to TCP connect scan (`-sT`) rather than SYN scan (`-sS`). TCP connect scan is slower but correct for this use case.

If SYN scanning is needed without running as root:
```bash
sudo setcap cap_net_raw+ep $(which nmap)
```

---

## Assumptions and Simplifications

**Synchronous execution.** `POST /scans` blocks until nmap finishes and returns the full result. For production at scale, the design is: POST returns 202 Accepted with a `scan_id` immediately, a Celery + Redis worker pool runs nmap asynchronously, client polls `GET /scans/{scan_id}/status`. The HTTP tier and the nmap execution tier scale independently.

**SQLite for dev.** Set `DATABASE_URL=postgresql://user:pass@host/db` to switch to PostgreSQL. All queries go through SQLAlchemy ORM — no SQL changes needed.

**DEMO_MODE=true** uses `-F` (top 100 ports, ~3-8 seconds). Set `DEMO_MODE=false` for `-sV -T4` (version detection, ~15-60 seconds).

**Scans are keyed by target as provided** (after lowercasing). Scanning a hostname and its resolved IP separately produces two independent history chains. Linking them would require DNS resolution at query time. Out of scope.

**BLOCK_PRIVATE_RANGES=false by default.** This is an internal debugging tool for engineers checking firewall rules against private hosts. Blocking private ranges defeats the primary use case. Set `BLOCK_PRIVATE_RANGES=true` for public deployments.

**No authentication.** Assumes a trusted internal network. Production would add API key authentication at the gateway layer.

**raw_xml stored inline in demo.** Production: write to S3/GCS, store only the object path in the DB. Storing large blobs inline bloats row size and slows queries that scan many rows.

**Concurrent scans of the same host** are allowed in V1. Two simultaneous POST requests both complete and write valid records. In the async V2 design, a DB check or Redis lock before enqueuing prevents redundant nmap processes.

---

## What I Would Add With More Time

- Async job queue (Celery + Redis) — POST returns 202 + scan_id, client polls status
- Authentication via API keys at the API gateway layer
- Rate limiting per API key — critical when wrapping a network scanning tool
- Port range parameter on POST /scans (`?ports=1-1024`)
- Webhook callback_url on POST /scans for async notification
- Prometheus metrics endpoint at `/metrics`
- Structured JSON logging with a correlation ID per request
- raw_xml → S3/GCS with path stored in DB; lifecycle policy handles 30-day expiry
- OpenAPI docs auto-generated by FastAPI at `/docs` (already enabled by default)
- Pagination on GET /scans/{host} with `?page=` and `?limit=` params
