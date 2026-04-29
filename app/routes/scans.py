from __future__ import annotations
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan
from app.schemas import (
    ScanRequest, ScanResponse, ScanSummary, ScanHistoryResponse,
    DiffResponse, DiffScanRef, DiffDetail, Port, ChangedPort,
)
from app.errors import (
    NotFoundError, InsufficientScansError,
    ScanTimeoutError, ScanExecutionError, ScanParseError, NmapNotFoundError,
)
from app.services.validator import validate_target, validate_target_structural
from app.services.scanner import run_scan
from app.services.diff import compute_diff
from app.config import settings

router = APIRouter()


def _ports_from_db(ports_json: str | None) -> list[dict]:
    if not ports_json:
        return []
    return json.loads(ports_json)


def _as_utc(dt: datetime | None) -> datetime | None:
    """SQLite strips timezone info on read-back; re-attach UTC so serialisation includes Z."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _scan_to_response(scan: Scan) -> ScanResponse:
    ports = [Port(**p) for p in _ports_from_db(scan.ports)]
    return ScanResponse(
        scan_id=scan.id,
        host=scan.host,
        resolved_ip=scan.resolved_ip,
        status=scan.status,
        started_at=_as_utc(scan.started_at),
        finished_at=_as_utc(scan.finished_at),
        duration_secs=scan.duration_secs,
        ports=ports,
    )


@router.post("/scans", response_model=ScanResponse)
def initiate_scan(body: ScanRequest, db: Session = Depends(get_db)):
    target = validate_target(body.target)

    started_at = datetime.now(timezone.utc)
    scan = Scan(
        host=target,
        status="running",
        started_at=started_at,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        result = run_scan(target)
    except (ScanTimeoutError, ScanExecutionError, ScanParseError, NmapNotFoundError) as e:
        scan.status = "failed"
        scan.finished_at = datetime.now(timezone.utc)
        scan.error_msg = e.message if hasattr(e, "message") else str(e)
        db.commit()
        if isinstance(e, ScanTimeoutError):
            raise ScanTimeoutError(e.message, scan_id=scan.id)
        raise

    now = datetime.now(timezone.utc)
    scan.status = "completed"
    scan.resolved_ip = result["resolved_ip"]
    scan.ports = json.dumps(result["ports"])
    scan.raw_xml = result["raw_xml"]
    scan.finished_at = now
    scan.duration_secs = (now - started_at).total_seconds()
    db.commit()
    db.refresh(scan)

    return _scan_to_response(scan)


@router.get("/scans/{host}", response_model=ScanHistoryResponse)
def get_scan_history(host: str, db: Session = Depends(get_db)):
    normalised = validate_target_structural(host)

    results = (
        db.query(Scan)
        .filter(Scan.host == normalised)
        .order_by(Scan.started_at.desc())
        .limit(settings.MAX_HISTORY)
        .all()
    )

    if not results:
        raise NotFoundError(f"No scans found for host: {normalised}")

    scans = [
        ScanSummary(
            scan_id=s.id,
            status=s.status,
            started_at=_as_utc(s.started_at),
            finished_at=_as_utc(s.finished_at),
            duration_secs=s.duration_secs,
            ports=[Port(**p) for p in _ports_from_db(s.ports)],
        )
        for s in results
    ]

    return ScanHistoryResponse(host=normalised, total=len(scans), scans=scans)


@router.get("/scans/{host}/diff", response_model=DiffResponse)
def get_scan_diff(host: str, db: Session = Depends(get_db)):
    normalised = validate_target_structural(host)

    results = (
        db.query(Scan)
        .filter(Scan.host == normalised, Scan.status == "completed")
        .order_by(Scan.started_at.desc())
        .limit(2)
        .all()
    )

    if len(results) < 2:
        raise InsufficientScansError(
            f"Need at least 2 completed scans to diff. Found: {len(results)}"
        )

    to_scan   = results[0]
    from_scan = results[1]

    diff_data = compute_diff(
        _ports_from_db(from_scan.ports),
        _ports_from_db(to_scan.ports),
    )

    return DiffResponse(
        host=normalised,
        from_scan=DiffScanRef(
            scan_id=from_scan.id,
            scanned_at=_as_utc(from_scan.started_at),
            resolved_ip=from_scan.resolved_ip,
        ),
        to_scan=DiffScanRef(
            scan_id=to_scan.id,
            scanned_at=_as_utc(to_scan.started_at),
            resolved_ip=to_scan.resolved_ip,
        ),
        ip_changed=from_scan.resolved_ip != to_scan.resolved_ip,
        diff=DiffDetail(
            opened=[Port(**p) for p in diff_data["opened"]],
            closed=[Port(**p) for p in diff_data["closed"]],
            changed=[ChangedPort(**p) for p in diff_data["changed"]],
            unchanged=[Port(**p) for p in diff_data["unchanged"]],
        ),
    )
