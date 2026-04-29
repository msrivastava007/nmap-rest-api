from __future__ import annotations
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class ScanRequest(BaseModel):
    target: str


class Port(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    version: str


class ScanResponse(BaseModel):
    scan_id: str
    host: str
    resolved_ip: Optional[str]
    status: str
    started_at: datetime
    finished_at: Optional[datetime]
    duration_secs: Optional[float]
    ports: list[Port]


class ScanSummary(BaseModel):
    scan_id: str
    status: str
    started_at: datetime
    finished_at: Optional[datetime]
    duration_secs: Optional[float]
    ports: list[Port]


class ScanHistoryResponse(BaseModel):
    host: str
    total: int
    scans: list[ScanSummary]


class DiffScanRef(BaseModel):
    scan_id: str
    scanned_at: datetime
    resolved_ip: Optional[str]


class ChangedPort(BaseModel):
    port: int
    protocol: str
    previous: dict
    current: dict


class DiffDetail(BaseModel):
    opened: list[Port]
    closed: list[Port]
    changed: list[ChangedPort]
    unchanged: list[Port]


class DiffResponse(BaseModel):
    host: str
    from_scan: DiffScanRef
    to_scan: DiffScanRef
    ip_changed: bool
    diff: DiffDetail


class ErrorResponse(BaseModel):
    error: str
    code: str
    detail: Optional[str] = None
