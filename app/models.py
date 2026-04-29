import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, Text, DateTime, Float, Index
from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id            = Column(Text, primary_key=True, default=lambda: str(uuid.uuid4()))
    host          = Column(Text, nullable=False)
    resolved_ip   = Column(Text, nullable=True)
    status        = Column(Text, nullable=False)
    started_at    = Column(DateTime(timezone=True), nullable=False,
                           default=lambda: datetime.now(timezone.utc))
    finished_at   = Column(DateTime(timezone=True), nullable=True)
    duration_secs = Column(Float, nullable=True)
    ports         = Column(Text, nullable=True)
    raw_xml       = Column(Text, nullable=True)
    raw_xml_path  = Column(Text, nullable=True)
    error_msg     = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_host_time", "host", "started_at"),
    )
