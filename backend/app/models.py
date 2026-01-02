from sqlalchemy import String, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime, timezone
from .db import Base
from sqlalchemy import String, DateTime, Text, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime, timezone
from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import Integer
from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB


class Scan(Base):
    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    workspace_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

# 추가
class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    scan_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tool: Mapped[str] = mapped_column(String(32), nullable=False, default="semgrep")

    rule_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)

    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    start_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)

    raw_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    normalized_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

class LLMAnswer(Base):
    __tablename__ = "llm_answers"
    __table_args__ = (
        UniqueConstraint("scan_id", "group_id", name="uq_llm_answers_scan_group"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    scan_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    group_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)

    model: Mapped[str] = mapped_column(String(128), nullable=False)   # ex) "llama3.1:8b"
    prompt: Mapped[str] = mapped_column(Text, nullable=False)

    # 파싱 성공 시 JSON 저장 / 실패 시 원문 저장
    response_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    response_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="done")
    # done / failed_parse / failed_call

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
