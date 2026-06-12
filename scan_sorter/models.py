from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class FileStatus(enum.Enum):
    PENDING = "pending"
    PARSED = "parsed"
    PRECHECK_OK = "precheck_ok"
    PRECHECK_FAIL = "precheck_fail"
    PROCESSING = "processing"
    DONE = "done"
    ERROR = "error"
    ROLLED_BACK = "rolled_back"


class ActionType(enum.Enum):
    MOVE = "move"
    COPY = "copy"


class BatchStatus(enum.Enum):
    OPEN = "open"
    COMPLETED = "completed"
    PARTIAL_FAILED = "partial_failed"
    ROLLED_BACK = "rolled_back"


class PlanAction(enum.Enum):
    ARCHIVE = "archive"
    SKIP_ERROR_QUEUE = "skip_error_queue"
    SKIP_QUEUE = "skip_queue"
    FAIL_PRECHECK = "fail_precheck"
    FAIL_TARGET_CONFLICT = "fail_target_conflict"
    FAIL_DUPLICATE = "fail_duplicate"


@dataclass
class ScanFile:
    path: str
    filename: str
    case_number: Optional[str] = None
    status: FileStatus = FileStatus.PENDING
    error_message: Optional[str] = None
    target_dir: Optional[str] = None
    target_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "filename": self.filename,
            "case_number": self.case_number,
            "status": self.status.value,
            "error_message": self.error_message,
            "target_dir": self.target_dir,
            "target_path": self.target_path,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ScanFile:
        return cls(
            path=d["path"],
            filename=d["filename"],
            case_number=d.get("case_number"),
            status=FileStatus(d.get("status", "pending")),
            error_message=d.get("error_message"),
            target_dir=d.get("target_dir"),
            target_path=d.get("target_path"),
        )


@dataclass
class ActionRecord:
    action_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    batch_id: str = ""
    source: str = ""
    destination: str = ""
    action_type: ActionType = ActionType.MOVE
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    operator: str = ""
    rolled_back: bool = False
    case_number: str = ""

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "batch_id": self.batch_id,
            "source": self.source,
            "destination": self.destination,
            "action_type": self.action_type.value,
            "timestamp": self.timestamp,
            "operator": self.operator,
            "rolled_back": self.rolled_back,
            "case_number": self.case_number,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ActionRecord:
        return cls(
            action_id=d.get("action_id", uuid.uuid4().hex[:12]),
            batch_id=d.get("batch_id", ""),
            source=d.get("source", ""),
            destination=d.get("destination", ""),
            action_type=ActionType(d.get("action_type", "move")),
            timestamp=d.get("timestamp", datetime.now().isoformat()),
            operator=d.get("operator", ""),
            rolled_back=d.get("rolled_back", False),
            case_number=d.get("case_number", ""),
        )


@dataclass
class BatchRecord:
    batch_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    operator: str = ""
    status: BatchStatus = BatchStatus.OPEN
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    action_ids: list = field(default_factory=list)
    error_file_paths: list = field(default_factory=list)
    error_details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "batch_id": self.batch_id,
            "created_at": self.created_at,
            "operator": self.operator,
            "status": self.status.value,
            "total": self.total,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "action_ids": self.action_ids,
            "error_file_paths": self.error_file_paths,
            "error_details": self.error_details,
        }

    @classmethod
    def from_dict(cls, d: dict) -> BatchRecord:
        return cls(
            batch_id=d.get("batch_id", uuid.uuid4().hex[:8]),
            created_at=d.get("created_at", datetime.now().isoformat()),
            operator=d.get("operator", ""),
            status=BatchStatus(d.get("status", "open")),
            total=d.get("total", 0),
            succeeded=d.get("succeeded", 0),
            failed=d.get("failed", 0),
            action_ids=d.get("action_ids", []),
            error_file_paths=d.get("error_file_paths", []),
            error_details=d.get("error_details", {}),
        )


@dataclass
class ErrorItem:
    path: str
    filename: str
    case_number: Optional[str]
    error: str
    retry_count: int = 0
    max_retries: int = 3
    added_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_retry_at: Optional[str] = None
    batch_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "filename": self.filename,
            "case_number": self.case_number,
            "error": self.error,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "added_at": self.added_at,
            "last_retry_at": self.last_retry_at,
            "batch_id": self.batch_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ErrorItem:
        return cls(
            path=d["path"],
            filename=d["filename"],
            case_number=d.get("case_number"),
            error=d["error"],
            retry_count=d.get("retry_count", 0),
            max_retries=d.get("max_retries", 3),
            added_at=d.get("added_at", datetime.now().isoformat()),
            last_retry_at=d.get("last_retry_at"),
            batch_id=d.get("batch_id"),
        )


@dataclass
class PrecheckResult:
    filename: str
    path: str
    ok: bool
    errors: list = field(default_factory=list)
    case_number: Optional[str] = None
    target_dir: Optional[str] = None
    target_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "path": self.path,
            "ok": self.ok,
            "errors": self.errors,
            "case_number": self.case_number,
            "target_dir": self.target_dir,
            "target_path": self.target_path,
        }


@dataclass
class DryRunPlanItem:
    filename: str
    path: str
    case_number: Optional[str] = None
    target_dir: Optional[str] = None
    target_path: Optional[str] = None
    action: PlanAction = PlanAction.ARCHIVE
    will_succeed: bool = True
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    in_processing_queue: bool = False
    in_error_queue: bool = False
    target_exists: bool = False
    action_type: str = "move"

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "path": self.path,
            "case_number": self.case_number,
            "target_dir": self.target_dir,
            "target_path": self.target_path,
            "action": self.action.value,
            "will_succeed": self.will_succeed,
            "errors": self.errors,
            "warnings": self.warnings,
            "in_processing_queue": self.in_processing_queue,
            "in_error_queue": self.in_error_queue,
            "target_exists": self.target_exists,
            "action_type": self.action_type,
        }


@dataclass
class DryRunResult:
    items: list = field(default_factory=list)
    total: int = 0
    will_succeed: int = 0
    will_fail: int = 0
    warnings: int = 0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "will_succeed": self.will_succeed,
            "will_fail": self.will_fail,
            "warnings": self.warnings,
            "items": [item.to_dict() for item in self.items],
        }


class SkipReason(enum.Enum):
    SOURCE_MISSING = "source_missing"
    TARGET_EXISTS = "target_exists"
    IN_PROCESSING_QUEUE = "in_processing_queue"
    DUPLICATE_IN_ERROR_QUEUE = "duplicate_in_error_queue"
    MAX_RETRIES_EXCEEDED = "max_retries_exceeded"
    PARSE_FAILED = "parse_failed"
    PRECHECK_FAILED = "precheck_failed"


class RetryStatus(enum.Enum):
    RETRYABLE = "retryable"
    SKIPPED = "skipped"
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class RetryPlanItem:
    path: str
    filename: str
    case_number: Optional[str] = None
    original_error: str = ""
    original_batch_id: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    added_at: str = ""
    last_retry_at: Optional[str] = None
    new_target_dir: Optional[str] = None
    new_target_path: Optional[str] = None
    expected_action: str = ""
    status: RetryStatus = RetryStatus.PENDING
    skip_reason: Optional[SkipReason] = None
    skip_detail: str = ""
    parse_errors: list = field(default_factory=list)
    precheck_errors: list = field(default_factory=list)
    target_exists: bool = False
    source_missing: bool = False
    in_processing_queue: bool = False
    duplicate_in_error_queue: bool = False
    action_type: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "filename": self.filename,
            "case_number": self.case_number,
            "original_error": self.original_error,
            "original_batch_id": self.original_batch_id,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "added_at": self.added_at,
            "last_retry_at": self.last_retry_at,
            "new_target_dir": self.new_target_dir,
            "new_target_path": self.new_target_path,
            "expected_action": self.expected_action,
            "status": self.status.value,
            "skip_reason": self.skip_reason.value if self.skip_reason else None,
            "skip_detail": self.skip_detail,
            "parse_errors": self.parse_errors,
            "precheck_errors": self.precheck_errors,
            "target_exists": self.target_exists,
            "source_missing": self.source_missing,
            "in_processing_queue": self.in_processing_queue,
            "duplicate_in_error_queue": self.duplicate_in_error_queue,
            "action_type": self.action_type,
        }


@dataclass
class RetryPlanResult:
    items: list = field(default_factory=list)
    total: int = 0
    retryable: int = 0
    skipped: int = 0
    retryable_items: list = field(default_factory=list)
    skipped_items: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "retryable": self.retryable,
            "skipped": self.skipped,
            "retryable_items": [item.to_dict() for item in self.retryable_items],
            "skipped_items": [item.to_dict() for item in self.skipped_items],
            "items": [item.to_dict() for item in self.items],
        }


@dataclass
class RetryExecutionItem:
    path: str
    filename: str
    case_number: Optional[str] = None
    status: RetryStatus = RetryStatus.PENDING
    error: str = ""
    action_id: str = ""
    batch_id: str = ""
    source: str = ""
    destination: str = ""
    action_type: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "filename": self.filename,
            "case_number": self.case_number,
            "status": self.status.value,
            "error": self.error,
            "action_id": self.action_id,
            "batch_id": self.batch_id,
            "source": self.source,
            "destination": self.destination,
            "action_type": self.action_type,
            "timestamp": self.timestamp,
        }


@dataclass
class RetryExecutionResult:
    items: list = field(default_factory=list)
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    batch_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "skipped": self.skipped,
            "batch_id": self.batch_id,
            "timestamp": self.timestamp,
            "items": [item.to_dict() for item in self.items],
        }
