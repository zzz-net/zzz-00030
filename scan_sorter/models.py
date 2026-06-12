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


class HandoffStatus(enum.Enum):
    PENDING = "pending"
    CREATING = "creating"
    CREATED = "created"
    FAILED = "failed"
    VERIFIED = "verified"
    IMPORTING = "importing"
    IMPORTED = "imported"
    PARTIAL_IMPORTED = "partial_imported"
    ROLLED_BACK = "rolled_back"


class ConflictType(enum.Enum):
    FILE_MISSING = "file_missing"
    CONTENT_TAMPERED = "content_tampered"
    DUPLICATE_CASE = "duplicate_case"
    TARGET_OCCUPIED = "target_occupied"
    DUPLICATE_PACKAGE = "duplicate_package"
    PARTIAL_IMPORT = "partial_import"
    CONFIG_MISMATCH = "config_mismatch"


@dataclass
class HandoffFileItem:
    original_path: str
    relative_path: str
    filename: str
    case_number: str
    batch_id: str
    size: int
    sha256: str
    source_destination: str = ""

    def to_dict(self) -> dict:
        return {
            "original_path": self.original_path,
            "relative_path": self.relative_path,
            "filename": self.filename,
            "case_number": self.case_number,
            "batch_id": self.batch_id,
            "size": self.size,
            "sha256": self.sha256,
            "source_destination": self.source_destination,
        }

    @classmethod
    def from_dict(cls, d: dict) -> HandoffFileItem:
        return cls(
            original_path=d.get("original_path", ""),
            relative_path=d.get("relative_path", ""),
            filename=d.get("filename", ""),
            case_number=d.get("case_number", ""),
            batch_id=d.get("batch_id", ""),
            size=d.get("size", 0),
            sha256=d.get("sha256", ""),
            source_destination=d.get("source_destination", ""),
        )


@dataclass
class HandoffManifest:
    package_id: str = field(default_factory=lambda: "HPK-" + uuid.uuid4().hex[:12].upper())
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    source_operator: str = ""
    source_host: str = ""
    source_config_summary: dict = field(default_factory=dict)
    case_numbers: list = field(default_factory=list)
    batch_ids: list = field(default_factory=list)
    files: list = field(default_factory=list)
    total_files: int = 0
    total_size: int = 0
    version: str = "1.0"
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "package_id": self.package_id,
            "created_at": self.created_at,
            "source_operator": self.source_operator,
            "source_host": self.source_host,
            "source_config_summary": self.source_config_summary,
            "case_numbers": self.case_numbers,
            "batch_ids": self.batch_ids,
            "files": [f.to_dict() for f in self.files],
            "total_files": self.total_files,
            "total_size": self.total_size,
            "version": self.version,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: dict) -> HandoffManifest:
        return cls(
            package_id=d.get("package_id", ""),
            created_at=d.get("created_at", ""),
            source_operator=d.get("source_operator", ""),
            source_host=d.get("source_host", ""),
            source_config_summary=d.get("source_config_summary", {}),
            case_numbers=d.get("case_numbers", []),
            batch_ids=d.get("batch_ids", []),
            files=[HandoffFileItem.from_dict(f) for f in d.get("files", [])],
            total_files=d.get("total_files", 0),
            total_size=d.get("total_size", 0),
            version=d.get("version", "1.0"),
            description=d.get("description", ""),
        )


@dataclass
class ConflictDetail:
    conflict_type: ConflictType
    file_item: HandoffFileItem | None = None
    target_path: str = ""
    detail: str = ""
    existing_info: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "conflict_type": self.conflict_type.value,
            "file_item": self.file_item.to_dict() if self.file_item else None,
            "target_path": self.target_path,
            "detail": self.detail,
            "existing_info": self.existing_info,
        }


@dataclass
class OperationRecord:
    operation_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    operation_type: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    operator: str = ""
    package_id: str = ""
    details: dict = field(default_factory=dict)
    status: str = ""

    def to_dict(self) -> dict:
        return {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "timestamp": self.timestamp,
            "operator": self.operator,
            "package_id": self.package_id,
            "details": self.details,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: dict) -> OperationRecord:
        return cls(
            operation_id=d.get("operation_id", uuid.uuid4().hex[:12]),
            operation_type=d.get("operation_type", ""),
            timestamp=d.get("timestamp", datetime.now().isoformat()),
            operator=d.get("operator", ""),
            package_id=d.get("package_id", ""),
            details=d.get("details", {}),
            status=d.get("status", ""),
        )


@dataclass
class HandoffCreateState:
    state_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: HandoffStatus = HandoffStatus.PENDING
    package_id: str = ""
    case_numbers: list = field(default_factory=list)
    batch_ids: list = field(default_factory=list)
    output_dir: str = ""
    files_processed: list = field(default_factory=list)
    files_pending: list = field(default_factory=list)
    files_failed: list = field(default_factory=list)
    manifest: HandoffManifest | None = None
    error: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "state_id": self.state_id,
            "status": self.status.value,
            "package_id": self.package_id,
            "case_numbers": self.case_numbers,
            "batch_ids": self.batch_ids,
            "output_dir": self.output_dir,
            "files_processed": self.files_processed,
            "files_pending": self.files_pending,
            "files_failed": self.files_failed,
            "manifest": self.manifest.to_dict() if self.manifest else None,
            "error": self.error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> HandoffCreateState:
        manifest_raw = d.get("manifest")
        return cls(
            state_id=d.get("state_id", uuid.uuid4().hex[:12]),
            status=HandoffStatus(d.get("status", "pending")),
            package_id=d.get("package_id", ""),
            case_numbers=d.get("case_numbers", []),
            batch_ids=d.get("batch_ids", []),
            output_dir=d.get("output_dir", ""),
            files_processed=d.get("files_processed", []),
            files_pending=d.get("files_pending", []),
            files_failed=d.get("files_failed", []),
            manifest=HandoffManifest.from_dict(manifest_raw) if manifest_raw else None,
            error=d.get("error", ""),
            created_at=d.get("created_at", datetime.now().isoformat()),
            updated_at=d.get("updated_at", datetime.now().isoformat()),
        )


@dataclass
class HandoffImportState:
    state_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: HandoffStatus = HandoffStatus.PENDING
    package_id: str = ""
    package_path: str = ""
    target_config_summary: dict = field(default_factory=dict)
    source_config_summary: dict = field(default_factory=dict)
    config_diff: dict = field(default_factory=dict)
    files_imported: list = field(default_factory=list)
    files_pending: list = field(default_factory=list)
    files_failed: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)
    written_files: list = field(default_factory=list)
    written_action_ids: list = field(default_factory=list)
    written_batch_ids: list = field(default_factory=list)
    error: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "state_id": self.state_id,
            "status": self.status.value,
            "package_id": self.package_id,
            "package_path": self.package_path,
            "target_config_summary": self.target_config_summary,
            "source_config_summary": self.source_config_summary,
            "config_diff": self.config_diff,
            "files_imported": self.files_imported,
            "files_pending": self.files_pending,
            "files_failed": self.files_failed,
            "conflicts": [c.to_dict() for c in self.conflicts],
            "written_files": self.written_files,
            "written_action_ids": self.written_action_ids,
            "written_batch_ids": self.written_batch_ids,
            "error": self.error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> HandoffImportState:
        conflicts_raw = d.get("conflicts", [])
        conflicts = []
        for c in conflicts_raw:
            ct = ConflictType(c.get("conflict_type", "file_missing"))
            fi_raw = c.get("file_item")
            fi = HandoffFileItem.from_dict(fi_raw) if fi_raw else None
            conflicts.append(ConflictDetail(
                conflict_type=ct,
                file_item=fi,
                target_path=c.get("target_path", ""),
                detail=c.get("detail", ""),
                existing_info=c.get("existing_info", {}),
            ))
        return cls(
            state_id=d.get("state_id", uuid.uuid4().hex[:12]),
            status=HandoffStatus(d.get("status", "pending")),
            package_id=d.get("package_id", ""),
            package_path=d.get("package_path", ""),
            target_config_summary=d.get("target_config_summary", {}),
            source_config_summary=d.get("source_config_summary", {}),
            config_diff=d.get("config_diff", {}),
            files_imported=d.get("files_imported", []),
            files_pending=d.get("files_pending", []),
            files_failed=d.get("files_failed", []),
            conflicts=conflicts,
            written_files=d.get("written_files", []),
            written_action_ids=d.get("written_action_ids", []),
            written_batch_ids=d.get("written_batch_ids", []),
            error=d.get("error", ""),
            created_at=d.get("created_at", datetime.now().isoformat()),
            updated_at=d.get("updated_at", datetime.now().isoformat()),
        )


@dataclass
class HandoffPreviewResult:
    case_numbers: list = field(default_factory=list)
    batch_ids: list = field(default_factory=list)
    files: list = field(default_factory=list)
    total_files: int = 0
    total_size: int = 0
    estimated_package_size: int = 0

    def to_dict(self) -> dict:
        return {
            "case_numbers": self.case_numbers,
            "batch_ids": self.batch_ids,
            "files": [f.to_dict() for f in self.files],
            "total_files": self.total_files,
            "total_size": self.total_size,
            "estimated_package_size": self.estimated_package_size,
        }


@dataclass
class HandoffVerifyResult:
    package_id: str = ""
    is_valid: bool = False
    integrity_ok: bool = False
    files_complete: bool = False
    files_match: bool = False
    manifest_exists: bool = False
    missing_files: list = field(default_factory=list)
    tampered_files: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    manifest: HandoffManifest | None = None

    def to_dict(self) -> dict:
        return {
            "package_id": self.package_id,
            "is_valid": self.is_valid,
            "integrity_ok": self.integrity_ok,
            "files_complete": self.files_complete,
            "files_match": self.files_match,
            "manifest_exists": self.manifest_exists,
            "missing_files": [f.to_dict() for f in self.missing_files],
            "tampered_files": [f.to_dict() for f in self.tampered_files],
            "errors": self.errors,
            "warnings": self.warnings,
            "manifest": self.manifest.to_dict() if self.manifest else None,
        }


@dataclass
class HandoffImportResult:
    package_id: str = ""
    success: bool = False
    status: HandoffStatus = HandoffStatus.FAILED
    total_files: int = 0
    imported: int = 0
    skipped: int = 0
    failed: int = 0
    conflicts: list = field(default_factory=list)
    imported_files: list = field(default_factory=list)
    failed_files: list = field(default_factory=list)
    operation_ids: list = field(default_factory=list)
    state_path: str = ""
    warnings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "package_id": self.package_id,
            "success": self.success,
            "status": self.status.value,
            "total_files": self.total_files,
            "imported": self.imported,
            "skipped": self.skipped,
            "failed": self.failed,
            "conflicts": [c.to_dict() for c in self.conflicts],
            "imported_files": self.imported_files,
            "failed_files": self.failed_files,
            "operation_ids": self.operation_ids,
            "state_path": self.state_path,
            "warnings": self.warnings,
        }


@dataclass
class HandoffRollbackResult:
    package_id: str = ""
    success: bool = False
    total_rolled_back: int = 0
    rolled_back_files: list = field(default_factory=list)
    failed_rollbacks: list = field(default_factory=list)
    kept_audit_log: bool = True
    operation_id: str = ""
    details: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "package_id": self.package_id,
            "success": self.success,
            "total_rolled_back": self.total_rolled_back,
            "rolled_back_files": self.rolled_back_files,
            "failed_rollbacks": self.failed_rollbacks,
            "kept_audit_log": self.kept_audit_log,
            "operation_id": self.operation_id,
            "details": self.details,
        }
