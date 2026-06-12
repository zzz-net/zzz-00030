from __future__ import annotations

import csv
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from scan_sorter.action_logger import ActionLogger
from scan_sorter.config import AppConfig
from scan_sorter.healthcheck import HealthChecker, Severity
from scan_sorter.models import ActionRecord, BatchRecord, ErrorItem
from scan_sorter.queue_manager import ErrorQueue, ProcessingQueue
from scan_sorter.utils import load_json, save_json


@dataclass
class ConflictInfo:
    filename: str
    intake_path: str
    target_path: str
    in_queue: bool = False
    in_error_queue: bool = False

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "intake_path": self.intake_path,
            "target_path": self.target_path,
            "in_queue": self.in_queue,
            "in_error_queue": self.in_error_queue,
        }


@dataclass
class RetryableItem:
    filename: str
    path: str
    error: str
    retry_count: int
    max_retries: int
    case_number: Optional[str] = None
    batch_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "path": self.path,
            "error": self.error,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "case_number": self.case_number,
            "batch_id": self.batch_id,
        }


@dataclass
class HealthcheckSummary:
    last_check_time: Optional[str] = None
    total_findings: int = 0
    critical_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    fixable_count: int = 0

    def to_dict(self) -> dict:
        return {
            "last_check_time": self.last_check_time,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "fixable_count": self.fixable_count,
        }


@dataclass
class BatchSummary:
    batch_id: str
    status: str
    created_at: str
    operator: str
    total: int
    succeeded: int
    failed: int
    target_dirs: list[str] = field(default_factory=list)
    success_files: list[dict] = field(default_factory=list)
    failed_files: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "batch_id": self.batch_id,
            "status": self.status,
            "created_at": self.created_at,
            "operator": self.operator,
            "total": self.total,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "target_dirs": self.target_dirs,
            "success_files": self.success_files,
            "failed_files": self.failed_files,
        }


@dataclass
class ReportResult:
    batches: list[BatchSummary] = field(default_factory=list)
    conflicts: list[ConflictInfo] = field(default_factory=list)
    retryable_items: list[RetryableItem] = field(default_factory=list)
    healthcheck_summary: HealthcheckSummary = field(default_factory=HealthcheckSummary)
    config_info: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "batches": [b.to_dict() for b in self.batches],
            "conflicts": [c.to_dict() for c in self.conflicts],
            "retryable_items": [r.to_dict() for r in self.retryable_items],
            "healthcheck_summary": self.healthcheck_summary.to_dict(),
            "config_info": self.config_info,
            "warnings": self.warnings,
            "errors": self.errors,
            "generated_at": self.generated_at,
        }

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0

    @property
    def exit_code(self) -> int:
        if self.errors:
            return 2
        if self.warnings:
            return 1
        return 0


class ReportGenerator:
    def __init__(self, config: AppConfig):
        self.config = config
        self.action_logger = ActionLogger(config.logging.action_log_path())
        self.error_queue = ErrorQueue(config.logging.error_queue_path())
        self.processing_queue = ProcessingQueue(config.logging.queue_path())
        self.health_checker = HealthChecker(config)

    def _load_batches(self) -> list[BatchRecord]:
        raw = load_json(
            self.config.logging.batch_history_path(), default=[]
        )
        return [BatchRecord.from_dict(d) for d in raw]

    def _find_conflicts(self) -> list[ConflictInfo]:
        conflicts: list[ConflictInfo] = []
        intake_dir = os.path.abspath(self.config.intake_dir)
        target_base = os.path.abspath(self.config.target_base)

        if not os.path.isdir(intake_dir):
            return conflicts

        queue_paths = {q["path"] for q in self.processing_queue.all()}
        error_queue_paths = {e.path for e in self.error_queue.all()}

        for filename in os.listdir(intake_dir):
            intake_path = os.path.join(intake_dir, filename)
            if not os.path.isfile(intake_path):
                continue

            case_number = None
            m = re.search(
                self.config.rules.case_number_pattern, filename
            )
            if m:
                case_number = m.group(1)

            if case_number:
                target_dir = os.path.join(
                    target_base,
                    self.config.rules.target_structure.replace(
                        "{case_number}", case_number
                    ),
                )
                target_path = os.path.join(target_dir, filename)
                if os.path.exists(target_path):
                    conflicts.append(ConflictInfo(
                        filename=filename,
                        intake_path=intake_path,
                        target_path=target_path,
                        in_queue=intake_path in queue_paths,
                        in_error_queue=intake_path in error_queue_paths,
                    ))

        return conflicts

    def _get_retryable_items(self) -> list[RetryableItem]:
        items: list[RetryableItem] = []
        for e in self.error_queue.all():
            if e.retry_count < e.max_retries:
                items.append(RetryableItem(
                    filename=e.filename,
                    path=e.path,
                    error=e.error,
                    retry_count=e.retry_count,
                    max_retries=e.max_retries,
                    case_number=e.case_number,
                    batch_id=e.batch_id,
                ))
        return items

    def _get_healthcheck_summary(self) -> HealthcheckSummary:
        summary = HealthcheckSummary()
        last_check = self.health_checker.state.get_last_check_time()
        summary.last_check_time = last_check

        last_findings = self.health_checker.state.get_last_findings()
        if last_findings:
            summary.total_findings = len(last_findings)
            summary.critical_count = sum(
                1 for f in last_findings if f.severity == Severity.CRITICAL
            )
            summary.warning_count = sum(
                1 for f in last_findings if f.severity == Severity.WARNING
            )
            summary.info_count = sum(
                1 for f in last_findings if f.severity == Severity.INFO
            )
            summary.fixable_count = sum(1 for f in last_findings if f.fixable)

        return summary

    def _summarize_batch(
        self, batch: BatchRecord, actions: list[ActionRecord]
    ) -> BatchSummary:
        batch_actions = [a for a in actions if a.batch_id == batch.batch_id]
        target_dirs = sorted({
            os.path.dirname(a.destination)
            for a in batch_actions
            if a.destination and not a.rolled_back
        })

        success_files = [
            {
                "filename": os.path.basename(a.source),
                "source": a.source,
                "destination": a.destination,
                "case_number": a.case_number,
                "timestamp": a.timestamp,
            }
            for a in batch_actions
            if not a.rolled_back
        ]

        recovered_sources = {
            a.source for a in actions
            if not a.rolled_back and a.source
        }

        failed_files: list[dict] = []
        error_queue_paths = {e.path for e in self.error_queue.all()}
        for err_path in batch.error_file_paths:
            err_item = self.error_queue.find_by_path(err_path)
            err_msg = batch.error_details.get(err_path) if batch.error_details else None
            if err_msg is None and err_item:
                err_msg = err_item.error
            if err_msg is None:
                err_msg = "未知错误"
            filename = os.path.basename(err_path)
            failed_files.append({
                "filename": filename,
                "path": err_path,
                "error": err_msg,
                "recovered": err_path in recovered_sources,
                "in_error_queue": err_path in error_queue_paths,
                "retry_count": err_item.retry_count if err_item else 0,
            })

        return BatchSummary(
            batch_id=batch.batch_id,
            status=batch.status.value,
            created_at=batch.created_at,
            operator=batch.operator,
            total=batch.total,
            succeeded=batch.succeeded,
            failed=batch.failed,
            target_dirs=target_dirs,
            success_files=success_files,
            failed_files=failed_files,
        )

    def generate(
        self,
        batch_id: Optional[str] = None,
        include_details: bool = True,
    ) -> ReportResult:
        result = ReportResult()

        result.config_info = {
            "intake_dir": os.path.abspath(self.config.intake_dir),
            "target_base": os.path.abspath(self.config.target_base),
            "target_structure": self.config.rules.target_structure,
            "operator": self.config.operator,
            "action": self.config.rules.action,
            "logging_dir": os.path.abspath(self.config.logging.dir),
        }

        batches = self._load_batches()

        if not batches:
            result.warnings.append("batch_history.json 为空，无历史批次记录")
            batch_records: list[BatchRecord] = []
        elif batch_id:
            batch_records = [b for b in batches if b.batch_id == batch_id]
            if not batch_records:
                result.errors.append(
                    f"批次 {batch_id} 不存在，请检查 batch_id 是否正确"
                )
                batch_records = []
        else:
            batch_records = batches

        actions = self.action_logger.all_records()

        for batch in batch_records:
            summary = self._summarize_batch(batch, actions)
            if not include_details:
                summary.success_files = []
                summary.failed_files = []
            result.batches.append(summary)

        result.conflicts = self._find_conflicts()
        if result.conflicts:
            result.warnings.append(
                f"发现 {len(result.conflicts)} 个文件名冲突（intake 和 target 同时存在同名文件）"
            )

        result.retryable_items = self._get_retryable_items()
        if result.retryable_items:
            result.warnings.append(
                f"有 {len(result.retryable_items)} 个失败项可重试"
            )

        result.healthcheck_summary = self._get_healthcheck_summary()
        if result.healthcheck_summary.total_findings > 0:
            result.warnings.append(
                f"最近一次健康检查发现 {result.healthcheck_summary.total_findings} 个问题"
            )

        action_log_path = self.config.logging.action_log_path()
        if not os.path.exists(action_log_path) or os.path.getsize(action_log_path) == 0:
            result.warnings.append("action_log.jsonl 为空或不存在")

        queue_path = self.config.logging.queue_path()
        if not os.path.exists(queue_path) or os.path.getsize(queue_path) == 0:
            result.warnings.append("queue.json 为空或不存在")

        error_queue_path = self.config.logging.error_queue_path()
        if not os.path.exists(error_queue_path) or os.path.getsize(error_queue_path) == 0:
            pass

        batch_history_path = self.config.logging.batch_history_path()
        if not os.path.exists(batch_history_path) or os.path.getsize(batch_history_path) == 0:
            result.warnings.append("batch_history.json 为空或不存在")

        if not os.path.isdir(self.config.intake_dir):
            result.warnings.append(
                f"intake 目录不存在: {self.config.intake_dir}"
            )

        if not os.path.isdir(self.config.target_base):
            result.warnings.append(
                f"target 目录不存在: {self.config.target_base}"
            )

        return result


def export_report_json(report: ReportResult, path: str) -> None:
    save_json(path, report.to_dict())


def export_report_csv(report: ReportResult, base_path: str) -> list[str]:
    exported_paths: list[str] = []

    if report.batches:
        batches_path = f"{os.path.splitext(base_path)[0]}_batches.csv"
        with open(batches_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "batch_id", "status", "created_at", "operator",
                "total", "succeeded", "failed", "target_dirs",
            ])
            for b in report.batches:
                writer.writerow([
                    b.batch_id, b.status, b.created_at, b.operator,
                    b.total, b.succeeded, b.failed, "; ".join(b.target_dirs),
                ])
        exported_paths.append(batches_path)

    if report.conflicts:
        conflicts_path = f"{os.path.splitext(base_path)[0]}_conflicts.csv"
        with open(conflicts_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "filename", "intake_path", "target_path",
                    "in_queue", "in_error_queue",
                ],
            )
            writer.writeheader()
            for c in report.conflicts:
                writer.writerow(c.to_dict())
        exported_paths.append(conflicts_path)

    if report.retryable_items:
        retry_path = f"{os.path.splitext(base_path)[0]}_retryable.csv"
        with open(retry_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "filename", "path", "error", "retry_count",
                    "max_retries", "case_number", "batch_id",
                ],
            )
            writer.writeheader()
            for r in report.retryable_items:
                writer.writerow(r.to_dict())
        exported_paths.append(retry_path)

    summary_path = f"{os.path.splitext(base_path)[0]}_summary.csv"
    with open(summary_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["item", "value"])
        writer.writerow(["生成时间", report.generated_at])
        writer.writerow(["批次总数", len(report.batches)])
        writer.writerow(["冲突文件数", len(report.conflicts)])
        writer.writerow(["可重试项数", len(report.retryable_items)])
        writer.writerow(["健康检查问题总数", report.healthcheck_summary.total_findings])
        writer.writerow(["  严重", report.healthcheck_summary.critical_count])
        writer.writerow(["  警告", report.healthcheck_summary.warning_count])
        writer.writerow(["  信息", report.healthcheck_summary.info_count])
        writer.writerow(["  可修复", report.healthcheck_summary.fixable_count])
        writer.writerow(["警告数", len(report.warnings)])
        writer.writerow(["错误数", len(report.errors)])
        for i, w in enumerate(report.warnings, 1):
            writer.writerow([f"警告 {i}", w])
        for i, e in enumerate(report.errors, 1):
            writer.writerow([f"错误 {i}", e])
    exported_paths.append(summary_path)

    return exported_paths
