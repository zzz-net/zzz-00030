from __future__ import annotations

import os
import csv
import json
from typing import Optional

from scan_sorter.config import AppConfig
from scan_sorter.action_logger import ActionLogger
from scan_sorter.executor import execute_file
from scan_sorter.models import (
    ActionRecord,
    ActionType,
    BatchRecord,
    BatchStatus,
    ErrorItem,
    FileStatus,
    RetryExecutionItem,
    RetryExecutionResult,
    RetryPlanItem,
    RetryPlanResult,
    RetryStatus,
    ScanFile,
    SkipReason,
)
from scan_sorter.parser import parse_file
from scan_sorter.prechecker import precheck_files
from scan_sorter.queue_manager import ErrorQueue, ProcessingQueue
from scan_sorter.utils import iso_now


class RetryManager:
    def __init__(self, config: AppConfig):
        self.config = config
        self.error_queue = ErrorQueue(config.logging.error_queue_path())
        self.processing_queue = ProcessingQueue(config.logging.queue_path())
        self.action_logger = ActionLogger(config.logging.action_log_path())
        self._batch_history: list[BatchRecord] = self._load_history()

    def _load_history(self) -> list[BatchRecord]:
        from scan_sorter.utils import load_json
        raw = load_json(self.config.logging.batch_history_path(), default=[])
        return [BatchRecord.from_dict(d) for d in raw]

    def _save_history(self) -> None:
        from scan_sorter.utils import save_json
        save_json(
            self.config.logging.batch_history_path(),
            [b.to_dict() for b in self._batch_history],
        )

    def _find_duplicates_in_error_queue(self) -> set[str]:
        path_counts: dict[str, int] = {}
        for item in self.error_queue.all():
            path_counts[item.path] = path_counts.get(item.path, 0) + 1
        return {p for p, c in path_counts.items() if c > 1}

    def _has_active_processing(self, path: str) -> bool:
        entry = self.processing_queue.find_by_path(path)
        if entry is None:
            return False
        status = entry.get("status", "")
        return status in ("queued", "processing")

    def build_retry_plan(
        self,
        limit: Optional[int] = None,
        include_skipped: bool = True,
    ) -> RetryPlanResult:
        all_items = self.error_queue.all()
        if not all_items:
            return RetryPlanResult(
                items=[],
                total=0,
                retryable=0,
                skipped=0,
                retryable_items=[],
                skipped_items=[],
            )

        duplicates = self._find_duplicates_in_error_queue()
        plan_items: list[RetryPlanItem] = []
        retryable_items: list[RetryPlanItem] = []
        skipped_items: list[RetryPlanItem] = []

        for err_item in all_items:
            if limit is not None and len(retryable_items) >= limit:
                if include_skipped:
                    continue
                else:
                    break

            plan_item = RetryPlanItem(
                path=err_item.path,
                filename=err_item.filename,
                case_number=err_item.case_number,
                original_error=err_item.error,
                original_batch_id=err_item.batch_id,
                retry_count=err_item.retry_count,
                max_retries=err_item.max_retries,
                added_at=err_item.added_at,
                last_retry_at=err_item.last_retry_at,
                action_type=self.config.rules.action.lower(),
            )

            sf = ScanFile(path=err_item.path, filename=err_item.filename)

            if not os.path.exists(err_item.path):
                plan_item.source_missing = True
                plan_item.status = RetryStatus.SKIPPED
                plan_item.skip_reason = SkipReason.SOURCE_MISSING
                plan_item.skip_detail = "源文件不存在"
                plan_item.expected_action = "跳过"
                skipped_items.append(plan_item)
                plan_items.append(plan_item)
                continue

            if err_item.retry_count >= err_item.max_retries:
                plan_item.status = RetryStatus.SKIPPED
                plan_item.skip_reason = SkipReason.MAX_RETRIES_EXCEEDED
                plan_item.skip_detail = f"已达最大重试次数 {err_item.max_retries}"
                plan_item.expected_action = "跳过"
                skipped_items.append(plan_item)
                plan_items.append(plan_item)
                continue

            if err_item.path in duplicates:
                plan_item.duplicate_in_error_queue = True
                plan_item.status = RetryStatus.SKIPPED
                plan_item.skip_reason = SkipReason.DUPLICATE_IN_ERROR_QUEUE
                plan_item.skip_detail = "错误队列中存在重复记录"
                plan_item.expected_action = "跳过"
                skipped_items.append(plan_item)
                plan_items.append(plan_item)
                continue

            if self._has_active_processing(err_item.path):
                plan_item.in_processing_queue = True
                plan_item.status = RetryStatus.SKIPPED
                plan_item.skip_reason = SkipReason.IN_PROCESSING_QUEUE
                plan_item.skip_detail = "处理队列中已有待处理记录"
                plan_item.expected_action = "跳过"
                skipped_items.append(plan_item)
                plan_items.append(plan_item)
                continue

            parse_file(sf, self.config)

            plan_item.case_number = sf.case_number
            plan_item.new_target_dir = sf.target_dir
            plan_item.new_target_path = sf.target_path

            if sf.status == FileStatus.PRECHECK_FAIL:
                plan_item.parse_errors = [sf.error_message] if sf.error_message else []
                plan_item.status = RetryStatus.SKIPPED
                plan_item.skip_reason = SkipReason.PARSE_FAILED
                plan_item.skip_detail = f"解析失败: {sf.error_message}"
                plan_item.expected_action = "跳过"
                skipped_items.append(plan_item)
                plan_items.append(plan_item)
                continue

            if sf.target_path and os.path.exists(sf.target_path):
                plan_item.target_exists = True
                plan_item.status = RetryStatus.SKIPPED
                plan_item.skip_reason = SkipReason.TARGET_EXISTS
                plan_item.skip_detail = f"目标路径已存在: {sf.target_path}"
                plan_item.expected_action = "跳过"
                skipped_items.append(plan_item)
                plan_items.append(plan_item)
                continue

            pre_results = precheck_files([sf], self.config)
            if pre_results and not pre_results[0].ok:
                plan_item.precheck_errors = list(pre_results[0].errors)
                plan_item.status = RetryStatus.SKIPPED
                plan_item.skip_reason = SkipReason.PRECHECK_FAILED
                plan_item.skip_detail = "; ".join(pre_results[0].errors)
                plan_item.expected_action = "跳过"
                skipped_items.append(plan_item)
                plan_items.append(plan_item)
                continue

            sf.status = FileStatus.PRECHECK_OK
            plan_item.status = RetryStatus.RETRYABLE
            plan_item.expected_action = f"{self.config.rules.action.lower()}: {sf.path} -> {sf.target_path}"
            retryable_items.append(plan_item)
            plan_items.append(plan_item)

        return RetryPlanResult(
            items=plan_items,
            total=len(plan_items),
            retryable=len(retryable_items),
            skipped=len(skipped_items),
            retryable_items=retryable_items,
            skipped_items=skipped_items,
        )

    def execute_retry(
        self,
        plan: Optional[RetryPlanResult] = None,
        paths: Optional[list[str]] = None,
        limit: Optional[int] = None,
    ) -> RetryExecutionResult:
        if plan is None:
            plan = self.build_retry_plan(limit=limit)

        retryable = plan.retryable_items
        if paths:
            path_set = set(paths)
            retryable = [item for item in retryable if item.path in path_set]

        if limit is not None:
            retryable = retryable[:limit]

        if not retryable:
            return RetryExecutionResult(
                items=[],
                total=0,
                succeeded=0,
                failed=0,
                skipped=plan.skipped,
                batch_id="",
            )

        batch = BatchRecord(
            operator=self.config.operator,
            status=BatchStatus.OPEN,
            total=len(retryable),
        )

        execution_items: list[RetryExecutionItem] = []
        succeeded = 0
        failed = 0
        action_ids: list[str] = []
        error_file_paths: list[str] = []
        error_details: dict[str, str] = {}

        for plan_item in retryable:
            exec_item = RetryExecutionItem(
                path=plan_item.path,
                filename=plan_item.filename,
                case_number=plan_item.case_number,
                batch_id=batch.batch_id,
                source=plan_item.path,
                destination=plan_item.new_target_path or "",
                action_type=plan_item.action_type,
            )

            if self._has_active_processing(plan_item.path):
                other_entry = self.processing_queue.find_by_path(plan_item.path)
                self.error_queue.increment_retry(plan_item.path)
                exec_item.status = RetryStatus.FAILED
                exec_item.error = f"处理队列中已有活跃记录: {other_entry.get('status', '')}"
                failed += 1
                error_file_paths.append(plan_item.path)
                error_details[plan_item.path] = exec_item.error
                execution_items.append(exec_item)
                continue

            if not os.path.exists(plan_item.path):
                self.error_queue.increment_retry(plan_item.path)
                exec_item.status = RetryStatus.FAILED
                exec_item.error = "源文件不存在"
                failed += 1
                error_file_paths.append(plan_item.path)
                error_details[plan_item.path] = exec_item.error
                execution_items.append(exec_item)
                continue

            sf = ScanFile(path=plan_item.path, filename=plan_item.filename)
            parse_file(sf, self.config)
            if sf.status == FileStatus.PRECHECK_FAIL:
                self.error_queue.increment_retry(plan_item.path)
                exec_item.status = RetryStatus.FAILED
                exec_item.error = sf.error_message or "解析失败"
                failed += 1
                error_file_paths.append(plan_item.path)
                error_details[plan_item.path] = exec_item.error
                execution_items.append(exec_item)
                continue

            pre_results = precheck_files([sf], self.config)
            if pre_results and not pre_results[0].ok:
                self.error_queue.increment_retry(plan_item.path)
                exec_item.status = RetryStatus.FAILED
                exec_item.error = "; ".join(pre_results[0].errors)
                failed += 1
                error_file_paths.append(plan_item.path)
                error_details[plan_item.path] = exec_item.error
                execution_items.append(exec_item)
                continue

            sf.status = FileStatus.PRECHECK_OK

            existing_target = sf.target_path and os.path.exists(sf.target_path)
            if existing_target:
                self.error_queue.increment_retry(plan_item.path)
                exec_item.status = RetryStatus.FAILED
                exec_item.error = f"目标路径已存在: {sf.target_path}"
                failed += 1
                error_file_paths.append(plan_item.path)
                error_details[plan_item.path] = exec_item.error
                execution_items.append(exec_item)
                continue

            self.processing_queue.enqueue(
                plan_item.path,
                plan_item.case_number,
                filename=plan_item.filename,
            )

            success, err = execute_file(sf, self.config)
            exec_item.timestamp = iso_now()

            if success:
                succeeded += 1
                self.error_queue.remove(plan_item.path)
                self.processing_queue.mark_done(plan_item.path)

                record = ActionRecord(
                    batch_id=batch.batch_id,
                    source=sf.path,
                    destination=sf.target_path or "",
                    action_type=ActionType(self.config.rules.action.lower()),
                    operator=self.config.operator,
                    case_number=sf.case_number or "",
                )
                self.action_logger.log(record)
                action_ids.append(record.action_id)

                exec_item.status = RetryStatus.SUCCESS
                exec_item.action_id = record.action_id
                exec_item.destination = sf.target_path or ""
            else:
                self.error_queue.increment_retry(plan_item.path)
                self.processing_queue.mark_failed(plan_item.path)
                failed += 1
                error_file_paths.append(plan_item.path)
                err_msg = err or "执行失败"
                error_details[plan_item.path] = err_msg
                exec_item.status = RetryStatus.FAILED
                exec_item.error = err_msg

            execution_items.append(exec_item)

        if failed > 0:
            batch.status = BatchStatus.PARTIAL_FAILED
        else:
            batch.status = BatchStatus.COMPLETED

        batch.succeeded = succeeded
        batch.failed = failed
        batch.action_ids = action_ids
        batch.error_file_paths = error_file_paths
        batch.error_details = error_details

        self._batch_history.append(batch)
        self._save_history()

        return RetryExecutionResult(
            items=execution_items,
            total=len(execution_items),
            succeeded=succeeded,
            failed=failed,
            skipped=plan.skipped,
            batch_id=batch.batch_id,
        )


def export_retry_plan_json(plan: RetryPlanResult, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(plan.to_dict(), f, ensure_ascii=False, indent=2)


def export_retry_plan_csv(plan: RetryPlanResult, output_path: str) -> None:
    fieldnames = [
        "path", "filename", "case_number",
        "original_error", "original_batch_id",
        "retry_count", "max_retries",
        "added_at", "last_retry_at",
        "new_target_dir", "new_target_path",
        "expected_action", "status",
        "skip_reason", "skip_detail",
        "parse_errors", "precheck_errors",
        "target_exists", "source_missing",
        "in_processing_queue", "duplicate_in_error_queue",
        "action_type",
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in plan.items:
            row = item.to_dict()
            row["parse_errors"] = "; ".join(row.get("parse_errors", []))
            row["precheck_errors"] = "; ".join(row.get("precheck_errors", []))
            writer.writerow(row)


def export_retry_result_json(result: RetryExecutionResult, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)


def export_retry_result_csv(result: RetryExecutionResult, output_path: str) -> None:
    fieldnames = [
        "path", "filename", "case_number",
        "status", "error", "action_id", "batch_id",
        "source", "destination", "action_type", "timestamp",
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in result.items:
            writer.writerow(item.to_dict())
