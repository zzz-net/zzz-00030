from __future__ import annotations

import os
from typing import Optional

from scan_sorter.config import AppConfig
from scan_sorter.models import (
    ActionRecord,
    ActionType,
    BatchRecord,
    BatchStatus,
    ErrorItem,
    FileStatus,
    PrecheckResult,
    ScanFile,
)
from scan_sorter.action_logger import ActionLogger
from scan_sorter.executor import execute_file
from scan_sorter.prechecker import precheck_files
from scan_sorter.queue_manager import ErrorQueue, ProcessingQueue
from scan_sorter.scanner import scan_intake
from scan_sorter.utils import iso_now


class BatchManager:
    def __init__(self, config: AppConfig):
        self.config = config
        self.action_logger = ActionLogger(config.logging.action_log_path())
        self.error_queue = ErrorQueue(config.logging.error_queue_path())
        self.processing_queue = ProcessingQueue(config.logging.queue_path())
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

    def precheck(self) -> list[PrecheckResult]:
        files = scan_intake(self.config)
        if not files:
            return []
        results = precheck_files(files, self.config)
        return results

    def process(
        self, max_files: int | None = None
    ) -> dict:
        files = scan_intake(self.config)
        if not files:
            return {"status": "no_files", "detail": "intake 目录无待处理文件"}

        results = precheck_files(files, self.config)

        ok_files = [f for f, r in zip(files, results) if r.ok]
        fail_files = [f for f, r in zip(files, results) if not r.ok]
        precheck_fail_count = len(fail_files)

        for sf, pr in zip(files, results):
            self.processing_queue.enqueue(
                sf.path,
                sf.case_number,
                filename=sf.filename,
            )

        precheck_error_paths: list[str] = []
        for sf, pr in zip(files, results):
            if not pr.ok:
                self.processing_queue.mark_failed(sf.path)
                precheck_error_paths.append(sf.path)
                self.error_queue.add(
                    ErrorItem(
                        path=sf.path,
                        filename=sf.filename,
                        case_number=sf.case_number,
                        error="; ".join(pr.errors),
                        retry_count=0,
                    )
                )

        if not ok_files:
            return {
                "status": "all_precheck_failed",
                "total": len(files),
                "succeeded": 0,
                "failed": precheck_fail_count,
            }

        batch_limit = max_files or self.config.batch.max_size
        ok_files = ok_files[:batch_limit]

        batch = BatchRecord(
            operator=self.config.operator,
            status=BatchStatus.OPEN,
            total=len(files),
        )

        succeeded = 0
        exec_failed = 0
        action_ids: list[str] = []
        stop_threshold = self.config.batch.stop_on_failure_ratio
        error_file_paths: list[str] = list(precheck_error_paths)

        for sf in ok_files:
            success, err = execute_file(sf, self.config)

            if success:
                succeeded += 1
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
                self.processing_queue.mark_done(sf.path)
            else:
                exec_failed += 1
                error_file_paths.append(sf.path)
                self.processing_queue.mark_failed(sf.path)
                self.error_queue.add(
                    ErrorItem(
                        path=sf.path,
                        filename=sf.filename,
                        case_number=sf.case_number,
                        error=err or "执行失败",
                        batch_id=batch.batch_id,
                    )
                )

                if succeeded + exec_failed > 0:
                    ratio = exec_failed / (succeeded + exec_failed)
                    if ratio >= stop_threshold:
                        batch.status = BatchStatus.PARTIAL_FAILED
                        break

        total_failed = precheck_fail_count + exec_failed
        if batch.status != BatchStatus.PARTIAL_FAILED:
            if total_failed > 0:
                batch.status = BatchStatus.PARTIAL_FAILED
            else:
                batch.status = BatchStatus.COMPLETED

        batch.succeeded = succeeded
        batch.failed = total_failed
        batch.action_ids = action_ids
        batch.error_file_paths = error_file_paths

        self._batch_history.append(batch)
        self._save_history()

        return {
            "status": batch.status.value,
            "batch_id": batch.batch_id,
            "total": batch.total,
            "succeeded": succeeded,
            "failed": total_failed,
            "precheck_failed": precheck_fail_count,
            "exec_failed": exec_failed,
        }

    def retry_failed(self, limit: int | None = None) -> dict:
        retryable = self.error_queue.get_retryable(limit=limit)
        if not retryable:
            return {"status": "no_retryable", "detail": "无可用重试项"}

        succeeded = 0
        failed = 0

        for item in retryable:
            if not os.path.exists(item.path):
                self.error_queue.increment_retry(item.path)
                failed += 1
                continue

            sf = ScanFile(path=item.path, filename=item.filename)
            from scan_sorter.parser import parse_file
            parse_file(sf, self.config)

            if sf.status == FileStatus.PRECHECK_FAIL:
                self.error_queue.increment_retry(item.path)
                failed += 1
                continue

            from scan_sorter.prechecker import precheck_files
            pre_results = precheck_files([sf], self.config)
            if pre_results and not pre_results[0].ok:
                self.error_queue.increment_retry(item.path)
                failed += 1
                continue

            sf.status = FileStatus.PRECHECK_OK
            success, err = execute_file(sf, self.config)
            if success:
                succeeded += 1
                self.error_queue.remove(item.path)
                self.processing_queue.mark_done(item.path)

                record = ActionRecord(
                    operator=self.config.operator,
                    source=sf.path,
                    destination=sf.target_path or "",
                    action_type=ActionType(self.config.rules.action.lower()),
                    case_number=sf.case_number or "",
                )
                self.action_logger.log(record)
            else:
                self.error_queue.increment_retry(item.path)
                failed += 1

        return {
            "status": "done",
            "retried": len(retryable),
            "succeeded": succeeded,
            "failed": failed,
        }

    def rollback(self, batch_id: str) -> dict:
        batch = self._find_batch(batch_id)
        if not batch:
            return {"status": "not_found", "detail": f"批次 {batch_id} 不存在"}

        if batch.status == BatchStatus.ROLLED_BACK:
            return {"status": "already_rolled_back", "detail": f"批次 {batch_id} 已回滚"}

        results = self.action_logger.rollback_batch(batch_id)
        ok_count = sum(1 for r in results if r["ok"])
        fail_count = sum(1 for r in results if not r["ok"])

        batch.status = BatchStatus.ROLLED_BACK
        self._save_history()

        rolled_back_actions = [
            a for a in self.action_logger.get_by_batch(batch_id)
            if a.rolled_back
        ]
        for action in rolled_back_actions:
            self.processing_queue.mark_rolled_back(action.source)

        return {
            "status": "done",
            "batch_id": batch_id,
            "rolled_back_ok": ok_count,
            "rolled_back_fail": fail_count,
            "details": results,
        }

    def _find_batch(self, batch_id: str) -> BatchRecord | None:
        for b in self._batch_history:
            if b.batch_id == batch_id:
                return b
        return None

    def list_batches(self) -> list[dict]:
        return [b.to_dict() for b in self._batch_history]

    def get_error_queue(self) -> list[dict]:
        return [item.to_dict() for item in self.error_queue.all()]

    def export_action_log(self) -> list[dict]:
        return self.action_logger.export_dicts()
