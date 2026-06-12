from __future__ import annotations

import os
from typing import Optional

from scan_sorter.config import AppConfig
from scan_sorter.models import (
    ActionRecord,
    ActionType,
    BatchRecord,
    BatchStatus,
    DryRunPlanItem,
    DryRunResult,
    ErrorItem,
    FileStatus,
    PlanAction,
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

    def dry_run(self, max_files: int | None = None) -> DryRunResult:
        files = scan_intake(self.config)
        if not files:
            return DryRunResult(items=[], total=0, will_succeed=0, will_fail=0, warnings=0)

        results = precheck_files(files, self.config)

        plan_items: list[DryRunPlanItem] = []
        will_succeed = 0
        will_fail = 0
        warning_count = 0

        batch_limit = max_files or self.config.batch.max_size
        processed = 0

        for sf, pr in zip(files, results):
            if processed >= batch_limit:
                break
            processed += 1

            item = DryRunPlanItem(
                filename=sf.filename,
                path=sf.path,
                case_number=sf.case_number,
                target_dir=sf.target_dir,
                target_path=sf.target_path,
                action_type=self.config.rules.action.lower(),
            )

            in_eq = self.error_queue.find_by_path(sf.path) is not None
            in_pq = self.processing_queue.find_by_path(sf.path) is not None
            target_exists = sf.target_path and os.path.exists(sf.target_path)

            item.in_error_queue = in_eq
            item.in_processing_queue = in_pq
            item.target_exists = bool(target_exists)

            if in_eq:
                item.warnings.append("文件已在错误队列中")
                warning_count += 1
            if in_pq:
                item.warnings.append("文件已在处理队列中")
                warning_count += 1
            if target_exists:
                item.warnings.append("目标目录已有同名文件")
                warning_count += 1

            if not pr.ok:
                item.will_succeed = False
                item.errors = list(pr.errors)
                will_fail += 1

                has_target_conflict = any("目标路径已被占用" in e for e in pr.errors)
                has_illegal = any("非法字符" in e or "文件名不合法" in e for e in pr.errors)
                has_duplicate = any("重复文件名" in e for e in pr.errors)

                if has_target_conflict:
                    item.action = PlanAction.FAIL_TARGET_CONFLICT
                elif has_duplicate:
                    item.action = PlanAction.FAIL_DUPLICATE
                else:
                    item.action = PlanAction.FAIL_PRECHECK
            else:
                item.will_succeed = True
                will_succeed += 1
                item.action = PlanAction.ARCHIVE

            plan_items.append(item)

        return DryRunResult(
            items=plan_items,
            total=len(plan_items),
            will_succeed=will_succeed,
            will_fail=will_fail,
            warnings=warning_count,
        )

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
        error_details: dict[str, str] = {}
        for sf, pr in zip(files, results):
            if not pr.ok:
                self.processing_queue.mark_failed(sf.path)
                precheck_error_paths.append(sf.path)
                err_msg = "; ".join(pr.errors)
                error_details[sf.path] = err_msg
                self.error_queue.add(
                    ErrorItem(
                        path=sf.path,
                        filename=sf.filename,
                        case_number=sf.case_number,
                        error=err_msg,
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

        for p in precheck_error_paths:
            existing = self.error_queue.find_by_path(p)
            if existing:
                existing.batch_id = batch.batch_id
                self.error_queue.add(ErrorItem(
                    path=existing.path,
                    filename=existing.filename,
                    case_number=existing.case_number,
                    error=existing.error,
                    retry_count=existing.retry_count,
                    batch_id=batch.batch_id,
                ))

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
                err_msg = err or "执行失败"
                error_details[sf.path] = err_msg
                self.processing_queue.mark_failed(sf.path)
                self.error_queue.add(
                    ErrorItem(
                        path=sf.path,
                        filename=sf.filename,
                        case_number=sf.case_number,
                        error=err_msg,
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
        batch.error_details = error_details

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
                    batch_id=item.batch_id or "",
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
