from __future__ import annotations

import os
import re
import stat
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Optional

try:
    from zoneinfo import ZoneInfo
except Exception:
    try:
        from backports.zoneinfo import ZoneInfo
    except Exception:
        def ZoneInfo(key):
            return timezone.utc

from scan_sorter.action_logger import ActionLogger
from scan_sorter.config import AppConfig, reload_config
from scan_sorter.models import (
    ArchivedFile,
    ConflictCategory,
    RetentionConflictDetail,
    DisposalItem,
    DisposalStatus,
    RetentionPreviewResult,
    RetentionRun,
    RetentionRule,
)
from scan_sorter.queue_manager import ErrorQueue, ProcessingQueue
from scan_sorter.utils import append_jsonl, file_hash, iso_now, load_json, save_json


class RetentionManager:
    def __init__(self, config: AppConfig):
        self.config = config
        self._reload_if_needed()
        self.logging_dir = os.path.abspath(config.logging.dir)
        self.state_path = config.retention.state_path(self.logging_dir)
        self.log_path = config.retention.log_path(self.logging_dir)
        self.action_logger = ActionLogger(config.logging.action_log_path())
        self.error_queue = ErrorQueue(config.logging.error_queue_path())
        self.processing_queue = ProcessingQueue(config.logging.queue_path())
        self._state = self._load_state()

    def _reload_if_needed(self) -> None:
        new_config = reload_config(self.config)
        self.config = new_config

    def _load_state(self) -> dict:
        data = load_json(self.state_path, default={})
        if not data:
            data = {
                "retention_runs": [],
                "config_signature": self._config_signature(),
                "mark_index": {},
            }
        return data

    def _save_state(self) -> None:
        save_json(self.state_path, self._state)

    def _config_signature(self) -> dict:
        return {
            "default_retention_days": self.config.retention.default_retention_days,
            "rules": [r.to_dict() for r in self.config.retention.rules],
            "target_base": os.path.abspath(self.config.target_base),
        }

    def _write_log(self, entry: dict) -> None:
        entry = {"timestamp": iso_now(), **entry}
        append_jsonl(self.log_path, entry)

    def _check_config_changed(self) -> Optional[str]:
        old_sig = self._state.get("config_signature", {})
        new_sig = self._config_signature()
        if old_sig and old_sig != new_sig:
            return f"配置已变更: 旧签名={old_sig}, 新签名={new_sig}"
        return None

    def scan_archived_files(
        self,
        case_numbers: Optional[list[str]] = None,
        batch_ids: Optional[list[str]] = None,
    ) -> list[ArchivedFile]:
        self._reload_if_needed()
        target_base = os.path.abspath(self.config.target_base)
        archived_map: dict[str, ArchivedFile] = {}

        all_records = self.action_logger.all_records()
        case_pattern = re.compile(self.config.rules.case_number_pattern)
        non_rolled = [r for r in all_records if not r.rolled_back]

        for rec in non_rolled:
            dest = os.path.abspath(rec.destination)
            if not dest.startswith(target_base):
                continue
            fname = os.path.basename(dest)
            cn = rec.case_number
            if not cn:
                rel = os.path.relpath(dest, target_base)
                cm = case_pattern.search(rel)
                cn = cm.group(0) if cm else ""
            if case_numbers and cn not in case_numbers:
                continue
            bid = rec.batch_id
            if batch_ids and bid not in batch_ids:
                continue
            if not cn:
                cm2 = case_pattern.search(fname)
                if cm2:
                    cn = cm2.group(0)
            if case_numbers and cn not in case_numbers:
                continue
            size = 0
            sha = ""
            exists = os.path.exists(dest)
            if exists:
                try:
                    size = os.path.getsize(dest)
                    sha = file_hash(dest)
                except (OSError, PermissionError):
                    pass
            raw_ts = getattr(rec, "created_at", None) or getattr(rec, "timestamp", None)
            if isinstance(raw_ts, datetime):
                arch_ts = raw_ts
            elif isinstance(raw_ts, str) and raw_ts:
                try:
                    arch_ts = datetime.fromisoformat(raw_ts)
                except Exception:
                    arch_ts = datetime.now(ZoneInfo("UTC"))
            else:
                arch_ts = datetime.now(ZoneInfo("UTC"))
            if arch_ts.tzinfo is None:
                arch_ts = arch_ts.replace(tzinfo=ZoneInfo("UTC"))
            archived_map[dest] = ArchivedFile(
                path=dest,
                filename=fname,
                case_number=cn,
                batch_id=bid,
                archived_at=arch_ts,
                size=size,
                sha256=sha,
                action_id=rec.action_id,
            )

        if os.path.isdir(target_base):
            for root, dirs, files in os.walk(target_base):
                for fname in files:
                    fpath = os.path.abspath(os.path.join(root, fname))
                    if fpath in archived_map:
                        continue
                    rel_path = os.path.relpath(fpath, target_base)
                    case_match = case_pattern.search(rel_path)
                    case_number = case_match.group(0) if case_match else ""
                    if case_numbers and case_number not in case_numbers:
                        continue
                    if batch_ids:
                        continue
                    try:
                        size = os.path.getsize(fpath)
                        mtime = datetime.fromtimestamp(os.path.getmtime(fpath))
                        if mtime.tzinfo is None:
                            mtime = mtime.replace(tzinfo=ZoneInfo("UTC"))
                        sha = file_hash(fpath)
                    except (OSError, PermissionError):
                        continue
                    archived_map[fpath] = ArchivedFile(
                        path=fpath,
                        filename=fname,
                        case_number=case_number,
                        batch_id="",
                        archived_at=mtime,
                        size=size,
                        sha256=sha,
                        action_id="",
                    )
        return list(archived_map.values())

    def _match_rule(self, case_number: str, batch_id: str) -> RetentionRule:
        rules = self.config.retention.rules
        if not rules:
            return RetentionRule(
                rule_id="default",
                name="默认规则",
                retention_days=self.config.retention.default_retention_days,
            )
        for rule in rules:
            case_ok = bool(re.search(rule.case_number_pattern, case_number or ""))
            batch_ok = bool(re.search(rule.batch_id_pattern, batch_id or ""))
            if case_ok and batch_ok:
                return rule
        return RetentionRule(
            rule_id="default",
            name="默认规则",
            retention_days=self.config.retention.default_retention_days,
        )

    def _parse_iso(self, s) -> datetime:
        if isinstance(s, datetime):
            dt = s
        elif not s:
            dt = datetime.now(ZoneInfo("UTC"))
        else:
            try:
                dt = datetime.fromisoformat(s)
            except (ValueError, TypeError):
                dt = datetime.now(ZoneInfo("UTC"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo("UTC"))
        return dt

    def _has_write_permission(self, path: str) -> bool:
        if not self.config.retention.check_write_permission:
            return True
        try:
            d = os.path.dirname(path)
            with tempfile.TemporaryFile(dir=d):
                return True
        except (OSError, PermissionError):
            return False

    def _check_conflicts(
        self,
        af: ArchivedFile,
        previous_marks: dict,
        check_config: bool = True,
    ) -> list[RetentionConflictDetail]:
        conflicts: list[RetentionConflictDetail] = []

        eq = self.error_queue.find_by_path(af.path)
        if eq is not None:
            conflicts.append(
                RetentionConflictDetail(
                    category=ConflictCategory.IN_ERROR_QUEUE,
                    detail=f"案件 {af.case_number} 文件 {af.filename} 仍在错误队列中 (错误: {eq.error})",
                    extra={"error": eq.error, "retry_count": eq.retry_count},
                )
            )

        if not os.path.exists(af.path):
            conflicts.append(
                RetentionConflictDetail(
                    category=ConflictCategory.FILE_MISSING,
                    detail=f"归档文件已丢失: {af.path}",
                    extra={"expected_path": af.path},
                )
            )

        if os.path.exists(af.path):
            try:
                st = os.stat(af.path)
                if not (st.st_mode & stat.S_IWUSR):
                    conflicts.append(
                        RetentionConflictDetail(
                            category=ConflictCategory.NO_WRITE_PERMISSION,
                            detail=f"目标文件无写权限: {af.path}",
                            extra={"path": af.path},
                        )
                    )
            except OSError:
                pass

        if not self._has_write_permission(af.path):
            if not any(c.category == ConflictCategory.NO_WRITE_PERMISSION for c in conflicts):
                conflicts.append(
                    RetentionConflictDetail(
                        category=ConflictCategory.NO_WRITE_PERMISSION,
                        detail=f"目标路径无写权限 (父目录不可写): {af.path}",
                        extra={"path": af.path},
                    )
                )

        idx_key = os.path.abspath(af.path)
        if idx_key in previous_marks:
            mark_info = previous_marks[idx_key]
            if mark_info.get("status") in ("marked", "deferred"):
                conflicts.append(
                    RetentionConflictDetail(
                        category=ConflictCategory.DUPLICATE_MARK,
                        detail=f"文件已被 {mark_info.get('run_id', '未知批次')} 标记为 {mark_info.get('status')}",
                        extra={"run_id": mark_info.get("run_id"), "status": mark_info.get("status")},
                    )
                )

        freeze_idx_path = os.path.join(self.logging_dir, "freeze_state.json")
        if os.path.exists(freeze_idx_path):
            try:
                freeze_state = load_json(freeze_idx_path, default={})
                freeze_idx = freeze_state.get("freeze_index", {})
                if idx_key in freeze_idx and freeze_idx[idx_key].get("status") == "active":
                    order_id = freeze_idx[idx_key].get("order_id", "未知封存单")
                    conflicts.append(
                        RetentionConflictDetail(
                            category=ConflictCategory.FROZEN_FILE,
                            detail=f"文件已被封存单 {order_id} 封存，不得清理",
                            extra={"order_id": order_id, "frozen_at": freeze_idx[idx_key].get("frozen_at", "")},
                        )
                    )
            except Exception:
                pass

        if check_config:
            change_msg = self._check_config_changed()
            if change_msg:
                conflicts.append(
                    RetentionConflictDetail(
                        category=ConflictCategory.RULE_CHANGED,
                        detail="保留规则配置已发生变化，建议先重新确认",
                        extra={"detail": change_msg},
                    )
                )

        return conflicts

    def _get_previous_marks_index(self) -> dict:
        return dict(self._state.get("mark_index", {}))

    def _update_mark_index(self, items: list[DisposalItem], run_id: str) -> None:
        idx = self._state.setdefault("mark_index", {})
        for item in items:
            if item.disposal_status == DisposalStatus.MARKED:
                if item.file:
                    key = os.path.abspath(item.file.path)
                    idx[key] = {
                        "status": "marked",
                        "run_id": run_id,
                        "item_id": item.item_id,
                        "marked_at": item.marked_at,
                    }
            elif item.disposal_status == DisposalStatus.DEFERRED:
                if item.file:
                    key = os.path.abspath(item.file.path)
                    idx[key] = {
                        "status": "deferred",
                        "run_id": run_id,
                        "item_id": item.item_id,
                        "defer_until": item.defer_until,
                    }
            elif item.disposal_status == DisposalStatus.UNDO:
                if item.file:
                    key = os.path.abspath(item.file.path)
                    if key in idx:
                        del idx[key]

    def preview(
        self,
        case_numbers: Optional[list[str]] = None,
        batch_ids: Optional[list[str]] = None,
        as_of: Optional[datetime] = None,
    ) -> RetentionPreviewResult:
        self._reload_if_needed()
        as_of = as_of or datetime.now(ZoneInfo("UTC"))
        if as_of.tzinfo is None:
            as_of = as_of.replace(tzinfo=ZoneInfo("UTC"))
        archived = self.scan_archived_files(case_numbers, batch_ids)
        previous_marks = self._get_previous_marks_index()

        items: list[DisposalItem] = []
        rule_summary: dict = {}
        expired_count = 0
        deferred_count = 0
        conflict_count = 0
        pending_count = 0

        for af in archived:
            rule = self._match_rule(af.case_number, af.batch_id)
            archived_dt = self._parse_iso(af.archived_at)
            expires_dt = archived_dt + timedelta(days=rule.retention_days)
            is_expired = expires_dt <= as_of

            key = f"{rule.rule_id}:{rule.name}"
            rule_summary[key] = rule_summary.get(key, 0) + 1

            conflicts = self._check_conflicts(af, previous_marks, check_config=False)
            status = DisposalStatus.PENDING
            defer_until = ""
            defer_reason = ""
            defer_run_id = ""

            idx_key = os.path.abspath(af.path)
            if idx_key in previous_marks:
                mark_info = previous_marks[idx_key]
                if mark_info.get("status") == "deferred":
                    deferred_count += 1
                    status = DisposalStatus.DEFERRED
                    defer_until = mark_info.get("defer_until", "")
                    defer_run_id = mark_info.get("run_id", "")
                    defer_reason = "已被暂缓标记"
                elif mark_info.get("status") == "marked":
                    status = DisposalStatus.MARKED

            if status == DisposalStatus.PENDING:
                if conflicts:
                    status = DisposalStatus.CONFLICT
                    conflict_count += 1
                elif is_expired:
                    status = DisposalStatus.EXPIRED
                    expired_count += 1
                else:
                    pending_count += 1

            item = DisposalItem(
                file=af,
                matched_rule_id=rule.rule_id,
                matched_rule_name=rule.name,
                retention_days=rule.retention_days,
                expires_at=expires_dt.isoformat(),
                disposal_status=status,
                defer_reason=defer_reason,
                defer_until=defer_until,
                defer_run_id=defer_run_id,
                conflicts=conflicts,
            )
            items.append(item)

        return RetentionPreviewResult(
            total_files=len(archived),
            expired_count=expired_count,
            deferred_count=deferred_count,
            conflict_count=conflict_count,
            pending_count=pending_count,
            items=items,
            rule_summary=rule_summary,
        )

    def generate_disposal_list(
        self,
        case_numbers: Optional[list[str]] = None,
        batch_ids: Optional[list[str]] = None,
        notes: str = "",
        as_of: Optional[datetime] = None,
    ) -> RetentionRun:
        self._reload_if_needed()
        as_of = as_of or datetime.now(ZoneInfo("UTC"))
        preview = self.preview(case_numbers, batch_ids, as_of)

        run = RetentionRun(
            run_type="generate",
            operator=self.config.operator,
            config_snapshot=self._config_signature(),
            notes=notes,
        )

        processed_items: list[DisposalItem] = []
        previous_marks = self._get_previous_marks_index()
        marked = 0
        conflicts = 0
        deferred = 0

        for item in preview.items:
            if item.disposal_status == DisposalStatus.DEFERRED:
                deferred += 1
                processed_items.append(item)
                continue
            if item.disposal_status == DisposalStatus.CONFLICT or item.conflicts:
                item.disposal_status = DisposalStatus.CONFLICT
                conflicts += 1
                processed_items.append(item)
                continue
            if item.disposal_status == DisposalStatus.EXPIRED:
                item.disposal_status = DisposalStatus.MARKED
                item.marked_run_id = run.run_id
                item.marked_at = iso_now()
                marked += 1
                processed_items.append(item)
                continue
            processed_items.append(item)

        run.items = processed_items
        run.total_marked = marked
        run.total_deferred = deferred
        run.total_conflicts = conflicts

        rule_change_msg = self._check_config_changed()
        if rule_change_msg:
            for item in run.items:
                has_rule_change = any(
                    c.category == ConflictCategory.RULE_CHANGED for c in item.conflicts
                )
                if not has_rule_change:
                    item.conflicts.append(
                        RetentionConflictDetail(
                            category=ConflictCategory.RULE_CHANGED,
                            detail="保留规则配置已发生变化，建议先重新确认",
                            extra={"detail": rule_change_msg},
                        )
                    )
                    if item.disposal_status == DisposalStatus.MARKED:
                        item.disposal_status = DisposalStatus.CONFLICT
                        marked -= 1
                        conflicts += 1
            run.total_marked = marked
            run.total_conflicts = conflicts

        self._write_log({
            "event": "retention_generate",
            "run_id": run.run_id,
            "operator": run.operator,
            "total_files": preview.total_files,
            "marked": marked,
            "deferred": deferred,
            "conflicts": conflicts,
            "notes": notes,
        })

        mark_index_items = [
            it for it in processed_items
            if it.disposal_status == DisposalStatus.MARKED
        ]
        self._update_mark_index(mark_index_items, run.run_id)
        runs = self._state.setdefault("retention_runs", [])
        runs.append(run.to_dict())
        self._state["config_signature"] = self._config_signature()
        self._save_state()

        return run

    def mark_deferred(
        self,
        paths: list[str],
        reason: str = "",
        defer_days: int = 30,
        case_numbers: Optional[list[str]] = None,
        batch_ids: Optional[list[str]] = None,
    ) -> RetentionRun:
        self._reload_if_needed()
        preview = self.preview(case_numbers, batch_ids)

        run = RetentionRun(
            run_type="defer",
            operator=self.config.operator,
            config_snapshot=self._config_signature(),
            notes=reason,
        )

        abs_paths = {os.path.abspath(p) for p in paths}
        previous_marks = self._get_previous_marks_index()
        processed: list[DisposalItem] = []
        deferred_count = 0
        conflict_count = 0

        for item in preview.items:
            if not item.file:
                continue
            abs_path = os.path.abspath(item.file.path)
            if abs_path not in abs_paths:
                continue

            item_conflicts = [
                c for c in item.conflicts
                if c.category == ConflictCategory.IN_ERROR_QUEUE
                or c.category == ConflictCategory.FILE_MISSING
                or c.category == ConflictCategory.NO_WRITE_PERMISSION
            ]

            has_dup = any(
                c.category == ConflictCategory.DUPLICATE_MARK
                for c in item.conflicts
            )

            if item_conflicts or has_dup:
                if item_conflicts:
                    item.conflicts = item_conflicts
                else:
                    item.conflicts = [
                        c for c in item.conflicts
                        if c.category == ConflictCategory.DUPLICATE_MARK
                    ]
                item.disposal_status = DisposalStatus.CONFLICT
                conflict_count += 1
                processed.append(item)
                continue

            item.disposal_status = DisposalStatus.DEFERRED
            item.defer_reason = reason
            item.defer_run_id = run.run_id
            until_dt = datetime.now(ZoneInfo("UTC")) + timedelta(days=defer_days)
            item.defer_until = until_dt.isoformat()
            deferred_count += 1
            processed.append(item)

        run.items = processed
        run.total_deferred = deferred_count
        run.total_conflicts = conflict_count

        self._write_log({
            "event": "retention_defer",
            "run_id": run.run_id,
            "operator": run.operator,
            "paths": paths,
            "reason": reason,
            "defer_days": defer_days,
            "deferred_count": deferred_count,
            "conflict_count": conflict_count,
        })

        self._update_mark_index(processed, run.run_id)
        runs = self._state.setdefault("retention_runs", [])
        runs.append(run.to_dict())
        self._state["config_signature"] = self._config_signature()
        self._save_state()

        return run

    def undo_run(self, run_id: str) -> RetentionRun:
        self._reload_if_needed()
        runs = self._state.get("retention_runs", [])
        target_run_data = None
        target_idx = -1
        for i, rd in enumerate(runs):
            if rd.get("run_id") == run_id:
                target_run_data = rd
                target_idx = i
                break

        if target_run_data is None:
            raise ValueError(f"未找到运行记录: {run_id}")

        target_run = RetentionRun.from_dict(target_run_data)

        undo_run = RetentionRun(
            run_type="undo",
            operator=self.config.operator,
            config_snapshot=self._config_signature(),
            notes=f"撤销运行 {run_id}",
        )

        previous_marks = self._get_previous_marks_index()
        undone_items: list[DisposalItem] = []
        undone_count = 0
        conflict_count = 0

        for item in target_run.items:
            if not item.file:
                continue
            key = os.path.abspath(item.file.path)

            if item.disposal_status == DisposalStatus.MARKED:
                cur = previous_marks.get(key)
                if cur and cur.get("run_id") == run_id and cur.get("status") == "marked":
                    new_item = DisposalItem(
                        item_id=item.item_id,
                        file=item.file,
                        matched_rule_id=item.matched_rule_id,
                        matched_rule_name=item.matched_rule_name,
                        retention_days=item.retention_days,
                        expires_at=item.expires_at,
                        disposal_status=DisposalStatus.UNDO,
                        marked_run_id=item.marked_run_id,
                        marked_at=item.marked_at,
                        undo_run_id=undo_run.run_id,
                        undo_at=iso_now(),
                    )
                    undone_count += 1
                    undone_items.append(new_item)
                else:
                    item.disposal_status = DisposalStatus.CONFLICT
                    item.conflicts = [
                        RetentionConflictDetail(
                            category=ConflictCategory.DUPLICATE_MARK,
                            detail=f"无法撤销: 当前标记归属 {cur.get('run_id') if cur else '未知'}，非本次运行",
                            extra={"target_run_id": run_id, "current_run_id": cur.get("run_id") if cur else None},
                        )
                    ]
                    conflict_count += 1
                    undone_items.append(item)
            elif item.disposal_status == DisposalStatus.DEFERRED:
                if target_run.run_type != "defer":
                    continue
                cur = previous_marks.get(key)
                if cur and cur.get("run_id") == run_id and cur.get("status") == "deferred":
                    new_item = DisposalItem(
                        item_id=item.item_id,
                        file=item.file,
                        matched_rule_id=item.matched_rule_id,
                        matched_rule_name=item.matched_rule_name,
                        retention_days=item.retention_days,
                        expires_at=item.expires_at,
                        disposal_status=DisposalStatus.UNDO,
                        defer_run_id=item.defer_run_id,
                        defer_reason=item.defer_reason,
                        defer_until=item.defer_until,
                        undo_run_id=undo_run.run_id,
                        undo_at=iso_now(),
                    )
                    undone_count += 1
                    undone_items.append(new_item)
                else:
                    item.disposal_status = DisposalStatus.CONFLICT
                    item.conflicts = [
                        RetentionConflictDetail(
                            category=ConflictCategory.DUPLICATE_MARK,
                            detail=f"无法撤销暂缓: 当前标记归属 {cur.get('run_id') if cur else '未知'}，非本次运行",
                            extra={"target_run_id": run_id},
                        )
                    ]
                    conflict_count += 1
                    undone_items.append(item)

        undo_run.items = undone_items
        undo_run.total_undone = undone_count
        undo_run.total_conflicts = conflict_count

        self._write_log({
            "event": "retention_undo",
            "run_id": undo_run.run_id,
            "operator": undo_run.operator,
            "target_run_id": run_id,
            "undone_count": undone_count,
            "conflict_count": conflict_count,
        })

        self._update_mark_index(undone_items, undo_run.run_id)
        runs = self._state.setdefault("retention_runs", [])
        runs.append(undo_run.to_dict())
        self._state["config_signature"] = self._config_signature()
        self._save_state()

        return undo_run

    def list_runs(
        self,
        run_type: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[RetentionRun]:
        runs = self._state.get("retention_runs", [])
        result = []
        for rd in runs:
            r = RetentionRun.from_dict(rd)
            if run_type and r.run_type != run_type:
                continue
            result.append(r)
        if limit:
            result = result[-limit:]
        return result

    def get_run(self, run_id: str) -> Optional[RetentionRun]:
        for rd in self._state.get("retention_runs", []):
            if rd.get("run_id") == run_id:
                return RetentionRun.from_dict(rd)
        return None

    def get_marked_files(self) -> list[DisposalItem]:
        result = []
        idx = self._state.get("mark_index", {})
        preview = self.preview()
        for item in preview.items:
            if not item.file:
                continue
            key = os.path.abspath(item.file.path)
            if key in idx and idx[key].get("status") in ("marked", "deferred"):
                if idx[key].get("status") == "marked":
                    item.disposal_status = DisposalStatus.MARKED
                else:
                    item.disposal_status = DisposalStatus.DEFERRED
                    item.defer_until = idx[key].get("defer_until", "")
                item.marked_run_id = idx[key].get("run_id", "")
                result.append(item)
        return result

    def consistency_check(self) -> dict:
        idx = self._state.get("mark_index", {})
        runs = self._state.get("retention_runs", [])
        issues = []
        mark_paths = set(idx.keys())

        run_marked_paths = set()
        for rd in runs:
            r = RetentionRun.from_dict(rd)
            if r.run_type == "undo":
                for it in r.items:
                    if it.disposal_status == DisposalStatus.UNDO and it.file:
                        k = os.path.abspath(it.file.path)
                        run_marked_paths.discard(k)
            else:
                for it in r.items:
                    if it.disposal_status in (DisposalStatus.MARKED, DisposalStatus.DEFERRED) and it.file:
                        k = os.path.abspath(it.file.path)
                        run_marked_paths.add(k)

        orphan_in_idx = mark_paths - run_marked_paths
        missing_in_idx = run_marked_paths - mark_paths

        if orphan_in_idx:
            issues.append({
                "type": "orphan_index_entries",
                "count": len(orphan_in_idx),
                "paths": list(orphan_in_idx),
            })
        if missing_in_idx:
            issues.append({
                "type": "missing_index_entries",
                "count": len(missing_in_idx),
                "paths": list(missing_in_idx),
            })

        file_missing_count = 0
        for p in mark_paths:
            if not os.path.exists(p):
                file_missing_count += 1
        if file_missing_count:
            issues.append({
                "type": "marked_files_missing",
                "count": file_missing_count,
            })

        return {
            "total_runs": len(runs),
            "total_marked_index": len(idx),
            "issues": issues,
            "is_consistent": len(issues) == 0,
        }


def export_preview_json(preview: RetentionPreviewResult, output_path: str) -> None:
    save_json(output_path, preview.to_dict())


def export_preview_csv(preview: RetentionPreviewResult, output_path: str) -> None:
    import csv as csv_mod
    from scan_sorter.utils import ensure_dir
    ensure_dir(os.path.dirname(output_path))
    fieldnames = [
        "item_id", "filename", "path", "case_number", "batch_id",
        "archived_at", "expires_at", "size", "sha256",
        "matched_rule_id", "matched_rule_name", "retention_days",
        "disposal_status", "defer_reason", "defer_until",
        "conflict_count", "conflict_categories", "conflict_details",
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv_mod.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in preview.items:
            file_info = item.file.to_dict() if item.file else {}
            conflict_cats = ";".join(c.category.value for c in item.conflicts)
            conflict_details = ";".join(c.detail for c in item.conflicts)
            row = {
                "item_id": item.item_id,
                "filename": file_info.get("filename", ""),
                "path": file_info.get("path", ""),
                "case_number": file_info.get("case_number", ""),
                "batch_id": file_info.get("batch_id", ""),
                "archived_at": file_info.get("archived_at", ""),
                "expires_at": item.expires_at,
                "size": file_info.get("size", 0),
                "sha256": file_info.get("sha256", ""),
                "matched_rule_id": item.matched_rule_id,
                "matched_rule_name": item.matched_rule_name,
                "retention_days": item.retention_days,
                "disposal_status": item.disposal_status.value,
                "defer_reason": item.defer_reason,
                "defer_until": item.defer_until,
                "conflict_count": len(item.conflicts),
                "conflict_categories": conflict_cats,
                "conflict_details": conflict_details,
            }
            writer.writerow(row)


def export_run_json(run: RetentionRun, output_path: str) -> None:
    save_json(output_path, run.to_dict())


def export_run_csv(run: RetentionRun, output_path: str) -> None:
    import csv as csv_mod
    from scan_sorter.utils import ensure_dir
    ensure_dir(os.path.dirname(output_path))
    fieldnames = [
        "run_id", "run_type", "created_at", "operator",
        "item_id", "filename", "path", "case_number", "batch_id",
        "archived_at", "expires_at",
        "matched_rule_id", "matched_rule_name", "retention_days",
        "disposal_status", "marked_at", "defer_reason", "defer_until",
        "undo_at", "conflict_count", "conflict_categories", "conflict_details",
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv_mod.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in run.items:
            file_info = item.file.to_dict() if item.file else {}
            conflict_cats = ";".join(c.category.value for c in item.conflicts)
            conflict_details = ";".join(c.detail for c in item.conflicts)
            row = {
                "run_id": run.run_id,
                "run_type": run.run_type,
                "created_at": run.created_at,
                "operator": run.operator,
                "item_id": item.item_id,
                "filename": file_info.get("filename", ""),
                "path": file_info.get("path", ""),
                "case_number": file_info.get("case_number", ""),
                "batch_id": file_info.get("batch_id", ""),
                "archived_at": file_info.get("archived_at", ""),
                "expires_at": item.expires_at,
                "matched_rule_id": item.matched_rule_id,
                "matched_rule_name": item.matched_rule_name,
                "retention_days": item.retention_days,
                "disposal_status": item.disposal_status.value,
                "marked_at": item.marked_at,
                "defer_reason": item.defer_reason,
                "defer_until": item.defer_until,
                "undo_at": item.undo_at,
                "conflict_count": len(item.conflicts),
                "conflict_categories": conflict_cats,
                "conflict_details": conflict_details,
            }
            writer.writerow(row)


def export_history_json(runs: list[RetentionRun], output_path: str) -> None:
    save_json(output_path, [r.to_dict() for r in runs])


def export_history_csv(runs: list[RetentionRun], output_path: str) -> None:
    import csv as csv_mod
    from scan_sorter.utils import ensure_dir
    ensure_dir(os.path.dirname(output_path))
    fieldnames = [
        "run_id", "run_type", "created_at", "operator",
        "total_items", "total_marked", "total_deferred",
        "total_conflicts", "total_undone", "notes",
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv_mod.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for run in runs:
            row = {
                "run_id": run.run_id,
                "run_type": run.run_type,
                "created_at": run.created_at,
                "operator": run.operator,
                "total_items": len(run.items),
                "total_marked": run.total_marked,
                "total_deferred": run.total_deferred,
                "total_conflicts": run.total_conflicts,
                "total_undone": run.total_undone,
                "notes": run.notes,
            }
            writer.writerow(row)
