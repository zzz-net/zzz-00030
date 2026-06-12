from __future__ import annotations

import csv
import json
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
    FreezeConflictCategory,
    FreezeConflictDetail,
    FreezeItem,
    FreezeOrder,
    FreezePreviewResult,
    FreezeStatus,
)
from scan_sorter.queue_manager import ErrorQueue, ProcessingQueue
from scan_sorter.utils import append_jsonl, file_hash, iso_now, load_json, save_json


class FreezeManager:
    def __init__(self, config: AppConfig):
        self.config = config
        self._reload_if_needed()
        self.logging_dir = os.path.abspath(config.logging.dir)
        self.state_path = config.freeze.state_path(self.logging_dir)
        self.log_path = config.freeze.log_path(self.logging_dir)
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
                "freeze_orders": [],
                "config_signature": self._config_signature(),
                "freeze_index": {},
            }
        return data

    def _save_state(self) -> None:
        save_json(self.state_path, self._state)

    def _config_signature(self) -> dict:
        return {
            "default_reason": self.config.freeze.default_reason,
            "default_valid_days": self.config.freeze.default_valid_days,
            "max_frozen_files": self.config.freeze.max_frozen_files,
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
        if not self.config.freeze.check_write_permission:
            return True
        try:
            d = os.path.dirname(path)
            with tempfile.TemporaryFile(dir=d):
                return True
        except (OSError, PermissionError):
            return False

    def _count_active_frozen(self) -> int:
        idx = self._state.get("freeze_index", {})
        count = 0
        for info in idx.values():
            if info.get("status") == "active":
                count += 1
        return count

    def scan_archived_files(
        self,
        case_numbers: Optional[list[str]] = None,
        batch_ids: Optional[list[str]] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
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

            if date_from:
                df = date_from
                if df.tzinfo is None:
                    df = df.replace(tzinfo=ZoneInfo("UTC"))
                if arch_ts < df:
                    continue
            if date_to:
                dt = date_to
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=ZoneInfo("UTC"))
                if arch_ts > dt:
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
                        if date_from:
                            df = date_from
                            if df.tzinfo is None:
                                df = df.replace(tzinfo=ZoneInfo("UTC"))
                            if mtime < df:
                                continue
                        if date_to:
                            dt = date_to
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=ZoneInfo("UTC"))
                            if mtime > dt:
                                continue
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

    def _check_conflicts(
        self,
        af: ArchivedFile,
        previous_freezes: dict,
        check_config: bool = True,
    ) -> list[FreezeConflictDetail]:
        conflicts: list[FreezeConflictDetail] = []

        pq = self.processing_queue.find_by_path(af.path)
        if pq is not None:
            batch_id = pq.get("batch_id", "") if isinstance(pq, dict) else getattr(pq, "batch_id", "")
            conflicts.append(
                FreezeConflictDetail(
                    category=FreezeConflictCategory.IN_PROCESSING_QUEUE,
                    detail=f"案件 {af.case_number} 文件 {af.filename} 仍在处理队列中",
                    extra={"batch_id": batch_id},
                )
            )

        eq = self.error_queue.find_by_path(af.path)
        if eq is not None:
            conflicts.append(
                FreezeConflictDetail(
                    category=FreezeConflictCategory.IN_ERROR_QUEUE,
                    detail=f"案件 {af.case_number} 文件 {af.filename} 仍在错误队列中 (错误: {eq.error})",
                    extra={"error": eq.error, "retry_count": eq.retry_count},
                )
            )

        if not os.path.exists(af.path):
            conflicts.append(
                FreezeConflictDetail(
                    category=FreezeConflictCategory.FILE_MISSING,
                    detail=f"归档文件已丢失: {af.path}",
                    extra={"expected_path": af.path},
                )
            )

        if os.path.exists(af.path):
            try:
                st = os.stat(af.path)
                if not (st.st_mode & stat.S_IWUSR):
                    conflicts.append(
                        FreezeConflictDetail(
                            category=FreezeConflictCategory.NO_WRITE_PERMISSION,
                            detail=f"目标文件无写权限: {af.path}",
                            extra={"path": af.path},
                        )
                    )
            except OSError:
                pass

        if not self._has_write_permission(af.path):
            if not any(c.category == FreezeConflictCategory.NO_WRITE_PERMISSION for c in conflicts):
                conflicts.append(
                    FreezeConflictDetail(
                        category=FreezeConflictCategory.NO_WRITE_PERMISSION,
                        detail=f"目标路径无写权限 (父目录不可写): {af.path}",
                        extra={"path": af.path},
                    )
                )

        idx_key = os.path.abspath(af.path)
        if idx_key in previous_freezes:
            freeze_info = previous_freezes[idx_key]
            if freeze_info.get("status") == "active":
                conflicts.append(
                    FreezeConflictDetail(
                        category=FreezeConflictCategory.DUPLICATE_FREEZE,
                        detail=f"文件已被 {freeze_info.get('order_id', '未知封存单')} 封存",
                        extra={"order_id": freeze_info.get("order_id"), "status": freeze_info.get("status")},
                    )
                )

        if check_config:
            change_msg = self._check_config_changed()
            if change_msg:
                conflicts.append(
                    FreezeConflictDetail(
                        category=FreezeConflictCategory.CONFIG_CHANGED,
                        detail="封存配置已发生变化，建议先重新确认",
                        extra={"detail": change_msg},
                    )
                )

        return conflicts

    def _get_previous_freezes_index(self) -> dict:
        return dict(self._state.get("freeze_index", {}))

    def _update_freeze_index(self, items: list[FreezeItem], order_id: str, is_freeze: bool = True) -> None:
        idx = self._state.setdefault("freeze_index", {})
        for item in items:
            if item.file:
                key = os.path.abspath(item.file.path)
                if is_freeze and item.freeze_status == FreezeStatus.ACTIVE:
                    idx[key] = {
                        "status": "active",
                        "order_id": order_id,
                        "item_id": item.item_id,
                        "frozen_at": item.frozen_at,
                        "expires_at": "",
                    }
                elif not is_freeze and item.freeze_status == FreezeStatus.RELEASED:
                    if key in idx:
                        del idx[key]

    def _check_state_file_writable(self) -> bool:
        try:
            d = os.path.dirname(self.state_path)
            with tempfile.TemporaryFile(dir=d):
                return True
        except (OSError, PermissionError):
            return False

    def preview_freeze(
        self,
        case_numbers: Optional[list[str]] = None,
        batch_ids: Optional[list[str]] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        reason: Optional[str] = None,
        valid_days: Optional[int] = None,
    ) -> FreezePreviewResult:
        self._reload_if_needed()
        reason = reason or self.config.freeze.default_reason
        valid_days = valid_days or self.config.freeze.default_valid_days

        archived = self.scan_archived_files(case_numbers, batch_ids, date_from, date_to)
        previous_freezes = self._get_previous_freezes_index()

        items: list[FreezeItem] = []
        will_freeze = 0
        will_conflict = 0
        now = datetime.now(ZoneInfo("UTC"))
        expires_at = (now + timedelta(days=valid_days)).isoformat()

        active_count = self._count_active_frozen()
        max_count = self.config.freeze.max_frozen_files

        for af in archived:
            conflicts = self._check_conflicts(af, previous_freezes, check_config=False)
            status = FreezeStatus.ACTIVE

            if conflicts:
                status = FreezeStatus.CONFLICT
                will_conflict += 1
            else:
                will_freeze += 1

            item = FreezeItem(
                file=af,
                freeze_status=status,
                conflicts=conflicts,
            )
            items.append(item)

        if active_count + will_freeze > max_count:
            overflow = active_count + will_freeze - max_count
            for item in reversed(items):
                if overflow <= 0:
                    break
                if item.freeze_status == FreezeStatus.ACTIVE:
                    item.freeze_status = FreezeStatus.CONFLICT
                    item.conflicts.append(
                        FreezeConflictDetail(
                            category=FreezeConflictCategory.MAX_COUNT_EXCEEDED,
                            detail=f"超出最大封存数量限制 (最大{max_count}个)",
                            extra={"max_count": max_count, "current_count": active_count},
                        )
                    )
                    will_freeze -= 1
                    will_conflict += 1
                    overflow -= 1

        return FreezePreviewResult(
            total_files=len(archived),
            will_freeze=will_freeze,
            will_conflict=will_conflict,
            items=items,
            reason=reason,
            valid_days=valid_days,
            expires_at=expires_at,
        )

    def confirm_freeze(
        self,
        case_numbers: Optional[list[str]] = None,
        batch_ids: Optional[list[str]] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        reason: Optional[str] = None,
        valid_days: Optional[int] = None,
        notes: str = "",
    ) -> FreezeOrder:
        self._reload_if_needed()
        reason = reason or self.config.freeze.default_reason
        valid_days = valid_days or self.config.freeze.default_valid_days

        if not self._check_state_file_writable():
            raise PermissionError(f"状态文件无写权限: {self.state_path}")

        preview = self.preview_freeze(case_numbers, batch_ids, date_from, date_to, reason, valid_days)

        now = datetime.now(ZoneInfo("UTC"))
        order = FreezeOrder(
            order_type="freeze",
            operator=self.config.operator,
            reason=reason,
            valid_days=valid_days,
            expires_at=(now + timedelta(days=valid_days)).isoformat(),
            config_snapshot=self._config_signature(),
            notes=notes,
            status="active",
        )

        processed_items: list[FreezeItem] = []
        frozen = 0
        conflicts = 0

        for item in preview.items:
            if item.freeze_status == FreezeStatus.CONFLICT:
                conflicts += 1
                item.freeze_order_id = order.order_id
                processed_items.append(item)
                continue

            item.freeze_status = FreezeStatus.ACTIVE
            item.freeze_order_id = order.order_id
            item.frozen_at = iso_now()
            frozen += 1
            processed_items.append(item)

        rule_change_msg = self._check_config_changed()
        if rule_change_msg:
            for item in processed_items:
                has_config_change = any(
                    c.category == FreezeConflictCategory.CONFIG_CHANGED for c in item.conflicts
                )
                if not has_config_change:
                    item.conflicts.append(
                        FreezeConflictDetail(
                            category=FreezeConflictCategory.CONFIG_CHANGED,
                            detail="封存配置已发生变化，建议先重新确认",
                            extra={"detail": rule_change_msg},
                        )
                    )
                    if item.freeze_status == FreezeStatus.ACTIVE:
                        item.freeze_status = FreezeStatus.CONFLICT
                        frozen -= 1
                        conflicts += 1

        order.items = processed_items
        order.total_files = len(processed_items)
        order.total_frozen = frozen
        order.total_conflicts = conflicts

        self._write_log({
            "event": "freeze_create",
            "order_id": order.order_id,
            "operator": order.operator,
            "reason": reason,
            "valid_days": valid_days,
            "total_files": order.total_files,
            "frozen": frozen,
            "conflicts": conflicts,
            "notes": notes,
        })

        freeze_items = [it for it in processed_items if it.freeze_status == FreezeStatus.ACTIVE]
        self._update_freeze_index(freeze_items, order.order_id, is_freeze=True)
        orders = self._state.setdefault("freeze_orders", [])
        orders.append(order.to_dict())
        self._state["config_signature"] = self._config_signature()
        self._save_state()

        return order

    def release_order(self, order_id: str, notes: str = "") -> FreezeOrder:
        self._reload_if_needed()

        if not self._check_state_file_writable():
            raise PermissionError(f"状态文件无写权限: {self.state_path}")

        orders = self._state.get("freeze_orders", [])
        target_order = None
        target_idx = -1
        for i, o in enumerate(orders):
            if o.get("order_id") == order_id:
                target_order = FreezeOrder.from_dict(o)
                target_idx = i
                break

        if target_order is None:
            raise ValueError(f"封存单不存在: {order_id}")

        if target_order.status == "released":
            raise ValueError(f"封存单已解封: {order_id}")

        now = datetime.now(ZoneInfo("UTC"))
        release_order = FreezeOrder(
            order_type="release",
            operator=self.config.operator,
            reason=f"解封封存单 {order_id}",
            valid_days=0,
            expires_at="",
            config_snapshot=self._config_signature(),
            notes=notes,
            status="completed",
        )

        released = 0
        conflicts = 0
        processed_items: list[FreezeItem] = []
        previous_freezes = self._get_previous_freezes_index()

        for item in target_order.items:
            if item.freeze_status != FreezeStatus.ACTIVE:
                new_item = FreezeItem(
                    item_id=item.item_id,
                    file=item.file,
                    freeze_status=FreezeStatus.CONFLICT,
                    conflicts=[
                        FreezeConflictDetail(
                            category=FreezeConflictCategory.DUPLICATE_FREEZE,
                            detail=f"文件当前状态为 {item.freeze_status.value}，无法解封",
                            extra={"original_status": item.freeze_status.value},
                        )
                    ],
                    freeze_order_id=order_id,
                    frozen_at=item.frozen_at,
                    released_at=iso_now(),
                    release_order_id=release_order.order_id,
                )
                conflicts += 1
                processed_items.append(new_item)
                continue

            if item.file:
                key = os.path.abspath(item.file.path)
                if key not in previous_freezes or previous_freezes[key].get("order_id") != order_id:
                    new_item = FreezeItem(
                        item_id=item.item_id,
                        file=item.file,
                        freeze_status=FreezeStatus.CONFLICT,
                        conflicts=[
                            FreezeConflictDetail(
                                category=FreezeConflictCategory.DUPLICATE_FREEZE,
                                detail="文件当前未被本封存单封存",
                                extra={},
                            )
                        ],
                        freeze_order_id=order_id,
                        frozen_at=item.frozen_at,
                        released_at=iso_now(),
                        release_order_id=release_order.order_id,
                    )
                    conflicts += 1
                    processed_items.append(new_item)
                    continue

            new_item = FreezeItem(
                item_id=item.item_id,
                file=item.file,
                freeze_status=FreezeStatus.RELEASED,
                conflicts=[],
                freeze_order_id=order_id,
                frozen_at=item.frozen_at,
                released_at=iso_now(),
                release_order_id=release_order.order_id,
            )
            released += 1
            processed_items.append(new_item)

        release_order.items = processed_items
        release_order.total_files = len(processed_items)
        release_order.total_released = released
        release_order.total_conflicts = conflicts

        target_order.status = "released"
        target_order.total_released = released
        orders[target_idx] = target_order.to_dict()

        release_items = [it for it in processed_items if it.freeze_status == FreezeStatus.RELEASED]
        self._update_freeze_index(release_items, order_id, is_freeze=False)

        orders.append(release_order.to_dict())
        self._state["freeze_orders"] = orders
        self._save_state()

        self._write_log({
            "event": "freeze_release",
            "order_id": release_order.order_id,
            "original_order_id": order_id,
            "operator": release_order.operator,
            "total_files": release_order.total_files,
            "released": released,
            "conflicts": conflicts,
            "notes": notes,
        })

        return release_order

    def list_orders(
        self,
        order_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[FreezeOrder]:
        orders_raw = self._state.get("freeze_orders", [])
        orders = [FreezeOrder.from_dict(o) for o in orders_raw]

        if order_type:
            orders = [o for o in orders if o.order_type == order_type]
        if status:
            orders = [o for o in orders if o.status == status]

        orders.sort(key=lambda o: o.created_at, reverse=True)

        if limit and limit > 0:
            orders = orders[:limit]

        return orders

    def get_order(self, order_id: str) -> Optional[FreezeOrder]:
        orders_raw = self._state.get("freeze_orders", [])
        for o in orders_raw:
            if o.get("order_id") == order_id:
                return FreezeOrder.from_dict(o)
        return None

    def get_active_frozen_files(self) -> list[FreezeItem]:
        idx = self._get_previous_freezes_index()
        items: list[FreezeItem] = []
        orders_raw = self._state.get("freeze_orders", [])

        for order_raw in orders_raw:
            order = FreezeOrder.from_dict(order_raw)
            for item in order.items:
                if item.file:
                    key = os.path.abspath(item.file.path)
                    if key in idx and idx[key].get("order_id") == order.order_id:
                        items.append(item)
        return items

    def consistency_check(self) -> dict:
        issues: list[str] = []
        idx = self._state.get("freeze_index", {})
        orders_raw = self._state.get("freeze_orders", [])

        index_paths = set(idx.keys())
        order_active_paths: set[str] = set()

        for order_raw in orders_raw:
            order = FreezeOrder.from_dict(order_raw)
            if order.status == "active" and order.order_type == "freeze":
                for item in order.items:
                    if item.freeze_status == FreezeStatus.ACTIVE and item.file:
                        order_active_paths.add(os.path.abspath(item.file.path))

        extra_in_index = index_paths - order_active_paths
        missing_in_index = order_active_paths - index_paths

        for p in extra_in_index:
            issues.append(f"索引中有但活跃封存单中没有: {p}")
        for p in missing_in_index:
            issues.append(f"活跃封存单中有但索引中没有: {p}")

        return {
            "is_consistent": len(issues) == 0,
            "issues": issues,
            "index_count": len(index_paths),
            "order_active_count": len(order_active_paths),
        }


def export_preview_json(preview: FreezePreviewResult, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(preview.to_dict(), f, ensure_ascii=False, indent=2)


def export_preview_csv(preview: FreezePreviewResult, output_path: str) -> None:
    fieldnames = [
        "filename", "path", "case_number", "batch_id",
        "archived_at", "size", "freeze_status",
        "conflict_count", "conflict_categories", "conflict_details",
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in preview.items:
            row = {
                "filename": item.file.filename if item.file else "",
                "path": item.file.path if item.file else "",
                "case_number": item.file.case_number if item.file else "",
                "batch_id": item.file.batch_id if item.file else "",
                "archived_at": item.file.archived_at.isoformat() if item.file and item.file.archived_at else "",
                "size": item.file.size if item.file else 0,
                "freeze_status": item.freeze_status.value,
                "conflict_count": len(item.conflicts),
                "conflict_categories": "; ".join([c.category.value for c in item.conflicts]),
                "conflict_details": "; ".join([c.detail for c in item.conflicts]),
            }
            writer.writerow(row)


def export_order_json(order: FreezeOrder, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(order.to_dict(), f, ensure_ascii=False, indent=2)


def export_order_csv(order: FreezeOrder, output_path: str) -> None:
    fieldnames = [
        "order_id", "order_type", "operator", "reason",
        "item_id", "filename", "path", "case_number", "batch_id",
        "freeze_status", "frozen_at", "released_at",
        "conflict_count", "conflict_categories", "conflict_details",
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in order.items:
            row = {
                "order_id": order.order_id,
                "order_type": order.order_type,
                "operator": order.operator,
                "reason": order.reason,
                "item_id": item.item_id,
                "filename": item.file.filename if item.file else "",
                "path": item.file.path if item.file else "",
                "case_number": item.file.case_number if item.file else "",
                "batch_id": item.file.batch_id if item.file else "",
                "freeze_status": item.freeze_status.value,
                "frozen_at": item.frozen_at,
                "released_at": item.released_at,
                "conflict_count": len(item.conflicts),
                "conflict_categories": "; ".join([c.category.value for c in item.conflicts]),
                "conflict_details": "; ".join([c.detail for c in item.conflicts]),
            }
            writer.writerow(row)


def export_history_json(orders: list[FreezeOrder], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([o.to_dict() for o in orders], f, ensure_ascii=False, indent=2)


def export_history_csv(orders: list[FreezeOrder], output_path: str) -> None:
    fieldnames = [
        "order_id", "order_type", "created_at", "operator",
        "reason", "valid_days", "expires_at", "status",
        "total_files", "total_frozen", "total_conflicts", "total_released",
        "notes",
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for order in orders:
            row = {
                "order_id": order.order_id,
                "order_type": order.order_type,
                "created_at": order.created_at,
                "operator": order.operator,
                "reason": order.reason,
                "valid_days": order.valid_days,
                "expires_at": order.expires_at,
                "status": order.status,
                "total_files": order.total_files,
                "total_frozen": order.total_frozen,
                "total_conflicts": order.total_conflicts,
                "total_released": order.total_released,
                "notes": order.notes,
            }
            writer.writerow(row)
