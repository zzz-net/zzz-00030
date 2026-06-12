from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from scan_sorter.config import AppConfig, load_config
from scan_sorter.models import ActionRecord, BatchRecord, ErrorItem
from scan_sorter.utils import append_jsonl, file_hash, load_json, read_jsonl, save_json


class MigrationItemType(Enum):
    QUEUE = "queue"
    ERROR_QUEUE = "error_queue"
    BATCH_HISTORY = "batch_history"
    ACTION_LOG = "action_log"


class MigrationAction(Enum):
    AUTO_MIGRATE = "auto_migrate"
    CONFLICT = "conflict"
    MANUAL = "manual"
    SKIPPED = "skipped"


class ConflictType(Enum):
    TARGET_DIR_EXISTS = "target_dir_exists"
    TARGET_FILE_EXISTS = "target_file_exists"
    PATTERN_MISMATCH = "pattern_mismatch"
    CASE_NUMBER_MISMATCH = "case_number_mismatch"
    ACTION_TYPE_CHANGE = "action_type_change"
    PATH_NOT_EXIST = "path_not_exist"
    OPERATOR_MISMATCH = "operator_mismatch"
    STRUCTURE_CHANGE = "structure_change"
    FILE_PATTERN_MISMATCH = "file_pattern_mismatch"


@dataclass
class ConfigDiff:
    old_intake_dir: str
    new_intake_dir: str
    old_target_base: str
    new_target_base: str
    old_operator: str
    new_operator: str
    old_case_pattern: str
    new_case_pattern: str
    old_file_pattern: str
    new_file_pattern: str
    old_target_structure: str
    new_target_structure: str
    old_action: str
    new_action: str

    @property
    def intake_changed(self) -> bool:
        return self.old_intake_dir != self.new_intake_dir

    @property
    def target_base_changed(self) -> bool:
        return self.old_target_base != self.new_target_base

    @property
    def operator_changed(self) -> bool:
        return self.old_operator != self.new_operator

    @property
    def case_pattern_changed(self) -> bool:
        return self.old_case_pattern != self.new_case_pattern

    @property
    def file_pattern_changed(self) -> bool:
        return self.old_file_pattern != self.new_file_pattern

    @property
    def target_structure_changed(self) -> bool:
        return self.old_target_structure != self.new_target_structure

    @property
    def action_changed(self) -> bool:
        return self.old_action != self.new_action

    @property
    def has_changes(self) -> bool:
        return any([
            self.intake_changed,
            self.target_base_changed,
            self.operator_changed,
            self.case_pattern_changed,
            self.file_pattern_changed,
            self.target_structure_changed,
            self.action_changed,
        ])

    def to_dict(self) -> dict:
        return {
            "intake_dir": {"old": self.old_intake_dir, "new": self.new_intake_dir},
            "target_base": {"old": self.old_target_base, "new": self.new_target_base},
            "operator": {"old": self.old_operator, "new": self.new_operator},
            "case_number_pattern": {"old": self.old_case_pattern, "new": self.new_case_pattern},
            "file_pattern": {"old": self.old_file_pattern, "new": self.new_file_pattern},
            "target_structure": {"old": self.old_target_structure, "new": self.new_target_structure},
            "action": {"old": self.old_action, "new": self.new_action},
        }


@dataclass
class MigrationItem:
    item_type: MigrationItemType
    record_id: str
    old_value: str
    new_value: str
    field_name: str
    action: MigrationAction
    conflict_type: Optional[ConflictType] = None
    conflict_detail: Optional[str] = None
    fingerprint: str = ""
    migrated: bool = False

    def to_dict(self) -> dict:
        return {
            "item_type": self.item_type.value,
            "record_id": self.record_id,
            "field_name": self.field_name,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "action": self.action.value,
            "conflict_type": self.conflict_type.value if self.conflict_type else None,
            "conflict_detail": self.conflict_detail,
            "fingerprint": self.fingerprint,
            "migrated": self.migrated,
        }


@dataclass
class MigrationPlan:
    config_diff: ConfigDiff
    items: list[MigrationItem] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def auto_migrate_count(self) -> int:
        return sum(1 for i in self.items if i.action == MigrationAction.AUTO_MIGRATE)

    @property
    def conflict_count(self) -> int:
        return sum(1 for i in self.items if i.action == MigrationAction.CONFLICT)

    @property
    def manual_count(self) -> int:
        return sum(1 for i in self.items if i.action == MigrationAction.MANUAL)

    @property
    def skipped_count(self) -> int:
        return sum(1 for i in self.items if i.action == MigrationAction.SKIPPED)

    def summary(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "config_changes": self.config_diff.to_dict(),
            "total_items": len(self.items),
            "auto_migrate": self.auto_migrate_count,
            "conflicts": self.conflict_count,
            "manual_required": self.manual_count,
            "skipped": self.skipped_count,
        }

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "items": [i.to_dict() for i in self.items],
        }


class MigrationState:
    def __init__(self, path: str):
        self.path = path
        self._migrated_fingerprints: set[str] = set()
        self._load()

    def _load(self) -> None:
        raw = load_json(self.path, default={"migrated_fingerprints": []})
        self._migrated_fingerprints = set(raw.get("migrated_fingerprints", []))

    def _save(self) -> None:
        save_json(self.path, {
            "migrated_fingerprints": sorted(list(self._migrated_fingerprints)),
            "last_migration_at": datetime.now().isoformat(),
        })

    def is_migrated(self, fingerprint: str) -> bool:
        return fingerprint in self._migrated_fingerprints

    def mark_migrated(self, fingerprint: str) -> None:
        self._migrated_fingerprints.add(fingerprint)
        self._save()

    def all_fingerprints(self) -> set[str]:
        return set(self._migrated_fingerprints)


def compute_fingerprint(item_type: str, record_id: str, field_name: str, old_value: str) -> str:
    raw = f"{item_type}:{record_id}:{field_name}:{old_value}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def detect_config_diff(old_config: AppConfig, new_config: AppConfig) -> ConfigDiff:
    return ConfigDiff(
        old_intake_dir=os.path.abspath(old_config.intake_dir),
        new_intake_dir=os.path.abspath(new_config.intake_dir),
        old_target_base=os.path.abspath(old_config.target_base),
        new_target_base=os.path.abspath(new_config.target_base),
        old_operator=old_config.operator,
        new_operator=new_config.operator,
        old_case_pattern=old_config.rules.case_number_pattern,
        new_case_pattern=new_config.rules.case_number_pattern,
        old_file_pattern=old_config.rules.file_pattern,
        new_file_pattern=new_config.rules.file_pattern,
        old_target_structure=old_config.rules.target_structure,
        new_target_structure=new_config.rules.target_structure,
        old_action=old_config.rules.action,
        new_action=new_config.rules.action,
    )


def _replace_path_prefix(path: str, old_prefix: str, new_prefix: str) -> str:
    norm_path = os.path.normpath(os.path.abspath(path))
    norm_old = os.path.normpath(os.path.abspath(old_prefix))
    norm_new = os.path.normpath(os.path.abspath(new_prefix))

    if norm_path.startswith(norm_old + os.sep) or norm_path == norm_old:
        return norm_path.replace(norm_old, norm_new, 1)
    return path


def _extract_case_number(filename: str, pattern: str) -> Optional[str]:
    match = re.search(pattern, filename)
    if match and match.groups():
        return match.group(1)
    return None


def _check_target_conflict(new_path: str, diff: ConfigDiff) -> tuple[bool, Optional[ConflictType], Optional[str]]:
    if not os.path.exists(new_path):
        return False, None, None

    if os.path.isdir(new_path):
        return True, ConflictType.TARGET_DIR_EXISTS, f"目标目录已存在: {new_path}"
    else:
        return True, ConflictType.TARGET_FILE_EXISTS, f"目标文件已存在: {new_path}"


def _matches_file_pattern(filename: str, pattern: str) -> bool:
    try:
        return re.match(pattern, filename) is not None
    except re.error:
        return False


def _analyze_file_pattern_item(
    filename: str,
    diff: ConfigDiff,
    item_type: MigrationItemType,
    record_id: str,
    state: MigrationState,
    field_name: str = "file_pattern_match",
) -> Optional[MigrationItem]:
    if not diff.file_pattern_changed or not filename:
        return None

    old_match = _matches_file_pattern(filename, diff.old_file_pattern)
    new_match = _matches_file_pattern(filename, diff.new_file_pattern)

    if old_match == new_match:
        return None

    fingerprint = compute_fingerprint(
        item_type.value, record_id, field_name, filename
    )

    if state.is_migrated(fingerprint):
        return MigrationItem(
            item_type=item_type,
            record_id=record_id,
            field_name=field_name,
            old_value="匹配" if old_match else "不匹配",
            new_value="匹配" if new_match else "不匹配",
            action=MigrationAction.SKIPPED,
            fingerprint=fingerprint,
            migrated=True,
        )

    if old_match and not new_match:
        return MigrationItem(
            item_type=item_type,
            record_id=record_id,
            field_name=field_name,
            old_value="匹配",
            new_value="不匹配",
            action=MigrationAction.MANUAL,
            conflict_type=ConflictType.FILE_PATTERN_MISMATCH,
            conflict_detail=f"文件名 {filename} 匹配旧规则但不匹配新规则，升级后将被视为非法",
            fingerprint=fingerprint,
        )

    if not old_match and new_match:
        return MigrationItem(
            item_type=item_type,
            record_id=record_id,
            field_name=field_name,
            old_value="不匹配",
            new_value="匹配",
            action=MigrationAction.AUTO_MIGRATE,
            conflict_detail=f"文件名 {filename} 之前不匹配旧规则，现在匹配新规则，已被纳入规范",
            fingerprint=fingerprint,
        )

    return None


def analyze_queue(
    diff: ConfigDiff,
    old_config: AppConfig,
    new_config: AppConfig,
    state: MigrationState,
) -> list[MigrationItem]:
    items: list[MigrationItem] = []
    queue_path = old_config.logging.queue_path()
    queue_data = load_json(queue_path, default=[])

    for idx, entry in enumerate(queue_data):
        record_id = f"queue_{idx}"

        if "path" in entry and diff.intake_changed:
            old_path = entry["path"]
            new_path = _replace_path_prefix(old_path, diff.old_intake_dir, diff.new_intake_dir)
            if old_path != new_path:
                fp = compute_fingerprint("queue", record_id, "path", old_path)
                if state.is_migrated(fp):
                    items.append(MigrationItem(
                        item_type=MigrationItemType.QUEUE,
                        record_id=record_id,
                        field_name="path",
                        old_value=old_path,
                        new_value=new_path,
                        action=MigrationAction.SKIPPED,
                        fingerprint=fp,
                        migrated=True,
                    ))
                else:
                    has_conflict, ctype, cdetail = _check_target_conflict(new_path, diff)
                    if has_conflict:
                        items.append(MigrationItem(
                            item_type=MigrationItemType.QUEUE,
                            record_id=record_id,
                            field_name="path",
                            old_value=old_path,
                            new_value=new_path,
                            action=MigrationAction.CONFLICT,
                            conflict_type=ctype,
                            conflict_detail=cdetail,
                            fingerprint=fp,
                        ))
                    else:
                        items.append(MigrationItem(
                            item_type=MigrationItemType.QUEUE,
                            record_id=record_id,
                            field_name="path",
                            old_value=old_path,
                            new_value=new_path,
                            action=MigrationAction.AUTO_MIGRATE,
                            fingerprint=fp,
                        ))

        if diff.case_pattern_changed and entry.get("filename"):
            filename = entry["filename"]
            old_case = entry.get("case_number")
            new_case = _extract_case_number(filename, diff.new_case_pattern)

            if old_case != new_case:
                fp = compute_fingerprint("queue", record_id, "case_number", str(old_case))
                if state.is_migrated(fp):
                    items.append(MigrationItem(
                        item_type=MigrationItemType.QUEUE,
                        record_id=record_id,
                        field_name="case_number",
                        old_value=str(old_case),
                        new_value=str(new_case),
                        action=MigrationAction.SKIPPED,
                        fingerprint=fp,
                        migrated=True,
                    ))
                elif new_case is None:
                    items.append(MigrationItem(
                        item_type=MigrationItemType.QUEUE,
                        record_id=record_id,
                        field_name="case_number",
                        old_value=str(old_case),
                        new_value=str(new_case),
                        action=MigrationAction.MANUAL,
                        conflict_type=ConflictType.CASE_NUMBER_MISMATCH,
                        conflict_detail=f"新规则无法从 {filename} 解析案卷号",
                        fingerprint=fp,
                    ))
                else:
                    items.append(MigrationItem(
                        item_type=MigrationItemType.QUEUE,
                        record_id=record_id,
                        field_name="case_number",
                        old_value=str(old_case),
                        new_value=new_case,
                        action=MigrationAction.AUTO_MIGRATE,
                        fingerprint=fp,
                    ))

        fp_item = _analyze_file_pattern_item(
            entry.get("filename", ""),
            diff,
            MigrationItemType.QUEUE,
            record_id,
            state,
        )
        if fp_item:
            items.append(fp_item)

    return items


def analyze_error_queue(
    diff: ConfigDiff,
    old_config: AppConfig,
    new_config: AppConfig,
    state: MigrationState,
) -> list[MigrationItem]:
    items: list[MigrationItem] = []
    error_items = load_json(old_config.logging.error_queue_path(), default=[])

    for idx, raw in enumerate(error_items):
        item = ErrorItem.from_dict(raw)
        record_id = f"error_{idx}"

        if diff.intake_changed:
            old_path = item.path
            new_path = _replace_path_prefix(old_path, diff.old_intake_dir, diff.new_intake_dir)
            if old_path != new_path:
                fp = compute_fingerprint("error_queue", record_id, "path", old_path)
                if state.is_migrated(fp):
                    items.append(MigrationItem(
                        item_type=MigrationItemType.ERROR_QUEUE,
                        record_id=record_id,
                        field_name="path",
                        old_value=old_path,
                        new_value=new_path,
                        action=MigrationAction.SKIPPED,
                        fingerprint=fp,
                        migrated=True,
                    ))
                else:
                    has_conflict, ctype, cdetail = _check_target_conflict(new_path, diff)
                    if has_conflict:
                        items.append(MigrationItem(
                            item_type=MigrationItemType.ERROR_QUEUE,
                            record_id=record_id,
                            field_name="path",
                            old_value=old_path,
                            new_value=new_path,
                            action=MigrationAction.CONFLICT,
                            conflict_type=ctype,
                            conflict_detail=cdetail,
                            fingerprint=fp,
                        ))
                    else:
                        items.append(MigrationItem(
                            item_type=MigrationItemType.ERROR_QUEUE,
                            record_id=record_id,
                            field_name="path",
                            old_value=old_path,
                            new_value=new_path,
                            action=MigrationAction.AUTO_MIGRATE,
                            fingerprint=fp,
                        ))

        if diff.case_pattern_changed and item.filename:
            old_case = item.case_number
            new_case = _extract_case_number(item.filename, diff.new_case_pattern)
            if old_case != new_case:
                fp = compute_fingerprint("error_queue", record_id, "case_number", str(old_case))
                if state.is_migrated(fp):
                    items.append(MigrationItem(
                        item_type=MigrationItemType.ERROR_QUEUE,
                        record_id=record_id,
                        field_name="case_number",
                        old_value=str(old_case),
                        new_value=str(new_case),
                        action=MigrationAction.SKIPPED,
                        fingerprint=fp,
                        migrated=True,
                    ))
                elif new_case is None:
                    items.append(MigrationItem(
                        item_type=MigrationItemType.ERROR_QUEUE,
                        record_id=record_id,
                        field_name="case_number",
                        old_value=str(old_case),
                        new_value=str(new_case),
                        action=MigrationAction.MANUAL,
                        conflict_type=ConflictType.CASE_NUMBER_MISMATCH,
                        conflict_detail=f"新规则无法从 {item.filename} 解析案卷号",
                        fingerprint=fp,
                    ))
                else:
                    items.append(MigrationItem(
                        item_type=MigrationItemType.ERROR_QUEUE,
                        record_id=record_id,
                        field_name="case_number",
                        old_value=str(old_case),
                        new_value=new_case,
                        action=MigrationAction.AUTO_MIGRATE,
                        fingerprint=fp,
                    ))

        fp_item = _analyze_file_pattern_item(
            item.filename or "",
            diff,
            MigrationItemType.ERROR_QUEUE,
            record_id,
            state,
        )
        if fp_item:
            items.append(fp_item)

    return items


def analyze_batch_history(
    diff: ConfigDiff,
    old_config: AppConfig,
    new_config: AppConfig,
    state: MigrationState,
) -> list[MigrationItem]:
    items: list[MigrationItem] = []
    batches = load_json(old_config.logging.batch_history_path(), default=[])

    for idx, raw in enumerate(batches):
        batch = BatchRecord.from_dict(raw)
        record_id = batch.batch_id or f"batch_{idx}"

        if diff.operator_changed and batch.operator != diff.new_operator:
            fp = compute_fingerprint("batch_history", record_id, "operator", batch.operator)
            if state.is_migrated(fp):
                items.append(MigrationItem(
                    item_type=MigrationItemType.BATCH_HISTORY,
                    record_id=record_id,
                    field_name="operator",
                    old_value=batch.operator,
                    new_value=diff.new_operator,
                    action=MigrationAction.SKIPPED,
                    fingerprint=fp,
                    migrated=True,
                ))
            else:
                items.append(MigrationItem(
                    item_type=MigrationItemType.BATCH_HISTORY,
                    record_id=record_id,
                    field_name="operator",
                    old_value=batch.operator,
                    new_value=diff.new_operator,
                    action=MigrationAction.AUTO_MIGRATE,
                    fingerprint=fp,
                ))

        seen_paths: set = set()
        for fidx, file_path in enumerate(batch.error_file_paths or []):
            if not file_path or file_path in seen_paths:
                continue
            seen_paths.add(file_path)
            filename = os.path.basename(file_path)
            fp_item = _analyze_file_pattern_item(
                filename,
                diff,
                MigrationItemType.BATCH_HISTORY,
                record_id,
                state,
                field_name=f"error_file_{fidx}_pattern_match",
            )
            if fp_item:
                items.append(fp_item)

        for didx, (file_path, _detail) in enumerate((batch.error_details or {}).items()):
            if not file_path or file_path in seen_paths:
                continue
            seen_paths.add(file_path)
            filename = os.path.basename(file_path)
            fp_item = _analyze_file_pattern_item(
                filename,
                diff,
                MigrationItemType.BATCH_HISTORY,
                record_id,
                state,
                field_name=f"error_detail_{didx}_pattern_match",
            )
            if fp_item:
                items.append(fp_item)

    return items


def analyze_action_log(
    diff: ConfigDiff,
    old_config: AppConfig,
    new_config: AppConfig,
    state: MigrationState,
) -> list[MigrationItem]:
    items: list[MigrationItem] = []
    records = read_jsonl(old_config.logging.action_log_path())

    for idx, raw in enumerate(records):
        record = ActionRecord.from_dict(raw)
        record_id = record.action_id or f"action_{idx}"

        if diff.intake_changed:
            old_source = record.source
            new_source = _replace_path_prefix(old_source, diff.old_intake_dir, diff.new_intake_dir)
            if old_source != new_source:
                fp = compute_fingerprint("action_log", record_id, "source", old_source)
                if state.is_migrated(fp):
                    items.append(MigrationItem(
                        item_type=MigrationItemType.ACTION_LOG,
                        record_id=record_id,
                        field_name="source",
                        old_value=old_source,
                        new_value=new_source,
                        action=MigrationAction.SKIPPED,
                        fingerprint=fp,
                        migrated=True,
                    ))
                else:
                    items.append(MigrationItem(
                        item_type=MigrationItemType.ACTION_LOG,
                        record_id=record_id,
                        field_name="source",
                        old_value=old_source,
                        new_value=new_source,
                        action=MigrationAction.AUTO_MIGRATE,
                        fingerprint=fp,
                    ))

        if diff.target_base_changed:
            old_dest = record.destination
            new_dest = _replace_path_prefix(old_dest, diff.old_target_base, diff.new_target_base)
            if old_dest != new_dest:
                fp = compute_fingerprint("action_log", record_id, "destination", old_dest)
                if state.is_migrated(fp):
                    items.append(MigrationItem(
                        item_type=MigrationItemType.ACTION_LOG,
                        record_id=record_id,
                        field_name="destination",
                        old_value=old_dest,
                        new_value=new_dest,
                        action=MigrationAction.SKIPPED,
                        fingerprint=fp,
                        migrated=True,
                    ))
                else:
                    has_conflict = False
                    conflict_type: Optional[ConflictType] = None
                    conflict_detail: Optional[str] = None
                    if os.path.exists(new_dest) and os.path.exists(old_dest):
                        try:
                            if file_hash(new_dest) != file_hash(old_dest):
                                has_conflict = True
                                conflict_type = ConflictType.TARGET_FILE_EXISTS
                                conflict_detail = f"目标文件已存在且内容与原文件不同: {new_dest}"
                        except OSError:
                            pass
                    elif os.path.exists(new_dest):
                        if os.path.isdir(new_dest):
                            has_conflict = True
                            conflict_type = ConflictType.TARGET_DIR_EXISTS
                            conflict_detail = f"目标目录已存在: {new_dest}"
                    if has_conflict:
                        items.append(MigrationItem(
                            item_type=MigrationItemType.ACTION_LOG,
                            record_id=record_id,
                            field_name="destination",
                            old_value=old_dest,
                            new_value=new_dest,
                            action=MigrationAction.CONFLICT,
                            conflict_type=conflict_type,
                            conflict_detail=conflict_detail,
                            fingerprint=fp,
                        ))
                    else:
                        items.append(MigrationItem(
                            item_type=MigrationItemType.ACTION_LOG,
                            record_id=record_id,
                            field_name="destination",
                            old_value=old_dest,
                            new_value=new_dest,
                            action=MigrationAction.AUTO_MIGRATE,
                            fingerprint=fp,
                        ))

        if diff.action_changed:
            old_action = record.action_type.value
            new_action = diff.new_action
            if old_action != new_action:
                fp = compute_fingerprint("action_log", record_id, "action_type", old_action)
                if state.is_migrated(fp):
                    items.append(MigrationItem(
                        item_type=MigrationItemType.ACTION_LOG,
                        record_id=record_id,
                        field_name="action_type",
                        old_value=old_action,
                        new_value=new_action,
                        action=MigrationAction.SKIPPED,
                        fingerprint=fp,
                        migrated=True,
                    ))
                else:
                    items.append(MigrationItem(
                        item_type=MigrationItemType.ACTION_LOG,
                        record_id=record_id,
                        field_name="action_type",
                        old_value=old_action,
                        new_value=new_action,
                        action=MigrationAction.MANUAL,
                        conflict_type=ConflictType.ACTION_TYPE_CHANGE,
                        conflict_detail=f"动作类型从 {old_action} 改为 {new_action}，可能影响回滚行为",
                        fingerprint=fp,
                    ))

        if diff.operator_changed and record.operator != diff.new_operator:
            fp = compute_fingerprint("action_log", record_id, "operator", record.operator)
            if state.is_migrated(fp):
                items.append(MigrationItem(
                    item_type=MigrationItemType.ACTION_LOG,
                    record_id=record_id,
                    field_name="operator",
                    old_value=record.operator,
                    new_value=diff.new_operator,
                    action=MigrationAction.SKIPPED,
                    fingerprint=fp,
                    migrated=True,
                ))
            else:
                items.append(MigrationItem(
                    item_type=MigrationItemType.ACTION_LOG,
                    record_id=record_id,
                    field_name="operator",
                    old_value=record.operator,
                    new_value=diff.new_operator,
                    action=MigrationAction.AUTO_MIGRATE,
                    fingerprint=fp,
                ))

        if diff.case_pattern_changed and record.case_number:
            old_case = record.case_number
            filename = os.path.basename(record.source) if record.source else ""
            new_case = _extract_case_number(filename, diff.new_case_pattern) if filename else None
            if old_case != new_case and new_case is not None:
                fp = compute_fingerprint("action_log", record_id, "case_number", old_case)
                if state.is_migrated(fp):
                    items.append(MigrationItem(
                        item_type=MigrationItemType.ACTION_LOG,
                        record_id=record_id,
                        field_name="case_number",
                        old_value=old_case,
                        new_value=str(new_case),
                        action=MigrationAction.SKIPPED,
                        fingerprint=fp,
                        migrated=True,
                    ))
                else:
                    items.append(MigrationItem(
                        item_type=MigrationItemType.ACTION_LOG,
                        record_id=record_id,
                        field_name="case_number",
                        old_value=old_case,
                        new_value=str(new_case),
                        action=MigrationAction.AUTO_MIGRATE,
                        fingerprint=fp,
                    ))

        filename = os.path.basename(record.source) if record.source else ""
        fp_item = _analyze_file_pattern_item(
            filename,
            diff,
            MigrationItemType.ACTION_LOG,
            record_id,
            state,
        )
        if fp_item:
            items.append(fp_item)

    return items


def generate_migration_plan(
    old_config_path: str,
    new_config: AppConfig,
) -> tuple[MigrationPlan, MigrationState]:
    old_config = load_config(old_config_path)
    diff = detect_config_diff(old_config, new_config)

    state_path = os.path.join(new_config.logging.dir, "migration_state.json")
    state = MigrationState(state_path)

    plan = MigrationPlan(config_diff=diff)

    if not diff.has_changes:
        return plan, state

    plan.items.extend(analyze_queue(diff, old_config, new_config, state))
    plan.items.extend(analyze_error_queue(diff, old_config, new_config, state))
    plan.items.extend(analyze_batch_history(diff, old_config, new_config, state))
    plan.items.extend(analyze_action_log(diff, old_config, new_config, state))

    return plan, state


def execute_migration(
    plan: MigrationPlan,
    state: MigrationState,
    old_config_path: str,
    new_config: AppConfig,
    dry_run: bool = True,
) -> tuple[list[MigrationItem], dict]:
    old_config = load_config(old_config_path)
    diff = plan.config_diff

    migrated: list[MigrationItem] = []
    stats = {
        "auto_migrated": 0,
        "conflicts": 0,
        "manual_required": 0,
        "skipped": 0,
        "failed": 0,
    }

    queue_updates: dict[int, dict[str, Any]] = {}
    error_queue_updates: dict[int, dict[str, Any]] = {}
    batch_updates: dict[int, dict[str, Any]] = {}
    action_updates: dict[int, dict[str, Any]] = {}

    for item in plan.items:
        if item.action == MigrationAction.SKIPPED:
            stats["skipped"] += 1
            continue
        if item.action == MigrationAction.CONFLICT:
            stats["conflicts"] += 1
            continue
        if item.action == MigrationAction.MANUAL:
            stats["manual_required"] += 1
            continue
        if item.action != MigrationAction.AUTO_MIGRATE:
            continue

        if state.is_migrated(item.fingerprint):
            item.migrated = True
            migrated.append(item)
            stats["skipped"] += 1
            continue

        idx_str = item.record_id.split("_")[-1]
        try:
            idx = int(idx_str) if idx_str.isdigit() else -1
        except ValueError:
            idx = -1

        if idx >= 0:
            if item.item_type == MigrationItemType.QUEUE:
                if idx not in queue_updates:
                    queue_updates[idx] = {}
                queue_updates[idx][item.field_name] = item.new_value
            elif item.item_type == MigrationItemType.ERROR_QUEUE:
                if idx not in error_queue_updates:
                    error_queue_updates[idx] = {}
                error_queue_updates[idx][item.field_name] = item.new_value

        if item.item_type == MigrationItemType.BATCH_HISTORY:
            batches = load_json(new_config.logging.batch_history_path(), default=[])
            for bidx, raw in enumerate(batches):
                if raw.get("batch_id") == item.record_id or f"batch_{bidx}" == item.record_id:
                    if bidx not in batch_updates:
                        batch_updates[bidx] = {}
                    batch_updates[bidx][item.field_name] = item.new_value
                    break

        if item.item_type == MigrationItemType.ACTION_LOG:
            records = read_jsonl(new_config.logging.action_log_path())
            for ridx, raw in enumerate(records):
                if raw.get("action_id") == item.record_id or f"action_{ridx}" == item.record_id:
                    if ridx not in action_updates:
                        action_updates[ridx] = {}
                    action_updates[ridx][item.field_name] = item.new_value
                    break

        if not dry_run:
            state.mark_migrated(item.fingerprint)
        item.migrated = not dry_run
        migrated.append(item)
        stats["auto_migrated"] += 1

    if not dry_run:
        if queue_updates:
            queue_data = load_json(new_config.logging.queue_path(), default=[])
            for idx, updates in queue_updates.items():
                if idx < len(queue_data):
                    queue_data[idx].update(updates)
            save_json(new_config.logging.queue_path(), queue_data)

        if error_queue_updates:
            error_data = load_json(new_config.logging.error_queue_path(), default=[])
            for idx, updates in error_queue_updates.items():
                if idx < len(error_data):
                    error_data[idx].update(updates)
            save_json(new_config.logging.error_queue_path(), error_data)

        if batch_updates:
            batch_data = load_json(new_config.logging.batch_history_path(), default=[])
            for idx, updates in batch_updates.items():
                if idx < len(batch_data):
                    batch_data[idx].update(updates)
            save_json(new_config.logging.batch_history_path(), batch_data)

        if action_updates:
            action_data = read_jsonl(new_config.logging.action_log_path())
            for idx, updates in action_updates.items():
                if idx < len(action_data):
                    action_data[idx].update(updates)
            with open(new_config.logging.action_log_path(), "w", encoding="utf-8") as f:
                for rec in action_data:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")

        if diff.target_base_changed:
            freeze_state_path = os.path.join(new_config.logging.dir, "freeze_state.json")
            if os.path.exists(freeze_state_path):
                try:
                    freeze_state = load_json(freeze_state_path, default={})
                    old_tb_norm = os.path.normpath(os.path.abspath(diff.old_target_base))
                    new_tb_norm = os.path.normpath(os.path.abspath(diff.new_target_base))

                    new_freeze_index = {}
                    for path_key, info in freeze_state.get("freeze_index", {}).items():
                        norm_path = os.path.normpath(os.path.abspath(path_key))
                        if norm_path.startswith(old_tb_norm + os.sep) or norm_path == old_tb_norm:
                            new_key = norm_path.replace(old_tb_norm, new_tb_norm, 1)
                            new_freeze_index[new_key] = info
                        else:
                            new_freeze_index[path_key] = info
                    freeze_state["freeze_index"] = new_freeze_index

                    for order_raw in freeze_state.get("freeze_orders", []):
                        for item in order_raw.get("items", []):
                            fi = item.get("file", {})
                            if fi and fi.get("path"):
                                norm_p = os.path.normpath(os.path.abspath(fi["path"]))
                                if norm_p.startswith(old_tb_norm + os.sep) or norm_p == old_tb_norm:
                                    fi["path"] = norm_p.replace(old_tb_norm, new_tb_norm, 1)

                    cfg_sig = freeze_state.get("config_signature", {})
                    if cfg_sig.get("target_base"):
                        sig_tb = os.path.normpath(os.path.abspath(cfg_sig["target_base"]))
                        if sig_tb == old_tb_norm:
                            cfg_sig["target_base"] = new_tb_norm
                    freeze_state["config_signature"] = cfg_sig

                    save_json(freeze_state_path, freeze_state)
                except Exception as e:
                    stats.setdefault("warnings", []).append(f"freeze_state 更新失败: {e}")

        migration_log_path = os.path.join(
            new_config.logging.dir, "migration_log.jsonl"
        )
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "old_config": os.path.abspath(old_config_path),
            "new_config": new_config._source_path,
            "dry_run": False,
            "stats": stats,
            "items": [i.to_dict() for i in migrated],
        }
        append_jsonl(migration_log_path, log_entry)

    return migrated, stats


def export_plan_json(plan: MigrationPlan, output_path: str) -> None:
    save_json(output_path, plan.to_dict())


def export_plan_csv(plan: MigrationPlan, output_path: str) -> None:
    if not plan.items:
        save_json(output_path, {"note": "无迁移项"})
        return

    fieldnames = [
        "item_type", "record_id", "field_name",
        "old_value", "new_value", "action",
        "conflict_type", "conflict_detail", "migrated"
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in plan.items:
            row = {
                "item_type": item.item_type.value,
                "record_id": item.record_id,
                "field_name": item.field_name,
                "old_value": item.old_value,
                "new_value": item.new_value,
                "action": item.action.value,
                "conflict_type": item.conflict_type.value if item.conflict_type else "",
                "conflict_detail": item.conflict_detail or "",
                "migrated": item.migrated,
            }
            writer.writerow(row)


def export_result_json(
    migrated: list[MigrationItem],
    stats: dict,
    output_path: str,
) -> None:
    data = {
        "executed_at": datetime.now().isoformat(),
        "stats": stats,
        "migrated_items": [i.to_dict() for i in migrated],
    }
    save_json(output_path, data)


def export_result_csv(
    migrated: list[MigrationItem],
    stats: dict,
    output_path: str,
) -> None:
    fieldnames = [
        "item_type", "record_id", "field_name",
        "old_value", "new_value", "action", "migrated"
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in migrated:
            row = {
                "item_type": item.item_type.value,
                "record_id": item.record_id,
                "field_name": item.field_name,
                "old_value": item.old_value,
                "new_value": item.new_value,
                "action": item.action.value,
                "migrated": item.migrated,
            }
            writer.writerow(row)
