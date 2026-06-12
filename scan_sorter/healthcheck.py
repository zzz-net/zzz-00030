from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from scan_sorter.action_logger import ActionLogger
from scan_sorter.config import AppConfig
from scan_sorter.models import BatchRecord, ErrorItem
from scan_sorter.queue_manager import ErrorQueue, ProcessingQueue
from scan_sorter.utils import load_json, read_jsonl, save_json


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class FindingCategory(str, Enum):
    QUEUE_FILE_MISMATCH = "queue_file_mismatch"
    TARGET_OCCUPIED = "target_occupied"
    CONFIG_DRIFT = "config_drift"
    ORPHAN_ACTION = "orphan_action"
    MISSING_ACTION = "missing_action"
    ERROR_QUEUE_STALE = "error_queue_stale"
    QUEUE_STALE_DONE = "queue_stale_done"
    ERROR_QUEUE_INCONSISTENCY = "error_queue_inconsistency"
    BATCH_ACTION_COUNT_MISMATCH = "batch_action_count_mismatch"
    ROLLED_BACK_FILE_MISSING = "rolled_back_file_missing"


@dataclass
class Finding:
    fingerprint: str
    category: FindingCategory
    severity: Severity
    description: str
    file_path: Optional[str] = None
    queue_path: Optional[str] = None
    batch_id: Optional[str] = None
    action_id: Optional[str] = None
    detail: Optional[dict] = None
    fixable: bool = False
    fix_description: str = ""

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "file_path": self.file_path,
            "queue_path": self.queue_path,
            "batch_id": self.batch_id,
            "action_id": self.action_id,
            "detail": self.detail or {},
            "fixable": self.fixable,
            "fix_description": self.fix_description,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(
            fingerprint=d["fingerprint"],
            category=FindingCategory(d["category"]),
            severity=Severity(d["severity"]),
            description=d["description"],
            file_path=d.get("file_path"),
            queue_path=d.get("queue_path"),
            batch_id=d.get("batch_id"),
            action_id=d.get("action_id"),
            detail=d.get("detail"),
            fixable=d.get("fixable", False),
            fix_description=d.get("fix_description", ""),
        )


@dataclass
class HealAction:
    fingerprint: str
    category: FindingCategory
    applied: bool
    description: str
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "category": self.category.value,
            "applied": self.applied,
            "description": self.description,
            "reason": self.reason,
        }


def _make_fingerprint(category: str, *keys: str) -> str:
    raw = "|".join([category] + list(keys))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class HealthCheckState:
    def __init__(self, path: str):
        self.path = path
        self._data: dict = self._load()

    def _load(self) -> dict:
        raw = load_json(self.path, default={})
        if not isinstance(raw, dict):
            return {}
        return raw

    def _save(self) -> None:
        save_json(self.path, self._data)

    def get_last_findings(self) -> list[Finding]:
        findings_raw = self._data.get("last_findings", [])
        return [Finding.from_dict(f) for f in findings_raw]

    def save_findings(self, findings: list[Finding]) -> None:
        self._data["last_check_time"] = datetime.now().isoformat()
        self._data["last_findings"] = [f.to_dict() for f in findings]
        self._data["finding_fingerprints"] = [f.fingerprint for f in findings]
        self._save()

    def get_known_fingerprints(self) -> set[str]:
        return set(self._data.get("finding_fingerprints", []))

    def get_last_check_time(self) -> Optional[str]:
        return self._data.get("last_check_time")

    def save_heal_log(self, actions: list[HealAction], dry_run: bool) -> None:
        heal_logs = self._data.get("heal_logs", [])
        heal_logs.append({
            "timestamp": datetime.now().isoformat(),
            "dry_run": dry_run,
            "actions": [a.to_dict() for a in actions],
        })
        self._data["heal_logs"] = heal_logs
        self._save()

    def get_heal_logs(self) -> list[dict]:
        return self._data.get("heal_logs", [])


class HealthChecker:
    def __init__(self, config: AppConfig):
        self.config = config
        self.action_logger = ActionLogger(config.logging.action_log_path())
        self.error_queue = ErrorQueue(config.logging.error_queue_path())
        self.processing_queue = ProcessingQueue(config.logging.queue_path())
        self._batch_history: list[BatchRecord] = self._load_history()
        state_path = os.path.join(
            config.logging.dir, "healthcheck_state.json"
        )
        self.state = HealthCheckState(state_path)

    def _load_history(self) -> list[BatchRecord]:
        raw = load_json(
            self.config.logging.batch_history_path(), default=[]
        )
        return [BatchRecord.from_dict(d) for d in raw]

    def check(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_queue_file_mismatch())
        findings.extend(self._check_target_occupied())
        findings.extend(self._check_config_drift())
        findings.extend(self._check_orphan_action())
        findings.extend(self._check_missing_action())
        findings.extend(self._check_error_queue_stale())
        findings.extend(self._check_queue_stale_done())
        findings.extend(self._check_error_queue_inconsistency())
        findings.extend(self._check_batch_action_count_mismatch())
        findings.extend(self._check_rolled_back_file_missing())
        self.state.save_findings(findings)
        return findings

    def heal(
        self,
        findings: list[Finding],
        dry_run: bool = True,
        fingerprints: set[str] | None = None,
    ) -> list[HealAction]:
        actions: list[HealAction] = []
        target_fps = fingerprints
        for f in findings:
            if target_fps is not None and f.fingerprint not in target_fps:
                continue
            if not f.fixable:
                actions.append(HealAction(
                    fingerprint=f.fingerprint,
                    category=f.category,
                    applied=False,
                    description=f"跳过不可修复项: {f.description}",
                    reason="finding.marked_fixable=False",
                ))
                continue
            action = self._heal_one(f, dry_run)
            actions.append(action)
        self.state.save_heal_log(actions, dry_run)
        return actions

    def _heal_one(self, f: Finding, dry_run: bool) -> HealAction:
        if f.category == FindingCategory.QUEUE_FILE_MISMATCH:
            return self._heal_queue_file_mismatch(f, dry_run)
        elif f.category == FindingCategory.ERROR_QUEUE_STALE:
            return self._heal_error_queue_stale(f, dry_run)
        elif f.category == FindingCategory.QUEUE_STALE_DONE:
            return self._heal_queue_stale_done(f, dry_run)
        elif f.category == FindingCategory.ERROR_QUEUE_INCONSISTENCY:
            return self._heal_error_queue_inconsistency(f, dry_run)
        elif f.category == FindingCategory.ROLLED_BACK_FILE_MISSING:
            return self._heal_rolled_back_file_missing(f, dry_run)
        else:
            return HealAction(
                fingerprint=f.fingerprint,
                category=f.category,
                applied=False,
                description=f"跳过: {f.description}",
                reason=f"category={f.category.value} 无自动修复策略",
            )

    def _ensure_error_item(self, file_path: str, error_msg: str) -> None:
        existing = self.error_queue.find_by_path(file_path)
        if existing:
            return
        filename = os.path.basename(file_path)
        case_number = None
        m = re.search(self.config.rules.case_number_pattern, filename)
        if m:
            case_number = m.group(1)
        self.error_queue.add(ErrorItem(
            path=file_path,
            filename=filename,
            case_number=case_number,
            error=error_msg,
            retry_count=0,
        ))

    def _heal_queue_file_mismatch(
        self, f: Finding, dry_run: bool
    ) -> HealAction:
        detail = f.detail or {}
        queue_status = detail.get("queue_status", "")
        file_path = f.file_path or ""
        if queue_status == "done":
            if not os.path.exists(file_path):
                if not dry_run:
                    self.processing_queue.mark_failed(file_path)
                    self._ensure_error_item(
                        file_path, "heal修正:队列done但源文件和目标都不存在"
                    )
                return HealAction(
                    fingerprint=f.fingerprint,
                    category=f.category,
                    applied=not dry_run,
                    description=f"{'[dry-run] ' if dry_run else ''}queue done→failed: {file_path} (源文件不在intake,目标也不在,标记为failed并补入error_queue)",
                    reason="文件已从intake移走但目标也不存在,修正队列状态为failed并补入error_queue",
                )
            if os.path.exists(file_path) and self._is_in_intake(file_path):
                if not dry_run:
                    self.processing_queue.mark_failed(file_path)
                    self._ensure_error_item(
                        file_path, "heal修正:队列done但文件仍在intake"
                    )
                return HealAction(
                    fingerprint=f.fingerprint,
                    category=f.category,
                    applied=not dry_run,
                    description=f"{'[dry-run] ' if dry_run else ''}queue done→failed: {file_path} (文件仍在intake,标记为failed并补入error_queue)",
                    reason="done状态文件仍在intake,说明移动未成功,修正为failed并补入error_queue",
                )
        elif queue_status == "failed":
            if os.path.exists(file_path) and not self._is_in_intake(file_path):
                if not dry_run:
                    self.processing_queue.mark_done(file_path)
                    self.error_queue.remove(file_path)
                return HealAction(
                    fingerprint=f.fingerprint,
                    category=f.category,
                    applied=not dry_run,
                    description=f"{'[dry-run] ' if dry_run else ''}queue failed→done: {file_path} (文件已在目标位置,修正为done并移出error_queue)",
                    reason="failed状态文件已不在intake且在目标位置,说明实际已成功",
                )
        return HealAction(
            fingerprint=f.fingerprint,
            category=f.category,
            applied=False,
            description=f"跳过: {f.description}",
            reason="无法自动判断正确状态",
        )

    def _heal_error_queue_stale(
        self, f: Finding, dry_run: bool
    ) -> HealAction:
        file_path = f.file_path or ""
        if not dry_run:
            self.error_queue.remove(file_path)
        return HealAction(
            fingerprint=f.fingerprint,
            category=f.category,
            applied=not dry_run,
            description=f"{'[dry-run] ' if dry_run else ''}移出error_queue: {file_path} (文件已不存在)",
            reason="文件已从磁盘删除,清理error_queue残留",
        )

    def _heal_queue_stale_done(
        self, f: Finding, dry_run: bool
    ) -> HealAction:
        file_path = f.file_path or ""
        detail = f.detail or {}
        target_path = detail.get("target_path", "")
        if not target_path:
            return HealAction(
                fingerprint=f.fingerprint,
                category=f.category,
                applied=False,
                description=f"跳过: {f.description}",
                reason="无法确定目标路径",
            )
        if not dry_run:
            self.processing_queue.mark_failed(file_path)
            self._ensure_error_item(
                file_path, f"heal修正:目标文件 {target_path} 被外部删除"
            )
        return HealAction(
            fingerprint=f.fingerprint,
            category=f.category,
            applied=not dry_run,
            description=f"{'[dry-run] ' if dry_run else ''}queue done→failed: {file_path} (目标文件 {target_path} 不存在,补入error_queue)",
            reason="目标文件被外部删除,修正队列状态并补入error_queue",
        )

    def _heal_error_queue_inconsistency(
        self, f: Finding, dry_run: bool
    ) -> HealAction:
        file_path = f.file_path or ""
        detail = f.detail or {}
        current_item = self.processing_queue.find_by_path(file_path)
        current_status = current_item.get("status", "") if current_item else "missing"
        if current_status == "done":
            if not dry_run:
                self.error_queue.remove(file_path)
            return HealAction(
                fingerprint=f.fingerprint,
                category=f.category,
                applied=not dry_run,
                description=f"{'[dry-run] ' if dry_run else ''}移出error_queue: {file_path} (processing_queue当前为done)",
                reason="队列当前标记done但error_queue仍有残留,清理",
            )
        if current_status == "failed":
            if not dry_run:
                self._ensure_error_item(
                    file_path, "heal修正:processing_queue为failed但error_queue缺失"
                )
            return HealAction(
                fingerprint=f.fingerprint,
                category=f.category,
                applied=not dry_run,
                description=f"{'[dry-run] ' if dry_run else ''}补入error_queue: {file_path} (processing_queue当前为failed但error_queue无此条目)",
                reason="processing_queue当前标记failed但error_queue缺失,补入error_queue",
            )
        if current_status == "missing":
            if not dry_run:
                self.error_queue.remove(file_path)
            return HealAction(
                fingerprint=f.fingerprint,
                category=f.category,
                applied=not dry_run,
                description=f"{'[dry-run] ' if dry_run else ''}移出error_queue: {file_path} (processing_queue已无此记录)",
                reason="processing_queue已无此条目,清理error_queue残留",
            )
        if dry_run:
            return HealAction(
                fingerprint=f.fingerprint,
                category=f.category,
                applied=False,
                description=f"[dry-run] 跳过: {file_path} (当前状态={current_status})",
                reason=f"队列当前状态为{current_status},不能自动处理",
            )
        return HealAction(
            fingerprint=f.fingerprint,
            category=f.category,
            applied=False,
            description=f"跳过: {f.description}",
            reason=f"队列当前状态为{current_status},不能自动处理",
        )

    def _heal_rolled_back_file_missing(
        self, f: Finding, dry_run: bool
    ) -> HealAction:
        file_path = f.file_path or ""
        detail = f.detail or {}
        target_path = detail.get("target_path", "")
        if not dry_run and target_path and os.path.exists(target_path):
            return HealAction(
                fingerprint=f.fingerprint,
                category=f.category,
                applied=False,
                description=f"跳过: {file_path} 回滚后不在intake",
                reason=f"目标文件 {target_path} 仍存在,可能回滚部分失败,需人工确认",
            )
        if not dry_run:
            self.processing_queue.mark_failed(file_path)
            self._ensure_error_item(
                file_path, "heal修正:回滚后文件既不在intake也不在target"
            )
        return HealAction(
            fingerprint=f.fingerprint,
            category=f.category,
            applied=not dry_run,
            description=f"{'[dry-run] ' if dry_run else ''}queue rolled_back→failed: {file_path} (源和目标都不在,标记failed并补入error_queue)",
            reason="回滚后文件既不在intake也不在target,修正为failed并补入error_queue",
        )

    def _is_in_intake(self, file_path: str) -> bool:
        intake_dir = os.path.abspath(self.config.intake_dir)
        abs_path = os.path.abspath(file_path)
        return abs_path.startswith(intake_dir + os.sep) or abs_path == intake_dir

    def _check_queue_file_mismatch(self) -> list[Finding]:
        findings: list[Finding] = []
        queue_items = self.processing_queue.all()
        for item in queue_items:
            fp = item["path"]
            status = item.get("status", "")
            if status == "done":
                if os.path.exists(fp) and self._is_in_intake(fp):
                    findings.append(Finding(
                        fingerprint=_make_fingerprint(
                            FindingCategory.QUEUE_FILE_MISMATCH.value,
                            fp, "done_but_in_intake",
                        ),
                        category=FindingCategory.QUEUE_FILE_MISMATCH,
                        severity=Severity.CRITICAL,
                        description=f"队列标记done但文件仍在intake: {os.path.basename(fp)}",
                        file_path=fp,
                        queue_path=self.config.logging.queue_path(),
                        detail={"queue_status": "done", "actual_location": "intake"},
                        fixable=True,
                        fix_description="将队列状态修正为failed",
                    ))
                elif not os.path.exists(fp):
                    target = self._resolve_target_from_actions(fp)
                    if target and not os.path.exists(target):
                        findings.append(Finding(
                            fingerprint=_make_fingerprint(
                                FindingCategory.QUEUE_FILE_MISMATCH.value,
                                fp, "done_but_nowhere",
                            ),
                            category=FindingCategory.QUEUE_FILE_MISMATCH,
                            severity=Severity.CRITICAL,
                            description=f"队列标记done但源文件和目标文件都不存在: {os.path.basename(fp)}",
                            file_path=fp,
                            queue_path=self.config.logging.queue_path(),
                            detail={"queue_status": "done", "actual_location": "nowhere", "target_path": target},
                            fixable=True,
                            fix_description="将队列状态修正为failed",
                        ))
            elif status == "failed":
                if os.path.exists(fp) and not self._is_in_intake(fp):
                    findings.append(Finding(
                        fingerprint=_make_fingerprint(
                            FindingCategory.QUEUE_FILE_MISMATCH.value,
                            fp, "failed_but_in_target",
                        ),
                        category=FindingCategory.QUEUE_FILE_MISMATCH,
                        severity=Severity.WARNING,
                        description=f"队列标记failed但文件已在目标位置: {os.path.basename(fp)}",
                        file_path=fp,
                        queue_path=self.config.logging.queue_path(),
                        detail={"queue_status": "failed", "actual_location": "target"},
                        fixable=True,
                        fix_description="将队列状态修正为done并移出error_queue",
                    ))
        return findings

    def _check_target_occupied(self) -> list[Finding]:
        findings: list[Finding] = []
        error_items = self.error_queue.all()
        for item in error_items:
            if not item.case_number:
                continue
            target_dir = os.path.join(
                os.path.abspath(self.config.target_base),
                self.config.rules.target_structure.replace(
                    "{case_number}", item.case_number
                ),
            )
            target_path = os.path.join(target_dir, item.filename)
            if os.path.exists(target_path):
                tracked = self._is_target_tracked(target_path)
                if not tracked:
                    findings.append(Finding(
                        fingerprint=_make_fingerprint(
                            FindingCategory.TARGET_OCCUPIED.value,
                            target_path,
                        ),
                        category=FindingCategory.TARGET_OCCUPIED,
                        severity=Severity.WARNING,
                        description=f"目标路径被非本工具占用的文件阻挡: {target_path}",
                        file_path=target_path,
                        detail={"error_item_path": item.path, "target_path": target_path},
                        fixable=False,
                        fix_description="需人工移除或确认占用文件",
                    ))
        return findings

    def _check_config_drift(self) -> list[Finding]:
        findings: list[Finding] = []
        actions = self.action_logger.all_records()
        for action in actions:
            if action.rolled_back:
                continue
            dest = action.destination
            if not dest:
                continue
            if not os.path.exists(dest):
                continue
            case_number = action.case_number
            if not case_number:
                continue
            expected_dir = os.path.join(
                os.path.abspath(self.config.target_base),
                self.config.rules.target_structure.replace(
                    "{case_number}", case_number
                ),
            )
            actual_dir = os.path.dirname(os.path.abspath(dest))
            if os.path.normpath(actual_dir) != os.path.normpath(expected_dir):
                findings.append(Finding(
                    fingerprint=_make_fingerprint(
                        FindingCategory.CONFIG_DRIFT.value,
                        dest,
                    ),
                    category=FindingCategory.CONFIG_DRIFT,
                    severity=Severity.WARNING,
                    description=f"配置变更导致目标路径偏移: {os.path.basename(dest)} 实际在 {actual_dir}, 当前配置指向 {expected_dir}",
                    file_path=dest,
                    batch_id=action.batch_id,
                    action_id=action.action_id,
                    detail={
                        "actual_dir": actual_dir,
                        "expected_dir": expected_dir,
                        "action_source": action.source,
                    },
                    fixable=False,
                    fix_description="配置已变更,旧记录路径与新配置不匹配,需人工确认",
                ))
        return findings

    def _check_orphan_action(self) -> list[Finding]:
        findings: list[Finding] = []
        actions = self.action_logger.all_records()
        batch_ids = {b.batch_id for b in self._batch_history}
        seen_batch_ids: set[str] = set()
        for action in actions:
            bid = action.batch_id
            if not bid:
                continue
            if bid not in batch_ids and bid not in seen_batch_ids:
                seen_batch_ids.add(bid)
                findings.append(Finding(
                    fingerprint=_make_fingerprint(
                        FindingCategory.ORPHAN_ACTION.value,
                        bid,
                    ),
                    category=FindingCategory.ORPHAN_ACTION,
                    severity=Severity.WARNING,
                    description=f"动作日志中存在批次 {bid} 的记录,但 batch_history.json 中无此批次",
                    batch_id=bid,
                    detail={"orphan_batch_id": bid},
                    fixable=False,
                    fix_description="需人工确认是否应补充批次记录或清理孤立动作",
                ))
        return findings

    def _check_missing_action(self) -> list[Finding]:
        findings: list[Finding] = []
        actions = self.action_logger.all_records()
        action_ids = {a.action_id for a in actions}
        for batch in self._batch_history:
            for aid in batch.action_ids:
                if aid not in action_ids:
                    findings.append(Finding(
                        fingerprint=_make_fingerprint(
                            FindingCategory.MISSING_ACTION.value,
                            batch.batch_id, aid,
                        ),
                        category=FindingCategory.MISSING_ACTION,
                        severity=Severity.CRITICAL,
                        description=f"批次 {batch.batch_id} 引用动作 {aid},但 action_log 中无此记录",
                        batch_id=batch.batch_id,
                        action_id=aid,
                        detail={"batch_id": batch.batch_id, "action_id": aid},
                        fixable=False,
                        fix_description="动作记录缺失,无法自动恢复,需人工排查",
                    ))
        return findings

    def _check_error_queue_stale(self) -> list[Finding]:
        findings: list[Finding] = []
        items = self.error_queue.all()
        queue_items = self.processing_queue.all()
        queue_failed_paths = {
            q["path"] for q in queue_items if q.get("status") == "failed"
        }
        for item in items:
            if not os.path.exists(item.path):
                if item.path in queue_failed_paths:
                    continue
                findings.append(Finding(
                    fingerprint=_make_fingerprint(
                        FindingCategory.ERROR_QUEUE_STALE.value,
                        item.path,
                    ),
                    category=FindingCategory.ERROR_QUEUE_STALE,
                    severity=Severity.WARNING,
                    description=f"error_queue 中文件已不存在: {os.path.basename(item.path)}",
                    file_path=item.path,
                    detail={"path": item.path, "error": item.error},
                    fixable=True,
                    fix_description="从error_queue中移除此条目",
                ))
        return findings

    def _check_queue_stale_done(self) -> list[Finding]:
        findings: list[Finding] = []
        queue_items = self.processing_queue.all()
        for item in queue_items:
            if item.get("status") != "done":
                continue
            fp = item["path"]
            if self._is_in_intake(fp) and os.path.exists(fp):
                continue
            target = self._resolve_target_from_actions(fp)
            if target and not os.path.exists(target):
                findings.append(Finding(
                    fingerprint=_make_fingerprint(
                        FindingCategory.QUEUE_STALE_DONE.value,
                        fp,
                    ),
                    category=FindingCategory.QUEUE_STALE_DONE,
                    severity=Severity.CRITICAL,
                    description=f"队列标记done但目标文件已被外部删除: {os.path.basename(fp)}",
                    file_path=fp,
                    detail={"target_path": target},
                    fixable=True,
                    fix_description="将队列状态修正为failed",
                ))
        return findings

    def _check_error_queue_inconsistency(self) -> list[Finding]:
        findings: list[Finding] = []
        error_items = self.error_queue.all()
        queue_items = self.processing_queue.all()
        queue_by_path = {q["path"]: q for q in queue_items}
        error_paths = {e.path for e in error_items}
        queue_failed_paths = {
            q["path"] for q in queue_items if q.get("status") == "failed"
        }
        queue_rolled_back_paths = {
            q["path"] for q in queue_items
            if q.get("status") == "rolled_back"
        }
        for e in error_items:
            if e.path not in queue_by_path:
                findings.append(Finding(
                    fingerprint=_make_fingerprint(
                        FindingCategory.ERROR_QUEUE_INCONSISTENCY.value,
                        e.path, "not_in_queue",
                    ),
                    category=FindingCategory.ERROR_QUEUE_INCONSISTENCY,
                    severity=Severity.WARNING,
                    description=f"error_queue 文件不在 processing_queue 中: {os.path.basename(e.path)}",
                    file_path=e.path,
                    detail={"path": e.path, "queue_status": "missing"},
                    fixable=False,
                    fix_description="processing_queue无此记录,需人工确认",
                ))
            else:
                q_status = queue_by_path[e.path].get("status", "")
                if q_status not in ("failed", "rolled_back"):
                    findings.append(Finding(
                        fingerprint=_make_fingerprint(
                            FindingCategory.ERROR_QUEUE_INCONSISTENCY.value,
                            e.path, f"queue_{q_status}",
                        ),
                        category=FindingCategory.ERROR_QUEUE_INCONSISTENCY,
                        severity=Severity.CRITICAL,
                        description=f"error_queue 文件在 processing_queue 状态为 {q_status}: {os.path.basename(e.path)}",
                        file_path=e.path,
                        detail={"path": e.path, "queue_status": q_status},
                        fixable=q_status == "done",
                        fix_description="从error_queue中移除此条目" if q_status == "done" else "需人工确认",
                    ))
        for q in queue_items:
            if q.get("status") == "failed" and q["path"] not in error_paths:
                findings.append(Finding(
                    fingerprint=_make_fingerprint(
                        FindingCategory.ERROR_QUEUE_INCONSISTENCY.value,
                        q["path"], "failed_not_in_error_queue",
                    ),
                    category=FindingCategory.ERROR_QUEUE_INCONSISTENCY,
                    severity=Severity.WARNING,
                    description=f"processing_queue 标记 failed 但不在 error_queue 中: {os.path.basename(q['path'])}",
                    file_path=q["path"],
                    detail={"path": q["path"], "queue_status": "failed"},
                    fixable=True,
                    fix_description="补入error_queue",
                ))
        return findings

    def _check_batch_action_count_mismatch(self) -> list[Finding]:
        findings: list[Finding] = []
        actions = self.action_logger.all_records()
        batch_action_map: dict[str, list] = {}
        for a in actions:
            batch_action_map.setdefault(a.batch_id, []).append(a)
        for batch in self._batch_history:
            if batch.status.value == "rolled_back":
                continue
            logged_actions = batch_action_map.get(batch.batch_id, [])
            non_rolled_logged = [
                a for a in logged_actions if not a.rolled_back
            ]
            if batch.succeeded != len(non_rolled_logged):
                findings.append(Finding(
                    fingerprint=_make_fingerprint(
                        FindingCategory.BATCH_ACTION_COUNT_MISMATCH.value,
                        batch.batch_id,
                    ),
                    category=FindingCategory.BATCH_ACTION_COUNT_MISMATCH,
                    severity=Severity.WARNING,
                    description=(
                        f"批次 {batch.batch_id} succeeded={batch.succeeded} "
                        f"但 action_log 中有 {len(non_rolled_logged)} 条未回滚动作"
                    ),
                    batch_id=batch.batch_id,
                    detail={
                        "batch_succeeded": batch.succeeded,
                        "logged_action_count": len(non_rolled_logged),
                    },
                    fixable=False,
                    fix_description="计数不一致,需人工核实批次记录和动作日志",
                ))
        return findings

    def _check_rolled_back_file_missing(self) -> list[Finding]:
        findings: list[Finding] = []
        queue_items = self.processing_queue.all()
        for item in queue_items:
            if item.get("status") != "rolled_back":
                continue
            fp = item["path"]
            in_intake = os.path.exists(fp) and self._is_in_intake(fp)
            target = self._resolve_target_from_actions(fp)
            in_target = target and os.path.exists(target)
            if not in_intake and not in_target:
                findings.append(Finding(
                    fingerprint=_make_fingerprint(
                        FindingCategory.ROLLED_BACK_FILE_MISSING.value,
                        fp,
                    ),
                    category=FindingCategory.ROLLED_BACK_FILE_MISSING,
                    severity=Severity.CRITICAL,
                    description=f"回滚后文件既不在intake也不在target: {os.path.basename(fp)}",
                    file_path=fp,
                    detail={"target_path": target or ""},
                    fixable=True,
                    fix_description="将队列状态修正为failed",
                ))
        return findings

    def _resolve_target_from_actions(self, source_path: str) -> Optional[str]:
        actions = self.action_logger.all_records()
        for a in actions:
            if a.source == source_path and not a.rolled_back:
                return a.destination
        return None

    def _is_target_tracked(self, target_path: str) -> bool:
        actions = self.action_logger.all_records()
        abs_target = os.path.abspath(target_path)
        for a in actions:
            if os.path.abspath(a.destination) == abs_target:
                return True
        return False


def export_findings_json(findings: list[Finding], path: str) -> None:
    data = [f.to_dict() for f in findings]
    save_json(path, data)


def export_findings_csv(findings: list[Finding], path: str) -> None:
    import csv
    fieldnames = [
        "fingerprint", "category", "severity", "description",
        "file_path", "queue_path", "batch_id", "action_id",
        "fixable", "fix_description",
    ]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = finding.to_dict()
            row["category"] = row["category"]
            row["severity"] = row["severity"]
            row["fixable"] = str(row["fixable"])
            writer.writerow(row)


@dataclass
class ComparisonResult:
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    persistent_findings: list[Finding] = field(default_factory=list)
    last_check_time: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "new_findings": [f.to_dict() for f in self.new_findings],
            "resolved_findings": [f.to_dict() for f in self.resolved_findings],
            "persistent_findings": [f.to_dict() for f in self.persistent_findings],
            "last_check_time": self.last_check_time,
            "summary": {
                "new_count": len(self.new_findings),
                "resolved_count": len(self.resolved_findings),
                "persistent_count": len(self.persistent_findings),
            },
        }


def compare_findings(
    current: list[Finding],
    previous: list[Finding],
    last_check_time: Optional[str] = None,
) -> ComparisonResult:
    prev_by_fp = {f.fingerprint: f for f in previous}
    curr_by_fp = {f.fingerprint: f for f in current}

    new_findings = [
        f for f in current if f.fingerprint not in prev_by_fp
    ]
    resolved_findings = [
        f for f in previous if f.fingerprint not in curr_by_fp
    ]
    persistent_findings = [
        f for f in current if f.fingerprint in prev_by_fp
    ]

    return ComparisonResult(
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        persistent_findings=persistent_findings,
        last_check_time=last_check_time,
    )


def export_comparison_json(result: ComparisonResult, path: str) -> None:
    save_json(path, result.to_dict())


def export_comparison_csv(result: ComparisonResult, path: str) -> None:
    import csv
    fieldnames = [
        "status", "fingerprint", "category", "severity", "description",
        "file_path", "queue_path", "batch_id", "action_id",
        "fixable", "fix_description",
    ]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for status, findings in [
            ("new", result.new_findings),
            ("resolved", result.resolved_findings),
            ("persistent", result.persistent_findings),
        ]:
            for finding in findings:
                row = finding.to_dict()
                row["status"] = status
                row["category"] = row["category"]
                row["severity"] = row["severity"]
                row["fixable"] = str(row["fixable"])
                writer.writerow(row)
