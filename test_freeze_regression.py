from __future__ import annotations

import copy
import csv
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import yaml

from scan_sorter.action_logger import ActionLogger
from scan_sorter.config import (
    AppConfig,
    FreezeConfig,
    LoggingConfig,
    RetentionConfig,
    RetentionRule,
    RuleConfig,
    load_config,
)
from scan_sorter.models import (
    ActionRecord,
    ActionType,
    BatchRecord,
    BatchStatus,
    ConflictCategory,
    DisposalStatus,
    ErrorItem,
    FreezeConflictCategory,
    FreezeStatus,
    HandoffStatus,
    ConflictType as HandoffConflictType,
)
from scan_sorter.utils import ensure_dir, file_hash, load_json, read_jsonl, save_json

from scan_sorter.freeze_manager import (
    FreezeManager,
    export_preview_json,
    export_preview_csv,
    export_order_json,
    export_order_csv,
    export_history_json,
    export_history_csv,
)
from scan_sorter.retention_manager import (
    RetentionManager,
)
from scan_sorter import migration as migration_mod
from scan_sorter.handoff_creator import (
    create_handoff_package,
)
from scan_sorter.handoff_importer import (
    import_handoff_package,
)


def _make_config(
    base_dir: str,
    default_reason: str = "临时封存",
    default_valid_days: int = 30,
    max_frozen_files: int = 100,
    target_base: str | None = None,
    case_number_pattern: str = r"CASE-(\d+)",
    operator: str = "freeze-operator-test",
) -> AppConfig:
    intake = os.path.join(base_dir, "intake")
    tgt = target_base or os.path.join(base_dir, "target")
    log_dir = os.path.join(base_dir, "logs")
    for d in [intake, tgt, log_dir]:
        ensure_dir(d)

    cfg = AppConfig(
        intake_dir=intake,
        target_base=tgt,
        operator=operator,
        rules=RuleConfig(
            case_number_pattern=case_number_pattern,
            file_pattern=r".*\.(pdf|jpg|png)$",
            target_structure="{case_number}",
            action="copy",
        ),
        logging=LoggingConfig(dir=log_dir),
        freeze=FreezeConfig(
            enabled=True,
            default_reason=default_reason,
            default_valid_days=default_valid_days,
            max_frozen_files=max_frozen_files,
            check_write_permission=True,
        ),
    )
    cfg_path = os.path.join(base_dir, "config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg.to_dict(), f, allow_unicode=True, default_flow_style=False)
    cfg._source_path = os.path.abspath(cfg_path)
    return cfg


def _seed_archive(
    config: AppConfig,
    count: int = 3,
    files_per_case: int = 2,
    archive_days_ago: int | list | None = None,
    operator: str | None = None,
) -> dict:
    intake = config.intake_dir
    target = config.target_base
    action_log_path = config.logging.action_log_path()
    batch_history_path = config.logging.batch_history_path()
    action_logger = ActionLogger(action_log_path)
    batches: list[BatchRecord] = []
    files_by_case: dict[str, list[str]] = {}
    cases = []
    for i in range(count):
        case_number = f"CASE-{(i + 1) * 100:04d}"
        cases.append(case_number)
        batch = BatchRecord(
            operator=operator or config.operator,
            status=BatchStatus.COMPLETED,
        )
        batches.append(batch)
        files_by_case[case_number] = []
        for j in range(files_per_case):
            days_ago = None
            if archive_days_ago is not None:
                if isinstance(archive_days_ago, list):
                    idx = i * files_per_case + j
                    if idx < len(archive_days_ago):
                        days_ago = archive_days_ago[idx]
                else:
                    days_ago = archive_days_ago

            filename = f"{case_number}_DOC{j + 1}.pdf"
            src = os.path.join(intake, filename)
            with open(src, "wb") as f:
                f.write(f"content for {case_number} doc {j + 1}".encode("utf-8") * (10 + j))
            dest_dir = os.path.join(target, case_number)
            ensure_dir(dest_dir)
            dest = os.path.join(dest_dir, filename)
            shutil.copy2(src, dest)

            ts_dt = datetime.now()
            if days_ago is not None:
                ts_dt = ts_dt - timedelta(days=days_ago)
            ts = ts_dt.isoformat()

            action = ActionRecord(
                batch_id=batch.batch_id,
                source=src,
                destination=dest,
                action_type=ActionType.COPY,
                operator=operator or config.operator,
                case_number=case_number,
                timestamp=ts,
            )
            action_logger.log(action)
            files_by_case[case_number].append(dest)
            batch.action_ids.append(action.action_id)

            if days_ago is not None:
                ts_time = ts_dt.timestamp()
                os.utime(dest, (ts_time, ts_time))
        batch.total = files_per_case
        batch.succeeded = files_per_case
        batch.failed = 0
    save_json(batch_history_path, [b.to_dict() for b in batches])
    return {
        "batches": batches,
        "files_by_case": files_by_case,
        "action_log_path": action_log_path,
        "batch_history_path": batch_history_path,
        "cases": cases,
    }


def _make_config_with_retention(
    base_dir: str,
    default_retention_days: int = 30,
    default_reason: str = "临时封存",
    default_valid_days: int = 90,
    max_frozen_files: int = 100,
    target_base: str | None = None,
    case_number_pattern: str = r"CASE-(\d+)",
    operator: str = "freeze-retention-test",
) -> AppConfig:
    intake = os.path.join(base_dir, "intake")
    tgt = target_base or os.path.join(base_dir, "target")
    log_dir = os.path.join(base_dir, "logs")
    for d in [intake, tgt, log_dir]:
        ensure_dir(d)

    retention_rules = [
        RetentionRule.from_dict({
            "rule_id": "R1",
            "name": "常规案件保留30天",
            "case_number_pattern": r"CASE-\d{4}",
            "batch_id_pattern": r".*",
            "retention_days": default_retention_days,
        }),
    ]

    cfg = AppConfig(
        intake_dir=intake,
        target_base=tgt,
        operator=operator,
        rules=RuleConfig(
            case_number_pattern=case_number_pattern,
            file_pattern=r".*\.(pdf|jpg|png)$",
            target_structure="{case_number}",
            action="copy",
        ),
        logging=LoggingConfig(dir=log_dir),
        freeze=FreezeConfig(
            enabled=True,
            default_reason=default_reason,
            default_valid_days=default_valid_days,
            max_frozen_files=max_frozen_files,
            check_write_permission=True,
        ),
        retention=RetentionConfig(
            enabled=True,
            default_retention_days=default_retention_days,
            rules=retention_rules,
            check_write_permission=True,
        ),
    )
    cfg_path = os.path.join(base_dir, "config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg.to_dict(), f, allow_unicode=True, default_flow_style=False)
    cfg._source_path = os.path.abspath(cfg_path)
    return cfg


class TestFreezeBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="freeze_test_")
        self.config = _make_config(self.tmp)

    def tearDown(self):
        for _ in range(3):
            try:
                shutil.rmtree(self.tmp, ignore_errors=True)
                break
            except Exception:
                time.sleep(0.05)


class TestFreezeModels(TestFreezeBase):
    def test_freeze_status_enum(self):
        self.assertEqual(FreezeStatus.ACTIVE.value, "active")
        self.assertEqual(FreezeStatus.EXPIRED.value, "expired")
        self.assertEqual(FreezeStatus.RELEASED.value, "released")
        self.assertEqual(FreezeStatus.CONFLICT.value, "conflict")

    def test_freeze_conflict_category_enum(self):
        self.assertEqual(FreezeConflictCategory.FILE_MISSING.value, "file_missing")
        self.assertEqual(FreezeConflictCategory.IN_PROCESSING_QUEUE.value, "in_processing_queue")
        self.assertEqual(FreezeConflictCategory.IN_ERROR_QUEUE.value, "in_error_queue")
        self.assertEqual(FreezeConflictCategory.DUPLICATE_FREEZE.value, "duplicate_freeze")
        self.assertEqual(FreezeConflictCategory.CONFIG_CHANGED.value, "config_changed")
        self.assertEqual(FreezeConflictCategory.NO_WRITE_PERMISSION.value, "no_write_permission")
        self.assertEqual(FreezeConflictCategory.EXPIRED.value, "expired")
        self.assertEqual(FreezeConflictCategory.MAX_COUNT_EXCEEDED.value, "max_count_exceeded")


class TestFreezePreview(TestFreezeBase):
    def test_preview_empty_target(self):
        mgr = FreezeManager(self.config)
        prev = mgr.preview_freeze()
        self.assertEqual(prev.total_files, 0)
        self.assertEqual(prev.will_freeze, 0)
        self.assertEqual(prev.will_conflict, 0)
        self.assertEqual(prev.items, [])

    def test_preview_normal_all_freeze(self):
        _seed_archive(self.config, count=2, files_per_case=2, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        prev = mgr.preview_freeze()
        self.assertEqual(prev.total_files, 4)
        self.assertEqual(prev.will_freeze, 4)
        self.assertEqual(prev.will_conflict, 0)
        for it in prev.items:
            self.assertEqual(it.freeze_status, FreezeStatus.ACTIVE)
            self.assertIsNotNone(it.file)
            self.assertTrue(it.file.case_number.startswith("CASE-"))

    def test_preview_filter_case_numbers(self):
        seed = _seed_archive(self.config, count=3, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        target_cases = [seed["cases"][0], seed["cases"][1]]
        prev = mgr.preview_freeze(case_numbers=target_cases)
        self.assertEqual(prev.total_files, 2)
        for it in prev.items:
            self.assertIn(it.file.case_number, target_cases)

    def test_preview_filter_batch_ids(self):
        seed = _seed_archive(self.config, count=3, files_per_case=2, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        bid = seed["batches"][0].batch_id
        prev = mgr.preview_freeze(batch_ids=[bid])
        self.assertEqual(prev.total_files, 2)
        for it in prev.items:
            self.assertEqual(it.file.batch_id, bid)

    def test_preview_filter_date_range(self):
        days = [60, 5, 60, 5, 60, 5]
        _seed_archive(self.config, count=3, files_per_case=2, archive_days_ago=days)
        mgr = FreezeManager(self.config)
        now = datetime.now()
        date_from = now - timedelta(days=10)
        date_to = now + timedelta(days=1)
        prev = mgr.preview_freeze(date_from=date_from, date_to=date_to)
        self.assertEqual(prev.total_files, 3)

    def test_preview_default_reason_and_valid_days(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        prev = mgr.preview_freeze()
        self.assertEqual(prev.reason, "临时封存")
        self.assertEqual(prev.valid_days, 30)

    def test_preview_custom_reason_and_valid_days(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        prev = mgr.preview_freeze(reason="审计封存", valid_days=90)
        self.assertEqual(prev.reason, "审计封存")
        self.assertEqual(prev.valid_days, 90)


class TestFreezeConfirm(TestFreezeBase):
    def test_confirm_normal(self):
        _seed_archive(self.config, count=2, files_per_case=2, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        order = mgr.confirm_freeze(reason="测试封存", notes="测试备注")
        self.assertEqual(order.order_type, "freeze")
        self.assertEqual(order.operator, "freeze-operator-test")
        self.assertEqual(order.total_frozen, 4)
        self.assertEqual(order.total_conflicts, 0)
        self.assertEqual(order.reason, "测试封存")
        self.assertEqual(order.notes, "测试备注")
        self.assertTrue(order.order_id.startswith("FRZ-"))
        for it in order.items:
            self.assertEqual(it.freeze_status, FreezeStatus.ACTIVE)
            self.assertIsNotNone(it.frozen_at)
            self.assertEqual(it.freeze_order_id, order.order_id)

    def test_confirm_skips_error_queue(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        path = list(seed["files_by_case"].values())[0][0]
        eq_path = self.config.logging.error_queue_path()
        from scan_sorter.queue_manager import ErrorQueue
        eq = ErrorQueue(eq_path)
        eq.add(ErrorItem(
            path=path,
            filename=os.path.basename(path),
            case_number="CASE-0100",
            error="模拟错误队列中的案件文件",
        ))
        mgr = FreezeManager(self.config)
        order = mgr.confirm_freeze()
        self.assertEqual(order.total_conflicts, 1)
        self.assertEqual(order.total_frozen, 1)
        conflict_items = [i for i in order.items if i.freeze_status == FreezeStatus.CONFLICT]
        self.assertEqual(len(conflict_items), 1)
        cats = [c.category for c in conflict_items[0].conflicts]
        self.assertIn(FreezeConflictCategory.IN_ERROR_QUEUE, cats)

    def test_confirm_skips_processing_queue(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        path = list(seed["files_by_case"].values())[0][0]
        from scan_sorter.queue_manager import ProcessingQueue
        pq = ProcessingQueue(self.config.logging.queue_path())
        pq.enqueue(path, "CASE-0100", status="processing", batch_id="batch-test-001")
        mgr = FreezeManager(self.config)
        order = mgr.confirm_freeze()
        self.assertEqual(order.total_conflicts, 1)
        self.assertEqual(order.total_frozen, 1)
        conflict_items = [i for i in order.items if i.freeze_status == FreezeStatus.CONFLICT]
        self.assertEqual(len(conflict_items), 1)
        cats = [c.category for c in conflict_items[0].conflicts]
        self.assertIn(FreezeConflictCategory.IN_PROCESSING_QUEUE, cats)

    def test_confirm_file_missing_conflict(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        path = list(seed["files_by_case"].values())[0][0]
        os.remove(path)
        mgr = FreezeManager(self.config)
        order = mgr.confirm_freeze()
        self.assertEqual(order.total_conflicts, 1)
        self.assertEqual(order.total_frozen, 1)
        ci = [i for i in order.items if i.freeze_status == FreezeStatus.CONFLICT][0]
        cats = [c.category for c in ci.conflicts]
        self.assertIn(FreezeConflictCategory.FILE_MISSING, cats)

    def test_confirm_duplicate_freeze_conflict(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        mgr.confirm_freeze()
        order2 = mgr.confirm_freeze()
        self.assertEqual(order2.total_conflicts, 2)
        self.assertEqual(order2.total_frozen, 0)
        for it in order2.items:
            self.assertEqual(it.freeze_status, FreezeStatus.CONFLICT)
            cats = [c.category for c in it.conflicts]
            self.assertIn(FreezeConflictCategory.DUPLICATE_FREEZE, cats)

    def test_confirm_max_count_exceeded(self):
        _seed_archive(self.config, count=3, files_per_case=2, archive_days_ago=5)
        cfg = _make_config(self.tmp, max_frozen_files=3)
        mgr = FreezeManager(cfg)
        order = mgr.confirm_freeze()
        self.assertEqual(order.total_frozen, 3)
        self.assertEqual(order.total_conflicts, 3)
        max_conflict_count = 0
        for it in order.items:
            cats = [c.category for c in it.conflicts]
            if FreezeConflictCategory.MAX_COUNT_EXCEEDED in cats:
                max_conflict_count += 1
        self.assertEqual(max_conflict_count, 3)

    def test_confirm_no_write_permission_conflict(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        path = list(seed["files_by_case"].values())[0][0]
        try:
            st = os.stat(path)
            os.chmod(path, st.st_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
            mgr = FreezeManager(self.config)
            order = mgr.confirm_freeze()
            conflict_cats = set()
            for it in order.items:
                for c in it.conflicts:
                    conflict_cats.add(c.category)
            self.assertIn(FreezeConflictCategory.NO_WRITE_PERMISSION, conflict_cats)
        finally:
            if os.path.exists(path):
                try:
                    st = os.stat(path)
                    os.chmod(path, st.st_mode | stat.S_IWUSR)
                except Exception:
                    pass


class TestFreezeStatePersistence(TestFreezeBase):
    def test_state_persisted_and_recoverable(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        mgr1 = FreezeManager(self.config)
        order1 = mgr1.confirm_freeze(notes="第一次封存")
        order_id_1 = order1.order_id

        mgr2 = FreezeManager(self.config)
        orders = mgr2.list_orders()
        self.assertEqual(len(orders), 1)
        self.assertEqual(orders[0].order_id, order_id_1)
        self.assertEqual(orders[0].total_frozen, 2)

        active_files = mgr2.get_active_frozen_files()
        self.assertEqual(len(active_files), 2)
        for af in active_files:
            self.assertEqual(af.freeze_status, FreezeStatus.ACTIVE)

    def test_cross_restart_history(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        mgr_a = FreezeManager(self.config)
        order_a = mgr_a.confirm_freeze(notes="重启前封存")
        frozen_paths_before = {it.file.path for it in mgr_a.get_active_frozen_files()}

        mgr_b = FreezeManager(self.config)
        orders = mgr_b.list_orders()
        self.assertEqual(len(orders), 1)
        self.assertEqual(orders[0].order_id, order_a.order_id)
        self.assertEqual(orders[0].notes, "重启前封存")
        frozen_after = {it.file.path for it in mgr_b.get_active_frozen_files()}
        self.assertEqual(frozen_paths_before, frozen_after)
        self.assertEqual(len(frozen_after), 2)

        mgr_b.release_order(order_a.order_id)
        mgr_c = FreezeManager(self.config)
        self.assertEqual(len(mgr_c.get_active_frozen_files()), 0)
        self.assertEqual(len(mgr_c.list_orders()), 2)

    def test_consistency_check_normal(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        mgr.confirm_freeze()
        check = mgr.consistency_check()
        self.assertTrue(check["is_consistent"])
        self.assertEqual(check["issues"], [])

    def test_log_file_written(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        mgr.confirm_freeze()
        log_path = self.config.freeze.log_path(self.config.logging.dir)
        self.assertTrue(os.path.exists(log_path))
        records = read_jsonl(log_path)
        self.assertGreater(len(records), 0)
        events = [r["event"] for r in records]
        self.assertIn("freeze_create", events)


class TestFreezeRelease(TestFreezeBase):
    def test_release_only_this_order(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        order_freeze = mgr.confirm_freeze()
        freeze_id = order_freeze.order_id
        order_release = mgr.release_order(freeze_id)
        self.assertEqual(order_release.order_type, "release")
        self.assertEqual(order_release.total_released, 2)
        self.assertEqual(order_release.total_conflicts, 0)
        for it in order_release.items:
            self.assertEqual(it.freeze_status, FreezeStatus.RELEASED)
            self.assertEqual(it.release_order_id, order_release.order_id)
        active = mgr.get_active_frozen_files()
        self.assertEqual(len(active), 0)

    def test_release_preserves_other_orders(self):
        seed = _seed_archive(self.config, count=3, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        all_cases = seed["cases"]
        order1 = mgr.confirm_freeze(case_numbers=[all_cases[0]])
        self.assertEqual(order1.total_frozen, 1)
        order2 = mgr.confirm_freeze(case_numbers=[all_cases[1], all_cases[2]])
        self.assertEqual(order2.total_frozen, 2)
        mgr.release_order(order1.order_id)
        active = mgr.get_active_frozen_files()
        self.assertEqual(len(active), 2)

    def test_release_unknown_order_raises(self):
        mgr = FreezeManager(self.config)
        with self.assertRaises(ValueError):
            mgr.release_order("FRZ-NONEXISTENT-123456")

    def test_release_twice_conflict(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        order_freeze = mgr.confirm_freeze()
        freeze_id = order_freeze.order_id
        mgr.release_order(freeze_id)
        with self.assertRaises(ValueError):
            mgr.release_order(freeze_id)

    def test_release_only_releases_own_files(self):
        seed = _seed_archive(self.config, count=2, files_per_case=2, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        case1 = seed["cases"][0]
        case2 = seed["cases"][1]

        order1 = mgr.confirm_freeze(case_numbers=[case1])
        self.assertEqual(order1.total_frozen, 2)
        order2 = mgr.confirm_freeze(case_numbers=[case2])
        self.assertEqual(order2.total_frozen, 2)

        self.assertEqual(len(mgr.get_active_frozen_files()), 4)

        release_order = mgr.release_order(order1.order_id)
        self.assertEqual(release_order.total_released, 2)
        self.assertEqual(release_order.total_conflicts, 0)

        active = mgr.get_active_frozen_files()
        self.assertEqual(len(active), 2)
        for af in active:
            self.assertEqual(af.file.case_number, case2)


class TestFreezeConfigReload(TestFreezeBase):
    def _rewrite_config(self, new_default_days: int, new_max: int, new_reason: str):
        cfg_path = self.config._source_path
        with open(cfg_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        raw.setdefault("freeze", {})
        raw["freeze"]["default_valid_days"] = new_default_days
        raw["freeze"]["max_frozen_files"] = new_max
        raw["freeze"]["default_reason"] = new_reason
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(raw, f, allow_unicode=True, default_flow_style=False)

    def test_config_reload_effect_on_new_operations(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=5)
        mgr1 = FreezeManager(self.config)
        prev1 = mgr1.preview_freeze()
        self.assertEqual(prev1.valid_days, 30)
        self.assertEqual(prev1.reason, "临时封存")

        self._rewrite_config(new_default_days=60, new_max=100, new_reason="新默认原因")

        mgr2 = FreezeManager(self.config)
        prev2 = mgr2.preview_freeze()
        self.assertEqual(prev2.valid_days, 60)
        self.assertEqual(prev2.reason, "新默认原因")

    def test_config_change_detection_on_confirm(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=5)
        mgr1 = FreezeManager(self.config)
        mgr1._state["config_signature"] = {
            "default_reason": "CHANGED",
            "default_valid_days": 9999,
            "max_frozen_files": 9999,
            "target_base": os.path.abspath(self.config.target_base),
        }
        mgr1._save_state()
        order = mgr1.confirm_freeze()
        conflict_cats = set()
        for it in order.items:
            for c in it.conflicts:
                conflict_cats.add(c.category)
        self.assertIn(FreezeConflictCategory.CONFIG_CHANGED, conflict_cats)


class TestFreezeExports(TestFreezeBase):
    def test_export_preview_json(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        prev = mgr.preview_freeze()
        out = os.path.join(self.tmp, "prev.json")
        export_preview_json(prev, out)
        self.assertTrue(os.path.exists(out))
        data = load_json(out)
        self.assertEqual(data["total_files"], 2)
        self.assertEqual(data["will_freeze"], 2)
        self.assertEqual(len(data["items"]), 2)

    def test_export_preview_csv_fields(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        prev = mgr.preview_freeze()
        out = os.path.join(self.tmp, "prev.csv")
        export_preview_csv(prev, out)
        self.assertTrue(os.path.exists(out))
        with open(out, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            self.assertIn("filename", fieldnames)
            self.assertIn("path", fieldnames)
            self.assertIn("case_number", fieldnames)
            self.assertIn("batch_id", fieldnames)
            self.assertIn("archived_at", fieldnames)
            self.assertIn("size", fieldnames)
            self.assertIn("freeze_status", fieldnames)
            self.assertIn("conflict_count", fieldnames)
            self.assertIn("conflict_categories", fieldnames)
            self.assertIn("conflict_details", fieldnames)
            rows = list(reader)
            self.assertEqual(len(rows), 2)
            for row in rows:
                self.assertEqual(row["freeze_status"], "active")
                self.assertIn("CASE-", row["case_number"])

    def test_export_order_json_and_csv(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        order = mgr.confirm_freeze(notes="导出测试")
        jout = os.path.join(self.tmp, "order.json")
        cout = os.path.join(self.tmp, "order.csv")
        export_order_json(order, jout)
        export_order_csv(order, cout)
        data = load_json(jout)
        self.assertEqual(data["order_id"], order.order_id)
        self.assertEqual(data["total_frozen"], 2)
        self.assertEqual(len(data["items"]), 2)
        with open(cout, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            self.assertIn("order_id", fieldnames)
            self.assertIn("order_type", fieldnames)
            self.assertIn("operator", fieldnames)
            self.assertIn("reason", fieldnames)
            self.assertIn("item_id", fieldnames)
            self.assertIn("filename", fieldnames)
            self.assertIn("case_number", fieldnames)
            self.assertIn("freeze_status", fieldnames)
            self.assertIn("frozen_at", fieldnames)
            rows = list(reader)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["order_type"], "freeze")

    def test_export_history_json_csv(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        mgr.confirm_freeze()
        orders = mgr.list_orders()
        jout = os.path.join(self.tmp, "hist.json")
        cout = os.path.join(self.tmp, "hist.csv")
        export_history_json(orders, jout)
        export_history_csv(orders, cout)
        data = load_json(jout)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["total_frozen"], 2)
        with open(cout, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            self.assertIn("order_id", fieldnames)
            self.assertIn("order_type", fieldnames)
            self.assertIn("created_at", fieldnames)
            self.assertIn("operator", fieldnames)
            self.assertIn("reason", fieldnames)
            self.assertIn("valid_days", fieldnames)
            self.assertIn("expires_at", fieldnames)
            self.assertIn("status", fieldnames)
            self.assertIn("total_files", fieldnames)
            self.assertIn("total_frozen", fieldnames)
            self.assertIn("total_conflicts", fieldnames)
            self.assertIn("total_released", fieldnames)
            self.assertIn("notes", fieldnames)
            rows = list(reader)
            self.assertEqual(len(rows), 1)


class TestFreezeCLIIntegration(TestFreezeBase):
    @classmethod
    def setUpClass(cls):
        import scan_sorter.cli as _cli_mod

    def _run_cli(self, argv: list) -> int:
        import io as _io
        import sys as _sys
        from contextlib import redirect_stdout, redirect_stderr
        bytes_out = _io.BytesIO()
        bytes_err = _io.BytesIO()
        wrap_out = _io.TextIOWrapper(
            bytes_out, encoding="utf-8", errors="replace"
        )
        wrap_err = _io.TextIOWrapper(
            bytes_err, encoding="utf-8", errors="replace"
        )
        try:
            from scan_sorter.cli import main as cli_main
            with redirect_stdout(wrap_out), redirect_stderr(wrap_err):
                try:
                    return cli_main(list(argv))
                except SystemExit as e:
                    return int(e.code) if e.code is not None else 0
        finally:
            try:
                wrap_out.flush()
            except Exception:
                pass
            try:
                wrap_err.flush()
            except Exception:
                pass

    def test_cli_preview_command(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        rc = self._run_cli([
            "-c", self.config._source_path,
            "freeze-preview",
        ])
        self.assertEqual(rc, 0)

    def test_cli_preview_with_export_json(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=5)
        out_json = os.path.join(self.tmp, "cli_prev.json")
        rc = self._run_cli([
            "-c", self.config._source_path,
            "freeze-preview",
            "--format", "json",
            "--output", out_json,
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out_json))
        data = load_json(out_json)
        self.assertEqual(data["total_files"], 2)
        self.assertEqual(data["will_freeze"], 2)

    def test_cli_preview_with_export_csv(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=5)
        out_csv = os.path.join(self.tmp, "cli_prev.csv")
        rc = self._run_cli([
            "-c", self.config._source_path,
            "freeze-preview",
            "--format", "csv",
            "--output", out_csv,
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out_csv))
        with open(out_csv, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["freeze_status"], "active")

    def test_cli_confirm(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        rc = self._run_cli([
            "-c", self.config._source_path,
            "freeze-confirm",
            "--notes", "CLI确认封存",
        ])
        self.assertEqual(rc, 0)
        mgr = FreezeManager(self.config)
        orders = mgr.list_orders()
        self.assertEqual(len(orders), 1)
        self.assertEqual(orders[0].total_frozen, 2)
        self.assertEqual(orders[0].notes, "CLI确认封存")

    def test_cli_confirm_filter_case(self):
        seed = _seed_archive(self.config, count=3, files_per_case=1, archive_days_ago=5)
        rc = self._run_cli([
            "-c", self.config._source_path,
            "freeze-confirm",
            "--case-numbers", f"{seed['cases'][0]},{seed['cases'][1]}",
        ])
        self.assertEqual(rc, 0)
        mgr = FreezeManager(self.config)
        orders = mgr.list_orders()
        self.assertEqual(orders[0].total_frozen, 2)

    def test_cli_history(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        mgr.confirm_freeze()
        rc = self._run_cli([
            "-c", self.config._source_path,
            "freeze-history",
        ])
        self.assertEqual(rc, 0)

    def test_cli_history_with_filter_and_export(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        mgr.confirm_freeze()
        out = os.path.join(self.tmp, "cli_hist.json")
        rc = self._run_cli([
            "-c", self.config._source_path,
            "freeze-history",
            "--order-type", "freeze",
            "--format", "json",
            "--output", out,
        ])
        self.assertEqual(rc, 0)
        data = load_json(out)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["order_type"], "freeze")

    def test_cli_release(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        mgr1 = FreezeManager(self.config)
        order = mgr1.confirm_freeze()
        rc = self._run_cli([
            "-c", self.config._source_path,
            "freeze-release",
            "--order-id", order.order_id,
        ])
        self.assertEqual(rc, 0)
        mgr2 = FreezeManager(self.config)
        release_orders = mgr2.list_orders(order_type="release")
        self.assertEqual(len(release_orders), 1)
        self.assertEqual(release_orders[0].total_released, 2)
        self.assertEqual(len(mgr2.get_active_frozen_files()), 0)

    def test_cli_export_active(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        mgr.confirm_freeze()
        out = os.path.join(self.tmp, "cli_active.csv")
        rc = self._run_cli([
            "-c", self.config._source_path,
            "freeze-export",
            "--source", "active",
            "--format", "csv",
            "--output", out,
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out))
        with open(out, "r", encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)


class TestFreezeEdgeCases(TestFreezeBase):
    def test_original_files_untouched_after_freeze(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        all_paths = []
        for case_files in seed["files_by_case"].values():
            all_paths.extend(case_files)
        hashes_before = {p: file_hash(p) for p in all_paths}
        mtimes_before = {p: os.path.getmtime(p) for p in all_paths}
        mgr = FreezeManager(self.config)
        mgr.confirm_freeze()
        for p in all_paths:
            self.assertTrue(os.path.exists(p))
            self.assertEqual(file_hash(p), hashes_before[p])
            self.assertEqual(os.path.getmtime(p), mtimes_before[p])

    def test_original_files_untouched_after_release(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        all_paths = []
        for case_files in seed["files_by_case"].values():
            all_paths.extend(case_files)
        hashes_before = {p: file_hash(p) for p in all_paths}
        mgr = FreezeManager(self.config)
        order = mgr.confirm_freeze()
        mgr.release_order(order.order_id)
        for p in all_paths:
            self.assertTrue(os.path.exists(p))
            self.assertEqual(file_hash(p), hashes_before[p])

    def test_marked_index_consistency_after_multiple_operations(self):
        seed = _seed_archive(self.config, count=3, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        all_cases = seed["cases"]

        order1 = mgr.confirm_freeze(case_numbers=[all_cases[0]])
        self.assertEqual(order1.total_frozen, 1)
        check1 = mgr.consistency_check()
        self.assertTrue(check1["is_consistent"], f"一致性问题1: {check1['issues']}")

        order2 = mgr.confirm_freeze(case_numbers=[all_cases[1], all_cases[2]])
        self.assertEqual(order2.total_frozen, 2)
        check2 = mgr.consistency_check()
        self.assertTrue(check2["is_consistent"], f"一致性问题2: {check2['issues']}")

        mgr.release_order(order1.order_id)
        check3 = mgr.consistency_check()
        self.assertTrue(check3["is_consistent"], f"一致性问题3: {check3['issues']}")

        order3 = mgr.confirm_freeze(case_numbers=[all_cases[0]])
        self.assertEqual(order3.total_frozen, 1)
        check4 = mgr.consistency_check()
        self.assertTrue(check4["is_consistent"], f"一致性问题4: {check4['issues']}")

        active = mgr.get_active_frozen_files()
        self.assertEqual(len(active), 3)

    def test_list_orders_limit(self):
        _seed_archive(self.config, count=3, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        for i in range(5):
            mgr.confirm_freeze(notes=f"第{i+1}次")
        limited = mgr.list_orders(limit=3)
        self.assertEqual(len(limited), 3)
        all_orders = mgr.list_orders()
        self.assertEqual(len(all_orders), 5)
        self.assertEqual(limited[0].order_id, all_orders[0].order_id)

    def test_get_order(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        order = mgr.confirm_freeze()
        mgr2 = FreezeManager(self.config)
        found = mgr2.get_order(order.order_id)
        self.assertIsNotNone(found)
        self.assertEqual(found.order_id, order.order_id)
        self.assertEqual(found.total_frozen, 1)
        self.assertIsNone(mgr2.get_order("FRZ-NOT-EXIST"))

    def test_log_consistency(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=5)
        mgr = FreezeManager(self.config)
        order = mgr.confirm_freeze()
        log_path = self.config.freeze.log_path(self.config.logging.dir)
        records = read_jsonl(log_path)
        create_records = [r for r in records if r["event"] == "freeze_create"]
        self.assertEqual(len(create_records), 1)
        self.assertEqual(create_records[0]["order_id"], order.order_id)
        self.assertEqual(create_records[0]["frozen"], 2)
        self.assertEqual(create_records[0]["conflicts"], 0)

        release_order = mgr.release_order(order.order_id)
        records = read_jsonl(log_path)
        release_records = [r for r in records if r["event"] == "freeze_release"]
        self.assertEqual(len(release_records), 1)
        self.assertEqual(release_records[0]["original_order_id"], order.order_id)
        self.assertEqual(release_records[0]["released"], 2)


class TestHardFreezeRetentionIntegration(TestFreezeBase):
    """场景1: confirm_freeze 后跨重启再跑 retention preview/generate，封存文件不能被标成待清理"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="freeze_ret_test_")
        self.config = _make_config_with_retention(self.tmp, default_retention_days=30)

    def test_frozen_files_excluded_from_retention_preview(self):
        """封存文件在 retention preview 中应标为冲突，不能是待清理"""
        days_ago = [45, 45, 45, 5]
        _seed_archive(self.config, count=2, files_per_case=2, archive_days_ago=days_ago)
        fm = FreezeManager(self.config)
        order = fm.confirm_freeze(notes="封存超期档案防清理")
        self.assertEqual(order.total_frozen, 4)

        fm2 = FreezeManager(self.config)
        active_before = {it.file.path for it in fm2.get_active_frozen_files()}
        self.assertEqual(len(active_before), 4)

        rm = RetentionManager(self.config)
        prev = rm.preview()

        frozen_in_prev = 0
        expired_count = 0
        conflict_count = 0
        for item in prev.items:
            if item.file and item.file.path in active_before:
                frozen_in_prev += 1
                self.assertNotEqual(
                    item.disposal_status,
                    DisposalStatus.EXPIRED,
                    f"封存文件 {item.file.path} 不应被标为 EXPIRED",
                )
                self.assertNotEqual(
                    item.disposal_status,
                    DisposalStatus.MARKED,
                    f"封存文件 {item.file.path} 不应被标为 MARKED",
                )
                cats = [c.category for c in item.conflicts]
                self.assertTrue(
                    any(c == ConflictCategory.FROZEN_FILE for c in cats) or item.disposal_status == DisposalStatus.CONFLICT,
                    f"封存文件 {item.file.path} 应有 FROZEN_FILE 冲突或 CONFLICT 状态",
                )
            if item.disposal_status == DisposalStatus.EXPIRED:
                expired_count += 1
            if item.disposal_status == DisposalStatus.CONFLICT:
                conflict_count += 1

        self.assertEqual(frozen_in_prev, 4)
        self.assertEqual(expired_count, 0, "封存的3个超期文件不应被视为 EXPIRED")
        self.assertGreaterEqual(conflict_count, 3)

    def test_frozen_files_not_marked_on_retention_generate(self):
        """封存文件在 retention generate 中不能被标记为待清理，跨重启后一致"""
        days_ago = [60, 60, 60, 60]
        _seed_archive(self.config, count=2, files_per_case=2, archive_days_ago=days_ago)
        fm = FreezeManager(self.config)
        order = fm.confirm_freeze(notes="封存防清理")
        frozen_paths = {it.file.path for it in fm.get_active_frozen_files() if it.file}
        self.assertEqual(len(frozen_paths), 4)

        del fm
        fm_restart_1 = FreezeManager(self.config)
        self.assertEqual(len({it.file.path for it in fm_restart_1.get_active_frozen_files() if it.file}), 4)

        rm1 = RetentionManager(self.config)
        run1 = rm1.generate_disposal_list(notes="第一次清理生成")
        self.assertEqual(run1.total_marked, 0, "所有文件已封存，不应有任何标记")
        self.assertGreaterEqual(run1.total_conflicts, 4)

        for item in run1.items:
            if item.file and item.file.path in frozen_paths:
                self.assertNotEqual(item.disposal_status, DisposalStatus.MARKED)

        del rm1, fm_restart_1

        fm_restart_2 = FreezeManager(self.config)
        still_active = {it.file.path for it in fm_restart_2.get_active_frozen_files() if it.file}
        self.assertEqual(still_active, frozen_paths)

        rm2 = RetentionManager(self.config)
        marked_now = rm2.get_marked_files()
        marked_paths = {it.file.path for it in marked_now if it.file}
        for fp in frozen_paths:
            self.assertNotIn(fp, marked_paths, f"封存文件 {fp} 不应出现在清理标记列表")

    def test_partial_freeze_mixed_with_expired(self):
        """部分封存：封存2个超期文件，另2个超期文件应正常被标记"""
        days_ago = [45, 45, 45, 45]
        seed = _seed_archive(self.config, count=2, files_per_case=2, archive_days_ago=days_ago)
        case_to_freeze = seed["cases"][0]
        fm = FreezeManager(self.config)
        order = fm.confirm_freeze(case_numbers=[case_to_freeze])
        self.assertEqual(order.total_frozen, 2)
        frozen_paths = {it.file.path for it in fm.get_active_frozen_files() if it.file}

        del fm
        rm = RetentionManager(self.config)
        run = rm.generate_disposal_list()
        self.assertEqual(run.total_marked, 2, "未封存的2个超期文件应被正常标记")

        for item in run.items:
            if not item.file:
                continue
            if item.file.path in frozen_paths:
                self.assertNotEqual(item.disposal_status, DisposalStatus.MARKED)
            else:
                if item.disposal_status != DisposalStatus.CONFLICT:
                    self.assertEqual(item.disposal_status, DisposalStatus.MARKED)

        marked_paths = {it.file.path for it in run.items if it.file and it.disposal_status == DisposalStatus.MARKED}
        self.assertEqual(len(marked_paths & frozen_paths), 0)


class TestHardFreezeMigrationIntegration(TestFreezeBase):
    """场景2: target_base 迁移后 action_log 目标路径更新，freeze_state/freeze_index 仍能和活跃封存单对上"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="freeze_mig_test_")
        self.target_old = os.path.join(self.tmp, "target_old")
        self.target_new = os.path.join(self.tmp, "target_new")
        ensure_dir(self.target_old)
        ensure_dir(self.target_new)
        self.config_old = _make_config(self.tmp, target_base=self.target_old)

    def _rewrite_config_target(self, new_target: str) -> str:
        cfg_path = self.config_old._source_path
        with open(cfg_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        raw["target_base"] = new_target
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(raw, f, allow_unicode=True, default_flow_style=False)
        return cfg_path

    def _copy_target_files(self, src: str, dst: str) -> None:
        if os.path.isdir(src):
            for item in os.listdir(src):
                s = os.path.join(src, item)
                d = os.path.join(dst, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)

    def test_freeze_index_updated_after_target_migration(self):
        """迁移后 freeze_index 键（路径）和封存单内 file.path 应同步更新"""
        _seed_archive(self.config_old, count=2, files_per_case=2, archive_days_ago=10)
        fm_old = FreezeManager(self.config_old)
        order = fm_old.confirm_freeze(notes="迁移前封存")
        self.assertEqual(order.total_frozen, 4)
        old_active_paths = {it.file.path for it in fm_old.get_active_frozen_files() if it.file}
        self.assertTrue(all(p.startswith(os.path.abspath(self.target_old)) for p in old_active_paths))

        self._copy_target_files(self.target_old, self.target_new)
        cfg_v1_path = os.path.join(self.tmp, "config_v1.yaml")
        shutil.copy2(self.config_old._source_path, cfg_v1_path)

        cfg_v2_path = self._rewrite_config_target(self.target_new)
        config_new = load_config(cfg_v2_path)

        plan, state = migration_mod.generate_migration_plan(cfg_v1_path, config_new)
        self.assertGreater(plan.auto_migrate_count, 0, "应检测到 action_log 路径迁移项")

        migrated, stats = migration_mod.execute_migration(
            plan, state, cfg_v1_path, config_new, dry_run=False
        )
        self.assertGreater(stats["auto_migrated"], 0)

        fm_new = FreezeManager(config_new)
        new_active = fm_new.get_active_frozen_files()
        new_paths = {it.file.path for it in new_active if it.file}
        self.assertEqual(len(new_paths), 4, f"迁移后活跃封存数应不变: {new_paths}")

        for p in new_paths:
            self.assertTrue(
                p.startswith(os.path.abspath(self.target_new)),
                f"封存路径 {p} 应更新为新 target_base",
            )

        check = fm_new.consistency_check()
        self.assertTrue(
            check["is_consistent"],
            f"迁移后封存状态不一致: {check['issues']}",
        )

    def test_freeze_config_signature_target_base_updated(self):
        """迁移后 freeze 的 config_signature.target_base 应同步更新"""
        _seed_archive(self.config_old, count=1, files_per_case=2, archive_days_ago=10)
        fm = FreezeManager(self.config_old)
        fm.confirm_freeze()
        old_sig_target = fm._state["config_signature"]["target_base"]
        self.assertEqual(old_sig_target, os.path.abspath(self.target_old))

        self._copy_target_files(self.target_old, self.target_new)
        cfg_v1_path = os.path.join(self.tmp, "config_v1.yaml")
        shutil.copy2(self.config_old._source_path, cfg_v1_path)
        cfg_v2_path = self._rewrite_config_target(self.target_new)
        config_new = load_config(cfg_v2_path)

        plan, state = migration_mod.generate_migration_plan(cfg_v1_path, config_new)
        migration_mod.execute_migration(plan, state, cfg_v1_path, config_new, dry_run=False)

        fm_new = FreezeManager(config_new)
        new_sig_target = fm_new._state["config_signature"]["target_base"]
        self.assertEqual(new_sig_target, os.path.abspath(self.target_new))

    def test_migration_does_not_break_release(self):
        """迁移后仍能正常解封存"""
        _seed_archive(self.config_old, count=1, files_per_case=2, archive_days_ago=10)
        fm_old = FreezeManager(self.config_old)
        order = fm_old.confirm_freeze(notes="迁移前封存")
        order_id = order.order_id

        self._copy_target_files(self.target_old, self.target_new)
        cfg_v1_path = os.path.join(self.tmp, "config_v1.yaml")
        shutil.copy2(self.config_old._source_path, cfg_v1_path)
        cfg_v2_path = self._rewrite_config_target(self.target_new)
        config_new = load_config(cfg_v2_path)

        plan, state = migration_mod.generate_migration_plan(cfg_v1_path, config_new)
        migration_mod.execute_migration(plan, state, cfg_v1_path, config_new, dry_run=False)

        fm_new = FreezeManager(config_new)
        self.assertEqual(len(fm_new.get_active_frozen_files()), 2)
        release = fm_new.release_order(order_id)
        self.assertEqual(release.total_released, 2)
        self.assertEqual(release.total_conflicts, 0)
        self.assertEqual(len(fm_new.get_active_frozen_files()), 0)


class TestHardFreezeHandoffIntegration(TestFreezeBase):
    """场景3: 交接导入碰到已封存目标时要冲突或跳过，不能覆盖文件，也不能写脏 batch/action 记录"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="freeze_handoff_test_")
        self.src_dir = os.path.join(self.tmp, "src")
        self.dst_dir = os.path.join(self.tmp, "dst")
        self.handoff_out = os.path.join(self.tmp, "handoff_pkgs")
        for d in [self.src_dir, self.dst_dir, self.handoff_out]:
            ensure_dir(d)

        import yaml as _yaml
        self.src_cfg_path = os.path.join(self.src_dir, "config.yaml")
        self.dst_cfg_path = os.path.join(self.dst_dir, "config.yaml")
        src_intake = os.path.join(self.src_dir, "intake")
        src_target = os.path.join(self.src_dir, "target")
        src_logs = os.path.join(self.src_dir, "logs")
        dst_intake = os.path.join(self.dst_dir, "intake")
        dst_target = os.path.join(self.dst_dir, "target")
        dst_logs = os.path.join(self.dst_dir, "logs")
        for d in [src_intake, src_target, src_logs, dst_intake, dst_target, dst_logs]:
            ensure_dir(d)

        cfg_dict = {
            "intake_dir": src_intake,
            "target_base": src_target,
            "operator": "handoff-src",
            "rules": {
                "case_number_pattern": r"CASE-(\d+)",
                "file_pattern": r".*\.(pdf|jpg|png)$",
                "target_structure": "{case_number}",
                "action": "copy",
            },
            "logging": {"dir": src_logs},
            "freeze": {
                "enabled": True,
                "default_reason": "交接源封存",
                "default_valid_days": 90,
                "max_frozen_files": 100,
            },
        }
        with open(self.src_cfg_path, "w", encoding="utf-8") as f:
            _yaml.safe_dump(cfg_dict, f, allow_unicode=True, default_flow_style=False)

        cfg_dict["intake_dir"] = dst_intake
        cfg_dict["target_base"] = dst_target
        cfg_dict["operator"] = "handoff-dst"
        cfg_dict["freeze"]["default_reason"] = "交接目标封存"
        with open(self.dst_cfg_path, "w", encoding="utf-8") as f:
            _yaml.safe_dump(cfg_dict, f, allow_unicode=True, default_flow_style=False)

        self.src_cfg = load_config(self.src_cfg_path)
        self.src_cfg._source_path = os.path.abspath(self.src_cfg_path)
        self.dst_cfg = load_config(self.dst_cfg_path)
        self.dst_cfg._source_path = os.path.abspath(self.dst_cfg_path)

    def _write_same_content(self, target_dir: str, case: str, fname: str, content: bytes) -> str:
        case_dir = os.path.join(target_dir, case)
        ensure_dir(case_dir)
        path = os.path.join(case_dir, fname)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_handoff_import_skips_frozen_target_no_overwrite(self):
        """目标已封存时，交接导入应冲突跳过，不覆盖文件"""
        case = "CASE-0100"
        src_seed = _seed_archive(self.src_cfg, count=1, files_per_case=2)
        _seed_archive(self.dst_cfg, count=2, files_per_case=1)

        dst_target_case = os.path.join(self.dst_cfg.target_base, case)
        ensure_dir(dst_target_case)
        conflict_content = b"ORIGINAL DST CONTENT - FROZEN"
        original_file_paths = []
        for j in range(2):
            fname = f"{case}_DOC{j + 1}.pdf"
            fpath = self._write_same_content(self.dst_cfg.target_base, case, fname, conflict_content)
            original_file_paths.append(fpath)

        from scan_sorter.action_logger import ActionLogger as _AL
        from scan_sorter.models import ActionRecord as _AR, ActionType as _AT, BatchRecord as _BR, BatchStatus as _BS
        al = _AL(self.dst_cfg.logging.action_log_path())
        batch = _BR(operator=self.dst_cfg.operator, status=_BS.COMPLETED, total=2, succeeded=2)
        for fp in original_file_paths:
            act = _AR(
                batch_id=batch.batch_id,
                source=fp,
                destination=fp,
                action_type=_AT.COPY,
                operator=self.dst_cfg.operator,
                case_number=case,
                timestamp=(datetime.now() - timedelta(days=15)).isoformat(),
            )
            al.log(act)
            batch.action_ids.append(act.action_id)
        save_json(self.dst_cfg.logging.batch_history_path(), [batch.to_dict()])

        fm_dst = FreezeManager(self.dst_cfg)
        order = fm_dst.confirm_freeze(case_numbers=[case])
        self.assertEqual(order.total_frozen, 2)

        src_hashes_before = {}
        for cf in src_seed["files_by_case"].values():
            for p in cf:
                src_hashes_before[p] = file_hash(p)
        dst_hashes_before = {p: file_hash(p) for p in original_file_paths}

        _, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_out,
            case_numbers=[case], resume=False, description="测试封存冲突交接",
        )
        self.assertTrue(os.path.exists(zip_path))

        action_before = set()
        for rec in read_jsonl(self.dst_cfg.logging.action_log_path()):
            action_before.add(rec.get("action_id"))
        batches_before = load_json(self.dst_cfg.logging.batch_history_path(), default=[])

        result = import_handoff_package(zip_path, self.dst_cfg, allow_partial=True, allow_config_mismatch=True)

        dst_hashes_after = {p: file_hash(p) for p in original_file_paths}
        self.assertEqual(dst_hashes_after, dst_hashes_before, "封存的目标文件内容不应被覆盖")

        conflict_types = [c.conflict_type for c in result.conflicts if c.file_item]
        self.assertTrue(
            any(ct in (HandoffConflictType.TARGET_OCCUPIED, HandoffConflictType.DUPLICATE_CASE)
                for ct in conflict_types) or result.skipped >= 2,
            f"应有冲突或跳过机制: conflict_types={conflict_types}, skipped={result.skipped}",
        )

        batches_after = load_json(self.dst_cfg.logging.batch_history_path(), default=[])
        new_batches = [b for b in batches_after if b not in batches_before]
        for nb in new_batches:
            total = nb.get("total", 0)
            succeeded = nb.get("succeeded", 0)
            failed = nb.get("failed", 0)
            self.assertEqual(
                succeeded + failed, total,
                f"脏 batch: total={total} 但 succeeded+failed={succeeded + failed}",
            )

        fm_after = FreezeManager(self.dst_cfg)
        still_active = {it.file.path for it in fm_after.get_active_frozen_files() if it.file}
        for op in original_file_paths:
            self.assertIn(op, still_active, f"封存状态不应被交接破坏: {op}")

    def test_handoff_import_partial_with_frozen_conflict(self):
        """部分封存：CASE-0100封存冲突，CASE-0200正常导入；封存文件不被覆盖，封存状态一致"""
        case_frozen = "CASE-0100"
        case_normal = "CASE-0200"
        src_seed = _seed_archive(self.src_cfg, count=2, files_per_case=1)

        from scan_sorter.action_logger import ActionLogger as _AL2
        from scan_sorter.models import ActionRecord as _AR2, ActionType as _AT2, BatchRecord as _BR2, BatchStatus as _BS2
        al2 = _AL2(self.dst_cfg.logging.action_log_path())
        batch2 = _BR2(operator=self.dst_cfg.operator, status=_BS2.COMPLETED, total=1, succeeded=1)
        case_dir_dst = os.path.join(self.dst_cfg.target_base, case_frozen)
        ensure_dir(case_dir_dst)
        frozen_fname = f"{case_frozen}_DOC1.pdf"
        frozen_path = os.path.join(case_dir_dst, frozen_fname)
        with open(frozen_path, "wb") as f:
            f.write(b"DST FROZEN ORIGINAL CONTENT")
        act = _AR2(
            batch_id=batch2.batch_id,
            source=frozen_path, destination=frozen_path,
            action_type=_AT2.COPY, operator=self.dst_cfg.operator,
            case_number=case_frozen,
            timestamp=(datetime.now() - timedelta(days=10)).isoformat(),
        )
        al2.log(act)
        batch2.action_ids.append(act.action_id)
        save_json(self.dst_cfg.logging.batch_history_path(), [batch2.to_dict()])

        fm_dst = FreezeManager(self.dst_cfg)
        freeze_order = fm_dst.confirm_freeze(case_numbers=[case_frozen])
        self.assertEqual(freeze_order.total_frozen, 1)

        _, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_out,
            case_numbers=[case_frozen, case_normal], resume=False,
            description="部分封存冲突测试",
        )
        frozen_hash_before = file_hash(frozen_path)
        action_before_count = sum(1 for _ in read_jsonl(self.dst_cfg.logging.action_log_path()))
        batches_before = load_json(self.dst_cfg.logging.batch_history_path(), default=[])

        result = import_handoff_package(zip_path, self.dst_cfg, allow_partial=True, allow_config_mismatch=True)

        self.assertEqual(file_hash(frozen_path), frozen_hash_before, "封存文件不应被覆盖")

        frozen_target_paths = {frozen_path}
        for tpath in frozen_target_paths:
            self.assertTrue(os.path.exists(tpath), f"封存文件应仍存在: {tpath}")

        batches_after = load_json(self.dst_cfg.logging.batch_history_path(), default=[])
        for nb in batches_after:
            total = nb.get("total", 0)
            succeeded = nb.get("succeeded", 0)
            failed = nb.get("failed", 0)
            self.assertEqual(
                succeeded + failed, total,
                f"脏 batch: total={total} 但 succeeded+failed={succeeded + failed}",
            )

        check = fm_dst.consistency_check()
        self.assertTrue(check["is_consistent"], f"封存一致性被破坏: {check['issues']}")

        active_after = {it.file.path for it in fm_dst.get_active_frozen_files() if it.file}
        self.assertIn(os.path.abspath(frozen_path), active_after, "封存文件应保持活跃封存状态")


if __name__ == "__main__":
    unittest.main()
