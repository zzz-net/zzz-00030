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
    RuleConfig,
    load_config,
)
from scan_sorter.models import (
    ActionRecord,
    ActionType,
    BatchRecord,
    BatchStatus,
    ErrorItem,
    FreezeConflictCategory,
    FreezeStatus,
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


if __name__ == "__main__":
    unittest.main()
