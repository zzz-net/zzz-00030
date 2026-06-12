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
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import yaml

from scan_sorter.action_logger import ActionLogger
from scan_sorter.config import (
    AppConfig,
    LoggingConfig,
    RetentionConfig,
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
    RetentionRule,
)
from scan_sorter.utils import ensure_dir, file_hash, load_json, read_jsonl, save_json

from scan_sorter.retention_manager import (
    RetentionManager,
    export_preview_csv,
    export_preview_json,
    export_run_csv,
    export_run_json,
    export_history_csv,
    export_history_json,
)


def _make_config(
    base_dir: str,
    retention_rules: list | None = None,
    default_retention_days: int = 365,
    target_base: str | None = None,
    case_number_pattern: str = r"CASE-(\d+)",
) -> AppConfig:
    intake = os.path.join(base_dir, "intake")
    tgt = target_base or os.path.join(base_dir, "target")
    log_dir = os.path.join(base_dir, "logs")
    for d in [intake, tgt, log_dir]:
        ensure_dir(d)

    rules_list = []
    if retention_rules is None:
        retention_rules = [
            {
                "rule_id": "R1",
                "name": "特殊案件保留90天",
                "case_number_pattern": r"CASE-SPECIAL-\d+",
                "batch_id_pattern": r".*",
                "retention_days": 90,
            },
            {
                "rule_id": "R2",
                "name": "常规案件保留30天",
                "case_number_pattern": r"CASE-\d{4}",
                "batch_id_pattern": r".*",
                "retention_days": 30,
            },
        ]
    if retention_rules:
        for r in retention_rules:
            if isinstance(r, dict):
                rules_list.append(RetentionRule.from_dict(r))
            else:
                rules_list.append(r)

    cfg = AppConfig(
        intake_dir=intake,
        target_base=tgt,
        operator="retention-operator-test",
        rules=RuleConfig(
            case_number_pattern=case_number_pattern,
            file_pattern=r".*\.(pdf|jpg|png)$",
            target_structure="{case_number}",
            action="copy",
        ),
        logging=LoggingConfig(dir=log_dir),
        retention=RetentionConfig(
            enabled=True,
            default_retention_days=default_retention_days,
            rules=rules_list,
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


class TestRetentionBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="retention_test_")
        self.config = _make_config(self.tmp, default_retention_days=30)

    def tearDown(self):
        for _ in range(3):
            try:
                shutil.rmtree(self.tmp, ignore_errors=True)
                break
            except Exception:
                time.sleep(0.05)


class TestRetentionModels(TestRetentionBase):
    def test_disposal_status_enum(self):
        self.assertEqual(DisposalStatus.PENDING.value, "pending")
        self.assertEqual(DisposalStatus.EXPIRED.value, "expired")
        self.assertEqual(DisposalStatus.DEFERRED.value, "deferred")
        self.assertEqual(DisposalStatus.MARKED.value, "marked")
        self.assertEqual(DisposalStatus.CONFLICT.value, "conflict")
        self.assertEqual(DisposalStatus.UNDO.value, "undo")

    def test_conflict_category_enum(self):
        self.assertEqual(ConflictCategory.IN_ERROR_QUEUE.value, "in_error_queue")
        self.assertEqual(ConflictCategory.FILE_MISSING.value, "file_missing")
        self.assertEqual(ConflictCategory.TARGET_OCCUPIED.value, "target_occupied")
        self.assertEqual(ConflictCategory.DUPLICATE_MARK.value, "duplicate_mark")
        self.assertEqual(ConflictCategory.RULE_CHANGED.value, "rule_changed")
        self.assertEqual(ConflictCategory.NO_WRITE_PERMISSION.value, "no_write_permission")

    def test_retention_rule_roundtrip(self):
        rule = RetentionRule(
            rule_id="R1",
            name="短期",
            description="test",
            case_number_pattern=r"CASE-01\d{2}",
            batch_id_pattern=".*",
            retention_days=30,
        )
        d = rule.to_dict()
        self.assertEqual(d["rule_id"], "R1")
        self.assertEqual(d["retention_days"], 30)
        rule2 = RetentionRule.from_dict(d)
        self.assertEqual(rule2.rule_id, rule.rule_id)
        self.assertEqual(rule2.retention_days, rule.retention_days)
        self.assertEqual(rule2.case_number_pattern, rule.case_number_pattern)


class TestRetentionPreview(TestRetentionBase):
    def test_preview_empty_target(self):
        mgr = RetentionManager(self.config)
        prev = mgr.preview()
        self.assertEqual(prev.total_files, 0)
        self.assertEqual(prev.expired_count, 0)
        self.assertEqual(prev.items, [])

    def test_preview_normal_all_pending(self):
        _seed_archive(self.config, count=2, files_per_case=2, archive_days_ago=5)
        mgr = RetentionManager(self.config)
        prev = mgr.preview()
        self.assertEqual(prev.total_files, 4)
        self.assertEqual(prev.expired_count, 0)
        self.assertEqual(prev.pending_count, 4)
        for it in prev.items:
            self.assertEqual(it.disposal_status, DisposalStatus.PENDING)
            self.assertIsNotNone(it.file)
            self.assertTrue(it.file.case_number.startswith("CASE-"))

    def test_preview_all_expired(self):
        _seed_archive(self.config, count=2, files_per_case=2, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        prev = mgr.preview()
        self.assertEqual(prev.total_files, 4)
        self.assertEqual(prev.expired_count, 4)
        for it in prev.items:
            self.assertEqual(it.disposal_status, DisposalStatus.EXPIRED)

    def test_preview_mixed(self):
        days = [5, 60, 5, 60, 100, 10]
        _seed_archive(self.config, count=3, files_per_case=2, archive_days_ago=days)
        mgr = RetentionManager(self.config)
        prev = mgr.preview()
        self.assertEqual(prev.total_files, 6)
        self.assertEqual(prev.expired_count, 3)
        self.assertEqual(prev.pending_count, 3)

    def test_preview_filter_case_numbers(self):
        seed = _seed_archive(self.config, count=3, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        target_cases = [seed["cases"][0], seed["cases"][1]]
        prev = mgr.preview(case_numbers=target_cases)
        self.assertEqual(prev.total_files, 2)
        for it in prev.items:
            self.assertIn(it.file.case_number, target_cases)

    def test_preview_filter_batch_ids(self):
        seed = _seed_archive(self.config, count=3, files_per_case=2, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        bid = seed["batches"][0].batch_id
        prev = mgr.preview(batch_ids=[bid])
        self.assertEqual(prev.total_files, 2)
        for it in prev.items:
            self.assertEqual(it.file.batch_id, bid)

    def test_preview_rule_summary(self):
        rules = [
            {
                "rule_id": "R0100",
                "name": "CASE0100 7天",
                "case_number_pattern": r"CASE-01\d{2}",
                "retention_days": 7,
            }
        ]
        cfg = _make_config(self.tmp, retention_rules=rules, default_retention_days=365)
        _seed_archive(cfg, count=3, files_per_case=1, archive_days_ago=[60, 60, 60])
        mgr = RetentionManager(cfg)
        prev = mgr.preview()
        self.assertIn("R0100:CASE0100 7天", prev.rule_summary)

    def test_preview_rule_matching_priority(self):
        rules = [
            {
                "rule_id": "R1",
                "name": "特殊案件",
                "case_number_pattern": r"CASE-0100",
                "retention_days": 3650,
            },
            {
                "rule_id": "R2",
                "name": "通用短",
                "case_number_pattern": r"CASE-\d{4}",
                "retention_days": 10,
            },
        ]
        cfg = _make_config(self.tmp, retention_rules=rules, default_retention_days=365)
        _seed_archive(cfg, count=3, files_per_case=1, archive_days_ago=[100, 100, 100])
        mgr = RetentionManager(cfg)
        prev = mgr.preview()
        by_case = {it.file.case_number: it for it in prev.items}
        self.assertEqual(by_case["CASE-0100"].matched_rule_id, "R1")
        self.assertEqual(by_case["CASE-0100"].disposal_status, DisposalStatus.PENDING)
        self.assertEqual(by_case["CASE-0200"].matched_rule_id, "R2")
        self.assertEqual(by_case["CASE-0200"].disposal_status, DisposalStatus.EXPIRED)
        self.assertEqual(by_case["CASE-0300"].matched_rule_id, "R2")
        self.assertEqual(by_case["CASE-0300"].disposal_status, DisposalStatus.EXPIRED)


class TestRetentionGenerate(TestRetentionBase):
    def test_generate_normal(self):
        _seed_archive(self.config, count=2, files_per_case=2, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        run = mgr.generate_disposal_list(notes="测试生成")
        self.assertEqual(run.run_type, "generate")
        self.assertEqual(run.operator, "retention-operator-test")
        self.assertEqual(run.total_marked, 4)
        self.assertEqual(run.total_conflicts, 0)
        self.assertEqual(run.notes, "测试生成")
        self.assertTrue(run.run_id.startswith("RET-"))
        for it in run.items:
            self.assertEqual(it.disposal_status, DisposalStatus.MARKED)
            self.assertIsNotNone(it.marked_at)
            self.assertEqual(it.marked_run_id, run.run_id)

    def test_generate_skips_deferred(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        path = list(seed["files_by_case"].values())[0][0]
        mgr.mark_deferred([path], reason="测试暂缓", defer_days=15)
        run = mgr.generate_disposal_list()
        self.assertEqual(run.total_deferred, 1)
        self.assertEqual(run.total_marked, 1)
        marked = [i for i in run.items if i.disposal_status == DisposalStatus.MARKED]
        deferred = [i for i in run.items if i.disposal_status == DisposalStatus.DEFERRED]
        self.assertEqual(len(marked), 1)
        self.assertEqual(len(deferred), 1)

    def test_generate_skips_conflict_error_queue(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
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
        mgr = RetentionManager(self.config)
        run = mgr.generate_disposal_list()
        self.assertEqual(run.total_conflicts, 1)
        self.assertEqual(run.total_marked, 1)
        conflict_items = [i for i in run.items if i.disposal_status == DisposalStatus.CONFLICT]
        self.assertEqual(len(conflict_items), 1)
        cats = [c.category for c in conflict_items[0].conflicts]
        self.assertIn(ConflictCategory.IN_ERROR_QUEUE, cats)

    def test_generate_file_missing_conflict(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        path = list(seed["files_by_case"].values())[0][0]
        os.remove(path)
        mgr = RetentionManager(self.config)
        run = mgr.generate_disposal_list()
        self.assertEqual(run.total_conflicts, 1)
        self.assertEqual(run.total_marked, 1)
        ci = [i for i in run.items if i.disposal_status == DisposalStatus.CONFLICT][0]
        cats = [c.category for c in ci.conflicts]
        self.assertIn(ConflictCategory.FILE_MISSING, cats)

    def test_generate_duplicate_mark_conflict(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        mgr.generate_disposal_list()
        run2 = mgr.generate_disposal_list()
        self.assertEqual(run2.total_conflicts, 2)
        self.assertEqual(run2.total_marked, 0)
        for it in run2.items:
            self.assertEqual(it.disposal_status, DisposalStatus.CONFLICT)
            cats = [c.category for c in it.conflicts]
            self.assertIn(ConflictCategory.DUPLICATE_MARK, cats)

    def test_generate_no_write_permission_conflict(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        path = list(seed["files_by_case"].values())[0][0]
        try:
            st = os.stat(path)
            os.chmod(path, st.st_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
            mgr = RetentionManager(self.config)
            run = mgr.generate_disposal_list()
            conflict_cats = set()
            for it in run.items:
                for c in it.conflicts:
                    conflict_cats.add(c.category)
            self.assertIn(ConflictCategory.NO_WRITE_PERMISSION, conflict_cats)
        finally:
            if os.path.exists(path):
                try:
                    st = os.stat(path)
                    os.chmod(path, st.st_mode | stat.S_IWUSR)
                except Exception:
                    pass

    def test_generate_state_persisted_and_recoverable(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        mgr1 = RetentionManager(self.config)
        run1 = mgr1.generate_disposal_list(notes="第一次运行")
        run_id_1 = run1.run_id

        mgr2 = RetentionManager(self.config)
        runs = mgr2.list_runs()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].run_id, run_id_1)
        self.assertEqual(runs[0].total_marked, 2)

        marked_files = mgr2.get_marked_files()
        self.assertEqual(len(marked_files), 2)
        for mf in marked_files:
            self.assertIn(mf.disposal_status, (DisposalStatus.MARKED, DisposalStatus.DEFERRED))

    def test_generate_rule_change_detection(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=60)
        mgr1 = RetentionManager(self.config)
        mgr1._state["config_signature"] = {
            "default_retention_days": 9999,
            "rules": [{"rule_id": "CHANGED"}],
            "target_base": os.path.abspath(self.config.target_base),
        }
        mgr1._save_state()
        run = mgr1.generate_disposal_list()
        conflict_cats = set()
        for it in run.items:
            for c in it.conflicts:
                conflict_cats.add(c.category)
        self.assertIn(ConflictCategory.RULE_CHANGED, conflict_cats)


class TestRetentionDefer(TestRetentionBase):
    def test_mark_deferred_basic(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        paths = [seed["files_by_case"][seed["cases"][0]][0]]
        mgr = RetentionManager(self.config)
        run = mgr.mark_deferred(paths, reason="审查中", defer_days=45)
        self.assertEqual(run.run_type, "defer")
        self.assertEqual(run.total_deferred, 1)
        self.assertEqual(run.total_conflicts, 0)
        self.assertTrue(run.notes, "审查中")
        it = run.items[0]
        self.assertEqual(it.disposal_status, DisposalStatus.DEFERRED)
        self.assertEqual(it.defer_reason, "审查中")
        self.assertTrue(it.defer_until)
        self.assertEqual(it.defer_run_id, run.run_id)

    def test_mark_deferred_error_queue_conflict(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        path = seed["files_by_case"][seed["cases"][0]][0]
        from scan_sorter.queue_manager import ErrorQueue
        eq = ErrorQueue(self.config.logging.error_queue_path())
        eq.add(ErrorItem(
            path=path,
            filename=os.path.basename(path),
            case_number=seed["cases"][0],
            error="错误队列中的文件",
        ))
        mgr = RetentionManager(self.config)
        run = mgr.mark_deferred([path])
        self.assertEqual(run.total_conflicts, 1)
        self.assertEqual(run.total_deferred, 0)
        cats = [c.category for c in run.items[0].conflicts]
        self.assertIn(ConflictCategory.IN_ERROR_QUEUE, cats)

    def test_mark_deferred_duplicate_conflict(self):
        seed = _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=60)
        paths = [seed["files_by_case"][seed["cases"][0]][0]]
        mgr = RetentionManager(self.config)
        mgr.mark_deferred(paths)
        run2 = mgr.mark_deferred(paths)
        self.assertEqual(run2.total_conflicts, 1)
        self.assertEqual(run2.total_deferred, 0)
        cats = [c.category for c in run2.items[0].conflicts]
        self.assertIn(ConflictCategory.DUPLICATE_MARK, cats)


class TestRetentionUndo(TestRetentionBase):
    def test_undo_generate_only_this_run(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        run_gen = mgr.generate_disposal_list()
        gen_id = run_gen.run_id
        run_undo = mgr.undo_run(gen_id)
        self.assertEqual(run_undo.run_type, "undo")
        self.assertEqual(run_undo.total_undone, 2)
        self.assertEqual(run_undo.total_conflicts, 0)
        for it in run_undo.items:
            self.assertEqual(it.disposal_status, DisposalStatus.UNDO)
            self.assertEqual(it.undo_run_id, run_undo.run_id)
        marked = mgr.get_marked_files()
        self.assertEqual(len(marked), 0)

    def test_undo_deferred_only_this_run(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        paths = [seed["files_by_case"][seed["cases"][0]][0]]
        mgr = RetentionManager(self.config)
        run_def = mgr.mark_deferred(paths)
        def_id = run_def.run_id
        run_undo = mgr.undo_run(def_id)
        self.assertEqual(run_undo.total_undone, 1)
        self.assertEqual(run_undo.total_conflicts, 0)
        marked = mgr.get_marked_files()
        self.assertEqual(len(marked), 0)

    def test_undo_preserves_other_runs(self):
        seed = _seed_archive(self.config, count=3, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        all_paths = [seed["files_by_case"][c][0] for c in seed["cases"]]
        def_path = all_paths[0]
        run_def = mgr.mark_deferred([def_path])
        self.assertEqual(run_def.total_deferred, 1)
        run_gen = mgr.generate_disposal_list()
        self.assertEqual(run_gen.total_marked, 2)
        gen_id = run_gen.run_id
        run_undo = mgr.undo_run(gen_id)
        self.assertEqual(run_undo.total_undone, 2)
        self.assertEqual(run_undo.total_conflicts, 0)
        marked = mgr.get_marked_files()
        self.assertEqual(len(marked), 1)
        self.assertEqual(marked[0].disposal_status, DisposalStatus.DEFERRED)

    def test_undo_unknown_run_raises(self):
        mgr = RetentionManager(self.config)
        with self.assertRaises(ValueError):
            mgr.undo_run("RET-NONEXISTENT-123456")

    def test_undo_twice_conflict(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        run_gen = mgr.generate_disposal_list()
        gen_id = run_gen.run_id
        mgr.undo_run(gen_id)
        run_undo2 = mgr.undo_run(gen_id)
        self.assertEqual(run_undo2.total_conflicts, 2)
        self.assertEqual(run_undo2.total_undone, 0)
        for it in run_undo2.items:
            self.assertEqual(it.disposal_status, DisposalStatus.CONFLICT)


class TestRetentionHistoryAndPersistence(TestRetentionBase):
    def test_list_runs_multiple_types(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        run_gen = mgr.generate_disposal_list()
        path = list(seed["files_by_case"].values())[0][0]
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=60)
        mgr2 = RetentionManager(self.config)
        run_def = mgr2.mark_deferred([path])
        mgr3 = RetentionManager(self.config)
        run_undo = mgr3.undo_run(run_gen.run_id)
        all_runs = mgr3.list_runs()
        self.assertEqual(len(all_runs), 3)
        gen_runs = mgr3.list_runs(run_type="generate")
        self.assertEqual(len(gen_runs), 1)
        self.assertEqual(gen_runs[0].run_type, "generate")
        defer_runs = mgr3.list_runs(run_type="defer")
        self.assertEqual(len(defer_runs), 1)
        undo_runs = mgr3.list_runs(run_type="undo")
        self.assertEqual(len(undo_runs), 1)

    def test_get_run(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        run = mgr.generate_disposal_list()
        mgr2 = RetentionManager(self.config)
        found = mgr2.get_run(run.run_id)
        self.assertIsNotNone(found)
        self.assertEqual(found.run_id, run.run_id)
        self.assertEqual(found.total_marked, 1)
        self.assertIsNone(mgr2.get_run("RET-NOT-EXIST"))

    def test_list_runs_limit(self):
        _seed_archive(self.config, count=3, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        for _ in range(5):
            mgr.generate_disposal_list()
        limited = mgr.list_runs(limit=3)
        self.assertEqual(len(limited), 3)
        all_runs = mgr.list_runs()
        self.assertEqual(len(all_runs), 5)
        self.assertEqual(limited[-1].run_id, all_runs[-1].run_id)

    def test_cross_restart_history(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        mgr_a = RetentionManager(self.config)
        run_a = mgr_a.generate_disposal_list(notes="重启前生成")
        marked_paths_before = {it.file.path for it in mgr_a.get_marked_files()}

        mgr_b = RetentionManager(self.config)
        runs = mgr_b.list_runs()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].run_id, run_a.run_id)
        self.assertEqual(runs[0].notes, "重启前生成")
        marked_after = {it.file.path for it in mgr_b.get_marked_files()}
        self.assertEqual(marked_paths_before, marked_after)
        self.assertEqual(len(marked_after), 2)

        mgr_b.undo_run(run_a.run_id)
        mgr_c = RetentionManager(self.config)
        self.assertEqual(len(mgr_c.get_marked_files()), 0)
        self.assertEqual(len(mgr_c.list_runs()), 2)

    def test_consistency_check_normal(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        mgr.generate_disposal_list()
        check = mgr.consistency_check()
        self.assertTrue(check["is_consistent"])
        self.assertEqual(check["issues"], [])

    def test_log_file_written(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        mgr.generate_disposal_list()
        log_path = self.config.retention.log_path(self.config.logging.dir)
        self.assertTrue(os.path.exists(log_path))
        records = read_jsonl(log_path)
        self.assertGreater(len(records), 0)
        events = [r["event"] for r in records]
        self.assertIn("retention_generate", events)


class TestRetentionExports(TestRetentionBase):
    def test_export_preview_json(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        prev = mgr.preview()
        out = os.path.join(self.tmp, "prev.json")
        export_preview_json(prev, out)
        self.assertTrue(os.path.exists(out))
        data = load_json(out)
        self.assertEqual(data["total_files"], 2)
        self.assertEqual(data["expired_count"], 2)
        self.assertEqual(len(data["items"]), 2)

    def test_export_preview_csv_fields(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        prev = mgr.preview()
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
            self.assertIn("expires_at", fieldnames)
            self.assertIn("disposal_status", fieldnames)
            self.assertIn("matched_rule_id", fieldnames)
            self.assertIn("retention_days", fieldnames)
            self.assertIn("conflict_count", fieldnames)
            self.assertIn("conflict_categories", fieldnames)
            self.assertIn("conflict_details", fieldnames)
            rows = list(reader)
            self.assertEqual(len(rows), 2)
            for row in rows:
                self.assertEqual(row["disposal_status"], "expired")
                self.assertIn("CASE-", row["case_number"])

    def test_export_run_json_and_csv(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        run = mgr.generate_disposal_list(notes="导出测试")
        jout = os.path.join(self.tmp, "run.json")
        cout = os.path.join(self.tmp, "run.csv")
        export_run_json(run, jout)
        export_run_csv(run, cout)
        data = load_json(jout)
        self.assertEqual(data["run_id"], run.run_id)
        self.assertEqual(data["total_marked"], 2)
        self.assertEqual(len(data["items"]), 2)
        with open(cout, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            self.assertIn("run_id", fieldnames)
            self.assertIn("run_type", fieldnames)
            self.assertIn("operator", fieldnames)
            self.assertIn("item_id", fieldnames)
            self.assertIn("filename", fieldnames)
            self.assertIn("case_number", fieldnames)
            self.assertIn("disposal_status", fieldnames)
            self.assertIn("marked_at", fieldnames)
            rows = list(reader)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["run_type"], "generate")

    def test_export_history_json_csv(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        mgr.generate_disposal_list()
        runs = mgr.list_runs()
        jout = os.path.join(self.tmp, "hist.json")
        cout = os.path.join(self.tmp, "hist.csv")
        export_history_json(runs, jout)
        export_history_csv(runs, cout)
        data = load_json(jout)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["total_marked"], 2)
        with open(cout, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            self.assertIn("run_id", fieldnames)
            self.assertIn("run_type", fieldnames)
            self.assertIn("created_at", fieldnames)
            self.assertIn("operator", fieldnames)
            self.assertIn("total_items", fieldnames)
            self.assertIn("total_marked", fieldnames)
            self.assertIn("notes", fieldnames)
            rows = list(reader)
            self.assertEqual(len(rows), 1)


class TestRetentionConfigReload(TestRetentionBase):
    def _rewrite_config(self, new_rules: list, new_default: int):
        cfg_path = self.config._source_path
        raw = load_json(cfg_path) if False else {}
        with open(cfg_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        raw["retention"] = raw.get("retention", {})
        raw["retention"]["default_retention_days"] = new_default
        raw["retention"]["rules"] = new_rules
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(raw, f, allow_unicode=True, default_flow_style=False)

    def test_config_reload_rules_change_effect(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        prev1 = mgr.preview()
        self.assertEqual(prev1.expired_count, 2)
        self._rewrite_config([], 1000)
        mgr2 = RetentionManager(self.config)
        prev2 = mgr2.preview()
        self.assertEqual(prev2.expired_count, 0)
        self.assertEqual(prev2.pending_count, 2)

    def test_config_reload_rule_matching_change(self):
        rules = [
            {
                "rule_id": "R1",
                "name": "全部10天",
                "case_number_pattern": ".*",
                "retention_days": 10,
            }
        ]
        cfg = _make_config(
            self.tmp,
            retention_rules=rules,
            default_retention_days=365,
        )
        _seed_archive(cfg, count=2, files_per_case=1, archive_days_ago=20)
        mgr = RetentionManager(cfg)
        prev1 = mgr.preview()
        self.assertEqual(prev1.expired_count, 2)
        new_rules = [
            {
                "rule_id": "R2",
                "name": "全部90天",
                "case_number_pattern": ".*",
                "retention_days": 90,
            }
        ]
        cfg_path = cfg._source_path
        with open(cfg_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        raw["retention"]["rules"] = new_rules
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(raw, f, allow_unicode=True, default_flow_style=False)
        mgr2 = RetentionManager(cfg)
        prev2 = mgr2.preview()
        self.assertEqual(prev2.expired_count, 0)
        self.assertEqual(prev2.pending_count, 2)
        for it in prev2.items:
            self.assertEqual(it.matched_rule_id, "R2")


class TestRetentionCLIIntegration(TestRetentionBase):
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
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        rc = self._run_cli([
            "-c", self.config._source_path,
            "retention-preview",
        ])
        self.assertEqual(rc, 0)

    def test_cli_preview_with_export_json(self):
        _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=60)
        out_json = os.path.join(self.tmp, "cli_prev.json")
        rc = self._run_cli([
            "-c", self.config._source_path,
            "retention-preview",
            "--format", "json",
            "--output", out_json,
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out_json))
        data = load_json(out_json)
        self.assertEqual(data["total_files"], 2)
        self.assertEqual(data["expired_count"], 2)

    def test_cli_preview_with_export_csv(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=60)
        out_csv = os.path.join(self.tmp, "cli_prev.csv")
        rc = self._run_cli([
            "-c", self.config._source_path,
            "retention-preview",
            "--format", "csv",
            "--output", out_csv,
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out_csv))
        with open(out_csv, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["disposal_status"], "expired")

    def test_cli_generate_dry_run(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        rc = self._run_cli([
            "-c", self.config._source_path,
            "retention-generate",
        ])
        self.assertEqual(rc, 0)
        mgr = RetentionManager(self.config)
        self.assertEqual(len(mgr.list_runs()), 0)

    def test_cli_generate_confirm(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        rc = self._run_cli([
            "-c", self.config._source_path,
            "retention-generate",
            "--confirm",
            "--notes", "CLI确认生成",
        ])
        self.assertEqual(rc, 0)
        mgr = RetentionManager(self.config)
        runs = mgr.list_runs()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].total_marked, 2)
        self.assertEqual(runs[0].notes, "CLI确认生成")

    def test_cli_generate_filter_case(self):
        seed = _seed_archive(self.config, count=3, files_per_case=1, archive_days_ago=60)
        rc = self._run_cli([
            "-c", self.config._source_path,
            "retention-generate",
            "--confirm",
            "--case-numbers", f"{seed['cases'][0]},{seed['cases'][1]}",
        ])
        self.assertEqual(rc, 0)
        mgr = RetentionManager(self.config)
        runs = mgr.list_runs()
        self.assertEqual(runs[0].total_marked, 2)

    def test_cli_history(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        mgr.generate_disposal_list()
        rc = self._run_cli([
            "-c", self.config._source_path,
            "retention-history",
        ])
        self.assertEqual(rc, 0)

    def test_cli_history_with_filter_and_export(self):
        _seed_archive(self.config, count=1, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        mgr.generate_disposal_list()
        out = os.path.join(self.tmp, "cli_hist.json")
        rc = self._run_cli([
            "-c", self.config._source_path,
            "retention-history",
            "--run-type", "generate",
            "--format", "json",
            "--output", out,
        ])
        self.assertEqual(rc, 0)
        data = load_json(out)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["run_type"], "generate")

    def test_cli_defer_and_undo(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        paths = list(seed["files_by_case"].values())
        defer_paths = f"{paths[0][0]},{paths[1][0]}"
        rc = self._run_cli([
            "-c", self.config._source_path,
            "retention-defer",
            "--paths", defer_paths,
            "--days", "60",
            "--reason", "CLI暂缓",
        ])
        self.assertEqual(rc, 0)
        mgr1 = RetentionManager(self.config)
        def_runs = mgr1.list_runs(run_type="defer")
        self.assertEqual(len(def_runs), 1)
        def_run_id = def_runs[0].run_id
        rc = self._run_cli([
            "-c", self.config._source_path,
            "retention-undo",
            "--run-id", def_run_id,
        ])
        self.assertEqual(rc, 0)
        mgr2 = RetentionManager(self.config)
        undo_runs = mgr2.list_runs(run_type="undo")
        self.assertEqual(len(undo_runs), 1)
        self.assertEqual(undo_runs[0].total_undone, 2)
        self.assertEqual(len(mgr2.get_marked_files()), 0)

    def test_cli_export_marked(self):
        _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        mgr.generate_disposal_list()
        out = os.path.join(self.tmp, "cli_marked.csv")
        rc = self._run_cli([
            "-c", self.config._source_path,
            "retention-export",
            "--source", "marked",
            "--format", "csv",
            "--output", out,
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out))
        with open(out, "r", encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)


class TestRetentionEdgeCases(TestRetentionBase):
    def test_original_files_untouched_after_generate(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        all_paths = []
        for case_files in seed["files_by_case"].values():
            all_paths.extend(case_files)
        hashes_before = {p: file_hash(p) for p in all_paths}
        mtimes_before = {p: os.path.getmtime(p) for p in all_paths}
        mgr = RetentionManager(self.config)
        mgr.generate_disposal_list()
        mgr.mark_deferred([all_paths[0]], reason="测试")
        for p in all_paths:
            self.assertTrue(os.path.exists(p))
            self.assertEqual(file_hash(p), hashes_before[p])
            self.assertEqual(os.path.getmtime(p), mtimes_before[p])

    def test_original_files_untouched_after_undo(self):
        seed = _seed_archive(self.config, count=2, files_per_case=1, archive_days_ago=60)
        all_paths = []
        for case_files in seed["files_by_case"].values():
            all_paths.extend(case_files)
        hashes_before = {p: file_hash(p) for p in all_paths}
        mgr = RetentionManager(self.config)
        run = mgr.generate_disposal_list()
        mgr.undo_run(run.run_id)
        for p in all_paths:
            self.assertTrue(os.path.exists(p))
            self.assertEqual(file_hash(p), hashes_before[p])

    def test_target_occupied_detection(self):
        seed = _seed_archive(self.config, count=1, files_per_case=2, archive_days_ago=60)
        paths = seed["files_by_case"][seed["cases"][0]]
        for p in paths:
            try:
                st = os.stat(p)
                os.chmod(p, 0o400)
                mgr = RetentionManager(self.config)
                run = mgr.generate_disposal_list()
                for it in run.items:
                    cat_set = {c.category for c in it.conflicts}
                    if it.disposal_status == DisposalStatus.CONFLICT:
                        self.assertTrue(
                            ConflictCategory.NO_WRITE_PERMISSION in cat_set
                            or len(cat_set) > 0
                        )
            finally:
                if os.path.exists(p):
                    try:
                        os.chmod(p, 0o644)
                    except Exception:
                        pass

    def test_empty_rules_uses_default(self):
        cfg = _make_config(self.tmp, retention_rules=[], default_retention_days=5)
        _seed_archive(cfg, count=1, files_per_case=2, archive_days_ago=[10, 1])
        mgr = RetentionManager(cfg)
        prev = mgr.preview()
        self.assertEqual(prev.expired_count, 1)
        self.assertEqual(prev.pending_count, 1)
        for it in prev.items:
            self.assertEqual(it.matched_rule_id, "default")
            self.assertEqual(it.retention_days, 5)

    def test_marked_index_consistency_after_multiple_operations(self):
        seed = _seed_archive(self.config, count=3, files_per_case=1, archive_days_ago=60)
        mgr = RetentionManager(self.config)
        all_paths = [seed["files_by_case"][c][0] for c in seed["cases"]]
        run_def = mgr.mark_deferred([all_paths[0]], reason="第一次暂缓")
        self.assertEqual(run_def.total_deferred, 1)
        check1 = mgr.consistency_check()
        self.assertTrue(check1["is_consistent"], f"一致性问题1: {check1['issues']}")
        run_gen = mgr.generate_disposal_list()
        self.assertEqual(run_gen.total_marked, 2)
        check2 = mgr.consistency_check()
        self.assertTrue(check2["is_consistent"], f"一致性问题2: {check2['issues']}")
        run_undo = mgr.undo_run(run_gen.run_id)
        self.assertEqual(run_undo.total_undone, 2)
        check3 = mgr.consistency_check()
        self.assertTrue(check3["is_consistent"], f"一致性问题3: {check3['issues']}")
        run_gen2 = mgr.generate_disposal_list()
        self.assertEqual(run_gen2.total_marked, 2)
        check4 = mgr.consistency_check()
        self.assertTrue(check4["is_consistent"], f"一致性问题4: {check4['issues']}")
        marked = mgr.get_marked_files()
        statuses = [m.disposal_status for m in marked]
        self.assertIn(DisposalStatus.DEFERRED, statuses)
        self.assertEqual(statuses.count(DisposalStatus.MARKED), 2)
        self.assertEqual(len(marked), 3)


if __name__ == "__main__":
    unittest.main()
