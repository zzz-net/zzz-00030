from __future__ import annotations

import copy
import csv
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scan_sorter.action_logger import ActionLogger
from scan_sorter.config import (
    AppConfig,
    LoggingConfig,
    RuleConfig,
    load_config,
)
from scan_sorter.models import (
    ActionRecord,
    ActionType,
    BatchRecord,
    BatchStatus,
    ConflictType,
    HandoffStatus,
)
from scan_sorter.utils import ensure_dir, file_hash, load_json, read_jsonl, save_json

from scan_sorter.handoff_creator import (
    _get_manifest_path,
    create_handoff_package,
    export_create_result_csv,
    export_create_result_json,
    preview_handoff,
)
from scan_sorter.handoff_validator import (
    export_verify_result_csv,
    export_verify_result_json,
    verify_handoff_package,
)
from scan_sorter.handoff_importer import (
    _get_handoff_history_path,
    _get_imported_packages_path,
    _target_config_summary,
    export_import_result_csv,
    export_import_result_json,
    export_rollback_result_csv,
    export_rollback_result_json,
    get_handoff_history,
    get_imported_packages,
    import_handoff_package,
    rollback_handoff_import,
)


def _make_config(base_dir: str, target_base: str | None = None) -> AppConfig:
    import yaml
    intake = os.path.join(base_dir, "intake")
    tgt = target_base or os.path.join(base_dir, "target")
    log_dir = os.path.join(base_dir, "logs")
    for d in [intake, tgt, log_dir]:
        ensure_dir(d)
    cfg = AppConfig(
        intake_dir=intake,
        target_base=tgt,
        operator="operator-test",
        rules=RuleConfig(
            case_number_pattern=r"CASE-(\d+)",
            file_pattern="*.pdf",
            target_structure="{case_number}/{filename}",
            action="copy",
        ),
        logging=LoggingConfig(dir=log_dir),
    )
    cfg_path = os.path.join(base_dir, "config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg.to_dict(), f, allow_unicode=True, default_flow_style=False)
    return cfg


def _seed_archive(config: AppConfig, count: int = 3) -> dict:
    intake = config.intake_dir
    target = config.target_base
    action_log_path = config.logging.action_log_path()
    batch_history_path = config.logging.batch_history_path()
    action_logger = ActionLogger(action_log_path)
    batches: list[BatchRecord] = []
    files_by_case: dict[str, list[str]] = {}
    for i in range(count):
        case_number = f"CASE-{(i + 1) * 100:04d}"
        batch = BatchRecord(operator=config.operator, status=BatchStatus.COMPLETED)
        batches.append(batch)
        files_by_case[case_number] = []
        for j in range(2):
            filename = f"{case_number}_DOC{j + 1}.pdf"
            src = os.path.join(intake, filename)
            with open(src, "wb") as f:
                f.write(f"content for {case_number} doc {j + 1}".encode("utf-8") * (10 + j))
            dest_dir = os.path.join(target, case_number)
            ensure_dir(dest_dir)
            dest = os.path.join(dest_dir, filename)
            shutil.copy2(src, dest)
            action = ActionRecord(
                batch_id=batch.batch_id,
                source=src,
                destination=dest,
                action_type=ActionType.COPY,
                operator=config.operator,
                case_number=case_number,
            )
            action_logger.log(action)
            files_by_case[case_number].append(dest)
            batch.action_ids.append(action.action_id)
        batch.total = 2
        batch.succeeded = 2
        batch.failed = 0
    save_json(batch_history_path, [b.to_dict() for b in batches])
    return {
        "batches": batches,
        "files_by_case": files_by_case,
        "action_log_path": action_log_path,
        "batch_history_path": batch_history_path,
    }


def _tamper_file(path: str) -> None:
    with open(path, "ab") as f:
        f.write(b"TAMPERED")


class TestHandoffBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="handoff_test_")
        self.src_cfg = _make_config(os.path.join(self.tmp, "src"))
        self.seed = _seed_archive(self.src_cfg, count=3)
        self.dst_cfg = _make_config(os.path.join(self.tmp, "dst"))
        self.handoff_dir = os.path.join(self.tmp, "handoff_out")
        ensure_dir(self.handoff_dir)

    def tearDown(self):
        for _ in range(3):
            try:
                shutil.rmtree(self.tmp, ignore_errors=True)
                break
            except Exception:
                time.sleep(0.05)


class TestHandoffPreview(TestHandoffBase):
    def test_preview_all(self):
        preview = preview_handoff(self.src_cfg)
        self.assertEqual(preview.total_files, 6)
        self.assertEqual(len(preview.case_numbers), 3)
        self.assertEqual(len(preview.batch_ids), 3)
        self.assertGreater(preview.total_size, 0)

    def test_preview_filter_case(self):
        case_list = ["CASE-0100", "CASE-0200"]
        preview = preview_handoff(self.src_cfg, case_numbers=case_list)
        self.assertEqual(preview.total_files, 4)
        self.assertEqual(set(preview.case_numbers), set(case_list))

    def test_preview_filter_batch(self):
        bid = self.seed["batches"][0].batch_id
        preview = preview_handoff(self.src_cfg, batch_ids=[bid])
        self.assertEqual(preview.total_files, 2)
        self.assertEqual(preview.batch_ids, [bid])

    def test_preview_no_match(self):
        preview = preview_handoff(self.src_cfg, case_numbers=["CASE-9999"])
        self.assertEqual(preview.total_files, 0)
        self.assertEqual(preview.case_numbers, [])


class TestHandoffCreate(TestHandoffBase):
    def test_create_normal(self):
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            case_numbers=["CASE-0100", "CASE-0200"],
            resume=False,
            description="test handoff",
        )
        self.assertEqual(state.status, HandoffStatus.CREATED)
        self.assertTrue(os.path.exists(zip_path))
        self.assertEqual(len(state.files_processed), 4)
        self.assertEqual(len(state.files_failed), 0)
        self.assertTrue(state.manifest is not None)
        self.assertEqual(state.manifest.total_files, 4)
        self.assertEqual(state.manifest.source_operator, "operator-test")
        self.assertIn("CASE-0100", state.manifest.case_numbers)
        self.assertEqual(state.manifest.description, "test handoff")
        for fi in state.manifest.files:
            self.assertTrue(fi.sha256)
            self.assertEqual(fi.size, os.path.getsize(fi.source_destination))

    def test_create_by_batch(self):
        bid = self.seed["batches"][1].batch_id
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            batch_ids=[bid], resume=False,
        )
        self.assertEqual(state.status, HandoffStatus.CREATED)
        self.assertEqual(state.manifest.total_files, 2)
        self.assertEqual(state.manifest.batch_ids, [bid])

    def test_create_resume_state_persists(self):
        bid = self.seed["batches"][0].batch_id
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir, batch_ids=[bid], resume=False,
        )
        self.assertEqual(state.status, HandoffStatus.CREATED)
        state_path = os.path.join(self.handoff_dir, ".handoff_create_state.json")
        self.assertTrue(os.path.exists(state_path))
        raw = load_json(state_path)
        self.assertEqual(raw["status"], "created")
        self.assertEqual(raw["package_id"], state.package_id)

    def test_create_no_files_raises(self):
        with self.assertRaises(ValueError):
            create_handoff_package(
                self.src_cfg, self.handoff_dir,
                case_numbers=["CASE-NOPE"], resume=False,
            )


class TestHandoffVerify(TestHandoffBase):
    def _make_pkg(self):
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            case_numbers=["CASE-0100"], resume=False,
        )
        return state, zip_path

    def test_verify_valid_package(self):
        state, zip_path = self._make_pkg()
        result, _ = verify_handoff_package(zip_path)
        self.assertTrue(result.is_valid)
        self.assertTrue(result.manifest_exists)
        self.assertTrue(result.integrity_ok)
        self.assertTrue(result.files_complete)
        self.assertTrue(result.files_match)
        self.assertEqual(result.package_id, state.package_id)
        self.assertEqual(len(result.missing_files), 0)
        self.assertEqual(len(result.tampered_files), 0)

    def test_verify_tampered_package(self):
        state, zip_path = self._make_pkg()
        import zipfile
        pkg_extract = os.path.join(self.tmp, "pkg_extract")
        ensure_dir(pkg_extract)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(pkg_extract)
        files_dir = os.path.join(pkg_extract, "files")
        target_rel = state.manifest.files[0].relative_path
        target_file = os.path.join(files_dir, target_rel)
        self.assertTrue(os.path.exists(target_file))
        _tamper_file(target_file)
        tampered_zip = zip_path + ".tampered.zip"
        with zipfile.ZipFile(tampered_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(pkg_extract):
                for f in files:
                    full = os.path.join(root, f)
                    arc = os.path.relpath(full, pkg_extract)
                    zf.write(full, arc)
        result, _ = verify_handoff_package(tampered_zip)
        self.assertFalse(result.is_valid)
        self.assertFalse(result.files_match)
        self.assertGreaterEqual(len(result.tampered_files), 1)

    def test_verify_missing_file_package(self):
        state, zip_path = self._make_pkg()
        import zipfile
        pkg_extract = os.path.join(self.tmp, "pkg_extract2")
        ensure_dir(pkg_extract)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(pkg_extract)
        files_dir = os.path.join(pkg_extract, "files")
        removed = False
        for root, _, files in os.walk(files_dir):
            for fn in files:
                if fn.endswith(".pdf"):
                    os.remove(os.path.join(root, fn))
                    removed = True
                    break
            if removed:
                break
        broken_zip = zip_path + ".broken.zip"
        with zipfile.ZipFile(broken_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(pkg_extract):
                for f in files:
                    full = os.path.join(root, f)
                    arc = os.path.relpath(full, pkg_extract)
                    zf.write(full, arc)
        result, _ = verify_handoff_package(broken_zip)
        self.assertFalse(result.is_valid)
        self.assertFalse(result.files_complete)
        self.assertGreaterEqual(len(result.missing_files), 1)

    def test_verify_nonexistent(self):
        result, _ = verify_handoff_package("/nope/does/not/exist.zip")
        self.assertFalse(result.is_valid)
        self.assertTrue(any("不存在" in e for e in result.errors))

    def test_verify_config_warning(self):
        state, zip_path = self._make_pkg()
        dst_summary = _target_config_summary(self.dst_cfg)
        result, _ = verify_handoff_package(zip_path, dst_summary)
        self.assertTrue(result.is_valid)
        self.assertTrue(any("配置差异" in w for w in result.warnings))


class TestHandoffImport(TestHandoffBase):
    def _make_pkg(self, case_numbers=None):
        cn = case_numbers or ["CASE-0100", "CASE-0200"]
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            case_numbers=cn, resume=False,
        )
        return state, zip_path

    def test_import_normal(self):
        state, zip_path = self._make_pkg()
        result = import_handoff_package(zip_path, self.dst_cfg, allow_config_mismatch=True)
        self.assertTrue(result.success)
        self.assertEqual(result.status, HandoffStatus.IMPORTED)
        self.assertEqual(result.imported, 4)
        self.assertEqual(result.skipped, 0)
        self.assertEqual(result.failed, 0)
        imported = get_imported_packages(os.path.abspath(self.dst_cfg.logging.dir))
        self.assertIn(state.package_id, imported)
        for case_number in ["CASE-0100", "CASE-0200"]:
            for j in range(1, 3):
                expected = os.path.join(
                    self.dst_cfg.target_base,
                    case_number, f"{case_number}_DOC{j}.pdf",
                )
                self.assertTrue(os.path.exists(expected), f"missing {expected}")
        actions = read_jsonl(self.dst_cfg.logging.action_log_path())
        self.assertEqual(len(actions), 4)
        for a in actions:
            self.assertEqual(a["action_type"], "copy")
            self.assertEqual(a["operator"], self.dst_cfg.operator)

    def test_import_config_mismatch_blocked(self):
        _, zip_path = self._make_pkg()
        result = import_handoff_package(zip_path, self.dst_cfg, allow_config_mismatch=False)
        self.assertFalse(result.success)
        self.assertEqual(result.status, HandoffStatus.FAILED)
        self.assertTrue(any(
            c.conflict_type == ConflictType.CONFIG_MISMATCH for c in result.conflicts
        ))
        for root, _, files in os.walk(self.dst_cfg.target_base):
            self.assertEqual(files, [])

    def test_import_permission_denied(self):
        import scan_sorter.handoff_importer as imp_mod
        _, zip_path = self._make_pkg()
        original_check = imp_mod._check_write_permission

        def fake_check_fail(path):
            return False, "模拟权限不足: Permission denied"

        try:
            imp_mod._check_write_permission = fake_check_fail
            result = import_handoff_package(
                zip_path, self.dst_cfg, allow_config_mismatch=True,
            )
            self.assertFalse(result.success)
            self.assertEqual(result.status, HandoffStatus.FAILED)
            self.assertTrue(any(
                c.conflict_type == ConflictType.TARGET_OCCUPIED for c in result.conflicts
            ))
            self.assertTrue(any("权限" in c.detail for c in result.conflicts))
        finally:
            imp_mod._check_write_permission = original_check

        def fake_check_ok(path):
            return True, ""

        try:
            imp_mod._check_write_permission = fake_check_ok
            result_ok = import_handoff_package(
                zip_path, self.dst_cfg, allow_config_mismatch=True,
            )
            self.assertTrue(result_ok.success)
        finally:
            imp_mod._check_write_permission = original_check

    def test_import_target_occupied_conflict(self):
        _, zip_path = self._make_pkg(["CASE-0100"])
        conflict_file = os.path.join(self.dst_cfg.target_base, "CASE-0100", "CASE-0100_DOC1.pdf")
        ensure_dir(os.path.dirname(conflict_file))
        with open(conflict_file, "wb") as f:
            f.write(b"existing content")
        result = import_handoff_package(
            zip_path, self.dst_cfg,
            allow_config_mismatch=True,
            allow_partial=True,
        )
        self.assertEqual(result.status, HandoffStatus.PARTIAL_IMPORTED)
        self.assertEqual(result.skipped, 1)
        self.assertTrue(any(
            c.conflict_type == ConflictType.TARGET_OCCUPIED for c in result.conflicts
        ))
        intact_file = os.path.join(self.dst_cfg.target_base, "CASE-0100", "CASE-0100_DOC2.pdf")
        self.assertTrue(os.path.exists(intact_file))
        with open(conflict_file, "rb") as f:
            self.assertEqual(f.read(), b"existing content")

    def test_import_duplicate_package_blocked(self):
        state, zip_path = self._make_pkg(["CASE-0100"])
        import_handoff_package(zip_path, self.dst_cfg, allow_config_mismatch=True)
        result2 = import_handoff_package(
            zip_path, self.dst_cfg,
            allow_config_mismatch=True,
            allow_partial=True,
        )
        dup = [c for c in result2.conflicts if c.conflict_type == ConflictType.DUPLICATE_PACKAGE]
        self.assertTrue(dup)
        self.assertTrue(result2.status in (HandoffStatus.FAILED, HandoffStatus.PARTIAL_IMPORTED))

    def test_import_partial_failed(self):
        import zipfile
        state, zip_path = self._make_pkg(["CASE-0100"])
        pkg_dir = os.path.join(self.handoff_dir, state.package_id)
        files_dir = os.path.join(pkg_dir, "files")
        target_rel = state.manifest.files[0].relative_path
        target_file = os.path.join(files_dir, target_rel)
        self.assertTrue(os.path.exists(target_file), f"missing {target_file}")
        before_hash = file_hash(target_file)
        self.assertEqual(before_hash, state.manifest.files[0].sha256)
        _tamper_file(target_file)
        after_hash = file_hash(target_file)
        self.assertNotEqual(before_hash, after_hash)
        if os.path.exists(zip_path):
            os.remove(zip_path)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(pkg_dir):
                for f in files:
                    full = os.path.join(root, f)
                    arc = os.path.relpath(full, pkg_dir)
                    zf.write(full, arc)
        self.assertTrue(os.path.exists(zip_path))
        result = import_handoff_package(
            zip_path, self.dst_cfg,
            allow_config_mismatch=True,
            allow_partial=True,
        )
        self.assertEqual(result.status, HandoffStatus.PARTIAL_IMPORTED)
        self.assertEqual(result.imported, 1)
        self.assertGreaterEqual(result.skipped, 1)
        tamper_types = [c.conflict_type for c in result.conflicts]
        self.assertIn(ConflictType.CONTENT_TAMPERED, tamper_types)

    def test_import_resume_after_interrupt(self):
        state, zip_path = self._make_pkg(["CASE-0100", "CASE-0200"])
        data_dir = os.path.abspath(self.dst_cfg.logging.dir)
        state_path = os.path.join(data_dir, f".handoff_import_{state.package_id}.json")
        ensure_dir(data_dir)
        fake_imported = list(state.manifest.files[0:1])
        fake_written_files = []
        for fi in fake_imported:
            dest = os.path.join(self.dst_cfg.target_base, fi.relative_path)
            ensure_dir(os.path.dirname(dest))
            with open(dest, "wb") as f:
                f.write(b"fake imported")
            fake_written_files.append(dest)
        pending_sha = [fi.sha256 for fi in state.manifest.files[1:]]
        fake_state_dict = {
            "state_id": "fake-interrupted",
            "status": "importing",
            "package_id": state.package_id,
            "package_path": zip_path,
            "target_config_summary": _target_config_summary(self.dst_cfg),
            "source_config_summary": state.manifest.source_config_summary,
            "config_diff": {},
            "files_imported": [fi.sha256 for fi in fake_imported],
            "files_pending": pending_sha,
            "files_failed": [],
            "conflicts": [],
            "written_files": fake_written_files,
            "written_action_ids": ["fake-action-id"],
            "written_batch_ids": ["BAT-FAKE001"],
            "created_at": state.created_at,
            "updated_at": state.created_at,
        }
        save_json(state_path, fake_state_dict)
        batches_path = self.dst_cfg.logging.batch_history_path()
        save_json(batches_path, [{
            "batch_id": "BAT-FAKE001",
            "operator": self.dst_cfg.operator,
            "status": "open",
            "created_at": state.created_at,
            "closed_at": None,
            "total": 0, "succeeded": 0, "failed": 0,
            "action_ids": ["fake-action-id"],
        }])
        action_path = self.dst_cfg.logging.action_log_path()
        save_json(action_path + ".tmp", [])
        result = import_handoff_package(
            zip_path, self.dst_cfg,
            allow_config_mismatch=True, resume=True,
        )
        self.assertEqual(result.imported + result.skipped + result.failed, 4)
        for fi in state.manifest.files:
            expected = os.path.join(self.dst_cfg.target_base, fi.relative_path)
            self.assertTrue(os.path.exists(expected))


class TestHandoffRollback(TestHandoffBase):
    def _import_pkg(self):
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            case_numbers=["CASE-0100"], resume=False,
        )
        result = import_handoff_package(zip_path, self.dst_cfg, allow_config_mismatch=True)
        return state, zip_path, result

    def test_rollback_normal(self):
        state, _, _ = self._import_pkg()
        imported_file = os.path.join(self.dst_cfg.target_base, "CASE-0100", "CASE-0100_DOC1.pdf")
        self.assertTrue(os.path.exists(imported_file))
        imp_state, rb_result = rollback_handoff_import(state.package_id, self.dst_cfg)
        self.assertTrue(rb_result.success)
        self.assertEqual(rb_result.total_rolled_back, 2)
        self.assertTrue(rb_result.kept_audit_log)
        self.assertFalse(os.path.exists(imported_file))
        imported = get_imported_packages(os.path.abspath(self.dst_cfg.logging.dir))
        self.assertNotIn(state.package_id, imported)
        self.assertEqual(imp_state.status, HandoffStatus.ROLLED_BACK)
        history = get_handoff_history(os.path.abspath(self.dst_cfg.logging.dir), state.package_id)
        self.assertTrue(any(h.get("operation_type") == "rollback" for h in history))

    def test_rollback_keeps_audit_log(self):
        state, _, _ = self._import_pkg()
        action_path = self.dst_cfg.logging.action_log_path()
        actions_before = read_jsonl(action_path)
        self.assertEqual(len(actions_before), 2)
        all_rb_before = all(a.get("rolled_back", False) for a in actions_before)
        self.assertFalse(all_rb_before)
        rollback_handoff_import(state.package_id, self.dst_cfg)
        actions_after = read_jsonl(action_path)
        self.assertEqual(len(actions_after), 2)
        self.assertTrue(all(a.get("rolled_back", False) for a in actions_after))
        history_path = _get_handoff_history_path(os.path.abspath(self.dst_cfg.logging.dir))
        self.assertTrue(os.path.exists(history_path))

    def test_rollback_nonexistent_package(self):
        _, rb_result = rollback_handoff_import("PKG-NOT-EXIST", self.dst_cfg)
        self.assertFalse(rb_result.success)
        self.assertTrue(any("未找到" in d.get("detail", "") for d in rb_result.details))

    def test_rollback_queue_batch_history_consistency(self):
        state, _, _ = self._import_pkg()
        rollback_handoff_import(state.package_id, self.dst_cfg)
        batch_hist = load_json(self.dst_cfg.logging.batch_history_path(), default=[])
        self.assertTrue(any(b.get("status") == "rolled_back" for b in batch_hist))
        action_log = read_jsonl(self.dst_cfg.logging.action_log_path())
        for a in action_log:
            self.assertTrue(a.get("rolled_back", False))


class TestHandoffExport(TestHandoffBase):
    def test_create_export_json_csv(self):
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            case_numbers=["CASE-0100"], resume=False,
        )
        out_json = os.path.join(self.tmp, "create.json")
        out_csv = os.path.join(self.tmp, "create.csv")
        export_create_result_json(state, out_json)
        export_create_result_csv(state, out_csv)
        self.assertTrue(os.path.exists(out_json))
        self.assertTrue(os.path.exists(out_csv))
        data = load_json(out_json)
        self.assertEqual(data["package_id"], state.package_id)
        self.assertEqual(data["status"], "created")
        with open(out_csv, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertEqual(len(rows), 2)
        self.assertIn("sha256", rows[0])

    def test_verify_export_json_csv(self):
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            case_numbers=["CASE-0100"], resume=False,
        )
        vresult, _ = verify_handoff_package(zip_path)
        out_json = os.path.join(self.tmp, "verify.json")
        out_csv = os.path.join(self.tmp, "verify.csv")
        export_verify_result_json(vresult, out_json)
        export_verify_result_csv(vresult, out_csv)
        self.assertTrue(os.path.exists(out_json))
        self.assertTrue(os.path.exists(out_csv))
        data = load_json(out_json)
        self.assertTrue(data["is_valid"])

    def test_import_export_json_csv(self):
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            case_numbers=["CASE-0100"], resume=False,
        )
        iresult = import_handoff_package(zip_path, self.dst_cfg, allow_config_mismatch=True)
        out_json = os.path.join(self.tmp, "import.json")
        out_csv = os.path.join(self.tmp, "import.csv")
        export_import_result_json(iresult, out_json)
        export_import_result_csv(iresult, out_csv)
        self.assertTrue(os.path.exists(out_json))
        self.assertTrue(os.path.exists(out_csv))
        data = load_json(out_json)
        self.assertEqual(data["imported"], 2)

    def test_rollback_export_json_csv(self):
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            case_numbers=["CASE-0100"], resume=False,
        )
        import_handoff_package(zip_path, self.dst_cfg, allow_config_mismatch=True)
        _, rresult = rollback_handoff_import(state.package_id, self.dst_cfg)
        out_json = os.path.join(self.tmp, "rollback.json")
        out_csv = os.path.join(self.tmp, "rollback.csv")
        export_rollback_result_json(rresult, out_json)
        export_rollback_result_csv(rresult, out_csv)
        self.assertTrue(os.path.exists(out_json))
        self.assertTrue(os.path.exists(out_csv))
        data = load_json(out_json)
        self.assertTrue(data["kept_audit_log"])


class TestHandoffHistory(TestHandoffBase):
    def test_history_tracks_all_operations(self):
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            case_numbers=["CASE-0100"], resume=False,
        )
        import_handoff_package(zip_path, self.dst_cfg, allow_config_mismatch=True)
        rollback_handoff_import(state.package_id, self.dst_cfg)
        data_dir = os.path.abspath(self.dst_cfg.logging.dir)
        history = get_handoff_history(data_dir, state.package_id)
        op_types = [h.get("operation_type") for h in history]
        self.assertIn("import", op_types)
        self.assertIn("rollback", op_types)
        all_history = get_handoff_history(data_dir)
        self.assertGreaterEqual(len(all_history), 2)
        imported = get_imported_packages(data_dir)
        self.assertNotIn(state.package_id, imported)

    def test_history_after_rollback_queue_clean(self):
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            case_numbers=["CASE-0100"], resume=False,
        )
        import_handoff_package(zip_path, self.dst_cfg, allow_config_mismatch=True)
        rollback_handoff_import(state.package_id, self.dst_cfg)
        for root, _, files in os.walk(self.dst_cfg.target_base):
            pdfs = [f for f in files if f.endswith(".pdf")]
            self.assertEqual(pdfs, [])
        batch_hist = load_json(self.dst_cfg.logging.batch_history_path(), default=[])
        statuses = [b["status"] for b in batch_hist]
        self.assertTrue(all(s == "rolled_back" for s in statuses))


class TestHandoffFilesystemLogConsistency(TestHandoffBase):
    def test_full_lifecycle_consistency(self):
        state, zip_path = create_handoff_package(
            self.src_cfg, self.handoff_dir,
            case_numbers=["CASE-0100", "CASE-0200"], resume=False,
        )
        manifest_path = _get_manifest_path(os.path.join(self.handoff_dir, state.package_id))
        manifest_raw = load_json(manifest_path)
        self.assertEqual(len(manifest_raw["files"]), 4)
        iresult = import_handoff_package(zip_path, self.dst_cfg, allow_config_mismatch=True)
        actions = read_jsonl(self.dst_cfg.logging.action_log_path())
        self.assertEqual(len(actions), iresult.imported)
        batch_hist = load_json(self.dst_cfg.logging.batch_history_path(), default=[])
        self.assertEqual(len(batch_hist), 1)
        b = batch_hist[0]
        self.assertEqual(b["total"], b["succeeded"] + b["failed"])
        self.assertEqual(b["succeeded"], 4)
        for fi in state.manifest.files:
            dest = os.path.join(self.dst_cfg.target_base, fi.relative_path)
            self.assertTrue(os.path.exists(dest))
            self.assertEqual(os.path.getsize(dest), fi.size)
            self.assertEqual(file_hash(dest), fi.sha256)
        imported_pkgs = load_json(
            _get_imported_packages_path(os.path.abspath(self.dst_cfg.logging.dir)),
            default=[],
        )
        self.assertIn(state.package_id, imported_pkgs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
