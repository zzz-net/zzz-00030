from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from typing import Optional

from scan_sorter.action_logger import ActionLogger
from scan_sorter.config import AppConfig
from scan_sorter.models import (
    ActionRecord,
    ActionType,
    BatchRecord,
    BatchStatus,
    ConflictDetail,
    ConflictType,
    HandoffFileItem,
    HandoffImportResult,
    HandoffImportState,
    HandoffManifest,
    HandoffStatus,
    OperationRecord,
)
from scan_sorter.utils import (
    append_jsonl,
    ensure_dir,
    file_hash,
    iso_now,
    load_json,
    read_jsonl,
    sanitize_path,
    save_json,
)
from scan_sorter.handoff_validator import (
    _extract_package,
    _load_manifest,
    detect_import_conflicts,
)


def _get_import_state_path(data_dir: str, package_id: str) -> str:
    return os.path.join(data_dir, f".handoff_import_{package_id}.json")


def _get_handoff_history_path(data_dir: str) -> str:
    return os.path.join(data_dir, "handoff_history.jsonl")


def _get_imported_packages_path(data_dir: str) -> str:
    return os.path.join(data_dir, "handoff_imported_packages.json")


def _target_config_summary(config: AppConfig) -> dict:
    return {
        "intake_dir": os.path.abspath(config.intake_dir),
        "target_base": os.path.abspath(config.target_base),
        "operator": config.operator,
        "case_number_pattern": config.rules.case_number_pattern,
        "file_pattern": config.rules.file_pattern,
        "target_structure": config.rules.target_structure,
        "action": config.rules.action,
        "logging_dir": os.path.abspath(config.logging.dir),
    }


def _compute_config_diff(source_cfg: dict, target_cfg: dict) -> dict:
    diff: dict[str, dict] = {}
    keys = [
        "target_base", "operator", "case_number_pattern",
        "file_pattern", "target_structure", "action",
    ]
    for k in keys:
        s = source_cfg.get(k)
        t = target_cfg.get(k)
        if s != t:
            diff[k] = {"source": s, "target": t}
    return diff


def _check_write_permission(path: str) -> tuple[bool, str]:
    try:
        ensure_dir(path)
        test_file = os.path.join(path, ".write_test_" + os.urandom(4).hex())
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        return True, ""
    except Exception as e:
        return False, str(e)


def _get_existing_sets(config: AppConfig, data_dir: str) -> tuple[set[str], set[str], set[str]]:
    action_records = read_jsonl(config.logging.action_log_path())
    destinations = {r.get("destination", "") for r in action_records if r.get("destination")}
    case_numbers = {r.get("case_number", "") for r in action_records if r.get("case_number")}

    imported_path = _get_imported_packages_path(data_dir)
    imported_data = load_json(imported_path, default=[])
    package_ids = set(imported_data)

    return destinations, case_numbers, package_ids


def _load_import_state(data_dir: str, package_id: str) -> Optional[HandoffImportState]:
    state_path = _get_import_state_path(data_dir, package_id)
    if os.path.exists(state_path):
        raw = load_json(state_path, default=None)
        if raw:
            return HandoffImportState.from_dict(raw)
    return None


def _save_import_state(state: HandoffImportState, data_dir: str) -> None:
    state.updated_at = iso_now()
    save_json(_get_import_state_path(data_dir, state.package_id), state.to_dict())


def _log_handoff_operation(
    data_dir: str,
    op_type: str,
    package_id: str,
    operator: str,
    status: str,
    details: dict,
) -> str:
    rec = OperationRecord(
        operation_type=op_type,
        operator=operator,
        package_id=package_id,
        status=status,
        details=details,
    )
    append_jsonl(_get_handoff_history_path(data_dir), rec.to_dict())
    return rec.operation_id


def _register_imported_package(data_dir: str, package_id: str) -> None:
    path = _get_imported_packages_path(data_dir)
    imported = load_json(path, default=[])
    if package_id not in imported:
        imported.append(package_id)
        save_json(path, imported)


def _unregister_imported_package(data_dir: str, package_id: str) -> None:
    path = _get_imported_packages_path(data_dir)
    imported = load_json(path, default=[])
    if package_id in imported:
        imported.remove(package_id)
        save_json(path, imported)


def import_handoff_package(
    package_path: str,
    config: AppConfig,
    resume: bool = True,
    allow_config_mismatch: bool = False,
    allow_partial: bool = False,
) -> HandoffImportResult:
    package_path = sanitize_path(package_path)
    data_dir = os.path.abspath(config.logging.dir)
    ensure_dir(data_dir)

    target_base = sanitize_path(config.target_base)

    write_ok, write_err = _check_write_permission(target_base)
    if not write_ok:
        return HandoffImportResult(
            success=False,
            status=HandoffStatus.FAILED,
            warnings=[],
            conflicts=[ConflictDetail(
                conflict_type=ConflictType.TARGET_OCCUPIED,
                detail=f"目标目录无写权限: {target_base}, 错误: {write_err}",
            )],
        )

    temp_dir = tempfile.mkdtemp(prefix="handoff_import_")
    extracted = _extract_package(package_path, temp_dir)
    if not extracted:
        return HandoffImportResult(
            success=False,
            status=HandoffStatus.FAILED,
            conflicts=[ConflictDetail(
                conflict_type=ConflictType.FILE_MISSING,
                detail=f"无法解压交接包: {package_path}",
            )],
        )

    manifest = _load_manifest(temp_dir)
    if manifest is None:
        return HandoffImportResult(
            success=False,
            status=HandoffStatus.FAILED,
            conflicts=[ConflictDetail(
                conflict_type=ConflictType.FILE_MISSING,
                detail="交接包中缺失 manifest.json",
            )],
        )

    target_cfg = _target_config_summary(config)
    source_cfg = manifest.source_config_summary or {}
    config_diff = _compute_config_diff(source_cfg, target_cfg)

    if config_diff and not allow_config_mismatch:
        config_warnings = [
            f"[{k}] 源={v['source']} -> 目标={v['target']}"
            for k, v in config_diff.items()
        ]
        config_conflict = ConflictDetail(
            conflict_type=ConflictType.CONFIG_MISMATCH,
            detail="源与目标配置存在差异，使用 --allow-config-mismatch 确认导入",
            existing_info=config_diff,
        )
        return HandoffImportResult(
            success=False,
            status=HandoffStatus.FAILED,
            warnings=config_warnings,
            conflicts=[config_conflict],
        )

    existing_destinations, existing_cases, existing_packages = _get_existing_sets(config, data_dir)

    state: Optional[HandoffImportState] = None
    if resume:
        state = _load_import_state(data_dir, manifest.package_id)

    has_dup_pkg = manifest.package_id in existing_packages

    if state is None or state.status in (HandoffStatus.ROLLED_BACK,):
        conflicts = detect_import_conflicts(
            manifest, temp_dir, target_base,
            existing_destinations, existing_cases, existing_packages,
        )

        pending_files = [fi.sha256 for fi in manifest.files]
        for c in conflicts:
            if c.file_item and c.file_item.sha256 in pending_files:
                pending_files.remove(c.file_item.sha256)

        state = HandoffImportState(
            status=HandoffStatus.IMPORTING,
            package_id=manifest.package_id,
            package_path=package_path,
            target_config_summary=target_cfg,
            source_config_summary=source_cfg,
            config_diff=config_diff,
            files_pending=pending_files,
            conflicts=conflicts,
        )
        _save_import_state(state, data_dir)
    else:
        if has_dup_pkg and not any(
            c.conflict_type == ConflictType.DUPLICATE_PACKAGE for c in state.conflicts
        ):
            state.conflicts.append(ConflictDetail(
                conflict_type=ConflictType.DUPLICATE_PACKAGE,
                target_path="",
                detail=f"交接包已导入过: {manifest.package_id}",
                existing_info={},
            ))
            _save_import_state(state, data_dir)

    if state.conflicts:
        non_config_conflicts = [
            c for c in state.conflicts
            if c.conflict_type != ConflictType.CONFIG_MISMATCH
        ]
        if non_config_conflicts and not allow_partial:
            state.status = HandoffStatus.FAILED
            state.error = f"存在 {len(non_config_conflicts)} 个冲突，使用 --allow-partial 允许部分导入"
            _save_import_state(state, data_dir)
            _log_handoff_operation(
                data_dir, "import", state.package_id,
                config.operator, "conflict",
                {"conflicts": [c.to_dict() for c in state.conflicts]},
            )
            return HandoffImportResult(
                package_id=state.package_id,
                success=False,
                status=HandoffStatus.FAILED,
                total_files=manifest.total_files,
                imported=len(state.files_imported),
                skipped=0,
                failed=len(state.files_pending),
                conflicts=state.conflicts,
                state_path=_get_import_state_path(data_dir, state.package_id),
                warnings=[w for w in []],
            )

    files_dir = os.path.join(temp_dir, "files")
    action_logger = ActionLogger(config.logging.action_log_path())
    batch_history_path = config.logging.batch_history_path()

    imported_sha_set = set(state.files_imported)
    pending_sha_set = set(state.files_pending)
    written_files_set = set(state.written_files)
    written_action_ids_set = set(state.written_action_ids)
    written_batch_ids_set = set(state.written_batch_ids)

    batch_id = None
    if not written_batch_ids_set:
        batch = BatchRecord(
            operator=config.operator,
            status=BatchStatus.OPEN,
        )
        batch_id = batch.batch_id
        written_batch_ids_set.add(batch_id)
        state.written_batch_ids = list(written_batch_ids_set)
        _save_import_state(state, data_dir)

        batches = load_json(batch_history_path, default=[])
        batches.append(batch.to_dict())
        save_json(batch_history_path, batches)
    else:
        batch_id = list(written_batch_ids_set)[0]

    result = HandoffImportResult(
        package_id=state.package_id,
        total_files=manifest.total_files,
        state_path=_get_import_state_path(data_dir, state.package_id),
    )

    conflict_sha_set = {c.file_item.sha256 for c in state.conflicts if c.file_item}

    try:
        for fi in manifest.files:
            if fi.sha256 in imported_sha_set:
                continue
            if fi.sha256 in conflict_sha_set:
                continue
            if fi.sha256 not in pending_sha_set:
                continue

            src_file = os.path.join(files_dir, fi.relative_path)
            dest_file = os.path.join(target_base, fi.relative_path)

            if not os.path.exists(src_file):
                state.files_failed.append(fi.sha256)
                if fi.sha256 in state.files_pending:
                    state.files_pending.remove(fi.sha256)
                _save_import_state(state, data_dir)
                continue

            actual_sha = file_hash(src_file)
            if actual_sha != fi.sha256:
                state.conflicts.append(ConflictDetail(
                    conflict_type=ConflictType.CONTENT_TAMPERED,
                    file_item=fi,
                    target_path=dest_file,
                    detail=f"导入时检测到文件篡改: {fi.filename}",
                ))
                if fi.sha256 in state.files_pending:
                    state.files_pending.remove(fi.sha256)
                _save_import_state(state, data_dir)
                continue

            if os.path.exists(dest_file):
                state.conflicts.append(ConflictDetail(
                    conflict_type=ConflictType.TARGET_OCCUPIED,
                    file_item=fi,
                    target_path=dest_file,
                    detail=f"导入时发现目标被占用: {dest_file}",
                ))
                if fi.sha256 in state.files_pending:
                    state.files_pending.remove(fi.sha256)
                _save_import_state(state, data_dir)
                continue

            try:
                ensure_dir(os.path.dirname(dest_file))
                shutil.copy2(src_file, dest_file)

                action = ActionRecord(
                    batch_id=batch_id,
                    source=fi.original_path,
                    destination=dest_file,
                    action_type=ActionType.COPY,
                    operator=config.operator,
                    case_number=fi.case_number,
                )
                action_logger.log(action)

                state.files_imported.append(fi.sha256)
                if fi.sha256 in state.files_pending:
                    state.files_pending.remove(fi.sha256)
                state.written_files.append(dest_file)
                state.written_action_ids.append(action.action_id)
                written_files_set.add(dest_file)
                written_action_ids_set.add(action.action_id)
                imported_sha_set.add(fi.sha256)

            except Exception as e:
                state.files_failed.append(fi.sha256)
                if fi.sha256 in state.files_pending:
                    state.files_pending.remove(fi.sha256)
                state.error = str(e)

            _save_import_state(state, data_dir)

        batches = load_json(batch_history_path, default=[])
        updated_batches = []
        succeeded_count = len([s for s in state.files_imported])
        non_config_conflicts = [
            c for c in state.conflicts
            if c.conflict_type != ConflictType.CONFIG_MISMATCH
        ]
        failed_count = len(state.files_failed) + len(non_config_conflicts)
        for b in batches:
            if b.get("batch_id") == batch_id:
                b["status"] = (
                    BatchStatus.COMPLETED.value
                    if failed_count == 0
                    else BatchStatus.PARTIAL_FAILED.value
                )
                b["total"] = succeeded_count + failed_count
                b["succeeded"] = succeeded_count
                b["failed"] = failed_count
                b["action_ids"] = list(written_action_ids_set)
            updated_batches.append(b)
        save_json(batch_history_path, updated_batches)

        if state.files_pending or state.files_failed or non_config_conflicts:
            state.status = HandoffStatus.PARTIAL_IMPORTED
        else:
            state.status = HandoffStatus.IMPORTED

        _save_import_state(state, data_dir)

        if state.status == HandoffStatus.IMPORTED:
            _register_imported_package(data_dir, state.package_id)

        op_id = _log_handoff_operation(
            data_dir, "import", state.package_id,
            config.operator, state.status.value,
            {
                "imported": len(state.files_imported),
                "failed": len(state.files_failed),
                "conflicts": len(state.conflicts),
                "pending": len(state.files_pending),
                "config_diff": state.config_diff,
                "written_batch_ids": list(written_batch_ids_set),
            },
        )

        result.package_id = state.package_id
        result.success = state.status in (HandoffStatus.IMPORTED, HandoffStatus.PARTIAL_IMPORTED)
        result.status = state.status
        result.imported = len(state.files_imported)
        result.skipped = len(state.conflicts)
        result.failed = len(state.files_failed)
        result.conflicts = list(state.conflicts)
        result.imported_files = list(state.written_files)
        result.failed_files = list(state.files_failed)
        result.operation_ids = [op_id]
        if config_diff:
            result.warnings = [
                f"配置差异 [{k}]: 源={v['source']} -> 目标={v['target']}"
                for k, v in config_diff.items()
            ]

        return result

    except Exception as e:
        state.status = HandoffStatus.FAILED
        state.error = str(e)
        _save_import_state(state, data_dir)
        _log_handoff_operation(
            data_dir, "import", state.package_id,
            config.operator, "failed",
            {"error": str(e)},
        )
        return HandoffImportResult(
            package_id=state.package_id,
            success=False,
            status=HandoffStatus.FAILED,
            total_files=manifest.total_files,
            imported=len(state.files_imported),
            skipped=len(state.conflicts),
            failed=len(state.files_pending) + len(state.files_failed),
            conflicts=state.conflicts,
            state_path=_get_import_state_path(data_dir, state.package_id),
            warnings=[f"导入中断: {e}"],
        )


def rollback_handoff_import(
    package_id: str,
    config: AppConfig,
) -> tuple[HandoffImportState, "HandoffRollbackResult"]:
    from scan_sorter.models import HandoffRollbackResult

    data_dir = os.path.abspath(config.logging.dir)
    state = _load_import_state(data_dir, package_id)

    result = HandoffRollbackResult(
        package_id=package_id,
        kept_audit_log=True,
    )

    if state is None:
        result.success = False
        result.details.append({"ok": False, "detail": f"未找到交接包导入状态: {package_id}"})
        empty_state = HandoffImportState(package_id=package_id)
        return empty_state, result

    action_logger = ActionLogger(config.logging.action_log_path())
    batch_history_path = config.logging.batch_history_path()

    rolled_back_files: list[str] = []
    failed_rollbacks: list[dict] = []

    for dest_file in reversed(state.written_files):
        try:
            if os.path.exists(dest_file):
                os.remove(dest_file)
                rolled_back_files.append(dest_file)
                result.details.append({"ok": True, "detail": f"已删除文件: {dest_file}"})
            else:
                result.details.append({"ok": True, "detail": f"文件已不存在，跳过: {dest_file}"})
        except Exception as e:
            failed_rollbacks.append({"path": dest_file, "error": str(e)})
            result.details.append({"ok": False, "detail": f"删除文件失败: {dest_file}, 错误: {e}"})

    for aid in state.written_action_ids:
        try:
            action_logger.mark_rolled_back(aid)
        except Exception:
            pass

    batches = load_json(batch_history_path, default=[])
    updated_batches = []
    for b in batches:
        if b.get("batch_id") in state.written_batch_ids:
            b["status"] = BatchStatus.ROLLED_BACK.value
        updated_batches.append(b)
    save_json(batch_history_path, updated_batches)

    state.status = HandoffStatus.ROLLED_BACK
    _save_import_state(state, data_dir)
    _unregister_imported_package(data_dir, package_id)

    op_id = _log_handoff_operation(
        data_dir, "rollback", package_id,
        config.operator, "rolled_back",
        {
            "rolled_back_files": rolled_back_files,
            "failed_rollbacks": failed_rollbacks,
            "kept_audit_log": True,
        },
    )

    result.success = True
    result.total_rolled_back = len(rolled_back_files)
    result.rolled_back_files = rolled_back_files
    result.failed_rollbacks = failed_rollbacks
    result.operation_id = op_id

    return state, result


def get_handoff_history(data_dir: str, package_id: Optional[str] = None) -> list[dict]:
    log_path = _get_handoff_history_path(data_dir)
    records = read_jsonl(log_path)
    if package_id:
        records = [r for r in records if r.get("package_id") == package_id]
    return records


def get_imported_packages(data_dir: str) -> list[str]:
    path = _get_imported_packages_path(data_dir)
    return load_json(path, default=[])


def export_import_result_json(result: HandoffImportResult, output_path: str) -> None:
    save_json(output_path, result.to_dict())


def export_import_result_csv(result: HandoffImportResult, output_path: str) -> None:
    import csv

    ensure_dir(os.path.dirname(output_path))
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["项目", "值"])
        writer.writerow(["package_id", result.package_id])
        writer.writerow(["success", result.success])
        writer.writerow(["status", result.status.value])
        writer.writerow(["total_files", result.total_files])
        writer.writerow(["imported", result.imported])
        writer.writerow(["skipped", result.skipped])
        writer.writerow(["failed", result.failed])
        writer.writerow(["state_path", result.state_path])
        writer.writerow([])
        writer.writerow(["已导入文件"])
        for p in result.imported_files:
            writer.writerow([p])
        if result.conflicts:
            writer.writerow([])
            writer.writerow(["冲突明细"])
            writer.writerow(["conflict_type", "filename", "target_path", "detail"])
            for c in result.conflicts:
                fn = c.file_item.filename if c.file_item else ""
                writer.writerow([c.conflict_type.value, fn, c.target_path, c.detail])
        if result.warnings:
            writer.writerow([])
            writer.writerow(["警告"])
            for w in result.warnings:
                writer.writerow([w])


def export_rollback_result_json(result, output_path: str) -> None:
    save_json(output_path, result.to_dict())


def export_rollback_result_csv(result, output_path: str) -> None:
    import csv

    ensure_dir(os.path.dirname(output_path))
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["项目", "值"])
        writer.writerow(["package_id", result.package_id])
        writer.writerow(["success", result.success])
        writer.writerow(["total_rolled_back", result.total_rolled_back])
        writer.writerow(["kept_audit_log", result.kept_audit_log])
        writer.writerow(["operation_id", result.operation_id])
        writer.writerow([])
        writer.writerow(["回滚的文件"])
        for p in result.rolled_back_files:
            writer.writerow([p])
        if result.failed_rollbacks:
            writer.writerow([])
            writer.writerow(["回滚失败项"])
            writer.writerow(["path", "error"])
            for fr in result.failed_rollbacks:
                writer.writerow([fr.get("path", ""), fr.get("error", "")])
