from __future__ import annotations

import os
import zipfile
import tempfile
import shutil
from typing import Optional

from scan_sorter.models import (
    ConflictDetail,
    ConflictType,
    HandoffFileItem,
    HandoffManifest,
    HandoffVerifyResult,
)
from scan_sorter.utils import (
    ensure_dir,
    file_hash,
    load_json,
)


def _extract_package(package_path: str, extract_dir: str) -> bool:
    ensure_dir(extract_dir)
    if zipfile.is_zipfile(package_path):
        with zipfile.ZipFile(package_path, "r") as zf:
            zf.extractall(extract_dir)
        return True
    else:
        if os.path.isdir(package_path):
            for item in os.listdir(package_path):
                s = os.path.join(package_path, item)
                d = os.path.join(extract_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)
            return True
    return False


def _load_manifest(package_dir: str) -> Optional[HandoffManifest]:
    manifest_path = os.path.join(package_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        return None
    raw = load_json(manifest_path, default=None)
    if raw is None:
        return None
    return HandoffManifest.from_dict(raw)


def verify_handoff_package(
    package_path: str,
    target_config_summary: Optional[dict] = None,
) -> tuple[HandoffVerifyResult, str]:
    if not os.path.exists(package_path):
        result = HandoffVerifyResult(
            is_valid=False,
            errors=[f"交接包路径不存在: {package_path}"],
        )
        return result, ""

    temp_dir = tempfile.mkdtemp(prefix="handoff_verify_")
    package_dir = temp_dir

    try:
        extracted = _extract_package(package_path, package_dir)
        if not extracted:
            result = HandoffVerifyResult(
                is_valid=False,
                errors=["无法解压或读取交接包"],
            )
            return result, temp_dir

        manifest = _load_manifest(package_dir)
        result = HandoffVerifyResult(manifest_exists=manifest is not None)

        if manifest is None:
            result.errors.append("manifest.json 缺失或格式错误")
            result.is_valid = False
            return result, temp_dir

        result.package_id = manifest.package_id
        result.manifest = manifest

        files_dir = os.path.join(package_dir, "files")
        if not os.path.exists(files_dir):
            result.errors.append("files 目录缺失")
            result.is_valid = False
            return result, temp_dir

        missing: list[HandoffFileItem] = []
        tampered: list[HandoffFileItem] = []

        for fi in manifest.files:
            file_path = os.path.join(files_dir, fi.relative_path)
            if not os.path.exists(file_path):
                missing.append(fi)
                continue

            actual_size = os.path.getsize(file_path)
            if actual_size != fi.size:
                tampered.append(fi)
                continue

            actual_sha = file_hash(file_path)
            if actual_sha != fi.sha256:
                tampered.append(fi)

        result.missing_files = missing
        result.tampered_files = tampered
        result.files_complete = len(missing) == 0
        result.files_match = len(tampered) == 0
        result.integrity_ok = result.files_complete and result.files_match

        if target_config_summary:
            source_cfg = manifest.source_config_summary or {}
            for key in ["target_base", "case_number_pattern", "file_pattern"]:
                src_val = source_cfg.get(key)
                tgt_val = target_config_summary.get(key)
                if src_val and tgt_val and src_val != tgt_val:
                    result.warnings.append(
                        f"配置差异 [{key}]: 源={src_val} -> 目标={tgt_val}"
                    )

        result.is_valid = result.manifest_exists and result.integrity_ok

        if not result.is_valid:
            if missing:
                result.errors.append(f"缺失 {len(missing)} 个文件")
            if tampered:
                result.errors.append(f"{len(tampered)} 个文件校验值不匹配（可能被篡改）")

        return result, temp_dir

    except Exception as e:
        result = HandoffVerifyResult(
            is_valid=False,
            errors=[f"校验过程异常: {e}"],
        )
        return result, temp_dir


def detect_import_conflicts(
    manifest: HandoffManifest,
    extracted_dir: str,
    target_base: str,
    existing_action_destinations: set[str],
    existing_case_numbers: set[str],
    existing_package_ids: set[str],
) -> list[ConflictDetail]:
    conflicts: list[ConflictDetail] = []
    files_dir = os.path.join(extracted_dir, "files")

    for fi in manifest.files:
        target_path = os.path.join(target_base, fi.relative_path)

        if not os.path.exists(os.path.join(files_dir, fi.relative_path)):
            conflicts.append(ConflictDetail(
                conflict_type=ConflictType.FILE_MISSING,
                file_item=fi,
                target_path=target_path,
                detail=f"包内文件缺失: {fi.relative_path}",
            ))
            continue

        file_path = os.path.join(files_dir, fi.relative_path)
        actual_sha = file_hash(file_path)
        if actual_sha != fi.sha256:
            conflicts.append(ConflictDetail(
                conflict_type=ConflictType.CONTENT_TAMPERED,
                file_item=fi,
                target_path=target_path,
                detail=f"文件内容被篡改，SHA256 不匹配: {fi.filename}",
                existing_info={
                    "expected_sha256": fi.sha256,
                    "actual_sha256": actual_sha,
                },
            ))
            continue

        if os.path.exists(target_path):
            conflicts.append(ConflictDetail(
                conflict_type=ConflictType.TARGET_OCCUPIED,
                file_item=fi,
                target_path=target_path,
                detail=f"目标路径已被占用: {target_path}",
                existing_info={
                    "existing_size": os.path.getsize(target_path),
                },
            ))
            continue

        if target_path in existing_action_destinations:
            conflicts.append(ConflictDetail(
                conflict_type=ConflictType.TARGET_OCCUPIED,
                file_item=fi,
                target_path=target_path,
                detail=f"目标路径已在操作日志中记录: {target_path}",
            ))
            continue

        if fi.case_number and fi.case_number in existing_case_numbers:
            conflicts.append(ConflictDetail(
                conflict_type=ConflictType.DUPLICATE_CASE,
                file_item=fi,
                target_path=target_path,
                detail=f"案件号已存在: {fi.case_number}",
            ))
            continue

    if manifest.package_id in existing_package_ids:
        conflicts.append(ConflictDetail(
            conflict_type=ConflictType.DUPLICATE_PACKAGE,
            target_path="",
            detail=f"交接包已导入过: {manifest.package_id}",
            existing_info={},
        ))

    return conflicts


def export_verify_result_json(result: HandoffVerifyResult, output_path: str) -> None:
    from scan_sorter.utils import save_json
    save_json(output_path, result.to_dict())


def export_verify_result_csv(result: HandoffVerifyResult, output_path: str) -> None:
    import csv
    from scan_sorter.utils import ensure_dir

    ensure_dir(os.path.dirname(output_path))
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["项目", "值"])
        writer.writerow(["package_id", result.package_id])
        writer.writerow(["is_valid", result.is_valid])
        writer.writerow(["manifest_exists", result.manifest_exists])
        writer.writerow(["integrity_ok", result.integrity_ok])
        writer.writerow(["files_complete", result.files_complete])
        writer.writerow(["files_match", result.files_match])
        writer.writerow(["missing_files_count", len(result.missing_files)])
        writer.writerow(["tampered_files_count", len(result.tampered_files)])
        writer.writerow([])
        writer.writerow(["错误列表"])
        for e in result.errors:
            writer.writerow([e])
        writer.writerow([])
        writer.writerow(["警告列表"])
        for w in result.warnings:
            writer.writerow([w])
        if result.missing_files:
            writer.writerow([])
            writer.writerow(["缺失文件"])
            writer.writerow(["filename", "relative_path", "case_number", "sha256"])
            for mf in result.missing_files:
                writer.writerow([mf.filename, mf.relative_path, mf.case_number, mf.sha256])
        if result.tampered_files:
            writer.writerow([])
            writer.writerow(["篡改文件"])
            writer.writerow(["filename", "relative_path", "case_number", "expected_sha256"])
            for tf in result.tampered_files:
                writer.writerow([tf.filename, tf.relative_path, tf.case_number, tf.sha256])
