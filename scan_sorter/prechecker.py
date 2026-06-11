from __future__ import annotations

import os
import re
from collections import Counter

from scan_sorter.config import AppConfig
from scan_sorter.models import FileStatus, PrecheckResult, ScanFile
from scan_sorter.parser import parse_file


def check_illegal_name(scan_file: ScanFile, config: AppConfig) -> list[str]:
    errors: list[str] = []
    for rule in config.rules.illegal_name_patterns:
        pattern = rule.get("pattern", "")
        message = rule.get("message", "文件名不合法")
        if pattern and re.search(pattern, scan_file.filename):
            errors.append(message)
    return errors


def check_target_conflict(scan_file: ScanFile, config: AppConfig) -> list[str]:
    errors: list[str] = []
    if not scan_file.target_path:
        return errors
    if os.path.exists(scan_file.target_path):
        errors.append(
            f"目标路径已被占用: {scan_file.target_path}"
        )
    return errors


def check_duplicate_filenames(
    files: list[ScanFile],
) -> dict[str, list[str]]:
    name_map: dict[str, list[str]] = {}
    for sf in files:
        if sf.status not in (FileStatus.PRECHECK_FAIL,):
            name_map.setdefault(sf.filename, []).append(sf.path)
    duplicates = {
        fn: paths for fn, paths in name_map.items() if len(paths) > 1
    }
    return duplicates


def check_duplicate_case_numbers_in_intake(
    files: list[ScanFile],
) -> dict[str, list[str]]:
    case_map: dict[str, list[str]] = {}
    for sf in files:
        if sf.case_number and sf.status not in (FileStatus.PRECHECK_FAIL,):
            case_map.setdefault(sf.case_number, []).append(sf.filename)
    return case_map


def precheck_files(
    files: list[ScanFile], config: AppConfig
) -> list[PrecheckResult]:
    parsed: list[ScanFile] = []
    for sf in files:
        parse_file(sf, config)
        parsed.append(sf)

    duplicate_filenames = check_duplicate_filenames(parsed)
    case_number_map = check_duplicate_case_numbers_in_intake(parsed)

    results: list[PrecheckResult] = []
    for sf in parsed:
        errors: list[str] = []

        illegal_errors = check_illegal_name(sf, config)
        errors.extend(illegal_errors)

        if sf.status == FileStatus.PRECHECK_FAIL:
            if sf.error_message:
                errors.append(sf.error_message)
            results.append(
                PrecheckResult(
                    filename=sf.filename,
                    path=sf.path,
                    ok=False,
                    errors=errors,
                    case_number=sf.case_number,
                    target_dir=sf.target_dir,
                    target_path=sf.target_path,
                )
            )
            continue

        target_errors = check_target_conflict(sf, config)
        errors.extend(target_errors)

        if sf.filename in duplicate_filenames:
            dup_paths = duplicate_filenames[sf.filename]
            errors.append(
                f"重复文件名 {sf.filename}: {', '.join(dup_paths)}"
            )

        ok = len(errors) == 0
        if ok:
            sf.status = FileStatus.PRECHECK_OK
        else:
            sf.status = FileStatus.PRECHECK_FAIL

        results.append(
            PrecheckResult(
                filename=sf.filename,
                path=sf.path,
                ok=ok,
                errors=errors,
                case_number=sf.case_number,
                target_dir=sf.target_dir,
                target_path=sf.target_path,
            )
        )

    return results
