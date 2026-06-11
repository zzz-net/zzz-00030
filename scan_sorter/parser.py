from __future__ import annotations

import os
import re
from typing import Optional

from scan_sorter.config import AppConfig
from scan_sorter.models import FileStatus, ScanFile


def parse_case_number(scan_file: ScanFile, config: AppConfig) -> Optional[str]:
    pattern = config.rules.case_number_pattern
    m = re.search(pattern, scan_file.filename)
    if m:
        return m.group(1)
    return None


def parse_target_path(scan_file: ScanFile, config: AppConfig) -> Optional[str]:
    if not scan_file.case_number:
        return None
    structure = config.rules.target_structure
    subdir = structure.replace("{case_number}", scan_file.case_number)
    target_dir = os.path.join(os.path.abspath(config.target_base), subdir)
    target_path = os.path.join(target_dir, scan_file.filename)
    return target_path


def parse_file(scan_file: ScanFile, config: AppConfig) -> ScanFile:
    case_number = parse_case_number(scan_file, config)
    scan_file.case_number = case_number

    if case_number is None:
        scan_file.status = FileStatus.PRECHECK_FAIL
        scan_file.error_message = "无法从文件名解析案卷号"
        return scan_file

    target_path = parse_target_path(scan_file, config)
    if target_path:
        scan_file.target_dir = os.path.dirname(target_path)
        scan_file.target_path = target_path

    scan_file.status = FileStatus.PARSED
    return scan_file
