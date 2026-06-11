from __future__ import annotations

import os
import shutil

from scan_sorter.config import AppConfig
from scan_sorter.models import ActionType, FileStatus, ScanFile
from scan_sorter.utils import ensure_dir


def execute_file(scan_file: ScanFile, config: AppConfig) -> tuple[bool, str]:
    if scan_file.status != FileStatus.PRECHECK_OK:
        return False, scan_file.error_message or "预检未通过"

    if not scan_file.target_path or not scan_file.target_dir:
        return False, "未计算目标路径"

    if not os.path.exists(scan_file.path):
        return False, "源文件不存在"

    try:
        ensure_dir(scan_file.target_dir)
        action = config.rules.action.lower()

        if action == "copy":
            shutil.copy2(scan_file.path, scan_file.target_path)
            scan_file.status = FileStatus.DONE
            return True, ""
        else:
            shutil.move(scan_file.path, scan_file.target_path)
            scan_file.status = FileStatus.DONE
            return True, ""

    except Exception as e:
        scan_file.status = FileStatus.ERROR
        scan_file.error_message = str(e)
        return False, str(e)
