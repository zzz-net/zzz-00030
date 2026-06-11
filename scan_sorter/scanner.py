from __future__ import annotations

import os
from pathlib import Path

from scan_sorter.config import AppConfig
from scan_sorter.models import ScanFile


def scan_intake(config: AppConfig) -> list[ScanFile]:
    intake_dir = os.path.abspath(config.intake_dir)
    if not os.path.isdir(intake_dir):
        return []

    allowed = set(ext.lower() for ext in config.rules.allowed_extensions)
    files: list[ScanFile] = []

    for entry in sorted(os.scandir(intake_dir), key=lambda e: e.name):
        if not entry.is_file():
            continue
        ext = os.path.splitext(entry.name)[1].lower()
        if ext not in allowed:
            continue
        sf = ScanFile(
            path=os.path.abspath(entry.path),
            filename=entry.name,
        )
        files.append(sf)

    return files
