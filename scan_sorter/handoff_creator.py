from __future__ import annotations

import os
import shutil
import socket
import zipfile
from pathlib import Path
from typing import Optional

from scan_sorter.config import AppConfig
from scan_sorter.models import (
    HandoffCreateState,
    HandoffFileItem,
    HandoffManifest,
    HandoffPreviewResult,
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


def _get_state_path(output_dir: str) -> str:
    return os.path.join(output_dir, ".handoff_create_state.json")


def _get_operations_log_path(output_dir: str) -> str:
    return os.path.join(output_dir, "operations.jsonl")


def _get_manifest_path(package_dir: str) -> str:
    return os.path.join(package_dir, "manifest.json")


def _get_files_dir(package_dir: str) -> str:
    return os.path.join(package_dir, "files")


def _config_summary(config: AppConfig) -> dict:
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


def _find_archived_files(
    config: AppConfig,
    case_numbers: Optional[list[str]] = None,
    batch_ids: Optional[list[str]] = None,
) -> list[dict]:
    action_log_path = config.logging.action_log_path()
    batch_history_path = config.logging.batch_history_path()

    action_records = read_jsonl(action_log_path)
    batch_records = load_json(batch_history_path, default=[])

    batch_case_map: dict[str, set[str]] = {}
    for b in batch_records:
        bid = b.get("batch_id", "")
        if bid:
            batch_case_map[bid] = set()

    for a in action_records:
        bid = a.get("batch_id", "")
        cn = a.get("case_number", "")
        if bid and cn and bid in batch_case_map:
            batch_case_map[bid].add(cn)

    result: list[dict] = []
    seen_paths: set[str] = set()

    for action in action_records:
        if action.get("rolled_back", False):
            continue

        dest = action.get("destination", "")
        if not dest or dest in seen_paths:
            continue
        if not os.path.exists(dest):
            continue

        cn = action.get("case_number", "")
        bid = action.get("batch_id", "")

        if case_numbers and cn not in case_numbers:
            continue
        if batch_ids and bid not in batch_ids:
            continue

        seen_paths.add(dest)
        result.append({
            "path": dest,
            "filename": os.path.basename(dest),
            "case_number": cn,
            "batch_id": bid,
            "source_path": action.get("source", ""),
            "action_id": action.get("action_id", ""),
            "action_type": action.get("action_type", ""),
            "operator": action.get("operator", ""),
            "timestamp": action.get("timestamp", ""),
        })

    return result


def preview_handoff(
    config: AppConfig,
    case_numbers: Optional[list[str]] = None,
    batch_ids: Optional[list[str]] = None,
) -> HandoffPreviewResult:
    archived = _find_archived_files(config, case_numbers, batch_ids)

    file_items: list[HandoffFileItem] = []
    total_size = 0
    case_set: set[str] = set()
    batch_set: set[str] = set()

    for info in archived:
        path = info["path"]
        size = os.path.getsize(path) if os.path.exists(path) else 0
        total_size += size
        case_set.add(info["case_number"])
        batch_set.add(info["batch_id"])

        file_items.append(HandoffFileItem(
            original_path=path,
            relative_path=os.path.join(info["case_number"], info["filename"]),
            filename=info["filename"],
            case_number=info["case_number"],
            batch_id=info["batch_id"],
            size=size,
            sha256="",
            source_destination=path,
        ))

    return HandoffPreviewResult(
        case_numbers=sorted(case_set),
        batch_ids=sorted(batch_set),
        files=file_items,
        total_files=len(file_items),
        total_size=total_size,
        estimated_package_size=total_size,
    )


def _save_state(state: HandoffCreateState) -> None:
    state.updated_at = iso_now()
    save_json(_get_state_path(state.output_dir), state.to_dict())


def _load_state(output_dir: str) -> Optional[HandoffCreateState]:
    state_path = _get_state_path(output_dir)
    if os.path.exists(state_path):
        raw = load_json(state_path, default=None)
        if raw:
            return HandoffCreateState.from_dict(raw)
    return None


def _log_operation(
    output_dir: str,
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
    append_jsonl(_get_operations_log_path(output_dir), rec.to_dict())
    return rec.operation_id


def create_handoff_package(
    config: AppConfig,
    output_dir: str,
    case_numbers: Optional[list[str]] = None,
    batch_ids: Optional[list[str]] = None,
    description: str = "",
    resume: bool = True,
) -> tuple[HandoffCreateState, str]:
    output_dir = sanitize_path(output_dir)
    ensure_dir(output_dir)

    state: Optional[HandoffCreateState] = None
    if resume:
        state = _load_state(output_dir)

    if state is None or state.status in (HandoffStatus.CREATED, HandoffStatus.FAILED):
        archived = _find_archived_files(config, case_numbers, batch_ids)
        if not archived:
            raise ValueError("未找到符合条件的归档文件")

        manifest = HandoffManifest(
            source_operator=config.operator,
            source_host=socket.gethostname(),
            source_config_summary=_config_summary(config),
            case_numbers=sorted({a["case_number"] for a in archived if a["case_number"]}),
            batch_ids=sorted({a["batch_id"] for a in archived if a["batch_id"]}),
            description=description,
        )

        pending_paths = [a["path"] for a in archived]

        state = HandoffCreateState(
            status=HandoffStatus.CREATING,
            package_id=manifest.package_id,
            case_numbers=manifest.case_numbers,
            batch_ids=manifest.batch_ids,
            output_dir=output_dir,
            files_pending=pending_paths,
            manifest=manifest,
        )
        _save_state(state)

    package_dir = os.path.join(output_dir, state.package_id)
    files_dir = _get_files_dir(package_dir)
    ensure_dir(files_dir)

    state.status = HandoffStatus.CREATING
    _save_state(state)

    pending_set = set(state.files_pending)
    processed_set = set(state.files_processed)

    archived_map: dict[str, dict] = {}
    for info in _find_archived_files(config, case_numbers, batch_ids):
        archived_map[info["path"]] = info

    try:
        for src_path in list(pending_set):
            if src_path in processed_set:
                continue

            if not os.path.exists(src_path):
                state.files_failed.append(src_path)
                if src_path in state.files_pending:
                    state.files_pending.remove(src_path)
                _save_state(state)
                continue

            info = archived_map.get(src_path, {})
            case_number = info.get("case_number", "unknown")
            filename = os.path.basename(src_path)
            relative_path = os.path.join(case_number, filename)
            dest_path = os.path.join(files_dir, relative_path)

            ensure_dir(os.path.dirname(dest_path))

            try:
                shutil.copy2(src_path, dest_path)

                sha = file_hash(dest_path)
                size = os.path.getsize(dest_path)

                file_item = HandoffFileItem(
                    original_path=src_path,
                    relative_path=relative_path,
                    filename=filename,
                    case_number=case_number,
                    batch_id=info.get("batch_id", ""),
                    size=size,
                    sha256=sha,
                    source_destination=src_path,
                )

                if state.manifest:
                    state.manifest.files.append(file_item)

                state.files_processed.append(src_path)
                if src_path in state.files_pending:
                    state.files_pending.remove(src_path)

            except Exception as e:
                state.files_failed.append(src_path)
                if src_path in state.files_pending:
                    state.files_pending.remove(src_path)
                state.error = str(e)

            _save_state(state)

        if state.manifest:
            state.manifest.total_files = len(state.manifest.files)
            state.manifest.total_size = sum(f.size for f in state.manifest.files)
            save_json(_get_manifest_path(package_dir), state.manifest.to_dict())

            op_log_path = _get_operations_log_path(output_dir)
            if os.path.exists(op_log_path):
                shutil.copy2(op_log_path, os.path.join(package_dir, "operations.jsonl"))

        if state.files_failed:
            state.status = HandoffStatus.FAILED
            state.error = f"有 {len(state.files_failed)} 个文件处理失败"
        else:
            state.status = HandoffStatus.CREATED

        _save_state(state)

        _log_operation(
            output_dir,
            "create",
            state.package_id,
            config.operator,
            state.status.value,
            {
                "total_files": len(state.manifest.files) if state.manifest else 0,
                "failed_count": len(state.files_failed),
                "case_numbers": state.case_numbers,
                "batch_ids": state.batch_ids,
            },
        )

        package_zip = os.path.join(output_dir, f"{state.package_id}.zip")
        with zipfile.ZipFile(package_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(package_dir):
                for f in files:
                    full = os.path.join(root, f)
                    arcname = os.path.relpath(full, package_dir)
                    zf.write(full, arcname)

        return state, package_zip

    except Exception as e:
        state.status = HandoffStatus.FAILED
        state.error = str(e)
        _save_state(state)
        raise


def get_create_history(output_dir: str) -> list[dict]:
    log_path = _get_operations_log_path(output_dir)
    records = read_jsonl(log_path)
    create_ops = [r for r in records if r.get("operation_type") == "create"]
    return create_ops


def export_create_result_json(state: HandoffCreateState, output_path: str) -> None:
    data = state.to_dict()
    save_json(output_path, data)


def export_create_result_csv(state: HandoffCreateState, output_path: str) -> None:
    import csv

    fieldnames = [
        "filename", "case_number", "batch_id", "size", "sha256",
        "original_path", "relative_path", "source_destination",
    ]
    ensure_dir(os.path.dirname(output_path))

    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        if state.manifest:
            for fi in state.manifest.files:
                writer.writerow(fi.to_dict())
