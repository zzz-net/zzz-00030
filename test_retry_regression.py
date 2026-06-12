"""
scan-sorter 重试预检/执行链路 回归测试脚本

验证功能：
  1. 空错误队列
  2. 混合可重试/不可重试（源文件丢失、目标已存在、处理队列中、错误队列重复、超最大重试次数）
  3. 配置变更后目标路径变化反映到重试计划
  4. 跨进程重启后状态对齐
  5. JSON/CSV 导出内容与日志可追溯
  6. 执行后日志和批次历史一致性
  7. 同一文件重复残留时稳定标记，不悄悄覆盖或重复执行

使用独立的 test_retry_run/ 目录。
运行方式: python test_retry_regression.py
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import sys
import traceback
from pathlib import Path

TEST_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "test_retry_run")
)

INTAKE_DIR = os.path.join(TEST_ROOT, "intake")
TARGET_DIR = os.path.join(TEST_ROOT, "target")
TARGET_DIR_V2 = os.path.join(TEST_ROOT, "target_v2")
DATA_DIR = os.path.join(TEST_ROOT, "data")
CONFIG_PATH = os.path.join(TEST_ROOT, "test_config.yaml")
CONFIG_V2_PATH = os.path.join(TEST_ROOT, "test_config_v2.yaml")

ACTION_LOG = os.path.join(DATA_DIR, "action_log.jsonl")
QUEUE_FILE = os.path.join(DATA_DIR, "queue.json")
ERROR_QUEUE_FILE = os.path.join(DATA_DIR, "error_queue.json")
BATCH_HISTORY_FILE = os.path.join(DATA_DIR, "batch_history.json")

PLAN_JSON = os.path.join(TEST_ROOT, "retry_plan.json")
PLAN_CSV = os.path.join(TEST_ROOT, "retry_plan.csv")
RESULT_JSON = os.path.join(TEST_ROOT, "retry_result.json")
RESULT_CSV = os.path.join(TEST_ROOT, "retry_result.csv")


def write_config(target_suffix: str = "", target_structure: str = "{case_number}") -> None:
    target_base = TARGET_DIR if not target_suffix else TARGET_DIR + target_suffix
    cfg = f"""intake_dir: {INTAKE_DIR}
target_base: {target_base}
operator: test_op_retry

rules:
  case_number_pattern: "(\\\\d{{4}}-[A-Z]\\\\d{{3}})"
  file_pattern: "(\\\\d{{4}}-[A-Z]\\\\d{{3}}-\\\\d{{3}})\\\\.(pdf|jpg|jpeg|png|tiff|bmp)$"
  allowed_extensions:
    - .pdf
    - .jpg
    - .jpeg
    - .png
    - .tiff
    - .bmp
  illegal_name_patterns:
    - pattern: "[^a-zA-Z0-9\\\\-_\\\\.]"
      message: "文件名包含非法字符"
  target_structure: "{target_structure}"
  action: move

batch:
  max_size: 50
  stop_on_failure_ratio: 0.5

logging:
  dir: {DATA_DIR}
  action_log: action_log.jsonl
  queue_file: queue.json
  error_queue_file: error_queue.json
  batch_history_file: batch_history.json

watch:
  poll_interval: 5
"""
    path = CONFIG_PATH if not target_suffix else CONFIG_V2_PATH
    with open(path, "w", encoding="utf-8") as f:
        f.write(cfg)


def reset_test_dirs() -> None:
    if os.path.isdir(TEST_ROOT):
        shutil.rmtree(TEST_ROOT)
    os.makedirs(INTAKE_DIR, exist_ok=True)
    os.makedirs(TARGET_DIR, exist_ok=True)
    os.makedirs(TARGET_DIR_V2, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)


def touch(path: str) -> None:
    Path(path).touch(exist_ok=True)


def load_json(path: str, default=None):
    if not os.path.exists(path):
        return default if default is not None else []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def read_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def read_csv(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        return list(reader)


def assert_eq(actual, expected, label: str) -> None:
    if actual != expected:
        raise AssertionError(
            f"[FAIL] {label}: expected={expected!r}, actual={actual!r}"
        )
    print(f"  [OK] {label} == {expected!r}")


def assert_in(member, container, label: str) -> None:
    if member not in container:
        raise AssertionError(
            f"[FAIL] {label}: {member!r} not in {container!r}"
        )
    print(f"  [OK] {label}: {member!r} present")


def assert_not_in(member, container, label: str) -> None:
    if member in container:
        raise AssertionError(
            f"[FAIL] {label}: {member!r} found in {container!r}"
        )
    print(f"  [OK] {label}: {member!r} absent")


def step(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def file_mtime(path: str) -> float:
    if os.path.exists(path):
        return os.path.getmtime(path)
    return 0.0


def setup_error_queue(config):
    from scan_sorter.models import ErrorItem
    from scan_sorter.queue_manager import ErrorQueue

    eq = ErrorQueue(config.logging.error_queue_path())

    file_a = os.path.join(INTAKE_DIR, "2024-A001-001.pdf")
    file_b = os.path.join(INTAKE_DIR, "2024-B002-001.jpg")
    file_c = os.path.join(INTAKE_DIR, "2024-C003-001.pdf")
    file_d = os.path.join(INTAKE_DIR, "2024-D004-001.pdf")
    file_e = os.path.join(INTAKE_DIR, "bad name#.pdf")
    file_f = os.path.join(INTAKE_DIR, "2024-F006-001.pdf")

    touch(file_a)
    touch(file_b)
    touch(file_c)
    touch(file_e)
    touch(file_f)

    eq.add(ErrorItem(
        path=file_a,
        filename="2024-A001-001.pdf",
        case_number="2024-A001",
        error="磁盘IO错误",
        retry_count=0,
        max_retries=3,
        batch_id="batch_001",
    ))

    eq.add(ErrorItem(
        path=file_b,
        filename="2024-B002-001.jpg",
        case_number="2024-B002",
        error="网络超时",
        retry_count=3,
        max_retries=3,
        batch_id="batch_001",
    ))

    eq.add(ErrorItem(
        path=file_c,
        filename="2024-C003-001.pdf",
        case_number="2024-C003",
        error="权限不足",
        retry_count=1,
        max_retries=3,
        batch_id="batch_002",
    ))

    eq.add(ErrorItem(
        path=file_d,
        filename="2024-D004-001.pdf",
        case_number="2024-D004",
        error="文件被占用",
        retry_count=0,
        max_retries=3,
        batch_id="batch_002",
    ))

    eq.add(ErrorItem(
        path=file_e,
        filename="bad name#.pdf",
        case_number=None,
        error="文件名不合法",
        retry_count=0,
        max_retries=3,
    ))

    eq.add(ErrorItem(
        path=file_f,
        filename="2024-F006-001.pdf",
        case_number="2024-F006",
        error="临时故障",
        retry_count=0,
        max_retries=3,
        batch_id="batch_003",
    ))

    target_dir_c = os.path.join(TARGET_DIR, "2024-C003")
    os.makedirs(target_dir_c, exist_ok=True)
    touch(os.path.join(target_dir_c, "2024-C003-001.pdf"))

    from scan_sorter.queue_manager import ProcessingQueue
    pq = ProcessingQueue(config.logging.queue_path())
    pq.enqueue(file_f, "2024-F006", filename="2024-F006-001.pdf")

    return {
        "file_a": file_a,
        "file_b": file_b,
        "file_c": file_c,
        "file_d": file_d,
        "file_e": file_e,
        "file_f": file_f,
    }


def main() -> int:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from scan_sorter.batch_manager import BatchManager
    from scan_sorter.config import load_config, reload_config
    from scan_sorter.cli import main as cli_main
    from scan_sorter.retry_manager import (
        RetryManager,
        RetryStatus,
        SkipReason,
        export_retry_plan_json,
        export_retry_plan_csv,
        export_retry_result_json,
        export_retry_result_csv,
    )
    from scan_sorter.queue_manager import ErrorQueue, ProcessingQueue

    reset_test_dirs()
    write_config()

    step("测试 1: 空错误队列")
    config = load_config(CONFIG_PATH)
    mgr = BatchManager(config)
    plan = mgr.build_retry_plan()
    assert_eq(plan.total, 0, "空队列 total")
    assert_eq(plan.retryable, 0, "空队列 retryable")
    assert_eq(plan.skipped, 0, "空队列 skipped")
    assert_eq(len(plan.items), 0, "空队列 items 为空")
    assert_eq(len(plan.retryable_items), 0, "空队列 retryable_items 为空")
    assert_eq(len(plan.skipped_items), 0, "空队列 skipped_items 为空")

    step("测试 2: CLI 空队列 retry-plan 命令")
    result = cli_main(["-c", CONFIG_PATH, "retry-plan", "--format", "json", "--output", PLAN_JSON])
    assert_eq(result, 0, "CLI retry-plan 退出码")
    exported = load_json(PLAN_JSON)
    assert_eq(exported["total"], 0, "导出 JSON total")
    assert_eq(exported["retryable"], 0, "导出 JSON retryable")

    step("测试 3: 混合可重试/不可重试 - 预检")
    files = setup_error_queue(config)

    mgr2 = BatchManager(config)
    plan2 = mgr2.build_retry_plan()
    assert_eq(plan2.total, 6, "总计错误项数")
    assert_eq(plan2.retryable, 1, "可重试项数（只有 file_a）")
    assert_eq(plan2.skipped, 5, "跳过项数")

    retryable_paths = [item.path for item in plan2.retryable_items]
    assert_in(files["file_a"], retryable_paths, "file_a 在可重试列表")

    skipped_by_reason = {}
    for item in plan2.skipped_items:
        if item.skip_reason:
            skipped_by_reason.setdefault(item.skip_reason.value, []).append(item.path)

    assert_in(SkipReason.MAX_RETRIES_EXCEEDED.value, skipped_by_reason, "有超最大重试次数的跳过项")
    assert_in(files["file_b"], skipped_by_reason[SkipReason.MAX_RETRIES_EXCEEDED.value], "file_b 因超最大重试跳过")

    assert_in(SkipReason.TARGET_EXISTS.value, skipped_by_reason, "有目标已存在的跳过项")
    assert_in(files["file_c"], skipped_by_reason[SkipReason.TARGET_EXISTS.value], "file_c 因目标已存在跳过")

    assert_in(SkipReason.SOURCE_MISSING.value, skipped_by_reason, "有源文件丢失的跳过项")
    assert_in(files["file_d"], skipped_by_reason[SkipReason.SOURCE_MISSING.value], "file_d 因源文件丢失跳过")

    assert_in(SkipReason.PARSE_FAILED.value, skipped_by_reason, "有解析失败的跳过项")
    assert_in(files["file_e"], skipped_by_reason[SkipReason.PARSE_FAILED.value], "file_e 因解析失败跳过")

    assert_in(SkipReason.IN_PROCESSING_QUEUE.value, skipped_by_reason, "有在处理队列中的跳过项")
    assert_in(files["file_f"], skipped_by_reason[SkipReason.IN_PROCESSING_QUEUE.value], "file_f 因在处理队列中跳过")

    file_a_item = [i for i in plan2.retryable_items if i.path == files["file_a"]][0]
    assert_eq(file_a_item.original_error, "磁盘IO错误", "原始错误保留")
    assert_eq(file_a_item.original_batch_id, "batch_001", "原始批次ID保留")
    assert_eq(file_a_item.case_number, "2024-A001", "案卷号正确")
    expected_target = os.path.join(TARGET_DIR, "2024-A001", "2024-A001-001.pdf")
    assert_eq(file_a_item.new_target_path, expected_target, "新目标路径正确")
    assert_in("move", file_a_item.expected_action, "预计动作包含 move")
    assert_in(files["file_a"], file_a_item.expected_action, "预计动作包含源路径")
    assert_eq(file_a_item.retry_count, 0, "重试计数正确")
    assert_eq(file_a_item.max_retries, 3, "最大重试次数正确")

    file_c_item = [i for i in plan2.skipped_items if i.path == files["file_c"]][0]
    assert_eq(file_c_item.target_exists, True, "file_c target_exists 标记正确")
    assert_in("目标路径已存在", file_c_item.skip_detail, "跳过详情包含目标已存在")

    file_f_item = [i for i in plan2.skipped_items if i.path == files["file_f"]][0]
    assert_eq(file_f_item.in_processing_queue, True, "file_f in_processing_queue 标记正确")

    step("测试 4: 错误队列重复记录检测")
    eq = ErrorQueue(config.logging.error_queue_path())
    eq._items.append(eq._items[0])
    eq._save()
    mgr3 = BatchManager(config)
    plan3 = mgr3.build_retry_plan()

    duplicate_skipped = [i for i in plan3.skipped_items
                         if i.skip_reason == SkipReason.DUPLICATE_IN_ERROR_QUEUE]
    assert_eq(len(duplicate_skipped), 2, "重复记录被正确识别并跳过")
    assert_eq(duplicate_skipped[0].duplicate_in_error_queue, True, "duplicate_in_error_queue 标记正确")

    eq2 = ErrorQueue(config.logging.error_queue_path())
    eq2._items = eq2._items[:-1]
    eq2._save()

    step("测试 5: 配置变更 - 目标路径变化")
    write_config(target_suffix="_v2", target_structure="archive/{case_number}")
    config_v2 = load_config(CONFIG_V2_PATH)

    mgr4 = BatchManager(config_v2)
    plan4 = mgr4.build_retry_plan()
    retryable_items_v2 = [i for i in plan4.retryable_items]

    file_a_v2 = [i for i in retryable_items_v2 if i.path == files["file_a"]][0]
    expected_target_v2 = os.path.join(TARGET_DIR + "_v2", "archive", "2024-A001", "2024-A001-001.pdf")
    assert_eq(file_a_v2.new_target_path, expected_target_v2, "配置变更后目标路径更新正确")
    assert_in(TARGET_DIR + "_v2", file_a_v2.expected_action, "预计动作反映新配置")

    step("测试 6: JSON 导出内容验证")
    export_retry_plan_json(plan2, PLAN_JSON)
    exported_plan = load_json(PLAN_JSON)
    assert_eq(exported_plan["total"], 6, "导出 total")
    assert_eq(exported_plan["retryable"], 1, "导出 retryable")
    assert_eq(exported_plan["skipped"], 5, "导出 skipped")
    assert_eq(len(exported_plan["retryable_items"]), 1, "导出 retryable_items 数量")
    assert_eq(len(exported_plan["skipped_items"]), 5, "导出 skipped_items 数量")

    exported_item = exported_plan["retryable_items"][0]
    assert_in("original_error", exported_item, "导出包含 original_error")
    assert_in("original_batch_id", exported_item, "导出包含 original_batch_id")
    assert_in("new_target_path", exported_item, "导出包含 new_target_path")
    assert_in("expected_action", exported_item, "导出包含 expected_action")
    assert_in("skip_reason", exported_item, "导出包含 skip_reason")
    assert_in("skip_detail", exported_item, "导出包含 skip_detail")
    assert_in("target_exists", exported_item, "导出包含 target_exists")
    assert_in("source_missing", exported_item, "导出包含 source_missing")
    assert_in("in_processing_queue", exported_item, "导出包含 in_processing_queue")
    assert_in("duplicate_in_error_queue", exported_item, "导出包含 duplicate_in_error_queue")
    assert_in("action_type", exported_item, "导出包含 action_type")

    step("测试 7: CSV 导出内容验证")
    export_retry_plan_csv(plan2, PLAN_CSV)
    csv_rows = read_csv(PLAN_CSV)
    assert_eq(len(csv_rows), 6, "CSV 行数正确")

    csv_headers = list(csv_rows[0].keys())
    assert_in("original_error", csv_headers, "CSV 包含 original_error")
    assert_in("new_target_path", csv_headers, "CSV 包含 new_target_path")
    assert_in("expected_action", csv_headers, "CSV 包含 expected_action")
    assert_in("skip_reason", csv_headers, "CSV 包含 skip_reason")
    assert_in("skip_detail", csv_headers, "CSV 包含 skip_detail")

    step("测试 8: 跨进程重启 - 状态持久化与对齐")
    config1 = load_config(CONFIG_PATH)
    mgr_before = BatchManager(config1)
    plan_before = mgr_before.build_retry_plan()

    error_queue_before = load_json(ERROR_QUEUE_FILE)
    processing_queue_before = load_json(QUEUE_FILE)
    batch_history_before = load_json(BATCH_HISTORY_FILE)

    import importlib
    import scan_sorter.retry_manager
    import scan_sorter.queue_manager
    importlib.reload(scan_sorter.retry_manager)
    importlib.reload(scan_sorter.queue_manager)

    from scan_sorter.retry_manager import RetryManager as RetryManagerReloaded

    config2 = load_config(CONFIG_PATH)
    retry_mgr = RetryManagerReloaded(config2)
    plan_after = retry_mgr.build_retry_plan()

    assert_eq(plan_after.total, plan_before.total, "重启后 total 一致")
    assert_eq(plan_after.retryable, plan_before.retryable, "重启后 retryable 一致")
    assert_eq(plan_after.skipped, plan_before.skipped, "重启后 skipped 一致")

    error_queue_after = load_json(ERROR_QUEUE_FILE)
    processing_queue_after = load_json(QUEUE_FILE)
    assert_eq(error_queue_before, error_queue_after, "重启后 error_queue 未被修改")
    assert_eq(processing_queue_before, processing_queue_after, "重启后 processing_queue 未被修改")

    step("测试 9: 重试执行 - 成功路径")
    reset_test_dirs()
    write_config()
    config_exec = load_config(CONFIG_PATH)

    from scan_sorter.models import ErrorItem
    eq_exec = ErrorQueue(config_exec.logging.error_queue_path())
    file_success = os.path.join(INTAKE_DIR, "2024-Z001-001.pdf")
    touch(file_success)
    eq_exec.add(ErrorItem(
        path=file_success,
        filename="2024-Z001-001.pdf",
        case_number="2024-Z001",
        error="临时故障",
        retry_count=0,
        max_retries=3,
        batch_id="batch_original",
    ))

    mgr_exec = BatchManager(config_exec)
    exec_result = mgr_exec.execute_retry()

    assert_eq(exec_result.total, 1, "执行总数")
    assert_eq(exec_result.succeeded, 1, "成功数")
    assert_eq(exec_result.failed, 0, "失败数")
    assert_eq(exec_result.skipped, 0, "跳过数")
    assert_ne(exec_result.batch_id, "", "生成批次ID")

    assert_eq(os.path.exists(file_success), False, "源文件已被移动")
    expected_target = os.path.join(TARGET_DIR, "2024-Z001", "2024-Z001-001.pdf")
    assert_eq(os.path.exists(expected_target), True, "目标文件已创建")

    eq_after = ErrorQueue(config_exec.logging.error_queue_path())
    assert_eq(eq_after.count(), 0, "成功后错误队列已清空")

    exec_item = exec_result.items[0]
    assert_eq(exec_item.status, RetryStatus.SUCCESS, "执行状态为成功")
    assert_ne(exec_item.action_id, "", "生成操作ID")
    assert_eq(exec_item.source, file_success, "源路径正确")
    assert_eq(exec_item.destination, expected_target, "目标路径正确")
    assert_eq(exec_item.action_type, "move", "操作类型正确")

    action_logs = read_jsonl(ACTION_LOG)
    assert_eq(len(action_logs), 1, "操作日志写入正确")
    assert_eq(action_logs[0]["action_id"], exec_item.action_id, "日志与结果可追溯")
    assert_eq(action_logs[0]["batch_id"], exec_result.batch_id, "日志批次ID一致")
    assert_eq(action_logs[0]["source"], file_success, "日志源路径正确")
    assert_eq(action_logs[0]["destination"], expected_target, "日志目标路径正确")

    batch_history = load_json(BATCH_HISTORY_FILE)
    assert_eq(len(batch_history), 1, "批次历史写入正确")
    assert_eq(batch_history[0]["batch_id"], exec_result.batch_id, "批次ID一致")
    assert_eq(batch_history[0]["total"], 1, "批次总数正确")
    assert_eq(batch_history[0]["succeeded"], 1, "批次成功数正确")
    assert_eq(batch_history[0]["failed"], 0, "批次失败数正确")
    assert_eq(batch_history[0]["status"], "completed", "批次状态正确")
    assert_eq(batch_history[0]["action_ids"], [exec_item.action_id], "批次操作ID列表正确")

    processing_queue = load_json(QUEUE_FILE)
    assert_eq(len(processing_queue), 1, "处理队列写入正确")
    assert_eq(processing_queue[0]["path"], file_success, "处理队列路径正确")
    assert_eq(processing_queue[0]["status"], "done", "处理队列状态正确")

    step("测试 10: 重试执行 - 混合成功/失败 + 导出")
    reset_test_dirs()
    write_config()
    config_mix = load_config(CONFIG_PATH)

    eq_mix = ErrorQueue(config_mix.logging.error_queue_path())
    file_ok = os.path.join(INTAKE_DIR, "2025-A001-001.pdf")
    file_fail = os.path.join(INTAKE_DIR, "2025-B002-001.pdf")
    file_skip = os.path.join(INTAKE_DIR, "2025-C003-001.pdf")
    touch(file_ok)
    touch(file_skip)

    target_dir_skip = os.path.join(TARGET_DIR, "2025-C003")
    os.makedirs(target_dir_skip, exist_ok=True)
    touch(os.path.join(target_dir_skip, "2025-C003-001.pdf"))

    eq_mix.add(ErrorItem(
        path=file_ok,
        filename="2025-A001-001.pdf",
        case_number="2025-A001",
        error="临时错误",
        retry_count=0,
        max_retries=3,
    ))
    eq_mix.add(ErrorItem(
        path=file_fail,
        filename="2025-B002-001.pdf",
        case_number="2025-B002",
        error="源文件将丢失",
        retry_count=0,
        max_retries=3,
    ))
    eq_mix.add(ErrorItem(
        path=file_skip,
        filename="2025-C003-001.pdf",
        case_number="2025-C003",
        error="目标已存在",
        retry_count=0,
        max_retries=3,
    ))

    mgr_mix = BatchManager(config_mix)
    plan_mix = mgr_mix.build_retry_plan()
    assert_eq(plan_mix.retryable, 1, "混合场景可重试数")
    assert_eq(plan_mix.skipped, 2, "混合场景跳过数")

    result_mix = mgr_mix.execute_retry(plan=plan_mix)

    assert_eq(result_mix.total, 1, "执行总数（只执行可重试的）")
    assert_eq(result_mix.succeeded, 1, "成功数")
    assert_eq(result_mix.failed, 0, "失败数")
    assert_eq(result_mix.skipped, 2, "预检跳过数")

    export_retry_result_json(result_mix, RESULT_JSON)
    export_retry_result_csv(result_mix, RESULT_CSV)

    exported_result = load_json(RESULT_JSON)
    assert_eq(exported_result["total"], 1, "结果导出 total")
    assert_eq(exported_result["succeeded"], 1, "结果导出 succeeded")
    assert_eq(exported_result["batch_id"], result_mix.batch_id, "结果导出 batch_id")
    assert_in("action_id", exported_result["items"][0], "结果导出包含 action_id")
    assert_in("error", exported_result["items"][0], "结果导出包含 error")

    csv_result = read_csv(RESULT_CSV)
    assert_eq(len(csv_result), 1, "CSV 结果行数")
    assert_in("action_id", csv_result[0], "CSV 结果包含 action_id")
    assert_in("batch_id", csv_result[0], "CSV 结果包含 batch_id")
    assert_in("error", csv_result[0], "CSV 结果包含 error")

    step("测试 11: 执行后不会重复执行 - 状态稳定性")
    mgr_check = BatchManager(config_mix)
    plan_check = mgr_check.build_retry_plan()
    assert_eq(plan_check.total, 2, "执行后只剩跳过项（file_fail, file_skip）")
    assert_eq(plan_check.retryable, 0, "没有可重试项，不会重复执行")

    result_check = mgr_check.execute_retry()
    assert_eq(result_check.total, 0, "第二次执行无操作")
    assert_eq(result_check.succeeded, 0, "第二次执行无成功")
    assert_eq(result_check.batch_id, "", "空执行不生成批次ID")

    batch_history_2 = load_json(BATCH_HISTORY_FILE)
    assert_eq(len(batch_history_2), 1, "只有第一次有执行的批次记录")

    step("测试 12: CLI 命令集成测试")
    reset_test_dirs()
    write_config()
    config_cli = load_config(CONFIG_PATH)

    eq_cli = ErrorQueue(config_cli.logging.error_queue_path())
    file_cli = os.path.join(INTAKE_DIR, "2026-A001-001.pdf")
    touch(file_cli)
    eq_cli.add(ErrorItem(
        path=file_cli,
        filename="2026-A001-001.pdf",
        case_number="2026-A001",
        error="CLI测试错误",
        retry_count=0,
        max_retries=3,
    ))

    rc = cli_main(["-c", CONFIG_PATH, "retry-plan", "--retryable-only"])
    assert_eq(rc, 0, "CLI retry-plan 退出码")

    rc = cli_main([
        "-c", CONFIG_PATH, "retry-plan",
        "--format", "json", "--output", PLAN_JSON,
    ])
    assert_eq(rc, 0, "CLI retry-plan 导出退出码")
    plan_data = load_json(PLAN_JSON)
    assert_eq(plan_data["retryable"], 1, "CLI 导出 retryable 正确")

    rc = cli_main([
        "-c", CONFIG_PATH, "retry-execute",
        "--format", "json", "--output", RESULT_JSON,
    ])
    assert_eq(rc, 0, "CLI retry-execute 退出码")

    result_data = load_json(RESULT_JSON)
    assert_eq(result_data["succeeded"], 1, "CLI 执行成功数正确")
    assert_ne(result_data["batch_id"], "", "CLI 执行生成批次ID")

    step("测试 13: 指定路径执行")
    reset_test_dirs()
    write_config()
    config_paths = load_config(CONFIG_PATH)

    eq_paths = ErrorQueue(config_paths.logging.error_queue_path())
    f1 = os.path.join(INTAKE_DIR, "2026-A001-001.pdf")
    f2 = os.path.join(INTAKE_DIR, "2026-B002-001.pdf")
    touch(f1)
    touch(f2)

    eq_paths.add(ErrorItem(
        path=f1, filename="2026-A001-001.pdf",
        case_number="2026-A001", error="err1",
    ))
    eq_paths.add(ErrorItem(
        path=f2, filename="2026-B002-001.pdf",
        case_number="2026-B002", error="err2",
    ))

    mgr_paths = BatchManager(config_paths)
    result_paths = mgr_paths.execute_retry(paths=[f1])
    assert_eq(result_paths.total, 1, "指定路径只执行1个")
    assert_eq(result_paths.succeeded, 1, "指定路径执行成功")

    eq_check = ErrorQueue(config_paths.logging.error_queue_path())
    items_remaining = eq_check.all()
    assert_eq(len(items_remaining), 1, "只剩未指定路径的项")
    assert_eq(items_remaining[0].path, f2, "剩余项是未指定的 f2")

    step("测试 14: 执行过程中目标被占用 - 不覆盖")
    reset_test_dirs()
    write_config()
    config_conflict = load_config(CONFIG_PATH)

    eq_conflict = ErrorQueue(config_conflict.logging.error_queue_path())
    f_conflict = os.path.join(INTAKE_DIR, "2026-X001-001.pdf")
    touch(f_conflict)

    target_dir_x = os.path.join(TARGET_DIR, "2026-X001")
    os.makedirs(target_dir_x, exist_ok=True)
    target_file = os.path.join(target_dir_x, "2026-X001-001.pdf")
    with open(target_file, "w") as f:
        f.write("existing content")

    eq_conflict.add(ErrorItem(
        path=f_conflict, filename="2026-X001-001.pdf",
        case_number="2026-X001", error="临时错误",
    ))

    pq_conflict = ProcessingQueue(config_conflict.logging.queue_path())
    for item in pq_conflict.all():
        if item.get("path") == f_conflict and item.get("status") == "queued":
            item["status"] = "done"
    pq_conflict._save()

    mgr_conflict = BatchManager(config_conflict)
    plan_conflict = mgr_conflict.build_retry_plan()
    assert_eq(plan_conflict.skipped, 1, "预检时因目标已存在被跳过")
    assert_eq(plan_conflict.retryable, 0, "没有可执行项")

    result_conflict = mgr_conflict.execute_retry(plan=plan_conflict)
    assert_eq(result_conflict.total, 0, "执行时不会覆盖")

    with open(target_file, "r") as f:
        content = f.read()
    assert_eq(content, "existing content", "原有目标文件未被覆盖")

    print(f"\n{'='*60}")
    print("  所有测试通过 ✓")
    print(f"{'='*60}\n")
    return 0


def assert_ne(actual, expected, label: str) -> None:
    if actual == expected:
        raise AssertionError(
            f"[FAIL] {label}: expected != {expected!r}, actual={actual!r}"
        )
    print(f"  [OK] {label} != {expected!r}")


if __name__ == "__main__":
    try:
        exit(main())
    except Exception as e:
        print(f"\n[ERROR] 测试失败: {e}")
        traceback.print_exc()
        exit(1)
