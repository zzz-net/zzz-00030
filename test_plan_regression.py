"""
scan-sorter plan (dry-run) 回归测试脚本

验证预演计划功能：
  1. 空 intake
  2. 混合成功/失败
  3. 配置切换后计划变化
  4. JSON/CSV 导出内容
  5. dry-run 不落状态（不写 queue、error_queue、batch_history、action_log）
  6. dry-run 后再 process 的日志和批次历史没有被污染
  7. 目标目录已有同名文件、队列已有待处理记录、错误队列残留同一文件稳定标出

使用独立的 test_plan_run/ 目录。
运行方式: python test_plan_regression.py
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
    os.path.join(os.path.dirname(__file__), "test_plan_run")
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

PLAN_JSON = os.path.join(TEST_ROOT, "plan.json")
PLAN_CSV = os.path.join(TEST_ROOT, "plan.csv")


def write_config(target_suffix: str = "") -> None:
    target_base = TARGET_DIR if not target_suffix else TARGET_DIR + target_suffix
    cfg = f"""intake_dir: {INTAKE_DIR}
target_base: {target_base}
operator: test_op

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
  target_structure: "{{case_number}}"
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


def write_config_v2() -> None:
    cfg = f"""intake_dir: {INTAKE_DIR}
target_base: {TARGET_DIR_V2}
operator: test_op_v2

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
  target_structure: "archive/{{case_number}}"
  action: copy

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
    with open(CONFIG_V2_PATH, "w", encoding="utf-8") as f:
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


def load_json(path: str):
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


def main() -> int:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from scan_sorter.batch_manager import BatchManager
    from scan_sorter.config import load_config, reload_config
    from scan_sorter.cli import main as cli_main

    reset_test_dirs()
    write_config()
    write_config_v2()
    print(f"测试目录: {TEST_ROOT}")
    print(f"配置文件: {CONFIG_PATH}")

    # ---------- 场景 1: 空 intake ----------
    step("场景 1: 空 intake 目录")

    config = load_config(CONFIG_PATH)
    mgr = BatchManager(config)
    plan = mgr.dry_run()

    print(f"  plan.total = {plan.total}")
    assert_eq(plan.total, 0, "空 intake 时 plan.total == 0")
    assert_eq(plan.will_succeed, 0, "空 intake 时 plan.will_succeed == 0")
    assert_eq(plan.will_fail, 0, "空 intake 时 plan.will_fail == 0")
    assert_eq(len(plan.items), 0, "空 intake 时 plan.items 为空列表")

    # 验证空计划导出
    cli_main(["-c", CONFIG_PATH, "plan", "--format", "json", "--output", PLAN_JSON])
    assert_eq(os.path.exists(PLAN_JSON), True, "空计划 JSON 文件存在")
    plan_json_data = load_json(PLAN_JSON)
    assert_eq(plan_json_data["total"], 0, "空计划 JSON total == 0")
    assert_eq(isinstance(plan_json_data["items"], list), True, "空计划 JSON items 是列表")
    assert_eq(len(plan_json_data["items"]), 0, "空计划 JSON items 长度为 0")

    cli_main(["-c", CONFIG_PATH, "plan", "--format", "csv", "--output", PLAN_CSV])
    assert_eq(os.path.exists(PLAN_CSV), True, "空计划 CSV 文件存在")
    with open(PLAN_CSV, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames
    assert_eq(len(rows), 0, "空计划 CSV 数据行 == 0")
    assert fieldnames is not None, "空计划 CSV 有表头"
    print(f"  CSV 表头: {fieldnames}")

    # ---------- 场景 2: 混合成功/失败 + 各种冲突 ----------
    step("场景 2: 混合成功/失败 + 目标冲突 + 非法文件名")

    valid_a = os.path.join(INTAKE_DIR, "2024-A001-001.pdf")
    valid_b = os.path.join(INTAKE_DIR, "2024-B002-001.pdf")
    illegal = os.path.join(INTAKE_DIR, "bad file#name.pdf")
    occupied_src = os.path.join(INTAKE_DIR, "2024-C003-001.pdf")
    occupied_target_dir = os.path.join(TARGET_DIR, "2024-C003")
    occupied_target = os.path.join(occupied_target_dir, "2024-C003-001.pdf")

    touch(valid_a)
    touch(valid_b)
    touch(illegal)
    touch(occupied_src)
    os.makedirs(occupied_target_dir, exist_ok=True)
    touch(occupied_target)

    print(f"  intake 正常文件 A: {valid_a}")
    print(f"  intake 正常文件 B: {valid_b}")
    print(f"  intake 非法命名: {illegal}")
    print(f"  intake 目标占用: {occupied_src}")
    print(f"  已预占目标文件: {occupied_target}")

    # 记录 dry-run 前的状态文件 mtime
    mtime_before = {
        "queue": file_mtime(QUEUE_FILE),
        "error_queue": file_mtime(ERROR_QUEUE_FILE),
        "batch_history": file_mtime(BATCH_HISTORY_FILE),
        "action_log": file_mtime(ACTION_LOG),
    }
    print(f"  dry-run 前状态文件 mtime: {mtime_before}")

    config2 = load_config(CONFIG_PATH)
    mgr2 = BatchManager(config2)
    plan2 = mgr2.dry_run()

    print(f"  plan.total = {plan2.total}")
    print(f"  plan.will_succeed = {plan2.will_succeed}")
    print(f"  plan.will_fail = {plan2.will_fail}")
    print(f"  plan.warnings = {plan2.warnings}")

    assert_eq(plan2.total, 4, "plan.total == 4 (2正常+非法+占用)")
    assert_eq(plan2.will_succeed, 2, "plan.will_succeed == 2")
    assert_eq(plan2.will_fail, 2, "plan.will_fail == 2 (非法+占用)")

    # 验证每个文件的计划项
    items_by_name = {item.filename: item for item in plan2.items}

    # 正常文件 A
    item_a = items_by_name["2024-A001-001.pdf"]
    assert_eq(item_a.will_succeed, True, "正常文件 A will_succeed == True")
    assert_eq(item_a.action.value, "archive", "正常文件 A action == archive")
    assert_eq(item_a.case_number, "2024-A001", "正常文件 A case_number")
    assert_eq(item_a.target_exists, False, "正常文件 A 目标不存在")
    assert_eq(item_a.in_processing_queue, False, "正常文件 A 不在处理队列")
    assert_eq(item_a.in_error_queue, False, "正常文件 A 不在错误队列")
    assert_eq(item_a.action_type, "move", "正常文件 A action_type == move")

    # 正常文件 B
    item_b = items_by_name["2024-B002-001.pdf"]
    assert_eq(item_b.will_succeed, True, "正常文件 B will_succeed == True")
    assert_eq(item_b.action.value, "archive", "正常文件 B action == archive")

    # 非法文件
    item_illegal = items_by_name["bad file#name.pdf"]
    assert_eq(item_illegal.will_succeed, False, "非法文件 will_succeed == False")
    assert_eq(item_illegal.action.value, "fail_precheck", "非法文件 action == fail_precheck")
    assert len(item_illegal.errors) > 0, "非法文件有错误信息"

    # 目标占用文件
    item_occupied = items_by_name["2024-C003-001.pdf"]
    assert_eq(item_occupied.will_succeed, False, "目标占用文件 will_succeed == False")
    assert_eq(item_occupied.action.value, "fail_target_conflict", "目标占用文件 action == fail_target_conflict")
    assert_eq(item_occupied.target_exists, True, "目标占用文件 target_exists == True")
    assert len(item_occupied.errors) > 0, "目标占用文件有错误信息"
    assert any("目标路径已被占用" in e for e in item_occupied.errors), "错误包含目标占用"

    # ---------- 场景 3: dry-run 不落状态 ----------
    step("场景 3: 验证 dry-run 不写任何状态文件")

    mtime_after = {
        "queue": file_mtime(QUEUE_FILE),
        "error_queue": file_mtime(ERROR_QUEUE_FILE),
        "batch_history": file_mtime(BATCH_HISTORY_FILE),
        "action_log": file_mtime(ACTION_LOG),
    }
    print(f"  dry-run 后状态文件 mtime: {mtime_after}")

    assert_eq(mtime_after["queue"], mtime_before["queue"], "queue.json mtime 未变化（dry-run 不写队列")
    assert_eq(mtime_after["error_queue"], mtime_before["error_queue"], "error_queue.json mtime 未变化（dry-run 不写错误队列）")
    assert_eq(mtime_after["batch_history"], mtime_before["batch_history"], "batch_history.json mtime 未变化（dry-run 不写批次历史")
    assert_eq(mtime_after["action_log"], mtime_before["action_log"], "action_log.jsonl mtime 未变化（dry-run 不写操作日志）")

    # 验证状态文件内容确实不存在或为空
    assert_eq(os.path.exists(QUEUE_FILE), False, "queue.json 不存在（dry-run 不创建）")
    assert_eq(os.path.exists(ERROR_QUEUE_FILE), False, "error_queue.json 不存在（dry-run 不创建）")
    assert_eq(os.path.exists(BATCH_HISTORY_FILE), False, "batch_history.json 不存在（dry-run 不创建）")
    assert_eq(os.path.exists(ACTION_LOG), False, "action_log.jsonl 不存在（dry-run 不创建）")

    # ---------- 场景 4: JSON/CSV 导出内容验证 ----------
    step("场景 4: 验证 JSON/CSV 导出内容")

    cli_main(["-c", CONFIG_PATH, "plan", "--format", "json", "--output", PLAN_JSON])
    assert_eq(os.path.exists(PLAN_JSON), True, "计划 JSON 导出文件存在")

    plan_json = load_json(PLAN_JSON)
    assert_eq(plan_json["total"], 4, "导出 JSON total == 4")
    assert_eq(plan_json["will_succeed"], 2, "导出 JSON will_succeed == 2")
    assert_eq(plan_json["will_fail"], 2, "导出 JSON will_fail == 2")
    assert_eq(len(plan_json["items"]), 4, "导出 JSON items 长度 == 4")

    # 验证每个 item 有完整字段
    for item in plan_json["items"]:
        required_fields = [
            "filename", "path", "case_number", "target_dir", "target_path",
            "action", "will_succeed", "errors", "warnings",
            "in_processing_queue", "in_error_queue", "target_exists", "action_type",
        ]
        for field in required_fields:
            assert_in(field, item, f"导出 JSON item 包含字段 {field}")

    # 验证 CSV 2024-A001-001.pdf
    json_items_by_name = {i["filename"]: i for i in plan_json["items"]}
    assert_eq(json_items_by_name["2024-A001-001.pdf"]["action"], "archive", "JSON: 正常文件 action")
    assert_eq(json_items_by_name["bad file#name.pdf"]["will_succeed"], False, "JSON: 非法文件 will_succeed")
    assert_eq(json_items_by_name["2024-C003-001.pdf"]["target_exists"], True, "JSON: 占用文件 target_exists")

    # CSV 导出验证
    cli_main(["-c", CONFIG_PATH, "plan", "--format", "csv", "--output", PLAN_CSV])
    assert_eq(os.path.exists(PLAN_CSV), True, "计划 CSV 导出文件存在")

    with open(PLAN_CSV, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        csv_rows = list(reader)
        csv_fields = reader.fieldnames

    assert_eq(len(csv_rows), 4, "CSV 行数 == 4")
    expected_csv_fields = {
        "filename", "path", "case_number", "target_dir", "target_path",
        "action", "will_succeed", "action_type",
        "errors", "warnings",
        "in_processing_queue", "in_error_queue", "target_exists",
    }
    assert expected_csv_fields.issubset(set(csv_fields)), f"CSV 字段齐全: {csv_fields}"

    csv_by_name = {r["filename"]: r for r in csv_rows}
    assert_eq(csv_by_name["2024-A001-001.pdf"]["action"], "archive", "CSV: 正常文件 action")
    assert_eq(csv_by_name["bad file#name.pdf"]["will_succeed"], "False", "CSV: 非法文件 will_succeed")

    # ---------- 场景 5: 配置切换后计划变化 ----------
    step("场景 5: 配置切换（reload）后计划变化")

    # 先用 v1 配置跑一次 plan 记录结果
    plan_v1 = mgr2.dry_run()
    v1_targets = {item.filename: item.target_path for item in plan_v1.items}
    print(f"  v1 配置目标路径: {v1_targets}")

    # 用 v2 配置（不同 target_base 和 target_structure 和 action）
    config_v2 = load_config(CONFIG_V2_PATH)
    mgr_v2 = BatchManager(config_v2)
    plan_v2 = mgr_v2.dry_run()

    v2_targets = {item.filename: item.target_path for item in plan_v2.items}
    print(f"  v2 配置目标路径: {v2_targets}")

    # v2 target_base 不同，target_structure 也变了
    assert_eq(plan_v2.total, 4, "v2 配置 plan.total == 4")

    # 验证目标路径变化
    v1_path_a = v1_targets["2024-A001-001.pdf"]
    v2_path_a = v2_targets["2024-A001-001.pdf"]
    print(f"  v1 target: {v1_path_a}")
    print(f"  v2 target: {v2_path_a}")
    assert v1_path_a != v2_path_a, "配置切换后目标路径应不同"
    assert "target_v2" in v2_path_a, "v2 目标路径应包含 target_v2"
    assert "archive" in v2_path_a, "v2 目标路径应包含 archive 子目录（target_structure 变化）"

    # 验证 action_type 变化
    v2_items_by_name = {item.filename: item for item in plan_v2.items}
    assert_eq(v2_items_by_name["2024-A001-001.pdf"].action_type, "copy", "v2 配置 action_type == copy")

    # 验证 v2 目标占用情况变化（v2 的 target 是新目录，没有预占文件在 v1 target）
    assert_eq(v2_items_by_name["2024-C003-001.pdf"].target_exists, False,
              "v2 配置下原占用文件目标不存在（因为 target_base 变了）")
    assert_eq(v2_items_by_name["2024-C003-001.pdf"].will_succeed, True,
              "v2 配置下原占用文件预计成功（目标不存在）")

    # ---------- 场景 6: 队列/错误队列残留同一文件标出
    step("场景 6: 队列已有待处理记录、错误队列残留同一文件稳定标出")

    # 先执行一次 process，让一些文件进入队列和错误队列
    config3 = load_config(CONFIG_PATH)
    mgr3 = BatchManager(config3)
    result_process = mgr3.process()
    print(f"  process 结果: {json.dumps(result_process, ensure_ascii=False, indent=2)}")

    # 现在再跑 dry-run，验证队列中的文件应标记
    mgr3b = BatchManager(config3)
    plan3 = mgr3b.dry_run()
    items3_by_name = {item.filename: item for item in plan3.items}

    # 非法文件应在错误队列中
    item_illegal2 = items3_by_name.get("bad file#name.pdf")
    # 注意：process 后非法文件还在 intake 吗？不，非法文件不会被移动，因为预检失败
    # 但它的 path 还是在错误队列里
    # 等等，让我们检查一下 intake 里还有什么文件
    intake_files = os.listdir(INTAKE_DIR)
    print(f"  process 后 intake 剩余文件: {intake_files}")

    # 重新扫描 intake 中应该还有: 非法文件、目标占用文件（因为预检失败不会移动）
    assert "bad file#name.pdf" in intake_files, "process 后非法文件仍在 intake"
    assert "2024-C003-001.pdf" in intake_files, "process 后占用文件仍在 intake"

    # 现在 intake 里还有这些文件，再跑 dry-run 应该能看到它们在错误队列里
    # 但因为 process 后，这些文件在 error_queue 里
    item_illegal3 = items3_by_name["bad file#name.pdf"]
    assert_eq(item_illegal3.in_error_queue, True, "非法文件在错误队列中")
    assert_in("文件已在错误队列中", item_illegal3.warnings, "非法文件有错误队列警告")

    item_occupied3 = items3_by_name["2024-C003-001.pdf"]
    assert_eq(item_occupied3.in_error_queue, True, "占用文件在错误队列中")
    assert_eq(item_occupied3.in_processing_queue, True, "占用文件在处理队列中")

    # ---------- 场景 7: dry-run 后再 process 不污染 ----------
    step("场景 7: dry-run 后再 process，日志和批次历史未被污染")

    # 重置测试环境
    reset_test_dirs()
    write_config()

    valid_x = os.path.join(INTAKE_DIR, "2026-X001-001.pdf")
    valid_y = os.path.join(INTAKE_DIR, "2026-Y002-001.pdf")
    touch(valid_x)
    touch(valid_y)

    # 第一次: 先 dry-run
    config4 = load_config(CONFIG_PATH)
    mgr4 = BatchManager(config4)
    plan_before = mgr4.dry_run()
    assert_eq(plan_before.total, 2, "dry-run 前有 2 个文件")

    # 记录 dry-run 后 state 应该还是空的
    assert_eq(os.path.exists(BATCH_HISTORY_FILE), False, "dry-run 后 batch_history 仍不存在")

    # 第二次: 真正 process
    mgr4b = BatchManager(config4)
    result_proc = mgr4b.process()
    print(f"  process 结果: {json.dumps(result_proc, ensure_ascii=False, indent=2)}")

    assert_eq(result_proc["status"], "completed", "process 状态 completed")
    assert_eq(result_proc["total"], 2, "process total == 2")
    assert_eq(result_proc["succeeded"], 2, "process succeeded == 2")
    assert_eq(result_proc["failed"], 0, "process failed == 0")

    # 验证批次历史只有 1 条（没有被 dry-run 污染）
    history = load_json(BATCH_HISTORY_FILE)
    assert_eq(len(history), 1, "批次历史只有 1 条（dry-run 不产生批次）")
    assert_eq(history[0]["succeeded"], 2, "批次 succeeded == 2")
    assert_eq(history[0]["status"], "completed", "批次 status == completed")

    # 验证 action_log 只有 2 条（没有被 dry-run 污染）
    actions = read_jsonl(ACTION_LOG)
    assert_eq(len(actions), 2, "action_log 只有 2 条（dry-run 不产生日志）")

    # 再跑一次 dry-run，验证计划结果
    mgr4c = BatchManager(config4)
    plan_after = mgr4c.dry_run()
    print(f"  process 后 dry-run: total={plan_after.total}")

    # process 后 intake 应该空了，所以 plan.total 应该是 0
    assert_eq(plan_after.total, 0, "process 后 intake 空，plan.total == 0")

    # 验证批次历史还是只有 1 条（第二次 dry-run 也不污染）
    history2 = load_json(BATCH_HISTORY_FILE)
    assert_eq(len(history2), 1, "第二次 dry-run 后批次历史仍为 1 条")

    # ---------- 场景 8: --max-files 参数 ----------
    step("场景 8: 验证 --max-files 参数")

    # 重置
    reset_test_dirs()
    write_config()

    for i in range(1, 6):
        touch(os.path.join(INTAKE_DIR, f"2025-D{i:03d}-001.pdf"))

    config5 = load_config(CONFIG_PATH)
    mgr5 = BatchManager(config5)

    plan_full = mgr5.dry_run()
    assert_eq(plan_full.total, 5, "无 max_files 时 total == 5")

    plan_limited = mgr5.dry_run(max_files=3)
    assert_eq(plan_limited.total, 3, "max_files=3 时 total == 3")

    # CLI 验证
    PLAN_MAX_JSON = os.path.join(TEST_ROOT, "plan_max.json")
    cli_main(["-c", CONFIG_PATH, "plan", "--max-files", "2",
              "--format", "json", "--output", PLAN_MAX_JSON])
    plan_max_json = load_json(PLAN_MAX_JSON)
    assert_eq(plan_max_json["total"], 2, "CLI --max-files 2 时 total == 2")

    step("所有断言通过 ✓")
    print(f"\n证据目录保留: {TEST_ROOT}")
    print(f"关键证据文件:")
    for p in [PLAN_JSON, PLAN_CSV, BATCH_HISTORY_FILE, QUEUE_FILE, ERROR_QUEUE_FILE, ACTION_LOG]:
        if os.path.exists(p):
            print(f"  {p}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as e:
        print(f"\n断言失败: {e}")
        traceback.print_exc()
        raise SystemExit(1)
    except Exception as e:
        print(f"\n异常: {e}")
        traceback.print_exc()
        raise SystemExit(2)
