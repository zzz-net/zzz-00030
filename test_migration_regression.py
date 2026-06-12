"""
scan-sorter 配置版本迁移 回归测试脚本

流程:
  1. 初始化测试环境，使用 v1 配置 process 建立基线数据
  2. 测试场景1: 配置字段变更迁移 (intake/target 目录、operator、case_pattern)
  3. 测试场景2: 目标目录冲突检测
  4. 测试场景3: 迁移计划和结果 JSON/CSV 导出
  5. 测试场景4: 重复执行幂等性 (跨重启)
  6. 测试场景5: 迁移后 process/retry/report 输出正常

运行方式: python test_migration_regression.py
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
    os.path.join(os.path.dirname(__file__), "test_migration_run")
)

INTAKE_DIR = os.path.join(TEST_ROOT, "intake")
TARGET_DIR = os.path.join(TEST_ROOT, "target")
TARGET_DIR_V2 = os.path.join(TEST_ROOT, "target_v2")
DATA_DIR = os.path.join(TEST_ROOT, "data")
CONFIG_V1_PATH = os.path.join(TEST_ROOT, "config_v1.yaml")
CONFIG_V2_PATH = os.path.join(TEST_ROOT, "config_v2.yaml")

ACTION_LOG = os.path.join(DATA_DIR, "action_log.jsonl")
QUEUE_FILE = os.path.join(DATA_DIR, "queue.json")
ERROR_QUEUE_FILE = os.path.join(DATA_DIR, "error_queue.json")
BATCH_HISTORY_FILE = os.path.join(DATA_DIR, "batch_history.json")
MIGRATION_STATE_FILE = os.path.join(DATA_DIR, "migration_state.json")
MIGRATION_LOG_FILE = os.path.join(DATA_DIR, "migration_log.jsonl")

PLAN_JSON = os.path.join(TEST_ROOT, "migration_plan.json")
PLAN_CSV = os.path.join(TEST_ROOT, "migration_plan.csv")
RESULT_JSON = os.path.join(TEST_ROOT, "migration_result.json")
RESULT_CSV = os.path.join(TEST_ROOT, "migration_result.csv")


def write_config_v1() -> None:
    cfg = f"""intake_dir: {INTAKE_DIR}
target_base: {TARGET_DIR}
operator: operator_v1

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
    with open(CONFIG_V1_PATH, "w", encoding="utf-8") as f:
        f.write(cfg)


def write_config_v2() -> None:
    cfg = f"""intake_dir: {INTAKE_DIR}
target_base: {TARGET_DIR_V2}
operator: operator_v2

rules:
  case_number_pattern: "(\\\\d{{4}}-[A-Z]\\\\d{{3}}-\\\\d{{3}})"
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
    - pattern: "^(?!\\\\d{{4}}-[A-Z]\\\\d{{3}}-\\\\d{{3}})"
      message: "文件名必须以档案号开头"
  target_structure: "{{case_number}}"
  action: copy

batch:
  max_size: 100
  stop_on_failure_ratio: 0.3

logging:
  dir: {DATA_DIR}
  action_log: action_log.jsonl
  queue_file: queue.json
  error_queue_file: error_queue.json
  batch_history_file: batch_history.json

watch:
  poll_interval: 3
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


def create_test_files() -> None:
    test_files = [
        ("2024-A001-001.pdf", b"%PDF-1.4 test content"),
        ("2024-A001-002.pdf", b"%PDF-1.4 test content"),
        ("2024-B002-001.jpg", b"\xff\xd8\xff\xe0 test content"),
        ("bad file#name.pdf", b"%PDF-1.4 invalid name"),
    ]
    for filename, content in test_files:
        with open(os.path.join(INTAKE_DIR, filename), "wb") as f:
            f.write(content)


def run_cli(args: list[str]) -> tuple[int, str, str]:
    from scan_sorter.cli import main
    import io
    import contextlib

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
        try:
            exit_code = main(args)
        except SystemExit as e:
            exit_code = e.code if e.code is not None else 0
        except Exception as e:
            print(f"CLI 异常: {e}", file=sys.stderr)
            traceback.print_exc()
            exit_code = 2

    return exit_code, stdout_capture.getvalue(), stderr_capture.getvalue()


def assert_equal(actual, expected, desc: str) -> None:
    if actual != expected:
        raise AssertionError(f"[{desc}] 期望 {expected}, 实际 {actual}")
    print(f"  ✓ {desc}")


def assert_in(item, container, desc: str) -> None:
    if item not in container:
        raise AssertionError(f"[{desc}] 期望包含 '{item}', 实际不包含")
    print(f"  ✓ {desc}")


def test_scenario_1_config_field_migration() -> None:
    """测试场景1: 配置字段变更迁移"""
    print("\n" + "=" * 60)
    print("测试场景1: 配置字段变更迁移")
    print("=" * 60)

    reset_test_dirs()
    write_config_v1()
    write_config_v2()
    create_test_files()

    code, out, err = run_cli(["-c", CONFIG_V1_PATH, "process"])
    assert_equal(code, 0, "v1 配置 process 成功")

    with open(QUEUE_FILE, "r", encoding="utf-8") as f:
        queue_v1 = json.load(f)
    with open(BATCH_HISTORY_FILE, "r", encoding="utf-8") as f:
        batches_v1 = json.load(f)
    with open(ACTION_LOG, "r", encoding="utf-8") as f:
        actions_v1 = [json.loads(line) for line in f if line.strip()]

    assert_equal(len(actions_v1), 3, "v1 process 产生 3 条 action_log")
    assert_equal(batches_v1[0]["operator"], "operator_v1", "v1 operator 正确")
    assert_in(TARGET_DIR, actions_v1[0]["destination"], "v1 destination 使用 target_v1")

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
        "--plan-format", "json",
        "--plan-output", PLAN_JSON,
    ])
    assert_equal(code, 0, "migrate dry-run 成功")
    assert_in("配置版本迁移计划", out, "输出包含计划标题")
    assert_in("target 目录:", out, "输出包含 target 目录变更")
    assert_in("操作者:", out, "输出包含 operator 变更")
    assert_in("案卷号规则:", out, "输出包含 case_pattern 变更")
    assert_in("可自动迁移:", out, "输出包含可自动迁移计数")

    with open(PLAN_JSON, "r", encoding="utf-8") as f:
        plan_data = json.load(f)
    assert_equal(plan_data["summary"]["total_items"] > 0, True, "计划包含迁移项")
    assert_equal(plan_data["summary"]["auto_migrate"] > 0, True, "计划包含自动迁移项")

    auto_items = [i for i in plan_data["items"] if i["action"] == "auto_migrate"]
    dest_items = [i for i in auto_items if i["field_name"] == "destination" and i["item_type"] == "action_log"]
    assert_equal(len(dest_items), 3, "action_log 有 3 个 destination 待迁移")
    assert_in(TARGET_DIR_V2, dest_items[0]["new_value"], "新 destination 使用 target_v2")

    op_items = [i for i in auto_items if i["field_name"] == "operator" and i["item_type"] == "batch_history"]
    assert_equal(len(op_items) >= 1, True, "batch_history 有 operator 待迁移")
    assert_equal(op_items[0]["new_value"], "operator_v2", "新 operator 为 operator_v2")

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
        "--confirm",
        "--result-format", "json",
        "--result-output", RESULT_JSON,
    ])
    assert_equal(code, 1, "migrate 执行返回 1 (存在 manual 项)")
    assert_in("配置版本迁移", out, "输出包含执行标题")
    assert_in("自动迁移成功:", out, "输出包含成功计数")
    assert_in("需人工处理:", out, "输出包含人工处理计数")

    with open(QUEUE_FILE, "r", encoding="utf-8") as f:
        queue_v2 = json.load(f)
    with open(BATCH_HISTORY_FILE, "r", encoding="utf-8") as f:
        batches_v2 = json.load(f)
    with open(ACTION_LOG, "r", encoding="utf-8") as f:
        actions_v2 = [json.loads(line) for line in f if line.strip()]

    assert_equal(batches_v2[0]["operator"], "operator_v2", "迁移后 batch operator 更新为 v2")
    assert_in(TARGET_DIR_V2, actions_v2[0]["destination"], "迁移后 action destination 更新为 v2")

    case_items = [i for i in queue_v2 if i.get("case_number")]
    if case_items:
        case_num = case_items[0].get("case_number", "")
        assert_equal(len(case_num) == len("2024-A001-001"), True,
                     f"迁移后 case_number 格式正确: {case_num}")

    assert os.path.exists(MIGRATION_LOG_FILE), "migration_log.jsonl 已创建"
    with open(MIGRATION_LOG_FILE, "r", encoding="utf-8") as f:
        log_lines = [json.loads(line) for line in f if line.strip()]
    assert_equal(len(log_lines), 1, "migration_log 有 1 条记录")
    assert_equal(log_lines[0]["dry_run"], False, "日志标记为实际执行")
    assert_equal(log_lines[0]["old_config"], os.path.abspath(CONFIG_V1_PATH),
                 "日志记录旧配置路径")

    print("\n  ✓ 配置字段变更迁移测试通过")


def test_scenario_2_target_conflict() -> None:
    """测试场景2: 目标目录冲突检测"""
    print("\n" + "=" * 60)
    print("测试场景2: 目标目录冲突检测")
    print("=" * 60)

    reset_test_dirs()
    write_config_v1()
    write_config_v2()
    create_test_files()

    code, out, err = run_cli(["-c", CONFIG_V1_PATH, "process"])
    assert_equal(code, 0, "v1 process 成功")

    with open(ACTION_LOG, "r", encoding="utf-8") as f:
        actions_v1 = [json.loads(line) for line in f if line.strip()]
    for action in actions_v1:
        old_dest = action["destination"]
        new_dest = old_dest.replace(TARGET_DIR, TARGET_DIR_V2)
        os.makedirs(os.path.dirname(new_dest), exist_ok=True)
        with open(new_dest, "wb") as f:
            f.write(b"conflict content")

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
    ])
    assert_equal(code, 0, "migrate dry-run 成功")
    assert_in("冲突:", out, "输出包含冲突计数")

    conflict_items = [line for line in out.split("\n") if "[冲突]" in line]
    assert_equal(len(conflict_items) >= 1, True, "检测到至少 1 个冲突")
    assert_in("目标文件已存在", out, "冲突原因为目标文件已存在")

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
        "--confirm",
    ])
    assert_equal(code, 1, "migrate 执行返回 1 (存在冲突)")
    assert_in("存在冲突或需人工处理的项", out, "输出冲突警告")

    with open(ACTION_LOG, "r", encoding="utf-8") as f:
        actions_after = [json.loads(line) for line in f if line.strip()]
    conflict_destinations = [a["destination"] for a in actions_after if TARGET_DIR in a["destination"]]
    assert_equal(len(conflict_destinations) >= 1, True,
                 "冲突项未被迁移，保留旧路径")

    print("\n  ✓ 目标目录冲突检测测试通过")


def test_scenario_3_export() -> None:
    """测试场景3: 迁移计划和结果 JSON/CSV 导出"""
    print("\n" + "=" * 60)
    print("测试场景3: 迁移计划和结果导出")
    print("=" * 60)

    reset_test_dirs()
    write_config_v1()
    write_config_v2()
    create_test_files()

    code, out, err = run_cli(["-c", CONFIG_V1_PATH, "process"])
    assert_equal(code, 0, "v1 process 成功")

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
        "--plan-format", "json",
        "--plan-output", PLAN_JSON,
    ])
    assert_equal(code, 0, "migrate dry-run 导出 JSON 成功")

    assert os.path.exists(PLAN_JSON), "JSON 计划导出成功"

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
        "--plan-format", "csv",
        "--plan-output", PLAN_CSV,
    ])
    assert_equal(code, 0, "migrate dry-run 导出 CSV 成功")

    assert os.path.exists(PLAN_CSV), "CSV 计划导出成功"

    with open(PLAN_JSON, "r", encoding="utf-8") as f:
        plan_json = json.load(f)
    assert "summary" in plan_json, "JSON 包含 summary"
    assert "items" in plan_json, "JSON 包含 items"
    assert_equal(plan_json["summary"]["config_changes"]["operator"]["old"], "operator_v1",
                 "JSON 配置差异正确")
    assert_equal(plan_json["summary"]["config_changes"]["operator"]["new"], "operator_v2",
                 "JSON 配置差异正确")

    with open(PLAN_CSV, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert_equal(len(rows) > 0, True, "CSV 包含数据行")
    assert "item_type" in rows[0], "CSV 包含 item_type 列"
    assert "field_name" in rows[0], "CSV 包含 field_name 列"
    assert "old_value" in rows[0], "CSV 包含 old_value 列"
    assert "new_value" in rows[0], "CSV 包含 new_value 列"
    assert "action" in rows[0], "CSV 包含 action 列"

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
        "--confirm",
        "--result-format", "json",
        "--result-output", RESULT_JSON,
    ])

    assert os.path.exists(RESULT_JSON), "JSON 结果导出成功"

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
        "--confirm",
        "--result-format", "csv",
        "--result-output", RESULT_CSV,
    ])

    assert os.path.exists(RESULT_CSV), "CSV 结果导出成功"

    with open(RESULT_JSON, "r", encoding="utf-8") as f:
        result_json = json.load(f)
    assert "stats" in result_json, "JSON 结果包含 stats"
    assert "migrated_items" in result_json, "JSON 结果包含 migrated_items"
    assert_equal(result_json["stats"]["auto_migrated"] > 0, True,
                 "JSON 结果包含自动迁移计数")

    with open(RESULT_CSV, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    if len(rows) > 0:
        assert "migrated" in rows[0], "CSV 结果包含 migrated 列"
    else:
        print("  ✓ CSV 结果为空 (幂等性，无新迁移项)")

    print("\n  ✓ 迁移计划和结果导出测试通过")


def test_scenario_4_idempotency() -> None:
    """测试场景4: 重复执行幂等性 (跨重启)"""
    print("\n" + "=" * 60)
    print("测试场景4: 重复执行幂等性")
    print("=" * 60)

    reset_test_dirs()
    write_config_v1()
    write_config_v2()
    create_test_files()

    code, out, err = run_cli(["-c", CONFIG_V1_PATH, "process"])
    assert_equal(code, 0, "v1 process 成功")

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
        "--confirm",
    ])
    assert_equal(code, 1, "首次 migrate 执行完成")

    with open(MIGRATION_STATE_FILE, "r", encoding="utf-8") as f:
        state_1 = json.load(f)
    fingerprints_1 = set(state_1["migrated_fingerprints"])
    assert_equal(len(fingerprints_1) > 0, True, "首次迁移记录了指纹")

    with open(ACTION_LOG, "r", encoding="utf-8") as f:
        actions_after_1 = [json.loads(line) for line in f if line.strip()]
    dests_1 = [a["destination"] for a in actions_after_1]

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
    ])
    assert_equal(code, 0, "第二次 dry-run 成功")
    assert_in("已迁移跳过:", out, "输出包含已迁移跳过计数")

    with open(MIGRATION_STATE_FILE, "r", encoding="utf-8") as f:
        state_data = json.load(f)
    assert_equal(len(state_data.get('migrated_fingerprints', [])) > 0,
                 True, "状态文件中有已迁移指纹")
    print(f"  ✓ 状态文件中有 {len(state_data.get('migrated_fingerprints', []))} 个已迁移指纹")

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
        "--confirm",
    ])

    with open(MIGRATION_STATE_FILE, "r", encoding="utf-8") as f:
        state_2 = json.load(f)
    fingerprints_2 = set(state_2["migrated_fingerprints"])
    assert_equal(fingerprints_1, fingerprints_2,
                 "重复执行不新增指纹，幂等性保证")

    with open(ACTION_LOG, "r", encoding="utf-8") as f:
        actions_after_2 = [json.loads(line) for line in f if line.strip()]
    dests_2 = [a["destination"] for a in actions_after_2]
    assert_equal(dests_1, dests_2, "重复执行不修改已迁移的数据")

    with open(MIGRATION_LOG_FILE, "r", encoding="utf-8") as f:
        log_lines = [json.loads(line) for line in f if line.strip()]
    assert_equal(len(log_lines), 2, "migration_log 有 2 条记录")
    assert_equal(log_lines[1]["stats"]["auto_migrated"], 0,
                 "第二次执行自动迁移数为 0")

    del fingerprints_1
    del state_1

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
        "--confirm",
    ])

    with open(MIGRATION_STATE_FILE, "r", encoding="utf-8") as f:
        state_3 = json.load(f)
    fingerprints_3 = set(state_3["migrated_fingerprints"])
    assert_equal(fingerprints_2, fingerprints_3,
                 "跨重启后仍保持幂等")

    with open(MIGRATION_LOG_FILE, "r", encoding="utf-8") as f:
        log_lines = [json.loads(line) for line in f if line.strip()]
    assert_equal(len(log_lines), 3, "migration_log 有 3 条记录")
    assert_equal(log_lines[2]["stats"]["auto_migrated"], 0,
                 "第三次执行自动迁移数仍为 0")

    print("\n  ✓ 重复执行幂等性测试通过")


def test_scenario_5_post_migration_operations() -> None:
    """测试场景5: 迁移后 process/retry/report 输出正常"""
    print("\n" + "=" * 60)
    print("测试场景5: 迁移后 process/retry/report 输出正常")
    print("=" * 60)

    reset_test_dirs()
    write_config_v1()
    write_config_v2()
    create_test_files()

    code, out, err = run_cli(["-c", CONFIG_V1_PATH, "process"])
    assert_equal(code, 0, "v1 process 成功")

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "migrate",
        "--old-config", CONFIG_V1_PATH,
        "--confirm",
    ])

    new_test_files = [
        ("2025-C003-001.pdf", b"%PDF-1.4 new file 1"),
        ("2025-C003-002.pdf", b"%PDF-1.4 new file 2"),
    ]
    for filename, content in new_test_files:
        with open(os.path.join(INTAKE_DIR, filename), "wb") as f:
            f.write(content)

    code, out, err = run_cli(["-c", CONFIG_V2_PATH, "process"])
    assert_equal(code, 0, "迁移后 process 成功")
    assert_in("处理结果", out, "process 输出包含处理结果")
    assert_in("succeeded:", out, "process 输出包含成功计数")

    with open(ACTION_LOG, "r", encoding="utf-8") as f:
        actions_after = [json.loads(line) for line in f if line.strip()]
    new_actions = [a for a in actions_after if "2025-C003" in a["destination"]]
    assert_equal(len(new_actions), 2, "新文件产生 2 条 action_log")
    assert_in(TARGET_DIR_V2, new_actions[0]["destination"],
              "新 action 使用 v2 target 目录")
    assert_equal(new_actions[0]["operator"], "operator_v2",
                 "新 action 使用 v2 operator")
    assert_equal(new_actions[0]["action_type"], "copy",
                 "新 action 使用 v2 copy 操作")

    code, out, err = run_cli(["-c", CONFIG_V2_PATH, "retry"])
    assert_equal(code, 0, "迁移后 retry 成功")
    assert_in("重试结果", out, "retry 输出包含重试结果")

    code, out, err = run_cli([
        "-c", CONFIG_V2_PATH, "report",
        "--format", "json",
        "--output", os.path.join(TEST_ROOT, "report.json"),
    ])
    assert_equal(code in [0, 1], True, "迁移后 report 执行成功 (exit_code 0 或 1)")
    assert_in("批次复盘报告", out, "report 输出包含报告标题")
    assert_in("批次汇总", out, "report 输出包含批次汇总")

    with open(os.path.join(TEST_ROOT, "report.json"), "r", encoding="utf-8") as f:
        report_data = json.load(f)
    assert_equal(report_data["config_info"]["operator"], "operator_v2",
                 "报告显示 v2 operator")
    assert_equal(report_data["config_info"]["target_base"], TARGET_DIR_V2,
                 "报告显示 v2 target 目录")
    assert_equal(len(report_data["batches"]) >= 2, True,
                 "报告包含至少 2 个批次")

    for batch in report_data["batches"]:
        if batch["operator"] == "operator_v2":
            assert_equal(batch["operator"], "operator_v2",
                         "v2 批次 operator 正确")
        else:
            assert_equal(batch["operator"], "operator_v2",
                         "迁移后的 v1 批次 operator 已更新为 v2")

    code, out, err = run_cli(["-c", CONFIG_V2_PATH, "status"])
    assert_equal(code, 0, "迁移后 status 成功")
    assert_in("系统状态", out, "status 输出包含系统状态")
    assert_in("历史批次:", out, "status 输出包含历史批次")
    assert_in("错误队列:", out, "status 输出包含错误队列")
    assert_in("操作日志:", out, "status 输出包含操作日志")

    print("\n  ✓ 迁移后 process/retry/report 测试通过")


FP_CONFIG_V1 = os.path.join(TEST_ROOT, "fp_config_v1.yaml")
FP_CONFIG_V2 = os.path.join(TEST_ROOT, "fp_config_v2.yaml")
FP_PLAN_JSON = os.path.join(TEST_ROOT, "fp_plan.json")
FP_DATA_DIR = os.path.join(TEST_ROOT, "fp_data")
FP_INTAKE = os.path.join(TEST_ROOT, "fp_intake")
FP_TARGET = os.path.join(TEST_ROOT, "fp_target")


def write_fp_config_v1() -> None:
    cfg = f"""intake_dir: {FP_INTAKE}
target_base: {FP_TARGET}
operator: same_operator

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
  illegal_name_patterns: []
  target_structure: "{{case_number}}"
  action: move

batch:
  max_size: 50
  stop_on_failure_ratio: 0.5

logging:
  dir: {FP_DATA_DIR}
  action_log: action_log.jsonl
  queue_file: queue.json
  error_queue_file: error_queue.json
  batch_history_file: batch_history.json

watch:
  poll_interval: 5
"""
    with open(FP_CONFIG_V1, "w", encoding="utf-8") as f:
        f.write(cfg)


def write_fp_config_v2() -> None:
    cfg = f"""intake_dir: {FP_INTAKE}
target_base: {FP_TARGET}
operator: same_operator

rules:
  case_number_pattern: "(\\\\d{{4}}-[A-Z]\\\\d{{3}})"
  file_pattern: "(DOC-\\\\d{{4}}-[A-Z]\\\\d{{3}}-\\\\d{{3}})\\\\.(pdf|jpg|jpeg|png|tiff|bmp)$"
  allowed_extensions:
    - .pdf
    - .jpg
    - .jpeg
    - .png
    - .tiff
    - .bmp
  illegal_name_patterns: []
  target_structure: "{{case_number}}"
  action: move

batch:
  max_size: 50
  stop_on_failure_ratio: 0.5

logging:
  dir: {FP_DATA_DIR}
  action_log: action_log.jsonl
  queue_file: queue.json
  error_queue_file: error_queue.json
  batch_history_file: batch_history.json

watch:
  poll_interval: 5
"""
    with open(FP_CONFIG_V2, "w", encoding="utf-8") as f:
        f.write(cfg)


def test_scenario_6_file_pattern_migration() -> None:
    """测试场景6: 文件名规则变更迁移"""
    print("\n" + "=" * 60)
    print("测试场景6: 文件名规则变更迁移")
    print("=" * 60)

    reset_test_dirs()
    os.makedirs(FP_INTAKE, exist_ok=True)
    os.makedirs(FP_TARGET, exist_ok=True)
    os.makedirs(FP_DATA_DIR, exist_ok=True)
    write_fp_config_v1()
    write_fp_config_v2()

    test_files = [
        ("2024-A001-001.pdf", b"%PDF-1.4 test content"),
        ("2024-A001-002.pdf", b"%PDF-1.4 test content"),
        ("2024-B002-001.jpg", b"\xff\xd8\xff\xe0 test content"),
        ("DOC-2025-C003-001.pdf", b"%PDF-1.4 both match"),
    ]
    for filename, content in test_files:
        with open(os.path.join(FP_INTAKE, filename), "wb") as f:
            f.write(content)

    code, out, err = run_cli(["-c", FP_CONFIG_V1, "process"])
    assert_equal(code, 0, "v1 配置 process 成功")

    with open(os.path.join(FP_DATA_DIR, "action_log.jsonl"), "r", encoding="utf-8") as f:
        actions = [json.loads(line) for line in f if line.strip()]
    assert_equal(len(actions), 4, "v1 process 产生 4 条 action_log")
    action_filenames = [os.path.basename(a["source"]) for a in actions]
    assert_in("2024-A001-001.pdf", str(action_filenames), "action_log 包含 v1 合法文件")
    assert_in("DOC-2025-C003-001.pdf", str(action_filenames), "action_log 包含 DOC- 前缀文件")

    queue_data = [
        {
            "path": os.path.join(FP_INTAKE, "2024-A001-998.pdf"),
            "filename": "2024-A001-998.pdf",
            "case_number": "2024-A001",
            "size": 1024,
            "timestamp": "2024-01-01T00:00:00",
        },
        {
            "path": os.path.join(FP_INTAKE, "DOC-2025-D004-001.pdf"),
            "filename": "DOC-2025-D004-001.pdf",
            "case_number": "2025-D004",
            "size": 2048,
            "timestamp": "2024-01-01T00:00:00",
        },
    ]
    with open(os.path.join(FP_DATA_DIR, "queue.json"), "w", encoding="utf-8") as f:
        json.dump(queue_data, f, ensure_ascii=False, indent=2)

    error_data = [
        {
            "path": os.path.join(FP_INTAKE, "2024-B002-999.pdf"),
            "filename": "2024-B002-999.pdf",
            "case_number": "2024-B002",
            "error": "ERR_ILLEGAL_NAME: 模拟错误",
            "retry_count": 0,
            "max_retries": 3,
            "added_at": "2024-01-01T00:00:00",
            "last_retry_at": None,
            "batch_id": "test_batch_1",
        },
        {
            "path": os.path.join(FP_INTAKE, "DOC-2025-E005-001.jpg"),
            "filename": "DOC-2025-E005-001.jpg",
            "case_number": "2025-E005",
            "error": "ERR_COPY_FAILED: 模拟复制失败",
            "retry_count": 1,
            "max_retries": 3,
            "added_at": "2024-01-01T00:00:00",
            "last_retry_at": "2024-01-01T00:00:00",
            "batch_id": "test_batch_1",
        },
    ]
    with open(os.path.join(FP_DATA_DIR, "error_queue.json"), "w", encoding="utf-8") as f:
        json.dump(error_data, f, ensure_ascii=False, indent=2)

    code, out, err = run_cli([
        "-c", FP_CONFIG_V2, "migrate",
        "--old-config", FP_CONFIG_V1,
        "--plan-format", "json",
        "--plan-output", FP_PLAN_JSON,
    ])
    assert_equal(code, 0, "migrate dry-run 成功")
    assert_in("文件名规则:", out, "控制台输出包含 文件名规则 差异")
    assert_in("需人工处理:", out, "控制台输出包含 需人工处理 计数")

    assert os.path.exists(FP_PLAN_JSON), "迁移计划 JSON 已导出"
    with open(FP_PLAN_JSON, "r", encoding="utf-8") as f:
        plan_data = json.load(f)

    summary = plan_data["summary"]
    assert_equal(summary["total_items"] > 0, True,
                 f"计划总项数 > 0, 实际: {summary['total_items']}")
    assert_equal(summary["config_changes"]["file_pattern"]["old"]
                 != summary["config_changes"]["file_pattern"]["new"],
                 True, "配置差异中记录了 file_pattern 变更")
    assert_equal(summary["manual_required"] >= 1, True,
                 "摘要 manual_required 计数 > 0")
    assert_equal(summary["auto_migrate"] >= 1, True,
                 "摘要 auto_migrate 计数 > 0")

    items = plan_data["items"]

    queue_fp_items = [i for i in items
                      if i["item_type"] == "queue" and i["field_name"] == "file_pattern_match"]
    assert_equal(len(queue_fp_items) >= 1, True,
                 "queue 中有至少 1 个 file_pattern_match 项")
    queue_manual = [i for i in queue_fp_items if i["action"] == "manual"]
    queue_auto = [i for i in queue_fp_items if i["action"] == "auto_migrate"]
    assert_equal(len(queue_manual) >= 1, True,
                 "queue 中有至少 1 个 manual 项（旧匹配新不匹配）")
    assert_equal(len(queue_auto) >= 1, True,
                 "queue 中有至少 1 个 auto_migrate 项（旧不匹配新匹配）")

    err_fp_items = [i for i in items
                    if i["item_type"] == "error_queue" and i["field_name"] == "file_pattern_match"]
    assert_equal(len(err_fp_items) >= 1, True,
                 "error_queue 中有至少 1 个 file_pattern_match 项")

    action_fp_items = [i for i in items
                       if i["item_type"] == "action_log" and i["field_name"] == "file_pattern_match"]
    assert_equal(len(action_fp_items) >= 1, True,
                 "action_log 中有至少 1 个 file_pattern_match 项")

    all_fp_items = queue_fp_items + err_fp_items + action_fp_items
    for fp_item in all_fp_items:
        if fp_item["action"] == "manual":
            assert_equal(fp_item.get("conflict_type"), "file_pattern_mismatch",
                         f"manual 项标记 file_pattern_mismatch: {fp_item['record_id']}")
            assert_in("匹配旧规则但不匹配新规则", fp_item.get("conflict_detail", ""),
                      "manual 项有说明原因的 conflict_detail")

    if summary["manual_required"] > 0:
        assert_in("[需人工处理]", out, "控制台有 [需人工处理] 区块提示")
    if summary["auto_migrate"] > 0:
        assert_in("[可自动迁移]", out, "控制台有 [可自动迁移] 区块提示")

    print("\n  ✓ 文件名规则变更迁移测试通过")


def main() -> int:
    print("=" * 60)
    print("scan-sorter 配置版本迁移 回归测试")
    print("=" * 60)

    scenarios = [
        test_scenario_1_config_field_migration,
        test_scenario_2_target_conflict,
        test_scenario_3_export,
        test_scenario_4_idempotency,
        test_scenario_5_post_migration_operations,
        test_scenario_6_file_pattern_migration,
    ]

    passed = 0
    failed = 0
    failed_tests: list[tuple[str, str]] = []

    for scenario in scenarios:
        try:
            scenario()
            passed += 1
        except Exception as e:
            failed += 1
            tb = traceback.format_exc()
            failed_tests.append((scenario.__name__, str(e) + "\n" + tb))
            print(f"\n  ✗ {scenario.__name__} 失败: {e}")

    print("\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)
    print(f"  通过: {passed}/{len(scenarios)}")
    print(f"  失败: {failed}/{len(scenarios)}")

    if failed_tests:
        print("\n失败详情:")
        for name, error in failed_tests:
            print(f"\n  [{name}]")
            print(f"    {error}")

    if os.path.isdir(TEST_ROOT):
        shutil.rmtree(TEST_ROOT)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
