"""
scan-sorter report 子命令回归测试脚本

覆盖:
  1. 正常批次报告 - 验证成功/失败计数、目标目录、文件列表
  2. 失败队列报告 - 验证可重试项识别
  3. 导出文件内容 - JSON/CSV 导出格式和字段完整性
  4. 配置重载后读取新目录 - 配置变更后报告正确读取新路径
  5. 边界情况: 日志为空、批次不存在、文件名冲突、空队列

运行方式: python test_report_regression.py
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
    os.path.join(os.path.dirname(__file__), "test_report_run")
)

INTAKE_DIR = os.path.join(TEST_ROOT, "intake")
TARGET_DIR = os.path.join(TEST_ROOT, "target")
TARGET_V2_DIR = os.path.join(TEST_ROOT, "target_v2")
DATA_DIR = os.path.join(TEST_ROOT, "data")
CONFIG_PATH = os.path.join(TEST_ROOT, "test_config.yaml")
CONFIG_V2_PATH = os.path.join(TEST_ROOT, "test_config_v2.yaml")

ACTION_LOG = os.path.join(DATA_DIR, "action_log.jsonl")
QUEUE_FILE = os.path.join(DATA_DIR, "queue.json")
ERROR_QUEUE_FILE = os.path.join(DATA_DIR, "error_queue.json")
BATCH_HISTORY_FILE = os.path.join(DATA_DIR, "batch_history.json")
HEALTHCHECK_STATE_FILE = os.path.join(DATA_DIR, "healthcheck_state.json")

REPORT_JSON = os.path.join(TEST_ROOT, "report.json")
REPORT_CSV_BASE = os.path.join(TEST_ROOT, "report.csv")


def write_config(path: str, target_base: str = TARGET_DIR) -> None:
    cfg = f"""intake_dir: {INTAKE_DIR}
target_base: {target_base}
operator: report_test_op

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
    with open(path, "w", encoding="utf-8") as f:
        f.write(cfg)


def write_config_v2() -> None:
    os.makedirs(TARGET_V2_DIR, exist_ok=True)
    write_config(CONFIG_V2_PATH, target_base=TARGET_V2_DIR)


def reset_test_dirs() -> None:
    if os.path.isdir(TEST_ROOT):
        shutil.rmtree(TEST_ROOT)
    os.makedirs(INTAKE_DIR, exist_ok=True)
    os.makedirs(TARGET_DIR, exist_ok=True)
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


def assert_gt(actual, threshold, label: str) -> None:
    if not (actual > threshold):
        raise AssertionError(
            f"[FAIL] {label}: {actual!r} not > {threshold!r}"
        )
    print(f"  [OK] {label}: {actual!r} > {threshold!r}")


def step(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def main() -> int:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from scan_sorter.batch_manager import BatchManager
    from scan_sorter.config import load_config
    from scan_sorter.cli import main as cli_main

    reset_test_dirs()
    write_config(CONFIG_PATH)
    write_config_v2()

    # ============================================================
    # Phase 1: 正常批次处理，建立测试数据
    # ============================================================
    step("Phase 1: 场景搭建 — 创建 intake 文件并 process")

    valid_a = os.path.join(INTAKE_DIR, "2024-A001-001.pdf")
    valid_b = os.path.join(INTAKE_DIR, "2024-A001-002.pdf")
    valid_b_target_dir = os.path.join(TARGET_DIR, "2024-A001")
    valid_b_target = os.path.join(valid_b_target_dir, "2024-A001-002.pdf")
    valid_c = os.path.join(INTAKE_DIR, "2024-B002-001.pdf")
    illegal = os.path.join(INTAKE_DIR, "bad file#name.pdf")
    occupied_src = os.path.join(INTAKE_DIR, "2024-C003-001.pdf")
    occupied_target_dir = os.path.join(TARGET_DIR, "2024-C003")
    occupied_target = os.path.join(occupied_target_dir, "2024-C003-001.pdf")

    touch(valid_a)
    touch(valid_b)
    touch(valid_c)
    touch(illegal)
    touch(occupied_src)
    os.makedirs(valid_b_target_dir, exist_ok=True)
    touch(valid_b_target)
    os.makedirs(occupied_target_dir, exist_ok=True)
    touch(occupied_target)

    config = load_config(CONFIG_PATH)
    mgr = BatchManager(config)
    result = mgr.process()

    assert_eq(result["status"], "partial_failed", "process 状态")
    assert_eq(result["total"], 5, "process total")
    assert_eq(result["succeeded"], 2, "process succeeded (valid_a + valid_c)")
    assert_eq(result["failed"], 3, "process failed")

    batch_history = load_json(BATCH_HISTORY_FILE)
    batch_id_1 = batch_history[0]["batch_id"]
    print(f"  批次 ID: {batch_id_1}")

    # ============================================================
    # Phase 2: 测试 report 基本功能 - 正常批次
    # ============================================================
    step("Phase 2: report 基本功能 — 显示所有批次")

    exit_code = cli_main(["-c", CONFIG_PATH, "report"])
    assert_eq(exit_code, 1, "report 退出码应为 1 (有警告)")

    # ============================================================
    # Phase 3: 测试 --batch-id 过滤
    # ============================================================
    step("Phase 3: report --batch-id — 按批次过滤")

    exit_code = cli_main(["-c", CONFIG_PATH, "report", "--batch-id", batch_id_1])
    assert_eq(exit_code, 1, "指定有效批次 ID 退出码应为 1")

    # 测试不存在的批次
    step("Phase 3b: report --batch-id 不存在 — 错误处理")

    exit_code = cli_main(["-c", CONFIG_PATH, "report", "--batch-id", "nonexistent"])
    assert_eq(exit_code, 2, "不存在的批次 ID 退出码应为 2 (错误)")

    # ============================================================
    # Phase 4: 测试 --brief 简洁模式
    # ============================================================
    step("Phase 4: report --brief — 简洁模式")

    exit_code = cli_main(["-c", CONFIG_PATH, "report", "--brief"])
    assert_eq(exit_code, 1, "简洁模式退出码")

    # ============================================================
    # Phase 5: 测试 JSON 导出
    # ============================================================
    step("Phase 5: report JSON 导出 — 验证导出文件内容")

    exit_code = cli_main([
        "-c", CONFIG_PATH, "report", "--format", "json", "--output", REPORT_JSON
    ])
    assert_eq(exit_code, 1, "JSON 导出退出码")
    assert_eq(os.path.exists(REPORT_JSON), True, "JSON 文件存在")

    report_data = load_json(REPORT_JSON)
    assert_in("batches", report_data, "JSON 含 batches 字段")
    assert_in("conflicts", report_data, "JSON 含 conflicts 字段")
    assert_in("retryable_items", report_data, "JSON 含 retryable_items 字段")
    assert_in("healthcheck_summary", report_data, "JSON 含 healthcheck_summary 字段")
    assert_in("config_info", report_data, "JSON 含 config_info 字段")
    assert_in("warnings", report_data, "JSON 含 warnings 字段")
    assert_in("errors", report_data, "JSON 含 errors 字段")
    assert_in("generated_at", report_data, "JSON 含 generated_at 字段")

    assert_gt(len(report_data["batches"]), 0, "JSON 批次列表非空")
    batch = report_data["batches"][0]
    assert_in("batch_id", batch, "批次含 batch_id")
    assert_in("status", batch, "批次含 status")
    assert_in("succeeded", batch, "批次含 succeeded")
    assert_in("failed", batch, "批次含 failed")
    assert_in("target_dirs", batch, "批次含 target_dirs")
    assert_in("success_files", batch, "批次含 success_files")
    assert_in("failed_files", batch, "批次含 failed_files")

    assert_eq(batch["batch_id"], batch_id_1, "批次 ID 匹配")
    assert_eq(batch["status"], "partial_failed", "批次状态正确")
    assert_eq(batch["succeeded"], 2, "批次成功数正确")
    assert_eq(batch["failed"], 3, "批次失败数正确")

    # 验证成功文件
    success_filenames = [f["filename"] for f in batch["success_files"]]
    assert_in("2024-A001-001.pdf", success_filenames, "成功文件包含 valid_a")
    assert_in("2024-B002-001.pdf", success_filenames, "成功文件包含 valid_c")

    # 验证失败文件
    failed_filenames = [f["filename"] for f in batch["failed_files"]]
    assert_in("2024-A001-002.pdf", failed_filenames, "失败文件包含 valid_b (目标冲突)")
    assert_in("bad file#name.pdf", failed_filenames, "失败文件包含 illegal")
    assert_in("2024-C003-001.pdf", failed_filenames, "失败文件包含 occupied_src")

    # 验证冲突检测
    assert_gt(len(report_data["conflicts"]), 0, "应检测到文件名冲突")
    conflict_filenames = [c["filename"] for c in report_data["conflicts"]]
    assert_in("2024-A001-002.pdf", conflict_filenames, "冲突包含 valid_b")
    assert_in("2024-C003-001.pdf", conflict_filenames, "冲突包含 occupied_src")

    # 验证可重试项
    assert_gt(len(report_data["retryable_items"]), 0, "应有可重试项")
    retryable_filenames = [r["filename"] for r in report_data["retryable_items"]]
    assert_in("bad file#name.pdf", retryable_filenames, "可重试项包含 illegal")

    # 验证配置信息
    assert_in("intake_dir", report_data["config_info"], "配置含 intake_dir")
    assert_in("target_base", report_data["config_info"], "配置含 target_base")
    assert_in("operator", report_data["config_info"], "配置含 operator")

    # ============================================================
    # Phase 6: 测试 CSV 导出
    # ============================================================
    step("Phase 6: report CSV 导出 — 验证多个 CSV 文件")

    exit_code = cli_main([
        "-c", CONFIG_PATH, "report", "--format", "csv", "--output", REPORT_CSV_BASE
    ])
    assert_eq(exit_code, 1, "CSV 导出退出码")

    expected_csv_files = [
        f"{os.path.splitext(REPORT_CSV_BASE)[0]}_batches.csv",
        f"{os.path.splitext(REPORT_CSV_BASE)[0]}_conflicts.csv",
        f"{os.path.splitext(REPORT_CSV_BASE)[0]}_retryable.csv",
        f"{os.path.splitext(REPORT_CSV_BASE)[0]}_summary.csv",
    ]

    for csv_path in expected_csv_files:
        assert_eq(os.path.exists(csv_path), True, f"CSV 文件存在: {csv_path}")

    # 验证 batches CSV
    with open(expected_csv_files[0], "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert_gt(len(rows), 0, "batches CSV 非空")
    assert_in("batch_id", rows[0], "batches CSV 含 batch_id 列")
    assert_in("succeeded", rows[0], "batches CSV 含 succeeded 列")
    assert_in("failed", rows[0], "batches CSV 含 failed 列")
    assert_eq(rows[0]["batch_id"], batch_id_1, "batches CSV 批次 ID 正确")

    # 验证 conflicts CSV
    with open(expected_csv_files[1], "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert_gt(len(rows), 0, "conflicts CSV 非空")
    assert_in("filename", rows[0], "conflicts CSV 含 filename 列")
    assert_in("intake_path", rows[0], "conflicts CSV 含 intake_path 列")
    assert_in("target_path", rows[0], "conflicts CSV 含 target_path 列")

    # 验证 retryable CSV
    with open(expected_csv_files[2], "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert_gt(len(rows), 0, "retryable CSV 非空")
    assert_in("filename", rows[0], "retryable CSV 含 filename 列")
    assert_in("error", rows[0], "retryable CSV 含 error 列")
    assert_in("retry_count", rows[0], "retryable CSV 含 retry_count 列")

    # 验证 summary CSV
    with open(expected_csv_files[3], "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert_gt(len(rows), 0, "summary CSV 非空")
    assert_in("item", rows[0], "summary CSV 含 item 列")
    assert_in("value", rows[0], "summary CSV 含 value 列")

    summary_items = {row["item"]: row["value"] for row in rows}
    assert_in("批次总数", summary_items, "summary 含批次总数")
    assert_in("冲突文件数", summary_items, "summary 含冲突文件数")
    assert_in("可重试项数", summary_items, "summary 含可重试项数")

    # ============================================================
    # Phase 7: 验证 retry 后报告更新
    # ============================================================
    step("Phase 7: retry 后报告 — 验证可重试项更新")

    # 解除占用后重试
    os.remove(occupied_target)
    os.remove(valid_b_target)
    mgr2 = BatchManager(config)
    retry_result = mgr2.retry_failed()
    assert_eq(retry_result["succeeded"], 2, "retry 成功数 (occupied + valid_b)")
    assert_eq(retry_result["failed"], 1, "retry 失败数 (illegal)")

    after_retry_json = os.path.join(TEST_ROOT, "after_retry.json")
    cli_main([
        "-c", CONFIG_PATH, "report", "--format", "json", "--output", after_retry_json
    ])

    after_retry = load_json(after_retry_json)
    retryable = after_retry["retryable_items"]
    assert_eq(len(retryable), 1, "retry 后应只剩 1 个可重试项 (illegal)")
    assert_eq(retryable[0]["filename"], "bad file#name.pdf", "可重试项为非法文件")
    assert_eq(retryable[0]["retry_count"], 1, "重试次数已更新为 1")

    # ============================================================
    # Phase 8: 配置重载后读取新目录
    # ============================================================
    step("Phase 8: 配置重载 — 修改 target_base 后报告正确读取")

    # 先在 v2 配置下做一次 process
    valid_v2 = os.path.join(INTAKE_DIR, "2024-D004-001.pdf")
    touch(valid_v2)

    config_v2 = load_config(CONFIG_V2_PATH)
    mgr_v2 = BatchManager(config_v2)
    result_v2 = mgr_v2.process()

    batch_history_v2 = load_json(BATCH_HISTORY_FILE)
    batch_id_2 = batch_history_v2[-1]["batch_id"]
    print(f"  第二批 ID (v2 配置): {batch_id_2}")

    # 用 v2 配置生成报告，验证 target_base 是新路径
    report_v2_json = os.path.join(TEST_ROOT, "report_v2.json")
    exit_code = cli_main([
        "-c", CONFIG_V2_PATH, "report", "--batch-id", batch_id_2,
        "--format", "json", "--output", report_v2_json
    ])
    assert_eq(os.path.exists(report_v2_json), True, "v2 报告 JSON 存在")

    report_v2_data = load_json(report_v2_json)
    assert_eq(
        report_v2_data["config_info"]["target_base"],
        os.path.abspath(TARGET_V2_DIR),
        "v2 配置 target_base 正确"
    )
    assert_eq(
        report_v2_data["config_info"]["intake_dir"],
        os.path.abspath(INTAKE_DIR),
        "v2 配置 intake_dir 正确"
    )

    # 验证第二批的 target_dirs 使用 v2 路径
    batch_2 = report_v2_data["batches"][0]
    for td in batch_2["target_dirs"]:
        assert TARGET_V2_DIR in td, f"第二批目标目录应使用 v2 路径: {td}"

    # ============================================================
    # Phase 9: 边界情况 - 空日志/空队列
    # ============================================================
    step("Phase 9: 边界情况 — 空数据目录")

    empty_data_dir = os.path.join(TEST_ROOT, "empty_data")
    os.makedirs(empty_data_dir, exist_ok=True)

    empty_config_path = os.path.join(TEST_ROOT, "empty_config.yaml")
    empty_cfg = f"""intake_dir: {INTAKE_DIR}
target_base: {TARGET_DIR}
operator: empty_test

rules:
  case_number_pattern: "(\\\\d{{4}}-[A-Z]\\\\d{{3}})"
  file_pattern: "(\\\\d{{4}}-[A-Z]\\\\d{{3}}-\\\\d{{3}})\\\\.(pdf|jpg|jpeg|png|tiff|bmp)$"
  allowed_extensions: [".pdf"]
  illegal_name_patterns: []
  target_structure: "{{case_number}}"
  action: move

batch:
  max_size: 50
  stop_on_failure_ratio: 0.5

logging:
  dir: {empty_data_dir}
  action_log: action_log.jsonl
  queue_file: queue.json
  error_queue_file: error_queue.json
  batch_history_file: batch_history.json

watch:
  poll_interval: 5
"""
    with open(empty_config_path, "w", encoding="utf-8") as f:
        f.write(empty_cfg)

    empty_report_json = os.path.join(TEST_ROOT, "empty_report.json")
    exit_code = cli_main([
        "-c", empty_config_path, "report",
        "--format", "json", "--output", empty_report_json
    ])
    assert_eq(exit_code, 1, "空数据目录退出码应为 1 (警告)")

    empty_report = load_json(empty_report_json)
    assert_eq(len(empty_report["batches"]), 0, "空数据批次列表为空")
    assert_eq(len(empty_report["conflicts"]), 0, "空数据冲突列表为空")
    assert_eq(len(empty_report["retryable_items"]), 0, "空数据可重试项为空")
    assert_gt(len(empty_report["warnings"]), 0, "空数据应有警告")

    # ============================================================
    # Phase 10: 边界情况 - healthcheck 摘要
    # ============================================================
    step("Phase 10: healthcheck 摘要 — 先运行 healthcheck 再 report")

    cli_main(["-c", CONFIG_PATH, "healthcheck"])

    hc_report_json = os.path.join(TEST_ROOT, "hc_report.json")
    cli_main([
        "-c", CONFIG_PATH, "report", "--format", "json", "--output", hc_report_json
    ])

    hc_report = load_json(hc_report_json)
    hc_summary = hc_report["healthcheck_summary"]
    assert_in("last_check_time", hc_summary, "healthcheck 摘要含上次检查时间")
    assert_in("total_findings", hc_summary, "healthcheck 摘要含问题总数")
    assert hc_summary["last_check_time"] is not None, "healthcheck 上次检查时间非空"

    # ============================================================
    # Phase 11: 测试报告显示文件名冲突
    # ============================================================
    step("Phase 11: 文件名冲突 — 手动创建冲突并验证报告")

    conflict_file = os.path.join(INTAKE_DIR, "2024-E005-001.pdf")
    conflict_target_dir = os.path.join(TARGET_DIR, "2024-E005")
    conflict_target = os.path.join(conflict_target_dir, "2024-E005-001.pdf")
    touch(conflict_file)
    os.makedirs(conflict_target_dir, exist_ok=True)
    touch(conflict_target)

    conflict_report_json = os.path.join(TEST_ROOT, "conflict_report.json")
    cli_main([
        "-c", CONFIG_PATH, "report", "--format", "json", "--output", conflict_report_json
    ])

    conflict_report = load_json(conflict_report_json)
    conflict_filenames = [c["filename"] for c in conflict_report["conflicts"]]
    assert_in("2024-E005-001.pdf", conflict_filenames, "检测到新的文件名冲突")

    # ============================================================
    # Phase 12: 测试 --batch-id 与导出功能结合
    # ============================================================
    step("Phase 12: --batch-id + 导出 — 仅导出指定批次数据")

    filtered_json = os.path.join(TEST_ROOT, "filtered_report.json")
    cli_main([
        "-c", CONFIG_PATH, "report", "--batch-id", batch_id_1,
        "--format", "json", "--output", filtered_json
    ])

    filtered = load_json(filtered_json)
    assert_eq(len(filtered["batches"]), 1, "过滤后应只有 1 个批次")
    assert_eq(filtered["batches"][0]["batch_id"], batch_id_1, "过滤批次 ID 正确")

    step("所有断言通过 ✓")
    print(f"\n证据目录保留: {TEST_ROOT}")
    print(f"关键证据文件:")
    for p in [
        BATCH_HISTORY_FILE, QUEUE_FILE, ERROR_QUEUE_FILE,
        ACTION_LOG, HEALTHCHECK_STATE_FILE,
        REPORT_JSON, REPORT_CSV_BASE,
    ]:
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
