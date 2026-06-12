"""
scan-sorter 回归测试脚本

复现并验证两个实 bug 的修复：
  Bug 1: 混合批次中预检失败项不计入批次 failed 计数和状态，process 返回 completed/failed:0
  Bug 2: 预检失败项在 queue.json 中保持 queued，与 error_queue.json 不一致

使用独立的 test_run/ 目录，不清空 data/ 或 samples/。
运行方式: python test_regression.py
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
    os.path.join(os.path.dirname(__file__), "test_run")
)

INTAKE_DIR = os.path.join(TEST_ROOT, "intake")
TARGET_DIR = os.path.join(TEST_ROOT, "target")
DATA_DIR = os.path.join(TEST_ROOT, "data")
CONFIG_PATH = os.path.join(TEST_ROOT, "test_config.yaml")

ACTION_LOG = os.path.join(DATA_DIR, "action_log.jsonl")
QUEUE_FILE = os.path.join(DATA_DIR, "queue.json")
ERROR_QUEUE_FILE = os.path.join(DATA_DIR, "error_queue.json")
BATCH_HISTORY_FILE = os.path.join(DATA_DIR, "batch_history.json")

EXPORT_JSON = os.path.join(TEST_ROOT, "export_actions.json")
EXPORT_CSV = os.path.join(TEST_ROOT, "export_errors.csv")


def write_config() -> None:
    cfg = f"""intake_dir: {INTAKE_DIR}
target_base: {TARGET_DIR}
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
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        f.write(cfg)


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


def assert_status(status_value: str, expected_set: set[str], label: str) -> None:
    if status_value not in expected_set:
        raise AssertionError(
            f"[FAIL] {label}: {status_value!r} not in {expected_set}"
        )
    print(f"  [OK] {label}: {status_value!r} in {expected_set}")


def step(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def main() -> int:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from scan_sorter.batch_manager import BatchManager
    from scan_sorter.config import load_config

    reset_test_dirs()
    write_config()
    print(f"测试目录: {TEST_ROOT}")
    print(f"配置文件: {CONFIG_PATH}")

    # ---------- 场景搭建 ----------
    step("场景搭建")

    valid_a = os.path.join(INTAKE_DIR, "2024-A001-001.pdf")
    illegal = os.path.join(INTAKE_DIR, "bad file#name.pdf")
    occupied_src = os.path.join(INTAKE_DIR, "2024-B002-001.pdf")
    occupied_target_dir = os.path.join(TARGET_DIR, "2024-B002")
    occupied_target = os.path.join(occupied_target_dir, "2024-B002-001.pdf")

    touch(valid_a)
    touch(illegal)
    touch(occupied_src)
    os.makedirs(occupied_target_dir, exist_ok=True)
    touch(occupied_target)

    print(f"  intake 正常文件:     {valid_a}")
    print(f"  intake 非法命名文件: {illegal}")
    print(f"  intake 已占用目标:   {occupied_src}")
    print(f"  已预占目标文件:      {occupied_target}")

    # ---------- Step 1: 执行 process ----------
    step("Step 1: 执行 process，验证返回结果")

    config = load_config(CONFIG_PATH)
    mgr = BatchManager(config)
    result = mgr.process()

    print(f"  返回: {json.dumps(result, ensure_ascii=False, indent=4)}")

    assert_eq(result["status"], "partial_failed", "process 返回状态")
    assert_eq(result["total"], 3, "process total（应为3个扫描文件）")
    assert_eq(result["succeeded"], 1, "process succeeded（仅1个正常文件）")
    assert_eq(result["failed"], 2, "process failed（非法名+目标占用 共2个）")
    assert_eq(result["precheck_failed"], 2, "process precheck_failed（两个预检失败）")
    assert_eq(result["exec_failed"], 0, "process exec_failed（没有执行阶段失败）")

    # ---------- Step 2: 验证 batch_history.json ----------
    step("Step 2: 验证 batch_history.json")

    history = load_json(BATCH_HISTORY_FILE)
    assert_eq(len(history), 1, "批次历史条数")
    batch = history[0]

    print(f"  batch = {json.dumps(batch, ensure_ascii=False, indent=4)}")

    assert_eq(batch["total"], 3, "batch.total")
    assert_eq(batch["succeeded"], 1, "batch.succeeded")
    assert_eq(batch["failed"], 2, "batch.failed（必须包含预检失败）")
    assert_eq(batch["status"], "partial_failed", "batch.status")
    assert_eq(batch["operator"], "test_op", "batch.operator")
    assert_eq(len(batch["action_ids"]), 1, "batch.action_ids 长度")
    assert_eq(len(batch["error_file_paths"]), 2, "batch.error_file_paths 长度（两个预检失败）")

    # ---------- Step 3: 验证 queue.json 状态（Bug 2） ----------
    step("Step 3: 验证 queue.json（不应再有 queued 的失败项）")

    queue_items = load_json(QUEUE_FILE)
    print(f"  queue = {json.dumps(queue_items, ensure_ascii=False, indent=4)}")

    assert_eq(len(queue_items), 3, "queue 总条数")
    queue_by_path = {q["path"]: q for q in queue_items}

    assert_eq(queue_by_path[valid_a]["status"], "done", f"正常文件 {os.path.basename(valid_a)} 队列状态")
    assert_eq(queue_by_path[illegal]["status"], "failed", f"非法文件 {os.path.basename(illegal)} 队列状态 = failed（Bug 2 修复验证）")
    assert_eq(queue_by_path[occupied_src]["status"], "failed", f"占用文件 {os.path.basename(occupied_src)} 队列状态 = failed（Bug 2 修复验证）")

    queued_remaining = [q for q in queue_items if q["status"] == "queued"]
    assert_eq(len(queued_remaining), 0, "queue.json 中不应残留 queued 状态项")

    # ---------- Step 4: 验证 error_queue.json 与 queue.json 一致 ----------
    step("Step 4: 验证 error_queue.json 与 queue.json 一致")

    errors = load_json(ERROR_QUEUE_FILE)
    print(f"  error_queue = {json.dumps(errors, ensure_ascii=False, indent=4)}")

    assert_eq(len(errors), 2, "error_queue 条数")
    error_paths = {e["path"] for e in errors}
    queue_failed_paths = {q["path"] for q in queue_items if q["status"] == "failed"}
    assert_eq(error_paths, queue_failed_paths, "error_queue 的 path 集合必须等于 queue 中 failed 的 path 集合")

    for e in errors:
        assert_in(e["path"], [illegal, occupied_src], "error_queue 中的文件路径")

    # ---------- Step 5: 验证磁盘上文件去向 ----------
    step("Step 5: 验证磁盘上文件去向")

    valid_target = os.path.join(TARGET_DIR, "2024-A001", "2024-A001-001.pdf")
    assert_eq(os.path.exists(valid_target), True, "正常文件已移动到目标")
    assert_eq(os.path.exists(valid_a), False, "正常文件已不在 intake")
    assert_eq(os.path.exists(illegal), True, "非法文件仍留在 intake")
    assert_eq(os.path.exists(occupied_src), True, "目标占用文件仍留在 intake")

    # ---------- Step 6: 测试 retry ----------
    step("Step 6: 删除占用目标文件后重试，验证 retry 逻辑")

    os.remove(occupied_target)
    print(f"  删除预占目标文件: {occupied_target}")

    mgr2 = BatchManager(config)
    retry_result = mgr2.retry_failed()
    print(f"  retry 返回: {json.dumps(retry_result, ensure_ascii=False, indent=4)}")

    assert_eq(retry_result["status"], "done", "retry 返回状态")
    assert_eq(retry_result["retried"], 2, "retry 处理条数（非法名 + 原占用）")
    assert_eq(retry_result["succeeded"], 1, "retry succeeded（目标占用已解除）")
    assert_eq(retry_result["failed"], 1, "retry failed（非法名仍无法解析）")

    errors_after = load_json(ERROR_QUEUE_FILE)
    assert_eq(len(errors_after), 1, "retry 后 error_queue 剩 1 条（非法名）")
    assert_eq(errors_after[0]["path"], illegal, "剩余错误为非法文件")
    assert_eq(errors_after[0]["retry_count"], 1, "非法文件重试次数+1")

    occupied_final_target = os.path.join(TARGET_DIR, "2024-B002", "2024-B002-001.pdf")
    assert_eq(os.path.exists(occupied_final_target), True, "目标占用解除后文件已入库")
    assert_eq(os.path.exists(occupied_src), False, "已入库文件不在 intake")

    queue_after = load_json(QUEUE_FILE)
    queue_by_path2 = {q["path"]: q for q in queue_after}
    assert_eq(queue_by_path2[occupied_src]["status"], "done", "retry 成功的占用文件 processing_queue 标记 done")
    assert_eq(queue_by_path2[illegal]["status"], "failed", "retry 失败的非法文件 processing_queue 仍为 failed")

    # ---------- Step 7: 测试 rollback ----------
    step("Step 7: 测试 rollback —— 回滚 Step 1 的成功动作，验证队列同步更新")

    batch_id = batch["batch_id"]
    rollback_result = mgr2.rollback(batch_id)
    print(f"  rollback 返回: {json.dumps(rollback_result, ensure_ascii=False, indent=4)}")

    assert_eq(rollback_result["status"], "done", "rollback 返回状态")
    assert_eq(rollback_result["batch_id"], batch_id, "rollback batch_id")
    assert_eq(rollback_result["rolled_back_ok"], 2, "rollback 成功数量（初始成功 + retry 补救成功的同一批次动作都回滚）")
    assert_eq(rollback_result["rolled_back_fail"], 0, "rollback 失败数量")

    assert_eq(os.path.exists(valid_target), False, "回滚后 Step1 目标文件应不存在")
    assert_eq(os.path.exists(valid_a), True, "回滚后 Step1 文件回到 intake")
    assert_eq(os.path.exists(occupied_final_target), False, "回滚后 retry 补救成功的目标文件也应不存在")
    assert_eq(os.path.exists(occupied_src), True, "回滚后 retry 补救成功的文件也回到 intake")

    history_after = load_json(BATCH_HISTORY_FILE)
    rolled_back = [b for b in history_after if b["batch_id"] == batch_id][0]
    assert_eq(rolled_back["status"], "rolled_back", "批次状态变为 rolled_back")

    queue_after_rollback = load_json(QUEUE_FILE)
    queue_by_path_rb = {q["path"]: q for q in queue_after_rollback}
    assert_eq(
        queue_by_path_rb[valid_a]["status"], "rolled_back",
        "回滚后 valid_a 的队列状态 = rolled_back（不能是 done）"
    )
    assert_eq(
        queue_by_path_rb[occupied_src]["status"], "rolled_back",
        "retry 成功的占用文件属于同一批次，回滚后队列状态 = rolled_back"
    )
    assert_eq(
        queue_by_path_rb[illegal]["status"], "failed",
        "非法文件队列状态仍为 failed"
    )

    actions_after_rollback = read_jsonl(ACTION_LOG)
    step1_actions = [a for a in actions_after_rollback if a.get("batch_id") == batch_id]
    assert_eq(len(step1_actions), 2, "该批次有 2 条 action 记录（初始成功 + retry 补救成功）")
    for a in step1_actions:
        assert_eq(a["rolled_back"], True, "action_log 中该批次所有 rolled_back=True")
    step1_sources = {a["source"] for a in step1_actions}
    assert_in(valid_a, step1_sources, "action_log source 包含 valid_a")
    assert_in(occupied_src, step1_sources, "action_log source 包含 retry 补救成功的 occupied_src")

    # ---------- Step 8: 测试 JSON/CSV 导出 ----------
    step("Step 8: 测试 JSON/CSV 导出")

    from scan_sorter.cli import main as cli_main

    cli_main(["-c", CONFIG_PATH, "export", "--source", "actions",
              "--format", "json", "--output", EXPORT_JSON])
    assert_eq(os.path.exists(EXPORT_JSON), True, "actions JSON 导出文件存在")
    with open(EXPORT_JSON, "r", encoding="utf-8") as f:
        exported_actions = json.load(f)
    assert len(exported_actions) >= 2, "actions JSON 至少包含 Step1(1) + retry(1) = 2 条"
    print(f"  导出 actions JSON 条数: {len(exported_actions)}")

    cli_main(["-c", CONFIG_PATH, "export", "--source", "errors",
              "--format", "csv", "--output", EXPORT_CSV])
    assert_eq(os.path.exists(EXPORT_CSV), True, "errors CSV 导出文件存在")
    with open(EXPORT_CSV, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert_eq(len(rows), 1, "errors CSV 应为 1 行（剩余非法命名错误）")
    assert_in("path", rows[0], "CSV 含 path 列")
    assert_in("error", rows[0], "CSV 含 error 列")
    assert_in("retry_count", rows[0], "CSV 含 retry_count 列")

    # ---------- Step 9: 重启一致性验证 ----------
    step("Step 9: 重启后载入 BatchManager，验证队列一致")

    mgr3 = BatchManager(config)
    status_view = mgr3.get_error_queue()
    print(f"  重启后 error_queue = {json.dumps(status_view, ensure_ascii=False, indent=4)}")
    assert_eq(len(status_view), 1, "重启后 error_queue 仍为 1 条")

    batches_view = mgr3.list_batches()
    assert_eq(len(batches_view), 1, "重启后批次历史为 1 条")
    assert_eq(batches_view[0]["status"], "rolled_back", "重启后批次 rolled_back 状态保留")
    assert_eq(batches_view[0]["failed"], 2, "重启后批次 failed=2 保留（预检失败计入）")

    actions_view = mgr3.export_action_log()
    assert len(actions_view) >= 2, "重启后动作日志保留（step1 + retry 至少 2 条）"

    queue_view = mgr3.processing_queue.all()
    queue_statuses = {q["path"]: q["status"] for q in queue_view}
    assert_eq(
        queue_statuses[valid_a], "rolled_back",
        "重启后 processing_queue: 正常文件 rolled_back（回滚后不能是 done）"
    )
    assert_eq(
        queue_statuses[occupied_src], "rolled_back",
        "重启后 processing_queue: 占用文件 rolled_back（retry 成功归回批次，回滚时同步更新）"
    )
    assert_eq(
        queue_statuses[illegal], "failed",
        "重启后 processing_queue: 非法文件 failed"
    )

    queue_not_done_paths = {
        q["path"] for q in queue_view
        if q["status"] in ("failed", "rolled_back")
    }
    error_paths = {e["path"] for e in status_view}
    assert_eq(
        error_paths.issubset(queue_not_done_paths),
        True,
        "error_queue 中的文件在 processing_queue 中都应是非 done 状态（failed 或 rolled_back）"
    )

    step("所有断言通过 ✓")
    print(f"\n证据目录保留: {TEST_ROOT}")
    print(f"关键证据文件:")
    for p in [BATCH_HISTORY_FILE, QUEUE_FILE, ERROR_QUEUE_FILE, ACTION_LOG, EXPORT_JSON, EXPORT_CSV]:
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
