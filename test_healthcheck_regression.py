"""
scan-sorter 状态体检与恢复 回归测试脚本

流程:
  1. 正常 process/retry/rollback 建立基线
  2. 手工制造冲突和配置变更
  3. 运行 healthcheck 发现问题
  4. 导出 JSON/CSV
  5. heal dry-run (通过 CLI)
  6. heal --confirm (通过 CLI)
  7. 再次 healthcheck 验证修复后 queue/error_queue/体检一致
  8. 跨重启验证 fingerprint 持久性
  9. 验证 status / export 在修复后一致
  10. heal_log.jsonl 条数 == CLI heal 调用次数
  11. 配置偏移场景
  12. failed-without-error_queue 专项: 手动把 queue 改 failed 但不补 error_queue,
     然后 CLI heal --confirm, 再 healthcheck, 验证不再新增不一致

运行方式: python test_healthcheck_regression.py
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
    os.path.join(os.path.dirname(__file__), "test_hc_run")
)

INTAKE_DIR = os.path.join(TEST_ROOT, "intake")
TARGET_DIR = os.path.join(TEST_ROOT, "target")
DATA_DIR = os.path.join(TEST_ROOT, "data")
CONFIG_PATH = os.path.join(TEST_ROOT, "test_config.yaml")
CONFIG_V2_PATH = os.path.join(TEST_ROOT, "test_config_v2.yaml")

ACTION_LOG = os.path.join(DATA_DIR, "action_log.jsonl")
QUEUE_FILE = os.path.join(DATA_DIR, "queue.json")
ERROR_QUEUE_FILE = os.path.join(DATA_DIR, "error_queue.json")
BATCH_HISTORY_FILE = os.path.join(DATA_DIR, "batch_history.json")
HEALTHCHECK_STATE_FILE = os.path.join(DATA_DIR, "healthcheck_state.json")
HEAL_LOG_FILE = os.path.join(DATA_DIR, "heal_log.jsonl")

HC_JSON = os.path.join(TEST_ROOT, "healthcheck.json")
HC_CSV = os.path.join(TEST_ROOT, "healthcheck.csv")


def write_config(path: str, target_base: str = TARGET_DIR) -> None:
    cfg = f"""intake_dir: {INTAKE_DIR}
target_base: {target_base}
operator: hc_test_op

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
    alt_target = os.path.join(TEST_ROOT, "target_v2")
    os.makedirs(alt_target, exist_ok=True)
    write_config(CONFIG_V2_PATH, target_base=alt_target)


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


def save_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


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
            f"[FAIL] {label}: {member!r} not in container"
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
    from scan_sorter.healthcheck import (
        FindingCategory,
        HealthChecker,
        Severity,
    )
    from scan_sorter.models import ActionRecord, ActionType

    reset_test_dirs()
    write_config(CONFIG_PATH)
    write_config_v2()

    # ============================================================
    # Phase 1: 正常 process / retry / rollback 建立基线
    # ============================================================
    step("Phase 1a: 场景搭建 — 创建 intake 文件")

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

    step("Phase 1b: process — 建立基线状态")

    config = load_config(CONFIG_PATH)
    mgr = BatchManager(config)
    result = mgr.process()
    assert_eq(result["status"], "partial_failed", "process 状态")
    assert_eq(result["succeeded"], 1, "process succeeded")
    assert_eq(result["failed"], 2, "process failed")

    batch_history = load_json(BATCH_HISTORY_FILE)
    batch_id = batch_history[0]["batch_id"]

    step("Phase 1c: retry — 清除目标占用后重试")

    os.remove(occupied_target)
    mgr2 = BatchManager(config)
    retry_result = mgr2.retry_failed()
    assert_eq(retry_result["succeeded"], 1, "retry succeeded (占用解除)")
    assert_eq(retry_result["failed"], 1, "retry failed (非法名)")

    step("Phase 1d: rollback — 回滚第一批")

    rollback_result = mgr2.rollback(batch_id)
    assert_eq(rollback_result["status"], "done", "rollback 状态")
    assert_eq(rollback_result["rolled_back_ok"], 2, "rollback 成功（初始成功 + retry 补救成功的同一批次动作都回滚）")

    step("Phase 1e: 基线 healthcheck — 正常状态应无严重问题")

    checker = HealthChecker(config)
    findings = checker.check()
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    print(f"  基线体检: {len(findings)} 个问题, {len(critical)} 个严重")

    # ============================================================
    # Phase 2: 手工制造冲突
    # ============================================================
    step("Phase 2a: 冲突1 — 将已 done 文件复制回 intake (模拟移动失败但队列误标 done)")

    done_file_in_target = os.path.join(TARGET_DIR, "2024-B002", "2024-B002-001.pdf")
    mgr_reset = BatchManager(config)
    mgr_reset.processing_queue.mark_done(occupied_src)
    os.makedirs(os.path.dirname(done_file_in_target), exist_ok=True)
    shutil.copy2(occupied_src, done_file_in_target)
    print(f"  手动: occupied_src 队列 -> done, 并复制到 target: {done_file_in_target}")
    assert_eq(os.path.exists(done_file_in_target), True, "target 上应有 2024-B002-001.pdf 副本")

    mgr_reset.action_logger.log(ActionRecord(
        source=occupied_src,
        destination=done_file_in_target,
        action_type=ActionType.MOVE,
        operator="hc_test_op",
        case_number="2024-B002",
    ))
    print(f"  手动: 写入 action_log 记录（不 rolled_back，destination 在 target 下）")

    step("Phase 2b: 冲突2 — 添加一个 done 条目但目标文件不存在")

    extra_file = os.path.join(INTAKE_DIR, "2024-C003-001.pdf")
    touch(extra_file)
    mgr_extra = BatchManager(config)
    mgr_extra.processing_queue.enqueue(extra_file, "2024-C003", filename="2024-C003-001.pdf")
    mgr_extra.processing_queue.mark_done(extra_file)
    c003_target_dir = os.path.join(TARGET_DIR, "2024-C003")
    os.makedirs(c003_target_dir, exist_ok=True)
    c003_target = os.path.join(c003_target_dir, "2024-C003-001.pdf")
    mgr_extra.action_logger.log(ActionRecord(
        source=extra_file,
        destination=c003_target,
        action_type=ActionType.MOVE,
        operator="hc_test_op",
        case_number="2024-C003",
    ))
    os.remove(extra_file)
    print(f"  添加 done 条目(无目标): {extra_file} -> {c003_target}")

    step("Phase 2c: 冲突3 — 在 error_queue 中添加磁盘不存在的文件")

    from scan_sorter.models import ErrorItem
    ghost_path = os.path.join(INTAKE_DIR, "2024-G999-001.pdf")
    mgr3 = BatchManager(config)
    mgr3.error_queue.add(ErrorItem(
        path=ghost_path,
        filename="2024-G999-001.pdf",
        case_number="2024-G999",
        error="幽灵条目",
        retry_count=0,
    ))
    assert_eq(
        os.path.exists(ghost_path), False,
        "幽灵文件不在磁盘"
    )
    print(f"  error_queue 添加幽灵条目: {ghost_path}")

    step("Phase 2d: 冲突4 — 将 processing_queue 中 done 状态文件也放入 error_queue (队列不一致)")

    eq_items = mgr3.error_queue.all()
    pq_items = mgr3.processing_queue.all()
    occupied_src_item = [q for q in pq_items if q["path"] == occupied_src]
    if occupied_src_item and occupied_src_item[0].get("status") == "done":
        mgr3.error_queue.add(ErrorItem(
            path=occupied_src,
            filename="2024-B002-001.pdf",
            case_number="2024-B002",
            error="残留error_queue条目",
            retry_count=0,
        ))
        print(f"  error_queue 添加 done 文件条目: {occupied_src}")

    step("Phase 2e: 冲突5 — 修改配置 target_base 造成配置偏移")

    config_v2 = load_config(CONFIG_V2_PATH)
    checker_v2 = HealthChecker(config_v2)
    drift_findings = checker_v2.check()
    drift_items = [f for f in drift_findings if f.category == FindingCategory.CONFIG_DRIFT]
    print(f"  新配置下体检发现 CONFIG_DRIFT: {len(drift_items)} 个")

    # ============================================================
    # Phase 3: healthcheck 发现所有冲突
    # ============================================================
    step("Phase 3: healthcheck — 用原配置检查所有冲突")

    checker = HealthChecker(config)
    findings = checker.check()
    categories = {f.category for f in findings}
    print(f"  发现问题总数: {len(findings)}")
    print(f"  问题类别: {[c.value for c in categories]}")

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    warning = [f for f in findings if f.severity == Severity.WARNING]
    fixable = [f for f in findings if f.fixable]
    print(f"  严重: {len(critical)}, 警告: {len(warning)}, 可修复: {len(fixable)}")

    assert_gt(len(findings), 0, "应发现至少1个问题")
    assert_in(FindingCategory.QUEUE_FILE_MISMATCH, categories, "应发现队列文件不一致")
    assert_in(FindingCategory.QUEUE_STALE_DONE, categories, "应发现目标被删的done条目")
    assert_in(FindingCategory.ERROR_QUEUE_STALE, categories, "应发现幽灵error_queue条目")

    # ============================================================
    # Phase 4: 导出 JSON / CSV
    # ============================================================
    step("Phase 4a: 导出 healthcheck JSON")

    from scan_sorter.cli import main as cli_main
    cli_main(["-c", CONFIG_PATH, "healthcheck", "--format", "json", "--output", HC_JSON])
    assert_eq(os.path.exists(HC_JSON), True, "healthcheck JSON 文件存在")
    hc_json_data = load_json(HC_JSON)
    assert_gt(len(hc_json_data), 0, "JSON 至少有1条记录")
    first = hc_json_data[0]
    for field in ["fingerprint", "category", "severity", "description", "fixable"]:
        assert_in(field, first, f"JSON 记录含 {field} 字段")
    print(f"  JSON 导出 {len(hc_json_data)} 条")

    step("Phase 4b: 导出 healthcheck CSV")

    cli_main(["-c", CONFIG_PATH, "healthcheck", "--format", "csv", "--output", HC_CSV])
    assert_eq(os.path.exists(HC_CSV), True, "healthcheck CSV 文件存在")
    with open(HC_CSV, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert_gt(len(rows), 0, "CSV 至少有1行")
    assert_in("fingerprint", rows[0], "CSV 含 fingerprint 列")
    assert_in("category", rows[0], "CSV 含 category 列")
    assert_in("severity", rows[0], "CSV 含 severity 列")
    print(f"  CSV 导出 {len(rows)} 行")

    # ============================================================
    # Phase 5: heal dry-run (通过 CLI)
    # ============================================================
    step("Phase 5: heal dry-run (CLI) — 预览修复但不实际写入")

    fingerprints_before = {f.fingerprint for f in findings}
    cli_main(["-c", CONFIG_PATH, "heal"])

    queue_after_dry = load_json(QUEUE_FILE)
    queue_statuses = {q["path"]: q["status"] for q in queue_after_dry}
    occupied_in_queue = queue_statuses.get(occupied_src, "")
    assert_eq(occupied_in_queue, "done", "dry-run 不应修改队列状态")

    error_queue_after_dry = load_json(ERROR_QUEUE_FILE)
    eq_paths_after_dry = [e["path"] for e in error_queue_after_dry]
    assert_eq(
        ghost_path in eq_paths_after_dry, True,
        "dry-run 不应删除 error_queue 条目"
    )
    print(f"  dry-run 验证通过: 状态文件未变更")

    # ============================================================
    # Phase 6: heal --confirm (通过 CLI)
    # ============================================================
    step("Phase 6: heal --confirm (CLI) — 实际修复可修复项")

    cli_main(["-c", CONFIG_PATH, "heal", "--confirm"])

    # ============================================================
    # Phase 7: 再次 healthcheck 验证修复效果
    # ============================================================
    step("Phase 7: 修复后 healthcheck — 验证可修复项已消除, 无新增不一致")

    checker_after = HealthChecker(config)
    findings_after = checker_after.check()
    fixable_after = [f for f in findings_after if f.fixable]
    print(f"  修复后问题: {len(findings_after)}, 可修复: {len(fixable_after)}")

    fingerprints_after = {f.fingerprint for f in findings_after}
    resolved = fingerprints_before - fingerprints_after
    new_issues = fingerprints_after - fingerprints_before
    print(f"  已解决: {len(resolved)} 个, 新增: {len(new_issues)} 个")

    for f in findings_after:
        print(f"    [{f.severity.value}] [{f.category.value}] {f.description}")

    eq_data = load_json(ERROR_QUEUE_FILE)
    eq_paths = [e["path"] for e in eq_data]

    assert_eq(
        ghost_path in eq_paths, False,
        "幽灵文件应已从 error_queue 清除"
    )

    pq_data = load_json(QUEUE_FILE)
    done_paths_in_eq = []
    for e in eq_data:
        for q in pq_data:
            if q["path"] == e["path"] and q["status"] == "done":
                done_paths_in_eq.append(e["path"])
    assert_eq(len(done_paths_in_eq), 0, "不应有 done 状态文件残留在 error_queue")

    failed_not_in_eq = []
    for q in pq_data:
        if q.get("status") == "failed":
            if q["path"] not in eq_paths:
                failed_not_in_eq.append(q["path"])
    assert_eq(
        len(failed_not_in_eq), 0,
        f"heal 后不应有 failed 队列项缺失 error_queue: {failed_not_in_eq}"
    )

    inconsistency_after = [
        f for f in findings_after
        if f.category == FindingCategory.ERROR_QUEUE_INCONSISTENCY
    ]
    assert_eq(
        len(inconsistency_after), 0,
        f"heal 后不应新增 error_queue_inconsistency: {[f.description for f in inconsistency_after]}"
    )

    # ============================================================
    # Phase 8: 跨重启验证 fingerprint 持久性
    # ============================================================
    step("Phase 8: 跨重启 — 重新加载配置后识别同一批遗留问题")

    config_reload = load_config(CONFIG_PATH)
    checker_reload = HealthChecker(config_reload)
    findings_reload = checker_reload.check()

    fingerprints_reload = {f.fingerprint for f in findings_reload}
    overlap = fingerprints_after & fingerprints_reload
    print(f"  重载后问题: {len(findings_reload)}, 与修复后重叠: {len(overlap)}")

    assert_eq(
        fingerprints_after == fingerprints_reload,
        True,
        "跨重启 fingerprint 应保持一致"
    )

    state_data = load_json(HEALTHCHECK_STATE_FILE)
    assert_in("last_check_time", state_data, "state 文件含 last_check_time")
    assert_in("finding_fingerprints", state_data, "state 文件含 finding_fingerprints")
    assert_in("heal_logs", state_data, "state 文件含 heal_logs")

    heal_logs = state_data.get("heal_logs", [])
    assert_gt(len(heal_logs), 0, "state 文件应有 heal 操作日志")
    for hl in heal_logs:
        assert_in("dry_run", hl, "heal 日志含 dry_run 标记")
        assert_in("actions", hl, "heal 日志含 actions 列表")
        print(f"  heal 日志: dry_run={hl['dry_run']}, actions={len(hl['actions'])}")

    # ============================================================
    # Phase 9: 验证 status / export 在修复后一致
    # ============================================================
    step("Phase 9a: 修复后 status 验证")

    mgr_final = BatchManager(config)
    errors_final = mgr_final.get_error_queue()
    batches_final = mgr_final.list_batches()
    queue_final = mgr_final.processing_queue.all()

    print(f"  error_queue: {len(errors_final)} 条")
    print(f"  batch_history: {len(batches_final)} 条")
    print(f"  processing_queue: {len(queue_final)} 条")

    for e in errors_final:
        q_match = [q for q in queue_final if q["path"] == e["path"]]
        if q_match:
            q_status = q_match[0].get("status", "")
            assert_eq(
                q_status in ("failed", "rolled_back"),
                True,
                f"error_queue 中 {os.path.basename(e['path'])} 的队列状态应为 failed/rolled_back, 实际={q_status}",
            )

    step("Phase 9b: 修复后 export 验证")

    export_json = os.path.join(TEST_ROOT, "final_actions.json")
    export_csv = os.path.join(TEST_ROOT, "final_errors.csv")
    cli_main(["-c", CONFIG_PATH, "export", "--source", "actions", "--format", "json", "--output", export_json])
    cli_main(["-c", CONFIG_PATH, "export", "--source", "errors", "--format", "csv", "--output", export_csv])

    assert_eq(os.path.exists(export_json), True, "修复后 actions JSON 导出成功")
    assert_eq(os.path.exists(export_csv), True, "修复后 errors CSV 导出成功")

    with open(export_json, "r", encoding="utf-8") as f:
        exported_actions = json.load(f)
    assert_gt(len(exported_actions), 0, "修复后仍有 action 记录")

    with open(export_csv, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    for row in rows:
        assert_in("path", row, "CSV 含 path")
        assert_in("error", row, "CSV 含 error")

    # ============================================================
    # Phase 10: heal_log.jsonl 条数 == CLI heal 调用次数
    # ============================================================
    step("Phase 10: heal_log.jsonl — 条数应等于 CLI heal 调用次数")

    heal_log_records = read_jsonl(HEAL_LOG_FILE)
    cli_heal_calls = 2
    assert_eq(
        len(heal_log_records), cli_heal_calls,
        f"heal_log.jsonl 条数应等于 CLI heal 调用次数 ({cli_heal_calls})"
    )

    for i, rec in enumerate(heal_log_records):
        assert_in("dry_run", rec, f"heal 日志[{i}] 含 dry_run")
        assert_in("actions", rec, f"heal 日志[{i}] 含 actions")
        assert_in("applied_count", rec, f"heal 日志[{i}] 含 applied_count")
        assert_in("skipped_count", rec, f"heal 日志[{i}] 含 skipped_count")
        for a in rec["actions"]:
            assert_in("fingerprint", a, "heal action 含 fingerprint")
            assert_in("applied", a, "heal action 含 applied")
            assert_in("reason", a, "heal action 含 reason")
    print(f"  heal_log.jsonl: {len(heal_log_records)} 条 (CLI 调用 {cli_heal_calls} 次)")

    dry_run_rec = [r for r in heal_log_records if r["dry_run"]]
    confirm_rec = [r for r in heal_log_records if not r["dry_run"]]
    assert_eq(len(dry_run_rec), 1, "应有1条 dry-run 日志")
    assert_eq(len(confirm_rec), 1, "应有1条 confirm 日志")

    # ============================================================
    # Phase 11: 配置偏移场景独立验证
    # ============================================================
    step("Phase 11: 配置偏移 — 用 v2 配置体检验证 CONFIG_DRIFT")

    checker_drift = HealthChecker(config_v2)
    drift_findings = checker_drift.check()
    drift_items = [f for f in drift_findings if f.category == FindingCategory.CONFIG_DRIFT]
    assert_gt(len(drift_items), 0, "v2配置下应发现 CONFIG_DRIFT")
    for d in drift_items:
        assert_eq(d.fixable, False, "CONFIG_DRIFT 不可自动修复")
        print(f"  配置偏移: {d.description}")

    # ============================================================
    # Phase 12: failed-without-error_queue 专项
    #   手动把 queue 某项改为 failed 但不补 error_queue,
    #   然后 CLI heal --confirm, 再 healthcheck,
    #   验证不再新增 error_queue_inconsistency
    # ============================================================
    step("Phase 12a: failed-without-error_queue 专项 — 手动制造 queue=failed 但缺 error_queue")

    fresh_file = os.path.join(INTAKE_DIR, "2024-D004-001.pdf")
    touch(fresh_file)
    mgr_fresh = BatchManager(config)
    mgr_fresh.processing_queue.enqueue(
        fresh_file, "2024-D004", filename="2024-D004-001.pdf"
    )
    mgr_fresh.processing_queue.mark_failed(fresh_file)

    pq_check = load_json(QUEUE_FILE)
    d004_in_queue = [q for q in pq_check if q["path"] == fresh_file]
    assert_eq(len(d004_in_queue), 1, "D004 在 processing_queue 中")
    assert_eq(d004_in_queue[0]["status"], "failed", "D004 队列状态为 failed")

    eq_check = load_json(ERROR_QUEUE_FILE)
    d004_in_eq = [e for e in eq_check if e["path"] == fresh_file]
    assert_eq(len(d004_in_eq), 0, "D004 不在 error_queue (手动制造的不一致)")

    step("Phase 12b: healthcheck 发现 failed_not_in_error_queue")

    checker_12 = HealthChecker(config)
    findings_12 = checker_12.check()
    d004_inconsistency = [
        f for f in findings_12
        if f.file_path == fresh_file
        and f.category == FindingCategory.ERROR_QUEUE_INCONSISTENCY
    ]
    assert_gt(len(d004_inconsistency), 0, "应发现 D004 的 error_queue_inconsistency")
    print(f"  发现 D004 不一致: {d004_inconsistency[0].description}")

    step("Phase 12c: CLI heal --confirm 修复")

    cli_main(["-c", CONFIG_PATH, "heal", "--confirm"])

    step("Phase 12d: 修复后 healthcheck — D004 不再报不一致")

    checker_12d = HealthChecker(config)
    findings_12d = checker_12d.check()
    d004_inconsistency_after = [
        f for f in findings_12d
        if f.file_path == fresh_file
        and f.category == FindingCategory.ERROR_QUEUE_INCONSISTENCY
    ]
    assert_eq(
        len(d004_inconsistency_after), 0,
        "heal 后 D004 不应再报 error_queue_inconsistency"
    )

    eq_after_12 = load_json(ERROR_QUEUE_FILE)
    d004_in_eq_after = [e for e in eq_after_12 if e["path"] == fresh_file]
    assert_eq(len(d004_in_eq_after), 1, "D004 应已补入 error_queue")

    all_inconsistency_after = [
        f for f in findings_12d
        if f.category == FindingCategory.ERROR_QUEUE_INCONSISTENCY
    ]
    assert_eq(
        len(all_inconsistency_after), 0,
        f"heal 后不应有任何 error_queue_inconsistency: {[f.description for f in all_inconsistency_after]}"
    )

    step("Phase 12e: heal_log.jsonl 条数验证 (3 次 CLI heal 调用)")

    heal_log_records_final = read_jsonl(HEAL_LOG_FILE)
    assert_eq(
        len(heal_log_records_final), 3,
        "heal_log.jsonl 条数应等于 CLI heal 调用次数 (2+1=3)"
    )
    print(f"  heal_log.jsonl 最终: {len(heal_log_records_final)} 条")

    step("所有断言通过 ✓")
    print(f"\n证据目录保留: {TEST_ROOT}")
    print(f"关键证据文件:")
    for p in [
        BATCH_HISTORY_FILE, QUEUE_FILE, ERROR_QUEUE_FILE,
        ACTION_LOG, HEALTHCHECK_STATE_FILE, HEAL_LOG_FILE,
        HC_JSON, HC_CSV,
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
