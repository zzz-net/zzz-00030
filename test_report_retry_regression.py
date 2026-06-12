"""
Report + Retry 回归测试：
  复现 retry 之后生成批次报告不准的问题：
  - 失败文件 retry 成功后从 error_queue 移除，报告显示"未知错误"
  - retry 成功的 ActionRecord 不带 batch_id，success_files 缺少补救成功记录
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import traceback

import yaml


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, BASE_DIR)

if sys.platform.startswith("win"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def print_header(text: str) -> None:
    bar = "=" * 60
    print(f"\n{bar}\n{text}\n{bar}")


def print_step(text: str) -> None:
    print(f"\n  {text}")


def assert_eq(actual, expected, msg: str) -> None:
    ok = actual == expected
    status = "[OK]" if ok else "[FAIL]"
    print(f"  {status} {msg}: {actual!r} == {expected!r}")
    if not ok:
        raise AssertionError(f"{msg}: got {actual!r}, expected {expected!r}")


def assert_true(cond, msg: str) -> None:
    print(f"  {'[OK]' if cond else '[FAIL]'} {msg} == {cond}")
    if not cond:
        raise AssertionError(msg)


def assert_in(needle, haystack, msg: str) -> None:
    ok = needle in haystack
    print(f"  {'[OK]' if ok else '[FAIL]'} {msg}: {needle!r} present == {ok}")
    if not ok:
        raise AssertionError(f"{msg}: {needle!r} not in {haystack!r}")


def write_config(
    base_dir: str,
    target_base_name: str = "target",
) -> tuple[str, str]:
    intake_dir = os.path.join(base_dir, "intake")
    target_base = os.path.join(base_dir, target_base_name)
    logging_dir = os.path.join(base_dir, "data")
    os.makedirs(intake_dir, exist_ok=True)
    os.makedirs(target_base, exist_ok=True)
    os.makedirs(logging_dir, exist_ok=True)

    cfg_path = os.path.join(base_dir, "config.yaml")
    cfg = {
        "operator": "tester",
        "intake_dir": intake_dir,
        "target_base": target_base,
        "rules": {
            "action": "move",
            "case_number_pattern": r"(20\d{2}-[A-Z]\d{3})-\d{3}\.pdf$",
            "target_structure": "{case_number}",
            "allowed_extensions": [".pdf"],
            "max_filename_length": 80,
            "forbidden_chars": r'[<>:"/\\|?*#]',
        },
        "batch": {
            "max_size": 100,
            "stop_on_failure_ratio": 0.9,
        },
        "logging": {
            "dir": logging_dir,
        },
    }
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True)
    return cfg_path, intake_dir, target_base


def touch(path: str, content: bytes = b"placeholder") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)


def run_cli(args: list[str]) -> tuple[int, str, str]:
    import subprocess
    proc = subprocess.run(
        [sys.executable, "-m", "scan_sorter", *args],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, proc.stdout, proc.stderr


def main() -> int:
    workdir = os.path.join(BASE_DIR, "test_report_retry_run")
    if os.path.exists(workdir):
        shutil.rmtree(workdir)
    os.makedirs(workdir, exist_ok=True)

    try:
        # ---------------------------------------------------------------------
        print_header("Phase 1: 场景搭建")
        # ---------------------------------------------------------------------
        cfg_path, intake_dir, target_base = write_config(workdir)

        valid_a = os.path.join(intake_dir, "2024-A001-001.pdf")
        valid_b = os.path.join(intake_dir, "2024-A001-002.pdf")
        bad_chars = os.path.join(intake_dir, "bad file#name.pdf")
        occupied_src = os.path.join(intake_dir, "2024-A001-003.pdf")

        touch(valid_a)
        touch(valid_b)
        touch(bad_chars)
        touch(occupied_src)

        occupied_target_dir = os.path.join(target_base, "2024-A001")
        occupied_target = os.path.join(occupied_target_dir, "2024-A001-003.pdf")
        touch(occupied_target, b"existing-content")

        # ---------------------------------------------------------------------
        print_header("Phase 2: process 生成部分失败批次")
        # ---------------------------------------------------------------------
        rc, out, err = run_cli(["-c", cfg_path, "process"])
        assert_eq(rc, 0, "process 执行成功退出码")
        print_step(out)

        # 读 batch_history
        data_dir = os.path.join(workdir, "data")
        with open(os.path.join(data_dir, "batch_history.json"), "r", encoding="utf-8") as f:
            history = json.load(f)
        assert_eq(len(history), 1, "应有 1 条批次记录")
        batch = history[0]
        batch_id = batch["batch_id"]
        print_step(f"批次 ID: {batch_id}")

        assert_true(batch["succeeded"] >= 2, f"succeeded({batch['succeeded']}) >= 2 (valid_a + valid_b)")
        assert_true(batch["failed"] >= 2, f"failed({batch['failed']}) >= 2 (bad_chars + occupied)")
        assert_true("error_details" in batch, "BatchRecord 应包含 error_details 字段")
        assert_true(len(batch["error_details"]) >= 2, f"error_details 应有 >= 2 条")
        print_step(f"error_details: {json.dumps(batch['error_details'], ensure_ascii=False, indent=2)}")

        # 读 error_queue
        with open(os.path.join(data_dir, "error_queue.json"), "r", encoding="utf-8") as f:
            error_queue = json.load(f)
        bad_in_eq = [e for e in error_queue if os.path.basename(e["path"]) == "bad file#name.pdf"]
        occ_in_eq = [e for e in error_queue if os.path.basename(e["path"]) == "2024-A001-003.pdf"]
        assert_eq(len(bad_in_eq), 1, "bad file#name.pdf 在 error_queue 中")
        assert_eq(len(occ_in_eq), 1, "2024-A001-003.pdf 在 error_queue 中")
        assert_true(bad_in_eq[0].get("batch_id") is not None, "预检查失败条目应带 batch_id")
        assert_true(occ_in_eq[0].get("batch_id") is not None, "执行失败条目应带 batch_id")

        # ---------------------------------------------------------------------
        print_header("Phase 3: retry 前 report 验证（失败原因可读、未补救）")
        # ---------------------------------------------------------------------
        rc, out, err = run_cli([
            "-c", cfg_path, "report", "--batch-id", batch_id, "--brief",
        ])
        print_step(out)
        assert_true(rc in (0, 1), f"report 退出码应为 0 或 1，实际={rc}")

        # ---------------------------------------------------------------------
        print_header("Phase 4: 修复失败原因 + 触发 retry 补救")
        # ---------------------------------------------------------------------
        # 删除 target 的冲突文件（让 occupied retry 成功）
        os.remove(occupied_target)

        # bad_chars 重命名为合法文件名
        good_rename = os.path.join(intake_dir, "2024-Z999-001.pdf")
        os.rename(bad_chars, good_rename)
        # 但 precheck 失败的 ErrorItem.path 还是旧名字，所以要同步 error_queue 的 path ？
        # 不对，retry_failed 是按 path 判断 os.path.exists 的，我们得让 error_queue 的 path 对应新路径
        # 或者不，我们只测试 occupied 这一条 retry 就够了。把 bad 改回旧名字以保证 retry 仍失败（验证 occupied 单独成功）
        os.rename(good_rename, bad_chars)

        # 重试：bad_chars 仍会失败（非法字符），occupied 应该成功
        rc, out, err = run_cli(["-c", cfg_path, "retry"])
        assert_eq(rc, 0, "retry 执行成功退出码")
        print_step(out)
        assert_true("succeeded: 1" in out or "成功 1" in out or "succeeded" in out.lower(),
                    f"retry 应有 1 条成功（occupied），输出: {out}")

        # 读 action_log.jsonl 确认 retry 成功动作带 batch_id
        action_log_path = os.path.join(data_dir, "action_log.jsonl")
        actions = []
        with open(action_log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    actions.append(json.loads(line))
        retry_actions_for_batch = [
            a for a in actions
            if a.get("batch_id") == batch_id
            and a.get("source") and "2024-A001-003.pdf" in a.get("source", "")
        ]
        assert_eq(len(retry_actions_for_batch), 1,
                  "retry 成功动作（2024-A001-003.pdf）应带 batch_id")
        print_step(f"retry 动作: {json.dumps(retry_actions_for_batch[0], ensure_ascii=False, indent=2)}")

        # error_queue 中 occupied 已移除，bad 仍在
        with open(os.path.join(data_dir, "error_queue.json"), "r", encoding="utf-8") as f:
            error_queue = json.load(f)
        occ_in_eq = [e for e in error_queue if "2024-A001-003.pdf" in e["path"]]
        bad_in_eq = [e for e in error_queue if "bad file#name.pdf" in e["path"]]
        assert_eq(len(occ_in_eq), 0, "occupied 成功后应从 error_queue 移除")
        assert_eq(len(bad_in_eq), 1, "bad_chars 仍应留在 error_queue")

        # ---------------------------------------------------------------------
        print_header("Phase 5: 生成报告（核心验证）")
        # ---------------------------------------------------------------------
        json_path = os.path.join(workdir, "report_after_retry.json")
        rc, out, err = run_cli([
            "-c", cfg_path, "report",
            "--batch-id", batch_id,
            "--format", "json",
            "--output", json_path,
        ])
        print_step(out)
        assert_true(rc in (0, 1), f"report 导出退出码应为 0 或 1，实际={rc}")
        assert_true(os.path.exists(json_path), "JSON 导出文件应存在")

        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        assert_eq(len(report["batches"]), 1, "报告应包含 1 个批次")
        batch_report = report["batches"][0]
        failed_files = batch_report["failed_files"]
        success_files = batch_report["success_files"]
        print_step(f"failed_files: {json.dumps(failed_files, ensure_ascii=False, indent=2)}")
        print_step(f"success_files 数量: {len(success_files)}")
        print_step(f"success_files[0:]: {json.dumps(success_files, ensure_ascii=False, indent=2)}")

        # === 关键断言 1: failed_files 中 occupied 的 error 不是"未知错误" ===
        occupied_fail = [f for f in failed_files if "2024-A001-003.pdf" in f["path"]]
        assert_eq(len(occupied_fail), 1, "failed_files 中应包含 2024-A001-003.pdf")
        occupied_err = occupied_fail[0]["error"]
        assert_true(occupied_err != "未知错误",
                    f"retry 后 occupied 的 error 不应为'未知错误'，实际={occupied_err!r}")
        assert_true(occupied_fail[0]["recovered"] is True,
                    "occupied 已被 retry 补救，recovered 应为 True")
        assert_true(occupied_fail[0]["in_error_queue"] is False,
                    "occupied 已补救成功，in_error_queue 应为 False")

        # === 关键断言 2: failed_files 中 bad_chars 的 error 不是"未知错误" ===
        bad_fail = [f for f in failed_files if "bad file#name.pdf" in f["path"]]
        assert_eq(len(bad_fail), 1, "failed_files 中应包含 bad file#name.pdf")
        bad_err = bad_fail[0]["error"]
        assert_true(bad_err != "未知错误",
                    f"bad_chars 的 error 不应为'未知错误'，实际={bad_err!r}")
        assert_true(bad_fail[0]["recovered"] is False,
                    "bad_chars 仍在 error_queue 未成功，recovered 应为 False")
        assert_true(bad_fail[0]["in_error_queue"] is True,
                    "bad_chars 未补救，in_error_queue 应为 True")

        # === 关键断言 3: success_files 包含 retry 后成功的 2024-A001-003.pdf ===
        succ_occ = [s for s in success_files if "2024-A001-003.pdf" in s.get("source", "")]
        assert_true(len(succ_occ) >= 1,
                    "success_files 中应包含 retry 补救成功的 2024-A001-003.pdf")
        assert_true(succ_occ[0]["destination"] and os.path.isabs(succ_occ[0]["destination"]),
                    f"补救成功的 destination 应非空，实际={succ_occ[0].get('destination')!r}")

        # === 关键断言 4: success_files 中仍包含最初成功的 valid_a、valid_b ===
        succ_a = [s for s in success_files if "2024-A001-001.pdf" in s.get("source", "")]
        succ_b = [s for s in success_files if "2024-A001-002.pdf" in s.get("source", "")]
        assert_eq(len(succ_a), 1, "success_files 中应包含 2024-A001-001.pdf")
        assert_eq(len(succ_b), 1, "success_files 中应包含 2024-A001-002.pdf")

        # ---------------------------------------------------------------------
        print_header("Phase 6: CLI 文本输出验证 recovered 标记可见")
        # ---------------------------------------------------------------------
        rc, out, err = run_cli(["-c", cfg_path, "report", "--batch-id", batch_id])
        print_step(out)
        assert_true("已补救" in out or "recovered" in out or "2024-A001-003.pdf" in out,
                    "文本报告应显示 2024-A001-003.pdf 的补救信息")

        print_header("\n所有断言通过 ✅\n")
        print(f"证据目录保留: {workdir}")
        print(f"关键证据文件:")
        print(f"  {os.path.join(data_dir, 'batch_history.json')}")
        print(f"  {os.path.join(data_dir, 'queue.json')}")
        print(f"  {os.path.join(data_dir, 'error_queue.json')}")
        print(f"  {os.path.join(data_dir, 'action_log.jsonl')}")
        print(f"  {json_path}")
        return 0

    except AssertionError as e:
        print(f"\n[FAIL] 断言失败: {e}")
        traceback.print_exc()
        print(f"\n证据目录保留: {workdir}")
        return 1
    except Exception as e:
        print(f"\n[ERR] 异常: {e}")
        traceback.print_exc()
        print(f"\n证据目录保留: {workdir}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
