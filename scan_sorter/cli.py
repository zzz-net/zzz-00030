from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys

from scan_sorter.batch_manager import BatchManager
from scan_sorter.config import load_config, reload_config
from scan_sorter.healthcheck import (
    HealthChecker,
    export_findings_csv,
    export_findings_json,
)
from scan_sorter.watcher import Watcher

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


def cmd_precheck(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = BatchManager(config)
    results = mgr.precheck()

    if not results:
        print("intake 目录无待处理文件")
        return

    ok_count = sum(1 for r in results if r.ok)
    fail_count = sum(1 for r in results if not r.ok)

    print(f"\n{'='*60}")
    print(f"预检结果: {len(results)} 个文件, {ok_count} 通过, {fail_count} 不通过")
    print(f"{'='*60}")

    for r in results:
        status = "✓" if r.ok else "✗"
        line = f"  {status} {r.filename}"
        if r.case_number:
            line += f"  [案卷号: {r.case_number}]"
        if r.target_path:
            line += f"  -> {r.target_path}"
        print(line)
        for err in r.errors:
            print(f"      ⚠ {err}")

    if args.json:
        data = [r.to_dict() for r in results]
        _write_output(data, args.json, "预检结果")


def cmd_process(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = BatchManager(config)
    result = mgr.process(max_files=args.max_files)

    print(f"\n{'='*60}")
    print(f"处理结果")
    print(f"{'='*60}")
    _print_result(result)

    if args.json:
        _write_output(result, args.json, "处理结果")


def cmd_retry(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = BatchManager(config)
    result = mgr.retry_failed(limit=args.limit)

    print(f"\n{'='*60}")
    print(f"重试结果")
    print(f"{'='*60}")
    _print_result(result)

    if args.json:
        _write_output(result, args.json, "重试结果")


def cmd_rollback(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = BatchManager(config)
    result = mgr.rollback(args.batch_id)

    print(f"\n{'='*60}")
    print(f"回滚结果")
    print(f"{'='*60}")
    _print_result(result)

    if result.get("details"):
        print("\n  详细回滚记录:")
        for d in result["details"]:
            status = "✓" if d["ok"] else "✗"
            print(f"    {status} {d['detail']}")

    if args.json:
        _write_output(result, args.json, "回滚结果")


def cmd_watch(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    watcher = Watcher(config)
    watcher.start()


def cmd_status(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = BatchManager(config)

    print(f"\n{'='*60}")
    print(f"系统状态")
    print(f"{'='*60}")

    batches = mgr.list_batches()
    errors = mgr.get_error_queue()

    print(f"  历史批次: {len(batches)}")
    for b in batches[-5:]:
        print(
            f"    [{b['batch_id']}] {b['status']} "
            f"成功:{b['succeeded']} 失败:{b['failed']} "
            f"操作者:{b['operator']} "
            f"时间:{b['created_at']}"
        )

    print(f"\n  错误队列: {len(errors)} 项")
    for e in errors[:10]:
        print(
            f"    {e['filename']} - {e['error']} "
            f"(重试:{e['retry_count']}/{e['max_retries']})"
        )

    actions = mgr.export_action_log()
    print(f"\n  操作日志: {len(actions)} 条记录")


def cmd_export(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = BatchManager(config)
    fmt = args.format or "json"

    data_source = args.source or "actions"
    if data_source == "actions":
        data = mgr.export_action_log()
    elif data_source == "errors":
        data = mgr.get_error_queue()
    elif data_source == "batches":
        data = mgr.list_batches()
    else:
        print(f"未知数据源: {data_source}")
        return

    output_path = args.output
    if not output_path:
        ext = ".json" if fmt == "json" else ".csv"
        output_path = f"export_{data_source}{ext}"

    if fmt == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"已导出 JSON: {output_path} ({len(data)} 条)")
    elif fmt == "csv":
        if not data:
            print("无数据可导出")
            return
        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        print(f"已导出 CSV: {output_path} ({len(data)} 条)")


def cmd_reload(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    new_config = reload_config(config)
    print("配置已重新加载")
    print(json.dumps(new_config.to_dict(), ensure_ascii=False, indent=2))


def cmd_healthcheck(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    checker = HealthChecker(config)
    findings = checker.check()

    print(f"\n{'='*60}")
    print(f"状态体检结果")
    print(f"{'='*60}")

    if not findings:
        print("  未发现异常")
    else:
        critical = [f for f in findings if f.severity.value == "critical"]
        warning = [f for f in findings if f.severity.value == "warning"]
        info = [f for f in findings if f.severity.value == "info"]
        fixable = [f for f in findings if f.fixable]

        print(f"  总计: {len(findings)} 个问题")
        if critical:
            print(f"    严重: {len(critical)}")
        if warning:
            print(f"    警告: {len(warning)}")
        if info:
            print(f"    信息: {len(info)}")
        if fixable:
            print(f"    可修复: {len(fixable)}")

        print()
        for f in findings:
            sev = {"critical": "✗", "warning": "⚠", "info": "ℹ"}[f.severity.value]
            fix_tag = " [可修复]" if f.fixable else ""
            print(f"  {sev} [{f.category.value}]{fix_tag} {f.description}")
            if f.file_path:
                print(f"     文件: {f.file_path}")
            if f.batch_id:
                print(f"     批次: {f.batch_id}")

    last_check = checker.state.get_last_check_time()
    if last_check:
        print(f"\n  上次体检时间: {last_check}")

    known = checker.state.get_known_fingerprints()
    prev_findings = checker.state.get_last_findings()
    if prev_findings and len(prev_findings) != len(findings):
        new_fps = {f.fingerprint for f in findings} - {f.fingerprint for f in prev_findings}
        resolved_fps = {f.fingerprint for f in prev_findings} - {f.fingerprint for f in findings}
        if new_fps:
            print(f"  新增问题: {len(new_fps)} 个")
        if resolved_fps:
            print(f"  已解决: {len(resolved_fps)} 个")

    output_path = args.output
    fmt = args.format
    if output_path or fmt:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"healthcheck_result.{fmt}"
        if fmt == "json":
            export_findings_json(findings, output_path)
            print(f"\n  体检结果已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_findings_csv(findings, output_path)
            print(f"\n  体检结果已导出 CSV: {output_path}")


def cmd_heal(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    checker = HealthChecker(config)
    findings = checker.check()

    fixable = [f for f in findings if f.fixable]
    if not fixable:
        print("无可修复的问题")
        return

    dry_run = not args.confirm
    if dry_run:
        print(f"\n{'='*60}")
        print(f"恢复模式: dry-run (预览，不实际修改)")
        print(f"{'='*60}")
    else:
        print(f"\n{'='*60}")
        print(f"恢复模式: 实际执行")
        print(f"{'='*60}")

    fingerprints = None
    if args.fingerprints:
        fingerprints = set(args.fingerprints.split(","))

    actions = checker.heal(findings, dry_run=dry_run, fingerprints=fingerprints)

    applied = [a for a in actions if a.applied]
    skipped = [a for a in actions if not a.applied]

    print(f"\n  处理结果:")
    print(f"    应用修复: {len(applied)}")
    print(f"    跳过: {len(skipped)}")

    for a in actions:
        tag = "✓ 已修复" if a.applied else "✗ 跳过"
        print(f"    {tag} [{a.category.value}] {a.description}")
        if a.reason:
            print(f"       原因: {a.reason}")

    heal_log_path = os.path.join(
        config.logging.dir, "heal_log.jsonl"
    )
    from scan_sorter.utils import append_jsonl
    log_entry = {
        "timestamp": __import__("datetime").datetime.now().isoformat(),
        "dry_run": dry_run,
        "total_actions": len(actions),
        "applied_count": len(applied),
        "skipped_count": len(skipped),
        "actions": [a.to_dict() for a in actions],
    }
    append_jsonl(heal_log_path, log_entry)
    print(f"\n  恢复日志已写入: {heal_log_path}")


def _print_result(result: dict) -> None:
    for key, value in result.items():
        if key == "details":
            continue
        print(f"  {key}: {value}")


def _write_output(data, path: str, label: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"\n{label}已写入: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan-sorter",
        description="扫描件入库分拣守护工具",
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="配置文件路径 (默认: config.yaml)",
    )

    sub = parser.add_subparsers(dest="command", help="可用命令")

    p_precheck = sub.add_parser("precheck", help="预检 intake 目录文件")
    p_precheck.add_argument("--json", help="预检结果输出 JSON 路径")

    p_process = sub.add_parser("process", help="预检并执行入库")
    p_process.add_argument("--max-files", type=int, help="最大处理文件数")
    p_process.add_argument("--json", help="处理结果输出 JSON 路径")

    p_retry = sub.add_parser("retry", help="重试错误队列中的失败文件")
    p_retry.add_argument("--limit", type=int, help="最大重试数量")
    p_retry.add_argument("--json", help="重试结果输出 JSON 路径")

    p_rollback = sub.add_parser("rollback", help="回滚指定批次")
    p_rollback.add_argument("batch_id", help="要回滚的批次 ID")
    p_rollback.add_argument("--json", help="回滚结果输出 JSON 路径")

    p_watch = sub.add_parser("watch", help="启动监听模式")

    p_status = sub.add_parser("status", help="查看系统状态")

    p_export = sub.add_parser("export", help="导出日志数据")
    p_export.add_argument(
        "--source",
        choices=["actions", "errors", "batches"],
        default="actions",
        help="数据源 (默认: actions)",
    )
    p_export.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="导出格式 (默认: json)",
    )
    p_export.add_argument("--output", help="输出文件路径")

    p_reload = sub.add_parser("reload", help="重载配置")

    p_healthcheck = sub.add_parser("healthcheck", help="状态体检:扫描各状态文件一致性")
    p_healthcheck.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_healthcheck.add_argument("--output", help="体检结果导出路径")

    p_heal = sub.add_parser("heal", help="恢复:修复体检发现的一致性问题")
    p_heal.add_argument(
        "--confirm",
        action="store_true",
        default=False,
        help="确认实际执行 (默认 dry-run 预览)",
    )
    p_heal.add_argument(
        "--fingerprints",
        default=None,
        help="只修复指定指纹的问题,逗号分隔",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    dispatch = {
        "precheck": cmd_precheck,
        "process": cmd_process,
        "retry": cmd_retry,
        "rollback": cmd_rollback,
        "watch": cmd_watch,
        "status": cmd_status,
        "export": cmd_export,
        "reload": cmd_reload,
        "healthcheck": cmd_healthcheck,
        "heal": cmd_heal,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
        return 0
    else:
        parser.print_help()
        return 1
