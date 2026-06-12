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
    ComparisonResult,
    compare_findings,
    export_findings_csv,
    export_findings_json,
    export_comparison_csv,
    export_comparison_json,
)
from scan_sorter.migration import (
    execute_migration,
    export_plan_csv,
    export_plan_json,
    export_result_csv,
    export_result_json,
    generate_migration_plan,
)
from scan_sorter.report import (
    ReportGenerator,
    export_report_json,
    export_report_csv,
)
from scan_sorter.retry_manager import (
    RetryManager,
    RetryStatus,
    SkipReason,
    export_retry_plan_json,
    export_retry_plan_csv,
    export_retry_result_json,
    export_retry_result_csv,
)
from scan_sorter.watcher import Watcher

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


def export_dryrun_plan_json(plan, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(plan.to_dict(), f, ensure_ascii=False, indent=2)


def export_dryrun_plan_csv(plan, output_path: str) -> None:
    fieldnames = [
        "filename", "path", "case_number", "target_dir", "target_path",
        "action", "will_succeed", "action_type",
        "errors", "warnings",
        "in_processing_queue", "in_error_queue", "target_exists",
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in plan.items:
            row = item.to_dict()
            row["errors"] = "; ".join(row.get("errors", []))
            row["warnings"] = "; ".join(row.get("warnings", []))
            writer.writerow(row)


def cmd_plan(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = BatchManager(config)
    plan = mgr.dry_run(max_files=args.max_files)

    print(f"\n{'='*60}")
    print(f"预演计划 (dry-run)")
    print(f"{'='*60}")
    print(f"  总计文件: {plan.total}")
    print(f"  预计成功: {plan.will_succeed}")
    print(f"  预计失败: {plan.will_fail}")
    print(f"  潜在告警: {plan.warnings}")
    print(f"{'='*60}")

    if not plan.items:
        print("intake 目录无待处理文件")
    else:
        for item in plan.items:
            status_icon = "✓" if item.will_succeed else "✗"
            action_label = {
                "archive": "归档",
                "fail_precheck": "预检失败",
                "fail_target_conflict": "目标冲突",
                "fail_duplicate": "重复文件",
                "skip_error_queue": "在错误队列",
                "skip_queue": "在处理队列",
            }.get(item.action.value, item.action.value)

            line = f"  {status_icon} [{action_label}] {item.filename}"
            if item.case_number:
                line += f"  [案卷号: {item.case_number}]"
            if item.target_path:
                line += f"  -> {item.target_path}"
            print(line)

            tags = []
            if item.in_processing_queue:
                tags.append("在处理队列")
            if item.in_error_queue:
                tags.append("在错误队列")
            if item.target_exists:
                tags.append("目标已存在")
            if tags:
                print(f"      ℹ [{', '.join(tags)}]")

            for warn in item.warnings:
                print(f"      ⚠ {warn}")
            for err in item.errors:
                print(f"      ✗ {err}")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"process_plan.{fmt}"
        if fmt == "json":
            export_dryrun_plan_json(plan, output_path)
            print(f"\n  计划已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_dryrun_plan_csv(plan, output_path)
            print(f"\n  计划已导出 CSV: {output_path}")


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


def _skip_reason_label(reason: SkipReason) -> str:
    return {
        SkipReason.SOURCE_MISSING: "源文件丢失",
        SkipReason.TARGET_EXISTS: "目标已存在",
        SkipReason.IN_PROCESSING_QUEUE: "在处理队列中",
        SkipReason.DUPLICATE_IN_ERROR_QUEUE: "错误队列重复",
        SkipReason.MAX_RETRIES_EXCEEDED: "超最大重试次数",
        SkipReason.PARSE_FAILED: "解析失败",
        SkipReason.PRECHECK_FAILED: "预检失败",
    }.get(reason, reason.value)


def cmd_retry_plan(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = BatchManager(config)
    plan = mgr.build_retry_plan(
        limit=args.limit,
        include_skipped=not getattr(args, "retryable_only", False),
    )

    print(f"\n{'='*60}")
    print(f"重试预检计划")
    print(f"{'='*60}")
    print(f"  总计: {plan.total}")
    print(f"  可重试: {plan.retryable}")
    print(f"  跳过: {plan.skipped}")
    print(f"{'='*60}")

    if plan.total == 0:
        print("  错误队列为空，无待处理项")
    else:
        if plan.retryable_items:
            print(f"\n  [可重试] ({len(plan.retryable_items)} 项)")
            for item in plan.retryable_items:
                print(f"    ✓ {item.filename}")
                if item.original_error:
                    print(f"       原始错误: {item.original_error}")
                if item.case_number:
                    print(f"       案卷号: {item.case_number}")
                if item.new_target_path:
                    print(f"       新目标路径: {item.new_target_path}")
                print(f"       预计动作: {item.expected_action}")
                print(f"       重试进度: {item.retry_count}/{item.max_retries}")
                if item.original_batch_id:
                    print(f"       原始批次: {item.original_batch_id}")

        if plan.skipped_items and not getattr(args, "retryable_only", False):
            print(f"\n  [跳过] ({len(plan.skipped_items)} 项)")
            for item in plan.skipped_items:
                reason_label = _skip_reason_label(item.skip_reason) if item.skip_reason else "未知原因"
                print(f"    ✗ {item.filename}  [{reason_label}]")
                if item.original_error:
                    print(f"       原始错误: {item.original_error}")
                if item.skip_detail:
                    print(f"       跳过原因: {item.skip_detail}")
                if item.new_target_path:
                    print(f"       新目标路径: {item.new_target_path}")
                if item.original_batch_id:
                    print(f"       原始批次: {item.original_batch_id}")
                tags = []
                if item.source_missing:
                    tags.append("源文件丢失")
                if item.target_exists:
                    tags.append("目标已存在")
                if item.in_processing_queue:
                    tags.append("处理队列中")
                if item.duplicate_in_error_queue:
                    tags.append("错误队列重复")
                if tags:
                    print(f"       标记: [{', '.join(tags)}]")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"retry_plan.{fmt}"
        if fmt == "json":
            export_retry_plan_json(plan, output_path)
            print(f"\n  计划已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_retry_plan_csv(plan, output_path)
            print(f"\n  计划已导出 CSV: {output_path}")


def cmd_retry_execute(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = BatchManager(config)

    paths = None
    if args.paths:
        paths = [p.strip() for p in args.paths.split(",")]

    result = mgr.execute_retry(
        paths=paths,
        limit=args.limit,
    )

    print(f"\n{'='*60}")
    print(f"重试执行结果")
    print(f"{'='*60}")
    print(f"  批次 ID: {result.batch_id}")
    print(f"  总计执行: {result.total}")
    print(f"  成功: {result.succeeded}")
    print(f"  失败: {result.failed}")
    print(f"  预检跳过: {result.skipped}")
    print(f"  执行时间: {result.timestamp}")
    print(f"{'='*60}")

    if result.total == 0:
        print("  无可执行的重试项")
    else:
        for item in result.items:
            if item.status == RetryStatus.SUCCESS:
                print(f"    ✓ [成功] {item.filename}")
                print(f"       动作: {item.action_type} {item.source} -> {item.destination}")
                print(f"       操作 ID: {item.action_id}")
            else:
                print(f"    ✗ [失败] {item.filename}")
                print(f"       错误: {item.error}")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"retry_result.{fmt}"
        if fmt == "json":
            export_retry_result_json(result, output_path)
            print(f"\n  结果已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_retry_result_csv(result, output_path)
            print(f"\n  结果已导出 CSV: {output_path}")


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

    case_number = getattr(args, "case_number", None)
    if case_number and data_source in ("actions", "errors"):
        original_len = len(data)
        data = [
            r for r in data
            if r.get("case_number") == case_number
        ]
        filtered_len = len(data)
        print(f"按案件号 {case_number} 筛选: {original_len} -> {filtered_len} 条")

    output_path = args.output
    if not output_path:
        ext = ".json" if fmt == "json" else ".csv"
        if case_number:
            output_path = f"export_{data_source}_{case_number}{ext}"
        else:
            output_path = f"export_{data_source}{ext}"

    if fmt == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        if not data:
            print(f"已导出空 JSON: {output_path} (0 条，无匹配案件号 {case_number})")
        else:
            print(f"已导出 JSON: {output_path} ({len(data)} 条)")
    elif fmt == "csv":
        fieldnames = []
        if data:
            fieldnames = list(data[0].keys())
        elif data_source == "actions":
            fieldnames = [
                "action_id", "batch_id", "source", "destination",
                "action_type", "timestamp", "operator", "rolled_back",
                "case_number",
            ]
        elif data_source == "errors":
            fieldnames = [
                "path", "filename", "case_number", "error",
                "retry_count", "max_retries", "added_at",
                "last_retry_at", "batch_id",
            ]
        elif data_source == "batches":
            fieldnames = [
                "batch_id", "created_at", "operator", "status",
                "total", "succeeded", "failed", "action_ids",
                "error_file_paths", "error_details",
            ]
        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            if data:
                writer.writerows(data)
        if not data:
            if case_number:
                print(f"已导出空 CSV (仅表头): {output_path} (0 条，无匹配案件号 {case_number})")
            else:
                print(f"已导出空 CSV (仅表头): {output_path} (0 条)")
        else:
            print(f"已导出 CSV: {output_path} ({len(data)} 条)")


def cmd_reload(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    new_config = reload_config(config)
    print("配置已重新加载")
    print(json.dumps(new_config.to_dict(), ensure_ascii=False, indent=2))


def _print_finding_list(findings: list, label: str, icon: str) -> None:
    if not findings:
        return False
    print(f"\n  {icon} {label} ({len(findings)} 个)")
    for f in findings:
        sev = {"critical": "✗", "warning": "⚠", "info": "ℹ"}[f.severity.value]
        fix_tag = " [可修复]" if f.fixable else ""
        print(f"    {sev} [{f.category.value}]{fix_tag} {f.description}")
        if f.file_path:
            print(f"       文件: {f.file_path}")
        if f.batch_id:
            print(f"       批次: {f.batch_id}")
    return True


def cmd_healthcheck(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    checker = HealthChecker(config)
    prev_findings = checker.state.get_last_findings()
    prev_check_time = checker.state.get_last_check_time()
    findings = checker.check()

    compare_last = getattr(args, "compare_last", False)

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

        if not compare_last:
            print()
            for f in findings:
                sev = {"critical": "✗", "warning": "⚠", "info": "ℹ"}[f.severity.value]
                fix_tag = " [可修复]" if f.fixable else ""
                print(f"  {sev} [{f.category.value}]{fix_tag} {f.description}")
                if f.file_path:
                    print(f"     文件: {f.file_path}")
                if f.batch_id:
                    print(f"     批次: {f.batch_id}")

    if compare_last:
        comparison = compare_findings(findings, prev_findings, prev_check_time)
        print(f"\n{'='*20} 与上次体检对比 {'='*20}")
        if prev_check_time is None:
            print("  无可对比的上次体检结果（首次运行）")
        else:
            print(f"  上次体检时间: {prev_check_time or '未知'}")
            print(f"  新增: {len(comparison.new_findings)} 个")
            print(f"  已解决: {len(comparison.resolved_findings)} 个")
            print(f"  持续存在: {len(comparison.persistent_findings)} 个")

            _print_finding_list(comparison.new_findings, "新增问题", "🆕")
            _print_finding_list(comparison.resolved_findings, "已解决问题", "✅")
            _print_finding_list(comparison.persistent_findings, "持续存在问题", "🔁")
    else:
        last_check = checker.state.get_last_check_time()
        if last_check:
            print(f"\n  上次体检时间: {last_check}")

        prev_findings_simple = checker.state.get_last_findings()
        if prev_findings_simple and len(prev_findings_simple) != len(findings):
            new_fps = {f.fingerprint for f in findings} - {f.fingerprint for f in prev_findings_simple}
            resolved_fps = {f.fingerprint for f in prev_findings_simple} - {f.fingerprint for f in findings}
            if new_fps:
                print(f"  新增问题: {len(new_fps)} 个")
            if resolved_fps:
                print(f"  已解决: {len(resolved_fps)} 个")

    output_path = args.output
    fmt = args.format
    if output_path or fmt:
        fmt = fmt or "json"
        if not output_path:
            if compare_last:
                output_path = f"healthcheck_comparison.{fmt}"
            else:
                output_path = f"healthcheck_result.{fmt}"
        if compare_last:
            comparison = compare_findings(findings, prev_findings, prev_check_time)
            if fmt == "json":
                export_comparison_json(comparison, output_path)
                print(f"\n  对比结果已导出 JSON: {output_path}")
            elif fmt == "csv":
                export_comparison_csv(comparison, output_path)
                print(f"\n  对比结果已导出 CSV: {output_path}")
        else:
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


def cmd_report(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    generator = ReportGenerator(config)

    batch_id = getattr(args, "batch_id", None)
    include_details = not getattr(args, "brief", False)

    report = generator.generate(
        batch_id=batch_id,
        include_details=include_details,
    )

    print(f"\n{'='*60}")
    print(f"批次复盘报告")
    print(f"{'='*60}")
    print(f"生成时间: {report.generated_at}")

    if report.config_info:
        print(f"\n{'='*20} 配置信息 {'='*20}")
        print(f"  intake 目录: {report.config_info['intake_dir']}")
        print(f"  target 目录: {report.config_info['target_base']}")
        print(f"  目录结构: {report.config_info['target_structure']}")
        print(f"  操作方式: {report.config_info['action']}")
        print(f"  操作者: {report.config_info['operator']}")
        print(f"  日志目录: {report.config_info['logging_dir']}")

    if report.errors:
        print(f"\n{'='*20} 错误 {'='*20}")
        for e in report.errors:
            print(f"  ✗ {e}")

    if report.warnings:
        print(f"\n{'='*20} 警告 {'='*20}")
        for w in report.warnings:
            print(f"  ⚠ {w}")

    if report.batches:
        print(f"\n{'='*20} 批次汇总 ({len(report.batches)} 个) {'='*20}")
        for b in report.batches:
            status_icon = {
                "completed": "✓",
                "partial_failed": "⚠",
                "rolled_back": "↺",
                "open": "○",
            }.get(b.status, "?")

            print(f"\n  [{status_icon}] 批次 {b.batch_id}")
            print(f"      状态: {b.status}")
            print(f"      创建时间: {b.created_at}")
            print(f"      操作者: {b.operator}")
            print(f"      总计: {b.total}, 成功: {b.succeeded}, 失败: {b.failed}")
            if b.target_dirs:
                print(f"      目标目录: {', '.join(b.target_dirs)}")

            if include_details and b.success_files:
                print(f"      成功文件 ({len(b.success_files)}):")
                for sf in b.success_files[:5]:
                    print(f"        ✓ {sf['filename']} -> {sf['destination']}")
                if len(b.success_files) > 5:
                    print(f"        ... 还有 {len(b.success_files) - 5} 个")

            if include_details and b.failed_files:
                print(f"      失败文件 ({len(b.failed_files)}):")
                for ff in b.failed_files:
                    retry_tag = f" (已重试 {ff['retry_count']} 次)" if ff["retry_count"] > 0 else ""
                    in_eq_tag = " [在错误队列]" if ff["in_error_queue"] else ""
                    print(f"        ✗ {ff['filename']}: {ff['error']}{retry_tag}{in_eq_tag}")
    else:
        print(f"\n  无批次数据")

    if report.conflicts:
        print(f"\n{'='*20} 文件名冲突 ({len(report.conflicts)} 个) {'='*20}")
        for c in report.conflicts:
            tags = []
            if c.in_queue:
                tags.append("在队列中")
            if c.in_error_queue:
                tags.append("在错误队列中")
            tag_str = f" [{', '.join(tags)}]" if tags else ""
            print(f"  ! {c.filename}")
            print(f"      intake: {c.intake_path}")
            print(f"      target: {c.target_path}{tag_str}")

    if report.retryable_items:
        print(f"\n{'='*20} 可重试项 ({len(report.retryable_items)} 个) {'='*20}")
        for r in report.retryable_items:
            progress = f" ({r.retry_count}/{r.max_retries})"
            batch_tag = f" [批次 {r.batch_id}]" if r.batch_id else ""
            print(f"  ↻ {r.filename}: {r.error}{progress}{batch_tag}")

    hc = report.healthcheck_summary
    print(f"\n{'='*20} 最近健康检查摘要 {'='*20}")
    if hc.last_check_time:
        print(f"  上次检查时间: {hc.last_check_time}")
    else:
        print(f"  上次检查时间: 未执行过")
    print(f"  问题总数: {hc.total_findings}")
    if hc.total_findings > 0:
        print(f"    严重: {hc.critical_count}, 警告: {hc.warning_count}, 信息: {hc.info_count}")
        print(f"    可自动修复: {hc.fixable_count}")

    output_path = args.output
    fmt = args.format
    if output_path or fmt:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"batch_report.{fmt}"

        if fmt == "json":
            export_report_json(report, output_path)
            print(f"\n  报告已导出 JSON: {output_path}")
        elif fmt == "csv":
            exported = export_report_csv(report, output_path)
            print(f"\n  报告已导出 CSV ({len(exported)} 个文件):")
            for p in exported:
                print(f"    {p}")

    print(f"\n{'='*60}")
    if report.exit_code == 0:
        print("✓ 报告生成成功，无异常")
    elif report.exit_code == 1:
        print("⚠ 报告生成成功，但存在警告")
    else:
        print("✗ 报告生成存在错误")

    return report.exit_code


def cmd_migrate(args: argparse.Namespace) -> int:
    new_config = load_config(args.config)
    old_config_path = args.old_config

    plan, state = generate_migration_plan(old_config_path, new_config)

    dry_run = not args.confirm

    if dry_run:
        print(f"\n{'='*60}")
        print(f"配置版本迁移计划 (dry-run 预览模式)")
        print(f"{'='*60}")
    else:
        print(f"\n{'='*60}")
        print(f"配置版本迁移 (执行模式)")
        print(f"{'='*60}")

    print(f"\n  旧配置: {os.path.abspath(old_config_path)}")
    print(f"  新配置: {new_config._source_path}")

    print(f"\n{'='*20} 配置差异 {'='*20}")
    diff = plan.config_diff
    if not diff.has_changes:
        print("  无配置差异，无需迁移")
        return 0

    if diff.intake_changed:
        print(f"  intake 目录: {diff.old_intake_dir} -> {diff.new_intake_dir}")
    if diff.target_base_changed:
        print(f"  target 目录: {diff.old_target_base} -> {diff.new_target_base}")
    if diff.operator_changed:
        print(f"  操作者: {diff.old_operator} -> {diff.new_operator}")
    if diff.case_pattern_changed:
        print(f"  案卷号规则: {diff.old_case_pattern} -> {diff.new_case_pattern}")
    if diff.file_pattern_changed:
        print(f"  文件名规则: {diff.old_file_pattern} -> {diff.new_file_pattern}")
    if diff.target_structure_changed:
        print(f"  目录结构: {diff.old_target_structure} -> {diff.new_target_structure}")
    if diff.action_changed:
        print(f"  操作方式: {diff.old_action} -> {diff.new_action}")

    summary = plan.summary()
    print(f"\n{'='*20} 迁移概览 {'='*20}")
    print(f"  总计待处理: {summary['total_items']} 项")
    print(f"  可自动迁移: {summary['auto_migrate']} 项")
    print(f"  冲突: {summary['conflicts']} 项")
    print(f"  需人工处理: {summary['manual_required']} 项")
    print(f"  已迁移跳过: {summary['skipped']} 项")

    if plan.items:
        print(f"\n{'='*20} 详细迁移项 {'='*20}")

        auto_items = [i for i in plan.items if i.action.value == "auto_migrate"]
        conflict_items = [i for i in plan.items if i.action.value == "conflict"]
        manual_items = [i for i in plan.items if i.action.value == "manual"]
        skipped_items = [i for i in plan.items if i.action.value == "skipped"]

        if auto_items:
            print(f"\n  [可自动迁移] ({len(auto_items)} 项)")
            for item in auto_items[:20]:
                print(f"    ✓ [{item.item_type.value}] {item.record_id} "
                      f"{item.field_name}: {item.old_value} -> {item.new_value}")
            if len(auto_items) > 20:
                print(f"    ... 还有 {len(auto_items) - 20} 项")

        if conflict_items:
            print(f"\n  [冲突] ({len(conflict_items)} 项)")
            for item in conflict_items[:20]:
                print(f"    ✗ [{item.item_type.value}] {item.record_id} "
                      f"{item.field_name}: {item.old_value} -> {item.new_value}")
                if item.conflict_detail:
                    print(f"       原因: {item.conflict_detail}")
            if len(conflict_items) > 20:
                print(f"    ... 还有 {len(conflict_items) - 20} 项")

        if manual_items:
            print(f"\n  [需人工处理] ({len(manual_items)} 项)")
            for item in manual_items[:20]:
                print(f"    ⚠ [{item.item_type.value}] {item.record_id} "
                      f"{item.field_name}: {item.old_value} -> {item.new_value}")
                if item.conflict_detail:
                    print(f"       原因: {item.conflict_detail}")
            if len(manual_items) > 20:
                print(f"    ... 还有 {len(manual_items) - 20} 项")

        if skipped_items:
            print(f"\n  [已迁移跳过] ({len(skipped_items)} 项)")
            for item in skipped_items[:10]:
                print(f"    ○ [{item.item_type.value}] {item.record_id} "
                      f"{item.field_name}: 已处理")
            if len(skipped_items) > 10:
                print(f"    ... 还有 {len(skipped_items) - 10} 项")

    plan_output = args.plan_output
    plan_format = args.plan_format
    if plan_output or plan_format:
        plan_format = plan_format or "json"
        if not plan_output:
            plan_output = f"migration_plan.{plan_format}"
        if plan_format == "json":
            export_plan_json(plan, plan_output)
            print(f"\n  迁移计划已导出 JSON: {plan_output}")
        elif plan_format == "csv":
            export_plan_csv(plan, plan_output)
            print(f"\n  迁移计划已导出 CSV: {plan_output}")

    if dry_run:
        print(f"\n{'='*60}")
        print("  预览完成。使用 --confirm 参数实际执行迁移")
        print(f"{'='*60}")
        return 0

    migrated, stats = execute_migration(
        plan, state, old_config_path, new_config, dry_run=False
    )

    print(f"\n{'='*20} 执行结果 {'='*20}")
    print(f"  自动迁移成功: {stats['auto_migrated']} 项")
    print(f"  冲突: {stats['conflicts']} 项")
    print(f"  需人工处理: {stats['manual_required']} 项")
    print(f"  跳过(已迁移): {stats['skipped']} 项")
    print(f"  失败: {stats['failed']} 项")

    result_output = args.result_output
    result_format = args.result_format
    if result_output or result_format:
        result_format = result_format or "json"
        if not result_output:
            result_output = f"migration_result.{result_format}"
        if result_format == "json":
            export_result_json(migrated, stats, result_output)
            print(f"\n  迁移结果已导出 JSON: {result_output}")
        elif result_format == "csv":
            export_result_csv(migrated, stats, result_output)
            print(f"\n  迁移结果已导出 CSV: {result_output}")

    if stats["conflicts"] > 0 or stats["manual_required"] > 0:
        print(f"\n{'='*60}")
        print("  ⚠ 存在冲突或需人工处理的项，请检查后手动处理")
        print(f"{'='*60}")
        return 1

    print(f"\n{'='*60}")
    print("✓ 配置迁移完成")
    print(f"{'='*60}")
    return 0


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

    p_plan = sub.add_parser("plan", help="预演计划 (dry-run): 预览归档结果，不实际执行")
    p_plan.add_argument("--max-files", type=int, help="最大预演文件数")
    p_plan.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_plan.add_argument("--output", help="计划导出路径")

    p_process = sub.add_parser("process", help="预检并执行入库")
    p_process.add_argument("--max-files", type=int, help="最大处理文件数")
    p_process.add_argument("--json", help="处理结果输出 JSON 路径")

    p_retry = sub.add_parser("retry", help="重试错误队列中的失败文件（简单模式，直接执行）")
    p_retry.add_argument("--limit", type=int, help="最大重试数量")
    p_retry.add_argument("--json", help="重试结果输出 JSON 路径")

    p_retry_plan = sub.add_parser("retry-plan", help="重试预检: 筛出可重试项，显示原始错误、新目标路径、预计动作、跳过原因")
    p_retry_plan.add_argument("--limit", type=int, help="最大预检数量")
    p_retry_plan.add_argument(
        "--retryable-only",
        action="store_true",
        default=False,
        help="只显示可重试项，不显示跳过项",
    )
    p_retry_plan.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_retry_plan.add_argument("--output", help="计划导出路径")

    p_retry_execute = sub.add_parser("retry-execute", help="重试执行: 按预检结果执行可重试项，生成独立批次")
    p_retry_execute.add_argument("--limit", type=int, help="最大执行数量")
    p_retry_execute.add_argument(
        "--paths",
        help="只执行指定路径的文件，多个路径用逗号分隔",
    )
    p_retry_execute.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_retry_execute.add_argument("--output", help="结果导出路径")

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
    p_export.add_argument(
        "--case-number",
        default=None,
        help="按案件号筛选 (仅 actions 和 errors 生效)",
    )

    p_reload = sub.add_parser("reload", help="重载配置")

    p_healthcheck = sub.add_parser("healthcheck", help="状态体检:扫描各状态文件一致性")
    p_healthcheck.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_healthcheck.add_argument("--output", help="体检结果导出路径")
    p_healthcheck.add_argument(
        "--compare-last",
        action="store_true",
        default=False,
        help="与上次体检结果对比，输出新增、已解决、持续存在三组结果",
    )

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

    p_report = sub.add_parser("report", help="批次复盘报告:汇总批次处理情况")
    p_report.add_argument(
        "--batch-id",
        default=None,
        help="指定批次 ID 过滤（默认显示所有批次）",
    )
    p_report.add_argument(
        "--brief",
        action="store_true",
        default=False,
        help="简洁模式，不显示文件详情",
    )
    p_report.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_report.add_argument("--output", help="报告导出路径")

    p_migrate = sub.add_parser("migrate", help="配置版本迁移:检查状态记录与新旧配置差异")
    p_migrate.add_argument(
        "--old-config",
        required=True,
        help="旧配置文件路径",
    )
    p_migrate.add_argument(
        "--confirm",
        action="store_true",
        default=False,
        help="确认实际执行迁移 (默认 dry-run 预览)",
    )
    p_migrate.add_argument(
        "--plan-format",
        choices=["json", "csv"],
        default=None,
        help="迁移计划导出格式 (不指定则不导出文件)",
    )
    p_migrate.add_argument(
        "--plan-output",
        help="迁移计划导出路径",
    )
    p_migrate.add_argument(
        "--result-format",
        choices=["json", "csv"],
        default=None,
        help="迁移结果导出格式 (不指定则不导出文件)",
    )
    p_migrate.add_argument(
        "--result-output",
        help="迁移结果导出路径",
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
        "plan": cmd_plan,
        "process": cmd_process,
        "retry": cmd_retry,
        "retry-plan": cmd_retry_plan,
        "retry-execute": cmd_retry_execute,
        "rollback": cmd_rollback,
        "watch": cmd_watch,
        "status": cmd_status,
        "export": cmd_export,
        "reload": cmd_reload,
        "healthcheck": cmd_healthcheck,
        "heal": cmd_heal,
        "report": cmd_report,
        "migrate": cmd_migrate,
    }

    handler = dispatch.get(args.command)
    if handler:
        result = handler(args)
        if isinstance(result, int):
            return result
        return 0
    else:
        parser.print_help()
        return 1
