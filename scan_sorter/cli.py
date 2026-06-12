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
from scan_sorter.handoff_creator import (
    create_handoff_package,
    export_create_result_csv,
    export_create_result_json,
    get_create_history,
    preview_handoff,
)
from scan_sorter.handoff_validator import (
    export_verify_result_csv,
    export_verify_result_json,
    verify_handoff_package,
)
from scan_sorter.handoff_importer import (
    export_import_result_csv,
    export_import_result_json,
    export_rollback_result_csv,
    export_rollback_result_json,
    get_handoff_history,
    get_imported_packages,
    import_handoff_package,
    rollback_handoff_import,
)
from scan_sorter.config import AppConfig
from scan_sorter.retention_manager import (
    RetentionManager,
    export_preview_json,
    export_preview_csv,
    export_run_json,
    export_run_csv,
    export_history_json,
    export_history_csv,
)

_stdout_wrapped = False


def _wrap_stdout_for_windows():
    global _stdout_wrapped
    if _stdout_wrapped:
        return
    if sys.platform != "win32":
        return
    if not hasattr(sys.stdout, "buffer") or not hasattr(sys.stderr, "buffer"):
        return
    try:
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True
        )
        _stdout_wrapped = True
    except Exception:
        pass


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


def _target_config_summary_for_cli(config: AppConfig) -> dict:
    return {
        "intake_dir": os.path.abspath(config.intake_dir),
        "target_base": os.path.abspath(config.target_base),
        "operator": config.operator,
        "case_number_pattern": config.rules.case_number_pattern,
        "file_pattern": config.rules.file_pattern,
        "target_structure": config.rules.target_structure,
        "action": config.rules.action,
    }


def cmd_handoff_preview(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    case_numbers = None
    if args.case_numbers:
        case_numbers = [c.strip() for c in args.case_numbers.split(",") if c.strip()]
    batch_ids = None
    if args.batch_ids:
        batch_ids = [b.strip() for b in args.batch_ids.split(",") if b.strip()]

    preview = preview_handoff(config, case_numbers, batch_ids)

    print(f"\n{'='*60}")
    print(f"交接包预览")
    print(f"{'='*60}")
    print(f"  案件号数量: {len(preview.case_numbers)}")
    if preview.case_numbers:
        print(f"  案件号列表: {', '.join(preview.case_numbers)}")
    print(f"  批次数量: {len(preview.batch_ids)}")
    if preview.batch_ids:
        print(f"  批次 ID 列表: {', '.join(preview.batch_ids)}")
    print(f"  文件总数: {preview.total_files}")
    print(f"  总大小: {preview.total_size} 字节")
    print(f"  预计包大小: {preview.estimated_package_size} 字节")

    if preview.files:
        print(f"\n  {'='*20} 文件清单 {'='*20}")
        for fi in preview.files[:20]:
            print(f"    - {fi.filename}")
            print(f"      案件号: {fi.case_number}, 批次: {fi.batch_id}")
            print(f"      源路径: {fi.original_path}")
            print(f"      大小: {fi.size} 字节")
        if len(preview.files) > 20:
            print(f"    ... 还有 {len(preview.files) - 20} 个文件")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"handoff_preview.{fmt}"
        if fmt == "json":
            from scan_sorter.utils import save_json
            save_json(output_path, preview.to_dict())
            print(f"\n  预览已导出 JSON: {output_path}")
        elif fmt == "csv":
            import csv as csv_mod
            from scan_sorter.utils import ensure_dir
            ensure_dir(os.path.dirname(output_path))
            fieldnames = [
                "filename", "case_number", "batch_id", "size",
                "original_path", "relative_path",
            ]
            with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv_mod.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for fi in preview.files:
                    row = fi.to_dict()
                    row = {k: row.get(k, "") for k in fieldnames}
                    writer.writerow(row)
            print(f"\n  预览已导出 CSV: {output_path}")


def cmd_handoff_create(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    case_numbers = None
    if args.case_numbers:
        case_numbers = [c.strip() for c in args.case_numbers.split(",") if c.strip()]
    batch_ids = None
    if args.batch_ids:
        batch_ids = [b.strip() for b in args.batch_ids.split(",") if b.strip()]

    output_dir = args.output_dir or "./handoff_packages"
    description = args.description or ""

    print(f"\n{'='*60}")
    print(f"创建交接包")
    print(f"{'='*60}")
    print(f"  输出目录: {os.path.abspath(output_dir)}")
    if case_numbers:
        print(f"  案件号: {', '.join(case_numbers)}")
    if batch_ids:
        print(f"  批次 ID: {', '.join(batch_ids)}")
    if description:
        print(f"  描述: {description}")

    try:
        state, package_zip = create_handoff_package(
            config, output_dir, case_numbers, batch_ids,
            description=description, resume=not args.no_resume,
        )
    except ValueError as e:
        print(f"\n  ✗ 创建失败: {e}")
        return 1

    print(f"\n{'='*20} 创建结果 {'='*20}")
    print(f"  包 ID: {state.package_id}")
    print(f"  状态: {state.status.value}")
    print(f"  文件总数: {state.manifest.total_files if state.manifest else 0}")
    print(f"  成功处理: {len(state.files_processed)}")
    print(f"  失败: {len(state.files_failed)}")
    print(f"  压缩包: {package_zip}")

    if state.files_failed:
        print(f"\n  失败文件:")
        for fp in state.files_failed[:10]:
            print(f"    - {fp}")
        if len(state.files_failed) > 10:
            print(f"    ... 还有 {len(state.files_failed) - 10} 个")

    fmt = args.format
    result_output = args.output
    if fmt or result_output:
        fmt = fmt or "json"
        if not result_output:
            result_output = f"handoff_create_{state.package_id}.{fmt}"
        if fmt == "json":
            export_create_result_json(state, result_output)
            print(f"\n  结果已导出 JSON: {result_output}")
        elif fmt == "csv":
            export_create_result_csv(state, result_output)
            print(f"\n  结果已导出 CSV: {result_output}")

    if state.status.value == "created":
        print(f"\n{'='*60}")
        print("✓ 交接包创建完成")
        print(f"{'='*60}")
        return 0
    else:
        print(f"\n{'='*60}")
        print("⚠ 交接包创建存在失败项")
        print(f"{'='*60}")
        return 1


def cmd_handoff_verify(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    package_path = args.package

    target_cfg = None
    if not args.ignore_config:
        target_cfg = _target_config_summary_for_cli(config)

    print(f"\n{'='*60}")
    print(f"校验交接包")
    print(f"{'='*60}")
    print(f"  包路径: {os.path.abspath(package_path)}")

    result, temp_dir = verify_handoff_package(package_path, target_cfg)

    print(f"\n  包 ID: {result.package_id or '未知'}")
    print(f"  是否有效: {result.is_valid}")
    print(f"  Manifest 存在: {result.manifest_exists}")
    print(f"  文件完整性: {result.integrity_ok}")
    print(f"  文件齐全: {result.files_complete}")
    print(f"  内容匹配: {result.files_match}")

    if result.errors:
        print(f"\n  错误 ({len(result.errors)} 项):")
        for e in result.errors:
            print(f"    ✗ {e}")

    if result.warnings:
        print(f"\n  警告 ({len(result.warnings)} 项):")
        for w in result.warnings:
            print(f"    ⚠ {w}")

    if result.missing_files:
        print(f"\n  缺失文件 ({len(result.missing_files)} 个):")
        for mf in result.missing_files:
            print(f"    - {mf.relative_path}")

    if result.tampered_files:
        print(f"\n  被篡改文件 ({len(result.tampered_files)} 个):")
        for tf in result.tampered_files:
            print(f"    - {tf.relative_path} (预期 SHA: {tf.sha256})")

    if result.manifest:
        m = result.manifest
        print(f"\n  {'='*20} 包信息 {'='*20}")
        print(f"    创建时间: {m.created_at}")
        print(f"    源操作者: {m.source_operator}")
        print(f"    源主机: {m.source_host}")
        print(f"    案件号: {', '.join(m.case_numbers)}")
        print(f"    批次: {', '.join(m.batch_ids)}")
        print(f"    文件数: {m.total_files}")
        print(f"    总大小: {m.total_size} 字节")
        if m.description:
            print(f"    描述: {m.description}")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            pid = result.package_id or "unknown"
            output_path = f"handoff_verify_{pid}.{fmt}"
        if fmt == "json":
            export_verify_result_json(result, output_path)
            print(f"\n  校验结果已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_verify_result_csv(result, output_path)
            print(f"\n  校验结果已导出 CSV: {output_path}")

    print(f"\n{'='*60}")
    if result.is_valid:
        print("✓ 交接包校验通过")
        print(f"{'='*60}")
        return 0
    else:
        print("✗ 交接包校验失败")
        print(f"{'='*60}")
        return 1


def cmd_handoff_import(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    package_path = args.package

    print(f"\n{'='*60}")
    print(f"导入交接包")
    print(f"{'='*60}")
    print(f"  包路径: {os.path.abspath(package_path)}")
    print(f"  目标目录: {os.path.abspath(config.target_base)}")

    result = import_handoff_package(
        package_path, config,
        resume=not args.no_resume,
        allow_config_mismatch=args.allow_config_mismatch,
        allow_partial=args.allow_partial,
    )

    print(f"\n{'='*20} 导入结果 {'='*20}")
    print(f"  包 ID: {result.package_id}")
    print(f"  状态: {result.status.value}")
    print(f"  成功: {result.success}")
    print(f"  文件总数: {result.total_files}")
    print(f"  已导入: {result.imported}")
    print(f"  跳过(冲突): {result.skipped}")
    print(f"  失败: {result.failed}")
    print(f"  状态文件: {result.state_path}")

    if result.warnings:
        print(f"\n  警告 ({len(result.warnings)} 项):")
        for w in result.warnings:
            print(f"    ⚠ {w}")

    if result.conflicts:
        print(f"\n  冲突明细 ({len(result.conflicts)} 项):")
        for c in result.conflicts:
            fn = c.file_item.filename if c.file_item else "无文件"
            print(f"    ✗ [{c.conflict_type.value}] {fn}")
            if c.target_path:
                print(f"       目标路径: {c.target_path}")
            if c.detail:
                print(f"       详情: {c.detail}")

    if result.imported_files:
        print(f"\n  已导入文件 ({len(result.imported_files)} 个):")
        for p in result.imported_files[:20]:
            print(f"    ✓ {p}")
        if len(result.imported_files) > 20:
            print(f"    ... 还有 {len(result.imported_files) - 20} 个")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"handoff_import_{result.package_id}.{fmt}"
        if fmt == "json":
            export_import_result_json(result, output_path)
            print(f"\n  导入结果已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_import_result_csv(result, output_path)
            print(f"\n  导入结果已导出 CSV: {output_path}")

    print(f"\n{'='*60}")
    if result.success:
        if result.status.value == "partial_imported":
            print("⚠ 部分导入成功（存在冲突或失败项）")
        else:
            print("✓ 交接包导入完成")
        print(f"{'='*60}")
        return 0 if result.status.value == "imported" else 1
    else:
        print("✗ 交接包导入失败")
        print(f"{'='*60}")
        return 1


def cmd_handoff_rollback(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    package_id = args.package_id

    print(f"\n{'='*60}")
    print(f"撤销交接包导入")
    print(f"{'='*60}")
    print(f"  包 ID: {package_id}")
    print(f"  注意: 仅回退本次导入实际写入的内容，审计日志将保留")

    state, result = rollback_handoff_import(package_id, config)

    print(f"\n{'='*20} 撤销结果 {'='*20}")
    print(f"  成功: {result.success}")
    print(f"  回退文件数: {result.total_rolled_back}")
    print(f"  保留审计日志: {result.kept_audit_log}")
    print(f"  操作 ID: {result.operation_id}")

    if result.rolled_back_files:
        print(f"\n  已回退文件 ({len(result.rolled_back_files)} 个):")
        for p in result.rolled_back_files:
            print(f"    ✓ {p}")

    if result.failed_rollbacks:
        print(f"\n  回退失败 ({len(result.failed_rollbacks)} 项):")
        for fr in result.failed_rollbacks:
            print(f"    ✗ {fr.get('path', '')}: {fr.get('error', '')}")

    if result.details:
        print(f"\n  详细记录:")
        for d in result.details:
            icon = "✓" if d.get("ok") else "✗"
            print(f"    {icon} {d.get('detail', '')}")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"handoff_rollback_{package_id}.{fmt}"
        if fmt == "json":
            export_rollback_result_json(result, output_path)
            print(f"\n  撤销结果已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_rollback_result_csv(result, output_path)
            print(f"\n  撤销结果已导出 CSV: {output_path}")

    print(f"\n{'='*60}")
    if result.success:
        print("✓ 交接包导入已撤销")
        print(f"{'='*60}")
        return 0
    else:
        print("✗ 撤销失败")
        print(f"{'='*60}")
        return 1


def cmd_handoff_history(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    data_dir = os.path.abspath(config.logging.dir)

    print(f"\n{'='*60}")
    print(f"交接包操作历史")
    print(f"{'='*60}")
    print(f"  数据目录: {data_dir}")

    imported = get_imported_packages(data_dir)
    print(f"\n  已导入包 ID ({len(imported)} 个):")
    for pid in imported:
        print(f"    - {pid}")

    history = get_handoff_history(data_dir, args.package_id)
    print(f"\n  操作记录 ({len(history)} 条):")

    if not history:
        print("    (无记录)")
    else:
        for rec in history:
            print(f"\n    [{rec.get('operation_type', '')}] {rec.get('timestamp', '')}")
            print(f"      包 ID: {rec.get('package_id', '')}")
            print(f"      操作者: {rec.get('operator', '')}")
            print(f"      状态: {rec.get('status', '')}")
            details = rec.get("details", {})
            if details:
                for k, v in details.items():
                    if isinstance(v, list) and len(v) > 5:
                        print(f"      {k}: [{len(v)} 项]")
                    else:
                        print(f"      {k}: {v}")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            suffix = args.package_id or "all"
            output_path = f"handoff_history_{suffix}.{fmt}"
        if fmt == "json":
            from scan_sorter.utils import save_json
            save_json(output_path, {
                "imported_packages": imported,
                "operations": history,
            })
            print(f"\n  历史已导出 JSON: {output_path}")
        elif fmt == "csv":
            import csv as csv_mod
            from scan_sorter.utils import ensure_dir
            ensure_dir(os.path.dirname(output_path))
            fieldnames = [
                "operation_id", "operation_type", "timestamp",
                "operator", "package_id", "status", "details",
            ]
            with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv_mod.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for rec in history:
                    row = {k: rec.get(k, "") for k in fieldnames}
                    if isinstance(row["details"], dict):
                        row["details"] = json.dumps(row["details"], ensure_ascii=False)
                    writer.writerow(row)
            print(f"\n  历史已导出 CSV: {output_path}")


def _disposal_status_label(status) -> str:
    from scan_sorter.models import DisposalStatus as DS
    return {
        DS.PENDING: "○ 未到期",
        DS.EXPIRED: "⏰ 已到期",
        DS.DEFERRED: "⏳ 暂缓",
        DS.MARKED: "🔴 已标记销毁",
        DS.CONFLICT: "⚠ 存在冲突",
        DS.UNDO: "↺ 已撤销",
    }.get(status, status.value)


def cmd_retention_preview(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = RetentionManager(config)

    case_numbers = None
    if args.case_numbers:
        case_numbers = [c.strip() for c in args.case_numbers.split(",") if c.strip()]
    batch_ids = None
    if args.batch_ids:
        batch_ids = [b.strip() for b in args.batch_ids.split(",") if b.strip()]

    preview = mgr.preview(case_numbers=case_numbers, batch_ids=batch_ids)

    print(f"\n{'='*60}")
    print(f"归档保留期限预览")
    print(f"{'='*60}")
    print(f"  目标目录: {os.path.abspath(config.target_base)}")
    print(f"  归档文件总数: {preview.total_files}")
    print(f"  已到期: {preview.expired_count}")
    print(f"  未到期: {preview.pending_count}")
    print(f"  暂缓: {preview.deferred_count}")
    print(f"  冲突: {preview.conflict_count}")

    if preview.rule_summary:
        print(f"\n  {'='*20} 规则统计 {'='*20}")
        for k, v in preview.rule_summary.items():
            print(f"    {k}: {v} 个文件")

    if preview.items:
        print(f"\n  {'='*20} 文件明细 {'='*20}")
        for item in preview.items[:50]:
            fname = item.file.filename if item.file else "(无文件)"
            case = item.file.case_number if item.file else ""
            status_label = _disposal_status_label(item.disposal_status)
            line = f"  {status_label} {fname}"
            if case:
                line += f" [案件: {case}]"
            line += f" 到期: {item.expires_at}"
            if item.matched_rule_name:
                line += f" 规则: {item.matched_rule_name}({item.retention_days}天)"
            print(line)

            if item.defer_reason:
                print(f"      ⏳ 暂缓原因: {item.defer_reason}")
                if item.defer_until:
                    print(f"      暂缓至: {item.defer_until}")
            if item.conflicts:
                for c in item.conflicts:
                    print(f"      ⚠ [{c.category.value}] {c.detail}")
        if len(preview.items) > 50:
            print(f"    ... 还有 {len(preview.items) - 50} 个文件")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"retention_preview.{fmt}"
        if fmt == "json":
            export_preview_json(preview, output_path)
            print(f"\n  预览已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_preview_csv(preview, output_path)
            print(f"\n  预览已导出 CSV: {output_path}")


def cmd_retention_generate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    mgr = RetentionManager(config)

    case_numbers = None
    if args.case_numbers:
        case_numbers = [c.strip() for c in args.case_numbers.split(",") if c.strip()]
    batch_ids = None
    if args.batch_ids:
        batch_ids = [b.strip() for b in args.batch_ids.split(",") if b.strip()]

    if not args.confirm:
        print(f"\n{'='*60}")
        print(f"归档销毁清单预览模式 (使用 --confirm 确认生成)")
        print(f"{'='*60}")
        preview = mgr.preview(case_numbers=case_numbers, batch_ids=batch_ids)
        print(f"  预计标记销毁: {preview.expired_count} 个文件")
        print(f"  冲突跳过: {preview.conflict_count} 个文件")
        print(f"  已暂缓: {preview.deferred_count} 个文件")
        return 0

    notes = args.notes or ""
    run = mgr.generate_disposal_list(
        case_numbers=case_numbers, batch_ids=batch_ids, notes=notes,
    )

    print(f"\n{'='*60}")
    print(f"归档销毁处置清单")
    print(f"{'='*60}")
    print(f"  运行 ID: {run.run_id}")
    print(f"  操作者: {run.operator}")
    print(f"  创建时间: {run.created_at}")
    print(f"  已标记销毁: {run.total_marked}")
    print(f"  暂缓: {run.total_deferred}")
    print(f"  冲突: {run.total_conflicts}")
    if run.notes:
        print(f"  备注: {run.notes}")

    for item in run.items:
        fname = item.file.filename if item.file else "(无文件)"
        status_label = _disposal_status_label(item.disposal_status)
        print(f"    {status_label} {fname}")
        if item.conflicts:
            for c in item.conflicts:
                print(f"        ⚠ [{c.category.value}] {c.detail}")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"retention_generate_{run.run_id}.{fmt}"
        if fmt == "json":
            export_run_json(run, output_path)
            print(f"\n  清单已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_run_csv(run, output_path)
            print(f"\n  清单已导出 CSV: {output_path}")

    check = mgr.consistency_check()
    print(f"\n  状态一致性: {'✓ 通过' if check['is_consistent'] else '✗ 存在问题'}")
    if not check["is_consistent"]:
        for issue in check["issues"]:
            print(f"    ⚠ {issue['type']}: {issue['count']} 项")
        return 1
    return 0


def cmd_retention_history(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = RetentionManager(config)

    run_type = getattr(args, "run_type", None)
    limit = getattr(args, "limit", None)

    runs = mgr.list_runs(run_type=run_type, limit=limit)

    print(f"\n{'='*60}")
    print(f"归档销毁运行历史")
    print(f"{'='*60}")
    print(f"  状态文件: {mgr.state_path}")
    print(f"  记录总数: {len(runs)}")

    if not runs:
        print("  (无记录)")
    else:
        for run in runs:
            print(f"\n  [{run.run_id}] {run.run_type}")
            print(f"      时间: {run.created_at}")
            print(f"      操作者: {run.operator}")
            if run.run_type == "generate":
                print(f"      标记销毁: {run.total_marked}, 暂缓: {run.total_deferred}, 冲突: {run.total_conflicts}")
            elif run.run_type == "defer":
                print(f"      暂缓: {run.total_deferred}, 冲突: {run.total_conflicts}")
            elif run.run_type == "undo":
                print(f"      撤销: {run.total_undone}, 冲突: {run.total_conflicts}")
            if run.notes:
                print(f"      备注: {run.notes}")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            suffix = run_type or "all"
            output_path = f"retention_history_{suffix}.{fmt}"
        if fmt == "json":
            export_history_json(runs, output_path)
            print(f"\n  历史已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_history_csv(runs, output_path)
            print(f"\n  历史已导出 CSV: {output_path}")


def cmd_retention_export(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    mgr = RetentionManager(config)

    fmt = args.format or "json"
    source = args.source or "marked"
    output_path = args.output

    if source == "marked":
        items = mgr.get_marked_files()
        from scan_sorter.models import RetentionPreviewResult
        data = {
            "source": "marked",
            "total": len(items),
            "items": [i.to_dict() for i in items],
        }
        if not output_path:
            output_path = f"retention_marked.{fmt}"
        if fmt == "json":
            from scan_sorter.utils import save_json
            save_json(output_path, data)
            print(f"已导出 JSON: {output_path} ({len(items)} 条)")
        elif fmt == "csv":
            import csv as csv_mod
            from scan_sorter.utils import ensure_dir
            ensure_dir(os.path.dirname(output_path))
            fieldnames = [
                "filename", "path", "case_number", "batch_id",
                "disposal_status", "expires_at", "defer_until",
                "matched_rule_name", "retention_days", "marked_run_id",
            ]
            with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv_mod.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for it in items:
                    fi = it.file.to_dict() if it.file else {}
                    row = {
                        "filename": fi.get("filename", ""),
                        "path": fi.get("path", ""),
                        "case_number": fi.get("case_number", ""),
                        "batch_id": fi.get("batch_id", ""),
                        "disposal_status": it.disposal_status.value,
                        "expires_at": it.expires_at,
                        "defer_until": it.defer_until,
                        "matched_rule_name": it.matched_rule_name,
                        "retention_days": it.retention_days,
                        "marked_run_id": it.marked_run_id,
                    }
                    writer.writerow(row)
            print(f"已导出 CSV: {output_path} ({len(items)} 条)")
    elif source == "runs":
        runs = mgr.list_runs()
        if not output_path:
            output_path = f"retention_runs.{fmt}"
        if fmt == "json":
            export_history_json(runs, output_path)
            print(f"已导出历史 JSON: {output_path} ({len(runs)} 条)")
        elif fmt == "csv":
            export_history_csv(runs, output_path)
            print(f"已导出历史 CSV: {output_path} ({len(runs)} 条)")
    elif source == "run":
        run_id = args.run_id
        if not run_id:
            print("✗ 导出单个运行需指定 --run-id")
            return
        run = mgr.get_run(run_id)
        if not run:
            print(f"✗ 未找到运行: {run_id}")
            return
        if not output_path:
            output_path = f"retention_run_{run_id}.{fmt}"
        if fmt == "json":
            export_run_json(run, output_path)
            print(f"已导出运行 JSON: {output_path} ({len(run.items)} 项)")
        elif fmt == "csv":
            export_run_csv(run, output_path)
            print(f"已导出运行 CSV: {output_path} ({len(run.items)} 项)")
    elif source == "preview":
        case_numbers = None
        if args.case_numbers:
            case_numbers = [c.strip() for c in args.case_numbers.split(",") if c.strip()]
        batch_ids = None
        if args.batch_ids:
            batch_ids = [b.strip() for b in args.batch_ids.split(",") if b.strip()]
        preview = mgr.preview(case_numbers=case_numbers, batch_ids=batch_ids)
        if not output_path:
            output_path = f"retention_preview_export.{fmt}"
        if fmt == "json":
            export_preview_json(preview, output_path)
            print(f"已导出预览 JSON: {output_path} ({preview.total_files} 项)")
        elif fmt == "csv":
            export_preview_csv(preview, output_path)
            print(f"已导出预览 CSV: {output_path} ({preview.total_files} 项)")


def cmd_retention_defer(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    mgr = RetentionManager(config)

    paths = None
    if args.paths:
        paths = [p.strip() for p in args.paths.split(",") if p.strip()]
    if not paths:
        print("✗ 请使用 --paths 指定要暂缓的文件路径，多个用逗号分隔")
        return 1

    case_numbers = None
    if args.case_numbers:
        case_numbers = [c.strip() for c in args.case_numbers.split(",") if c.strip()]
    batch_ids = None
    if args.batch_ids:
        batch_ids = [b.strip() for b in args.batch_ids.split(",") if b.strip()]

    reason = args.reason or ""
    defer_days = int(args.days) if args.days else 30

    run = mgr.mark_deferred(
        paths=paths,
        reason=reason,
        defer_days=defer_days,
        case_numbers=case_numbers,
        batch_ids=batch_ids,
    )

    print(f"\n{'='*60}")
    print(f"归档暂缓标记结果")
    print(f"{'='*60}")
    print(f"  运行 ID: {run.run_id}")
    print(f"  操作者: {run.operator}")
    print(f"  创建时间: {run.created_at}")
    print(f"  暂缓天数: {defer_days} 天")
    print(f"  暂缓成功: {run.total_deferred}")
    print(f"  冲突跳过: {run.total_conflicts}")
    if reason:
        print(f"  暂缓原因: {reason}")

    for item in run.items:
        fname = item.file.filename if item.file else "(无文件)"
        status_label = _disposal_status_label(item.disposal_status)
        print(f"    {status_label} {fname}")
        if item.disposal_status.value == "deferred":
            print(f"        暂缓至: {item.defer_until}")
        if item.conflicts:
            for c in item.conflicts:
                print(f"        ⚠ [{c.category.value}] {c.detail}")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"retention_defer_{run.run_id}.{fmt}"
        if fmt == "json":
            export_run_json(run, output_path)
            print(f"\n  暂缓结果已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_run_csv(run, output_path)
            print(f"\n  暂缓结果已导出 CSV: {output_path}")

    if run.total_conflicts > 0:
        return 1
    return 0


def cmd_retention_undo(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    mgr = RetentionManager(config)
    run_id = args.run_id

    if not run_id:
        print("✗ 请指定要撤销的运行 ID (--run-id)")
        return 1

    try:
        run = mgr.undo_run(run_id)
    except ValueError as e:
        print(f"✗ 撤销失败: {e}")
        return 1

    print(f"\n{'='*60}")
    print(f"撤销运行结果")
    print(f"{'='*60}")
    print(f"  撤销目标运行: {run_id}")
    print(f"  撤销操作 ID: {run.run_id}")
    print(f"  操作者: {run.operator}")
    print(f"  创建时间: {run.created_at}")
    print(f"  成功撤销: {run.total_undone}")
    print(f"  冲突跳过: {run.total_conflicts}")
    print(f"  注意: 仅回退本次运行的变更，审计日志保留")

    for item in run.items:
        fname = item.file.filename if item.file else "(无文件)"
        status_label = _disposal_status_label(item.disposal_status)
        print(f"    {status_label} {fname}")
        if item.conflicts:
            for c in item.conflicts:
                print(f"        ⚠ [{c.category.value}] {c.detail}")

    fmt = args.format
    output_path = args.output
    if fmt or output_path:
        fmt = fmt or "json"
        if not output_path:
            output_path = f"retention_undo_{run.run_id}.{fmt}"
        if fmt == "json":
            export_run_json(run, output_path)
            print(f"\n  撤销结果已导出 JSON: {output_path}")
        elif fmt == "csv":
            export_run_csv(run, output_path)
            print(f"\n  撤销结果已导出 CSV: {output_path}")

    if run.total_conflicts > 0:
        return 1
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

    p_hp = sub.add_parser("handoff-preview", help="交接包预览:查看待打包的归档文件和统计")
    p_hp.add_argument(
        "--case-numbers",
        default=None,
        help="按案件号筛选，多个用逗号分隔",
    )
    p_hp.add_argument(
        "--batch-ids",
        default=None,
        help="按批次 ID 筛选，多个用逗号分隔",
    )
    p_hp.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_hp.add_argument("--output", help="预览结果导出路径")

    p_hc = sub.add_parser("handoff-create", help="交接包创建:按案件号或批次生成可携带交接包")
    p_hc.add_argument(
        "--case-numbers",
        default=None,
        help="按案件号筛选，多个用逗号分隔",
    )
    p_hc.add_argument(
        "--batch-ids",
        default=None,
        help="按批次 ID 筛选，多个用逗号分隔",
    )
    p_hc.add_argument(
        "--output-dir",
        default=None,
        help="交接包输出目录 (默认: ./handoff_packages)",
    )
    p_hc.add_argument("--description", default=None, help="交接包描述")
    p_hc.add_argument(
        "--no-resume",
        action="store_true",
        default=False,
        help="不使用断点续传，从头开始创建",
    )
    p_hc.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_hc.add_argument("--output", help="创建结果导出路径")

    p_hv = sub.add_parser("handoff-verify", help="交接包校验:检查包完整性、文件未被篡改")
    p_hv.add_argument("package", help="交接包路径（zip 文件或目录）")
    p_hv.add_argument(
        "--ignore-config",
        action="store_true",
        default=False,
        help="跳过源/目标配置差异检查",
    )
    p_hv.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_hv.add_argument("--output", help="校验结果导出路径")

    p_hi = sub.add_parser("handoff-import", help="交接包导入:将交接包内容校验后导入目标环境")
    p_hi.add_argument("package", help="交接包路径（zip 文件或目录）")
    p_hi.add_argument(
        "--no-resume",
        action="store_true",
        default=False,
        help="不使用断点续传，从头开始导入",
    )
    p_hi.add_argument(
        "--allow-config-mismatch",
        action="store_true",
        default=False,
        help="允许源与目标配置存在差异（会显示警告）",
    )
    p_hi.add_argument(
        "--allow-partial",
        action="store_true",
        default=False,
        help="允许部分导入（存在冲突时仅导入无冲突文件）",
    )
    p_hi.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_hi.add_argument("--output", help="导入结果导出路径")

    p_hrb = sub.add_parser("handoff-rollback", help="交接包撤销:回退本次导入实际写入的文件，保留审计日志")
    p_hrb.add_argument("package_id", help="要撤销的交接包 ID")
    p_hrb.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_hrb.add_argument("--output", help="撤销结果导出路径")

    p_hh = sub.add_parser("handoff-history", help="交接包历史:查询交接包创建、导入、撤销操作记录")
    p_hh.add_argument(
        "--package-id",
        default=None,
        help="按交接包 ID 筛选",
    )
    p_hh.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_hh.add_argument("--output", help="历史记录导出路径")

    p_rp = sub.add_parser("retention-preview", help="保留期限预览:扫描归档目录，计算到期、暂缓、冲突情况")
    p_rp.add_argument(
        "--case-numbers",
        default=None,
        help="按案件号筛选，多个用逗号分隔",
    )
    p_rp.add_argument(
        "--batch-ids",
        default=None,
        help="按批次 ID 筛选，多个用逗号分隔",
    )
    p_rp.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_rp.add_argument("--output", help="预览结果导出路径")

    p_rg = sub.add_parser("retention-generate", help="生成销毁清单:确认后标记到期文件为待销毁，写入状态文件")
    p_rg.add_argument(
        "--case-numbers",
        default=None,
        help="按案件号筛选，多个用逗号分隔",
    )
    p_rg.add_argument(
        "--batch-ids",
        default=None,
        help="按批次 ID 筛选，多个用逗号分隔",
    )
    p_rg.add_argument(
        "--confirm",
        action="store_true",
        default=False,
        help="确认实际生成 (默认仅预览)",
    )
    p_rg.add_argument("--notes", default=None, help="本次运行备注")
    p_rg.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_rg.add_argument("--output", help="清单导出路径")

    p_rh = sub.add_parser("retention-history", help="保留运行历史:查询生成、暂缓、撤销操作记录")
    p_rh.add_argument(
        "--run-type",
        choices=["generate", "defer", "undo"],
        default=None,
        help="按运行类型筛选",
    )
    p_rh.add_argument(
        "--limit",
        type=int,
        default=None,
        help="限制返回的最近记录数",
    )
    p_rh.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_rh.add_argument("--output", help="历史记录导出路径")

    p_re = sub.add_parser("retention-export", help="保留数据导出:导出标记清单、运行历史、预览")
    p_re.add_argument(
        "--source",
        choices=["marked", "runs", "run", "preview"],
        default="marked",
        help="导出源 (默认: marked 标记的文件)",
    )
    p_re.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="导出格式 (默认: json)",
    )
    p_re.add_argument("--output", help="输出文件路径")
    p_re.add_argument("--run-id", default=None, help="单个运行 ID (source=run 时必填)")
    p_re.add_argument(
        "--case-numbers",
        default=None,
        help="source=preview 时按案件号筛选",
    )
    p_re.add_argument(
        "--batch-ids",
        default=None,
        help="source=preview 时按批次 ID 筛选",
    )

    p_rd = sub.add_parser("retention-defer", help="暂缓销毁:指定文件路径标记暂缓，可设暂缓天数和原因")
    p_rd.add_argument(
        "--paths",
        default=None,
        help="要暂缓的文件路径，多个用逗号分隔",
    )
    p_rd.add_argument(
        "--case-numbers",
        default=None,
        help="按案件号限定范围",
    )
    p_rd.add_argument(
        "--batch-ids",
        default=None,
        help="按批次 ID 限定范围",
    )
    p_rd.add_argument(
        "--days",
        type=int,
        default=30,
        help="暂缓天数 (默认 30 天)",
    )
    p_rd.add_argument("--reason", default=None, help="暂缓原因")
    p_rd.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_rd.add_argument("--output", help="暂缓结果导出路径")

    p_ru = sub.add_parser("retention-undo", help="撤销本次标记:仅回退指定运行的变更，保留审计日志")
    p_ru.add_argument("--run-id", help="要撤销的运行 ID")
    p_ru.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="导出格式 (不指定则不导出文件)",
    )
    p_ru.add_argument("--output", help="撤销结果导出路径")

    return parser


def main(argv: list[str] | None = None) -> int:
    _wrap_stdout_for_windows()
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
        "handoff-preview": cmd_handoff_preview,
        "handoff-create": cmd_handoff_create,
        "handoff-verify": cmd_handoff_verify,
        "handoff-import": cmd_handoff_import,
        "handoff-rollback": cmd_handoff_rollback,
        "handoff-history": cmd_handoff_history,
        "retention-preview": cmd_retention_preview,
        "retention-generate": cmd_retention_generate,
        "retention-history": cmd_retention_history,
        "retention-export": cmd_retention_export,
        "retention-defer": cmd_retention_defer,
        "retention-undo": cmd_retention_undo,
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
