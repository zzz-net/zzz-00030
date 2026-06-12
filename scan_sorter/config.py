from __future__ import annotations

import os
import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from scan_sorter.models import RetentionRule


@dataclass
class RetentionConfig:
    enabled: bool = False
    state_file: str = "retention_state.json"
    log_file: str = "retention_log.jsonl"
    default_retention_days: int = 365
    check_write_permission: bool = True
    rules: list = field(default_factory=list)

    def state_path(self, logging_dir: str) -> str:
        return os.path.join(logging_dir, self.state_file)

    def log_path(self, logging_dir: str) -> str:
        return os.path.join(logging_dir, self.log_file)

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "state_file": self.state_file,
            "log_file": self.log_file,
            "default_retention_days": self.default_retention_days,
            "check_write_permission": self.check_write_permission,
            "rules": [r.to_dict() if hasattr(r, "to_dict") else r for r in self.rules],
        }


@dataclass
class RuleConfig:
    case_number_pattern: str = r"(\d{4}-[A-Z]\d{3})"
    file_pattern: str = r"(\d{4}-[A-Z]\d{3}-\d{3})\.(pdf|jpg|jpeg|png|tiff|bmp)$"
    allowed_extensions: list[str] = field(
        default_factory=lambda: [".pdf", ".jpg", ".jpeg", ".png", ".tiff", ".bmp"]
    )
    illegal_name_patterns: list[dict] = field(default_factory=list)
    target_structure: str = "{case_number}"
    action: str = "move"

    def to_dict(self) -> dict:
        return {
            "case_number_pattern": self.case_number_pattern,
            "file_pattern": self.file_pattern,
            "allowed_extensions": self.allowed_extensions,
            "illegal_name_patterns": self.illegal_name_patterns,
            "target_structure": self.target_structure,
            "action": self.action,
        }


@dataclass
class BatchConfig:
    max_size: int = 50
    stop_on_failure_ratio: float = 0.5

    def to_dict(self) -> dict:
        return {
            "max_size": self.max_size,
            "stop_on_failure_ratio": self.stop_on_failure_ratio,
        }


@dataclass
class LoggingConfig:
    dir: str = "./data"
    action_log: str = "action_log.jsonl"
    queue_file: str = "queue.json"
    error_queue_file: str = "error_queue.json"
    batch_history_file: str = "batch_history.json"

    def action_log_path(self) -> str:
        return os.path.join(self.dir, self.action_log)

    def queue_path(self) -> str:
        return os.path.join(self.dir, self.queue_file)

    def error_queue_path(self) -> str:
        return os.path.join(self.dir, self.error_queue_file)

    def batch_history_path(self) -> str:
        return os.path.join(self.dir, self.batch_history_file)

    def to_dict(self) -> dict:
        return {
            "dir": self.dir,
            "action_log": self.action_log,
            "queue_file": self.queue_file,
            "error_queue_file": self.error_queue_file,
            "batch_history_file": self.batch_history_file,
        }


@dataclass
class WatchConfig:
    poll_interval: int = 5

    def to_dict(self) -> dict:
        return {"poll_interval": self.poll_interval}


@dataclass
class AppConfig:
    intake_dir: str = "./samples/intake"
    target_base: str = "./samples/target"
    operator: str = "unknown"
    rules: RuleConfig = field(default_factory=RuleConfig)
    batch: BatchConfig = field(default_factory=BatchConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    watch: WatchConfig = field(default_factory=WatchConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    _source_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "intake_dir": self.intake_dir,
            "target_base": self.target_base,
            "operator": self.operator,
            "rules": self.rules.to_dict(),
            "batch": self.batch.to_dict(),
            "logging": self.logging.to_dict(),
            "watch": self.watch.to_dict(),
            "retention": self.retention.to_dict(),
        }


def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    rules_raw = raw.get("rules", {})
    rules = RuleConfig(
        case_number_pattern=rules_raw.get("case_number_pattern", r"(\d{4}-[A-Z]\d{3})"),
        file_pattern=rules_raw.get(
            "file_pattern",
            r"(\d{4}-[A-Z]\d{3}-\d{3})\.(pdf|jpg|jpeg|png|tiff|bmp)$",
        ),
        allowed_extensions=rules_raw.get(
            "allowed_extensions", [".pdf", ".jpg", ".jpeg", ".png", ".tiff", ".bmp"]
        ),
        illegal_name_patterns=rules_raw.get("illegal_name_patterns", []),
        target_structure=rules_raw.get("target_structure", "{case_number}"),
        action=rules_raw.get("action", "move"),
    )

    batch_raw = raw.get("batch", {})
    batch = BatchConfig(
        max_size=batch_raw.get("max_size", 50),
        stop_on_failure_ratio=batch_raw.get("stop_on_failure_ratio", 0.5),
    )

    logging_raw = raw.get("logging", {})
    logging = LoggingConfig(
        dir=logging_raw.get("dir", "./data"),
        action_log=logging_raw.get("action_log", "action_log.jsonl"),
        queue_file=logging_raw.get("queue_file", "queue.json"),
        error_queue_file=logging_raw.get("error_queue_file", "error_queue.json"),
        batch_history_file=logging_raw.get("batch_history_file", "batch_history.json"),
    )

    watch_raw = raw.get("watch", {})
    watch = WatchConfig(
        poll_interval=watch_raw.get("poll_interval", 5),
    )

    retention_raw = raw.get("retention", {})
    rules_raw = retention_raw.get("rules", [])
    retention_rules = []
    for r in rules_raw:
        retention_rules.append(RetentionRule.from_dict(r))
    retention = RetentionConfig(
        enabled=retention_raw.get("enabled", False),
        state_file=retention_raw.get("state_file", "retention_state.json"),
        log_file=retention_raw.get("log_file", "retention_log.jsonl"),
        default_retention_days=retention_raw.get("default_retention_days", 365),
        check_write_permission=retention_raw.get("check_write_permission", True),
        rules=retention_rules,
    )

    config = AppConfig(
        intake_dir=raw.get("intake_dir", "./samples/intake"),
        target_base=raw.get("target_base", "./samples/target"),
        operator=raw.get("operator", "unknown"),
        rules=rules,
        batch=batch,
        logging=logging,
        watch=watch,
        retention=retention,
        _source_path=os.path.abspath(path),
    )
    return config


def reload_config(config: AppConfig) -> AppConfig:
    if config._source_path and os.path.exists(config._source_path):
        return load_config(config._source_path)
    return copy.deepcopy(config)
