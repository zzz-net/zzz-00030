from __future__ import annotations

import os
import signal
import time
from typing import Callable

from scan_sorter.batch_manager import BatchManager
from scan_sorter.config import AppConfig, reload_config


class Watcher:
    def __init__(
        self,
        config: AppConfig,
        on_process: Callable[[dict], None] | None = None,
    ):
        self.config = config
        self.poll_interval = config.watch.poll_interval
        self._running = False
        self._on_process = on_process
        self._seen: set[str] = set()
        self._init_seen()

    def _init_seen(self) -> None:
        intake_dir = os.path.abspath(self.config.intake_dir)
        if not os.path.isdir(intake_dir):
            return
        allowed = set(ext.lower() for ext in self.config.rules.allowed_extensions)
        for entry in os.scandir(intake_dir):
            if entry.is_file():
                ext = os.path.splitext(entry.name)[1].lower()
                if ext in allowed:
                    self._seen.add(os.path.abspath(entry.path))

    def _discover_new(self) -> list[str]:
        intake_dir = os.path.abspath(self.config.intake_dir)
        if not os.path.isdir(intake_dir):
            return []
        allowed = set(ext.lower() for ext in self.config.rules.allowed_extensions)
        new_files: list[str] = []
        for entry in os.scandir(intake_dir):
            if not entry.is_file():
                continue
            ext = os.path.splitext(entry.name)[1].lower()
            if ext not in allowed:
                continue
            abs_path = os.path.abspath(entry.path)
            if abs_path not in self._seen:
                new_files.append(abs_path)
                self._seen.add(abs_path)
        return new_files

    def _remove_seen(self, paths: list[str]) -> None:
        for p in paths:
            self._seen.discard(p)

    def start(self) -> None:
        self._running = True
        original_sigint = signal.getsignal(signal.SIGINT)
        original_sigterm = signal.getsignal(signal.SIGTERM)

        def _stop(signum, frame):
            self._running = False

        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)

        print(f"[watcher] 监听 {self.config.intake_dir}，间隔 {self.poll_interval}s，Ctrl+C 停止")

        while self._running:
            try:
                new_files = self._discover_new()
                if new_files:
                    print(f"[watcher] 发现 {len(new_files)} 个新文件，开始处理...")
                    mgr = BatchManager(self.config)
                    result = mgr.process()
                    if self._on_process:
                        self._on_process(result)
                    else:
                        print(f"[watcher] 处理结果: {result}")

                    remaining = []
                    for f in new_files:
                        if os.path.exists(f):
                            remaining.append(f)
                    self._remove_seen(remaining)

                time.sleep(self.poll_interval)
            except Exception as e:
                print(f"[watcher] 错误: {e}")
                time.sleep(self.poll_interval)

        signal.signal(signal.SIGINT, original_sigint)
        signal.signal(signal.SIGTERM, original_sigterm)
        print("[watcher] 已停止")

    def stop(self) -> None:
        self._running = False
