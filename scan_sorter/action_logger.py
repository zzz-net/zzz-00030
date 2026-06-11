from __future__ import annotations

import os
import shutil
from typing import Optional

from scan_sorter.models import ActionRecord, ActionType
from scan_sorter.utils import append_jsonl, read_jsonl


class ActionLogger:
    def __init__(self, path: str):
        self.path = path

    def log(self, record: ActionRecord) -> None:
        append_jsonl(self.path, record.to_dict())

    def get_by_batch(self, batch_id: str) -> list[ActionRecord]:
        records = read_jsonl(self.path)
        return [
            ActionRecord.from_dict(r)
            for r in records
            if r.get("batch_id") == batch_id
        ]

    def get_non_rolled_back(self, batch_id: str) -> list[ActionRecord]:
        return [
            r
            for r in self.get_by_batch(batch_id)
            if not r.rolled_back
        ]

    def mark_rolled_back(self, action_id: str) -> None:
        records = read_jsonl(self.path)
        updated = []
        for r in records:
            if r.get("action_id") == action_id:
                r["rolled_back"] = True
            updated.append(r)

        from scan_sorter.utils import save_json
        with open(self.path, "w", encoding="utf-8") as f:
            for rec in updated:
                f.write(
                    __import__("json").dumps(rec, ensure_ascii=False) + "\n"
                )

    def rollback_batch(self, batch_id: str) -> list[dict]:
        actions = self.get_non_rolled_back(batch_id)
        results: list[dict] = []

        for action in reversed(actions):
            result = self._rollback_action(action)
            results.append(result)
            if result["ok"]:
                self.mark_rolled_back(action.action_id)

        return results

    def _rollback_action(self, action: ActionRecord) -> dict:
        try:
            if action.action_type == ActionType.MOVE:
                if os.path.exists(action.destination):
                    shutil.move(action.destination, action.source)
                    return {
                        "ok": True,
                        "action_id": action.action_id,
                        "detail": f"回滚 MOVE: {action.destination} -> {action.source}",
                    }
                else:
                    return {
                        "ok": False,
                        "action_id": action.action_id,
                        "detail": f"目标文件不存在: {action.destination}",
                    }
            elif action.action_type == ActionType.COPY:
                if os.path.exists(action.destination):
                    os.remove(action.destination)
                    return {
                        "ok": True,
                        "action_id": action.action_id,
                        "detail": f"回滚 COPY: 删除 {action.destination}",
                    }
                else:
                    return {
                        "ok": False,
                        "action_id": action.action_id,
                        "detail": f"目标文件不存在: {action.destination}",
                    }
            else:
                return {
                    "ok": False,
                    "action_id": action.action_id,
                    "detail": f"未知操作类型: {action.action_type}",
                }
        except Exception as e:
            return {
                "ok": False,
                "action_id": action.action_id,
                "detail": f"回滚失败: {e}",
            }

    def all_records(self) -> list[ActionRecord]:
        records = read_jsonl(self.path)
        return [ActionRecord.from_dict(r) for r in records]

    def export_dicts(self) -> list[dict]:
        return read_jsonl(self.path)
