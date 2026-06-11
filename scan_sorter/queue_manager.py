from __future__ import annotations

from scan_sorter.models import ErrorItem
from scan_sorter.utils import load_json, save_json


class ErrorQueue:
    def __init__(self, path: str):
        self.path = path
        self._items: list[ErrorItem] = []
        self._load()

    def _load(self) -> None:
        raw = load_json(self.path, default=[])
        self._items = [ErrorItem.from_dict(d) for d in raw]

    def _save(self) -> None:
        save_json(self.path, [item.to_dict() for item in self._items])

    def add(self, item: ErrorItem) -> None:
        existing = self.find_by_path(item.path)
        if existing:
            existing.error = item.error
            existing.retry_count = item.retry_count
            existing.last_retry_at = item.last_retry_at
        else:
            self._items.append(item)
        self._save()

    def remove(self, path: str) -> None:
        self._items = [i for i in self._items if i.path != path]
        self._save()

    def find_by_path(self, path: str) -> ErrorItem | None:
        for item in self._items:
            if item.path == path:
                return item
        return None

    def get_retryable(self, limit: int | None = None) -> list[ErrorItem]:
        retryable = [
            i for i in self._items if i.retry_count < i.max_retries
        ]
        if limit:
            retryable = retryable[:limit]
        return retryable

    def increment_retry(self, path: str) -> None:
        item = self.find_by_path(path)
        if item:
            item.retry_count += 1
            from scan_sorter.utils import iso_now
            item.last_retry_at = iso_now()
            self._save()

    def all(self) -> list[ErrorItem]:
        return list(self._items)

    def count(self) -> int:
        return len(self._items)

    def clear(self) -> None:
        self._items.clear()
        self._save()


class ProcessingQueue:
    def __init__(self, path: str):
        self.path = path
        self._items: list[dict] = []
        self._load()

    def _load(self) -> None:
        self._items = load_json(self.path, default=[])

    def _save(self) -> None:
        save_json(self.path, self._items)

    def enqueue(self, file_path: str, case_number: str | None, **kwargs) -> None:
        entry = {
            "path": file_path,
            "case_number": case_number,
            "status": "queued",
            **kwargs,
        }
        self._items.append(entry)
        self._save()

    def dequeue(self, limit: int | None = None) -> list[dict]:
        items = [i for i in self._items if i.get("status") == "queued"]
        if limit:
            items = items[:limit]
        return items

    def mark_done(self, file_path: str) -> None:
        for item in self._items:
            if item["path"] == file_path:
                item["status"] = "done"
        self._save()

    def mark_failed(self, file_path: str) -> None:
        for item in self._items:
            if item["path"] == file_path:
                item["status"] = "failed"
        self._save()

    def mark_rolled_back(self, file_path: str) -> None:
        for item in self._items:
            if item["path"] == file_path:
                item["status"] = "rolled_back"
        self._save()

    def all(self) -> list[dict]:
        return list(self._items)

    def count(self) -> int:
        return len(self._items)

    def clear_done(self) -> None:
        self._items = [i for i in self._items if i.get("status") != "done"]
        self._save()
