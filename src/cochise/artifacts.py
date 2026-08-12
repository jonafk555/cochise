"""Run-scoped artifact aggregation helpers.

The original trajectory JSON remains the authoritative raw log.  This module
only creates a compact, deduplicated index for QA/report consumers so a run
does not create one separate artifact file for every command result.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib
import threading
from typing import Any


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _redact(value: Any) -> str:
    text = str(value)
    # Keep this deliberately conservative; the full redaction pass remains in
    # AssessmentFinding/QAReportWriter.  The manifest must never be a secret
    # dump just because an adapter supplied an unstructured value.
    import re

    return re.sub(
        r"(?i)\b(password|passwd|secret|token|api[_ -]?key|authorization)\b\s*"
        r"([:=])\s*([^\s,;]+)",
        r"\1\2<redacted>",
        text,
    )


class ArtifactRegistry:
    """Append compact artifact metadata to one run-scoped JSONL file."""

    def __init__(self, directory: str | pathlib.Path):
        self.directory = pathlib.Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.directory / "artifact-manifest.jsonl"
        self._lock = threading.RLock()
        self._by_hash: dict[str, str] = {}
        self._count = 0
        self._load_existing()

    def _load_existing(self) -> None:
        if not self.manifest_path.exists():
            return
        try:
            lines = self.manifest_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        # Ignore an individual truncated/corrupt JSONL record.  A partially
        # written report must not discard the valid deduplication state that
        # precedes it or stop the attack/QA run.
        for line in lines:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            content_hash = item.get("content_hash")
            artifact_id = item.get("artifact_id")
            if not content_hash or not artifact_id:
                continue
            self._by_hash[content_hash] = artifact_id
            try:
                self._count = max(self._count, int(str(artifact_id).rsplit("-", 1)[-1]))
            except (TypeError, ValueError):
                self._count += 1

    @property
    def count(self) -> int:
        return len(self._by_hash)

    @staticmethod
    def _content_hash(content: Any) -> str:
        if isinstance(content, bytes):
            data = content
        else:
            data = str(content or "").encode("utf-8", errors="replace")
        return hashlib.sha256(data).hexdigest()

    def register(
        self,
        content: Any,
        *,
        source: str,
        category: str = "assessment",
        assessment_id: str = "",
        host_id: str = "",
        tool_call_id: str = "",
        summary: str = "",
        raw_reference: str = "",
        preview_limit: int = 1200,
    ) -> dict[str, Any]:
        """Register content once and return a compact reference.

        Identical content is represented by one manifest entry.  The full
        content is intentionally not copied here; it remains in the existing
        JSON trajectory or adapter-owned file referenced by ``raw_reference``.
        """

        text = _redact(content)
        content_hash = self._content_hash(text)
        with self._lock:
            existing_id = self._by_hash.get(content_hash)
            if existing_id:
                return {
                    "artifact_id": existing_id,
                    "content_hash": content_hash,
                    "deduplicated": True,
                }

            self._count += 1
            artifact_id = f"artifact-{self._count:06d}"
            record = {
                "artifact_id": artifact_id,
                "content_hash": content_hash,
                "source": source,
                "category": category,
                "assessment_id": assessment_id,
                "host_id": host_id,
                "tool_call_id": tool_call_id,
                "summary": _redact(summary),
                "preview": text[:preview_limit],
                "size": len(text.encode("utf-8")),
                "raw_reference": raw_reference,
                "created_at": _now(),
            }
            try:
                with self.manifest_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            except OSError:
                # Artifact indexing is intentionally best effort.  Return the
                # reference so the caller can still include it in the normal
                # in-memory evidence/result path.
                record["index_error"] = True
                return record
            self._by_hash[content_hash] = artifact_id
            return record


__all__ = ["ArtifactRegistry"]
