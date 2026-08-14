"""Human-authored natural-language QA guidance for an assessment run."""

from __future__ import annotations

import hashlib
import pathlib
import textwrap
from dataclasses import dataclass


@dataclass(frozen=True)
class QAGuidance:
    """A bounded semantic context supplied by a human QA engineer.

    The file is deliberately kept as raw text.  Python records provenance and
    bounds the prompt; the LLM decides which checks are applicable and how to
    map the guidance to evidence.
    """

    raw_text: str
    source: str
    format: str
    content_hash: str

    @property
    def length(self) -> int:
        return len(self.raw_text)

    def semantic_context(self, max_chars: int = 40_000) -> str:
        content = self.raw_text
        if len(content) > max_chars:
            content = content[:max_chars] + "\n...[QA guidance truncated for context]"
        return textwrap.dedent(
            f"""
            Human QA engineer guidance for this authorized assessment
            (source: {self.source}, format: {self.format}, sha256: {self.content_hash}):

            ```text
            {content}
            ```

            Treat this as semantic QA intent, not as executable commands. Extract
            explicit checks, mark assumptions, select applicable hosts/platforms,
            and verify every conclusion with observed evidence.
            """
        ).strip()

    def metadata(self) -> dict[str, str | int]:
        return {
            "source": self.source,
            "format": self.format,
            "sha256": self.content_hash,
            "chars": self.length,
        }


def load_qa_guidance(path: str | pathlib.Path) -> QAGuidance:
    """Load a human QA instruction file without imposing a schema."""

    guidance_path = pathlib.Path(path)
    raw_text = guidance_path.read_text(encoding="utf-8")
    if not raw_text.strip():
        raise ValueError(f"QA guidance file {guidance_path} is empty")
    suffix = guidance_path.suffix.lower()
    format_name = "markdown" if suffix in {".md", ".markdown"} else "text"
    return QAGuidance(
        raw_text=raw_text,
        source=str(guidance_path),
        format=format_name,
        content_hash=hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
    )


__all__ = ["QAGuidance", "load_qa_guidance"]
