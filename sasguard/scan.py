"""Find SAS tokens that were committed to files. A SAS in a repository is a credential in a repository.

Matches are reported with the signature masked: this tool must never be the thing that prints a secret into a CI log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .audit import Finding, NotASas, audit, has_errors

_SIG = r"sig=[A-Za-z0-9%+/=._-]{8,}"
_URL = re.compile(rf"https?://[^\s\"'<>?]+\.(?:blob|queue|table|file|dfs)\.core\.windows\.net/[^\s\"'<>?]*\?[^\s\"'<>]*?{_SIG}[^\s\"'<>]*", re.I)
_BARE = re.compile(rf"(?<![A-Za-z0-9])sv=\d{{4}}-\d{{2}}-\d{{2}}&[^\s\"'<>]*?{_SIG}[^\s\"'<>]*", re.I)
_MASK = re.compile(r"(sig=)[^&\s\"'<>]+", re.I)
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", ".pytest_cache", ".terraform"}
MAX_BYTES = 2_000_000


def mask(text: str) -> str:
    return _MASK.sub(r"\1****", text)


@dataclass
class Hit:
    path: str
    line: int
    masked: str
    findings: list[Finding] = field(default_factory=list)


def scan_text(text: str, path: str = "<text>", now: datetime | None = None) -> list[Hit]:
    hits: list[Hit] = []
    for n, line in enumerate(text.splitlines(), 1):
        spans: list[tuple[int, int]] = []
        for pattern in (_URL, _BARE):
            for m in pattern.finditer(line):
                if any(s <= m.start() < e for s, e in spans):  # the bare pattern would match inside a URL already found
                    continue
                spans.append((m.start(), m.end()))
                try:
                    findings = audit(m.group(0), now)
                except NotASas:
                    continue
                hits.append(Hit(path, n, mask(m.group(0)), findings))
    return hits


def scan_paths(paths: list[str], now: datetime | None = None) -> list[Hit]:
    hits: list[Hit] = []
    for root in map(Path, paths):
        files = [root] if root.is_file() else [f for f in root.rglob("*") if f.is_file() and not (set(f.parts) & SKIP_DIRS)]
        for f in sorted(files):
            try:
                if f.stat().st_size > MAX_BYTES:
                    continue
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            hits.extend(scan_text(text, str(f), now))
    return hits


__all__ = ["Hit", "has_errors", "mask", "scan_paths", "scan_text"]
