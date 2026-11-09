"""A tiny YAML subset parser used only when PyYAML is unavailable.

Supports the shape used by this project's config/rules/plugin manifests:
  * nested mappings via indentation
  * block sequences (``- item`` and ``- key: value``)
  * scalars: str/int/float/bool/null, quoted strings, inline ``[a, b]``
  * comments (full-line and trailing `` #``), blank lines
  * ``|`` block scalars are NOT supported on purpose (config must stay simple)

It refuses ambiguous input rather than guessing: a bad document raises
``YamlSubsetError`` with the offending line number, which the config loader
turns into a readable startup error.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["safe_load", "YamlSubsetError"]


class YamlSubsetError(ValueError):
    def __init__(self, message: str, line: int = 0):
        super().__init__(f"yaml(line {line}): {message}" if line else message)
        self.line = line


_INT_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?\d+\.\d+$")
_KEY_RE = re.compile(r"^([^:#\-\s][^:]*|\"[^\"]+\"|'[^']+')\s*:(?:\s+(.*))?$")


def _strip_comment(line: str) -> str:
    out, quote = [], None
    for idx, ch in enumerate(line):
        if quote:
            out.append(ch)
            if ch == quote and (idx == 0 or line[idx - 1] != "\\"):
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (idx == 0 or line[idx - 1] in (" ", "\t")):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _scalar(raw: str) -> Any:
    raw = raw.strip()
    if raw == "":
        return None
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    lowered = raw.lower()
    if lowered in ("null", "~", "none"):
        return None
    if lowered in ("true", "yes", "on"):
        return True
    if lowered in ("false", "no", "off"):
        return False
    if _INT_RE.match(raw):
        return int(raw)
    if _FLOAT_RE.match(raw):
        return float(raw)
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part) for part in inner.split(",")]
    if raw.startswith("{") and raw.endswith("}"):
        inner = raw[1:-1].strip()
        if not inner:
            return {}
        result = {}
        for part in inner.split(","):
            if ":" not in part:
                raise YamlSubsetError(f"bad inline mapping item: {part!r}")
            key, value = part.split(":", 1)
            result[key.strip()] = _scalar(value)
        return result
    return raw


def _tokenize(text: str) -> list[tuple[int, str, int]]:
    rows = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        if "\t" in raw_line[: len(raw_line) - len(raw_line.lstrip())]:
            raise YamlSubsetError("tabs are not allowed for indentation", number)
        line = _strip_comment(raw_line)
        if not line.strip():
            continue
        if line.strip() in ("---", "..."):
            continue
        indent = len(line) - len(line.lstrip(" "))
        rows.append((indent, line.strip(), number))
    return rows


def _parse_block(rows: list[tuple[int, str, int]], start: int, indent: int) -> tuple[Any, int]:
    if start >= len(rows):
        return None, start
    first_indent, first_content, first_line = rows[start]
    if first_indent < indent:
        return None, start
    is_list = first_content == "-" or first_content.startswith("- ")
    if is_list:
        return _parse_list(rows, start, first_indent)
    return _parse_map(rows, start, first_indent)


def _parse_map(rows, start, indent):
    result: dict = {}
    idx = start
    while idx < len(rows):
        line_indent, content, number = rows[idx]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise YamlSubsetError(f"unexpected indentation for {content!r}", number)
        if content.startswith("- "):
            break
        match = _KEY_RE.match(content)
        if not match:
            raise YamlSubsetError(f"expected 'key: value', got {content!r}", number)
        key = match.group(1).strip().strip("'\"")
        value_raw = match.group(2)
        idx += 1
        if value_raw is not None and value_raw.strip() != "":
            result[key] = _scalar(value_raw)
            continue
        # nested block belongs to this key when the next row is deeper
        if idx < len(rows) and rows[idx][0] > indent:
            child, idx = _parse_block(rows, idx, rows[idx][0])
            result[key] = child
        elif idx < len(rows) and rows[idx][0] == indent and rows[idx][1].startswith("- "):
            child, idx = _parse_list(rows, idx, indent)
            result[key] = child
        else:
            result[key] = None
    return result, idx


def _parse_list(rows, start, indent):
    items: list = []
    idx = start
    while idx < len(rows):
        line_indent, content, number = rows[idx]
        if line_indent < indent or not (content == "-" or content.startswith("- ")):
            break
        if line_indent > indent:
            raise YamlSubsetError(f"unexpected indentation for {content!r}", number)
        body = content[1:].strip()
        idx += 1
        if not body:
            if idx < len(rows) and rows[idx][0] > indent:
                child, idx = _parse_block(rows, idx, rows[idx][0])
                items.append(child)
            else:
                items.append(None)
            continue
        if ":" in body and not body.startswith(("'", '"')):
            # mapping item: "- key: value" starts a map at this deeper column
            synthetic_indent = line_indent + 2
            sub_rows = [(synthetic_indent, body, number)]
            while idx < len(rows) and rows[idx][0] > line_indent:
                sub_rows.append(rows[idx])
                idx += 1
            child, _ = _parse_block(sub_rows, 0, synthetic_indent)
            items.append(child)
        else:
            items.append(_scalar(body))
            if idx < len(rows) and rows[idx][0] > indent:
                raise YamlSubsetError(f"scalar list item followed by nested block: {body!r}", number)
    return items, idx


def safe_load(text: str) -> Any:
    if not text or not text.strip():
        return {}
    rows = _tokenize(text)
    if not rows:
        return {}
    value, idx = _parse_block(rows, 0, rows[0][0])
    if idx != len(rows):
        raise YamlSubsetError(f"trailing content near line {rows[idx][2]}", rows[idx][2])
    return value
