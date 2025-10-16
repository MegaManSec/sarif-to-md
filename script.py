#!/usr/bin/env python3
"""
make_reports.py (fixed)

Generate per-file Markdown reports from one or more SARIF files.

For each artifactLocation.uri, this writes a single <uri>.md file under an
output directory (default: findings/). Issue content is rendered as Markdown.

Highlights
- Pure Markdown output (no XML).
- Strips duplicated, leading bold/header titles in issue markdown.
- Optional context sections:
    --repo-root PATH     : Append the source file as a fenced code block
    --numbered-code      : Append a numbered text code block instead
    --function-index     : Append a best-effort "Function index" table
    --scan-sinks         : Append a "Potentially risky calls" table
    --defines-from FILE  : Append a "Defines" section from a header file

Usage:
    python make_reports.py input.sarif [more.sarif ...] -o findings
    python make_reports.py input.sarif -o findings --repo-root /abs/path/to/repo \
        --numbered-code --function-index --scan-sinks --defines-from /path/to/config.h
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def uri_to_report_name(uri: str) -> str:
    """Convert a URI like 'lib/http2.c' to a safe filename like 'lib-http2-c.md'."""
    safe = re.sub(r'[^A-Za-z0-9]+', '-', uri).strip('-')
    return f"{safe}.md" if safe else "report.md"


def normalize_newlines(s: str) -> str:
    return s.replace("\r\n", "\n").replace("\r", "\n")


def strip_leading_title(md: str, title: str) -> str:
    """
    If the markdown starts with a bolded or header-style repeat of `title`
    followed by one or more newlines, remove that prefix.
    """
    if not md or not title:
        return md
    patterns = [
        r'^\s*\*\*' + re.escape(title) + r'\*\*\s*(?:\r?\n)+',  # **Title**\n+
        r'^\s*#{1,6}\s*' + re.escape(title) + r'\s*(?:\r?\n)+',  # # Title\n+
    ]
    for pat in patterns:
        new_md, n = re.subn(pat, "", md, flags=re.IGNORECASE)
        if n:
            return new_md.lstrip("\r\n")
    return md


def collect_issues_by_uri(paths: Iterable[Path]) -> Dict[str, List[Tuple[str, str]]]:
    """
    Load SARIF files and return mapping: uri -> list of (title, markdown_content).
    """
    by_uri: Dict[str, List[Tuple[str, str]]] = {}

    for p in paths:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"[WARN] Skipping {p}: JSON decode error: {e}", file=sys.stderr)
            continue

        for run in (data.get("runs") or []):
            for res in (run.get("results") or []):
                # Robust against sloppy SARIF producers that set message to a string
                msg = res.get("message") or {}
                if not isinstance(msg, dict):
                    msg = {"text": str(msg)}

                raw_title = (msg.get("text") or "").strip()
                content = msg.get("markdown") or msg.get("text") or ""
                if not content:
                    continue
                content = normalize_newlines(content)
                if msg.get("markdown") and raw_title:
                    content = strip_leading_title(content, raw_title)

                for loc in (res.get("locations") or []):
                    uri = (
                        (loc.get("physicalLocation") or {})
                        .get("artifactLocation", {})
                        .get("uri", "")
                    )
                    if not uri:
                        continue
                    lines = (
                          (loc.get("physicalLocation") or {})
                          .get("region", {})
                          .get("snippet", {})
                    )
                    start_line = lines.get("startLine", None)
                    end_line = lines.get("endLine", None)
                    if start_line and end_line:
                        raw_title += f" (L{start_line}-L{end_line})"
                    by_uri.setdefault(uri, []).append((raw_title, content.strip()))
    return by_uri


def read_repo_file(repo_root: Optional[Path], uri: str) -> Optional[str]:
    """Read repo file text for a given POSIX-style uri relative to repo_root."""
    if not repo_root:
        return None
    rel = Path(*uri.split("/"))
    code_path = (repo_root / rel).resolve()
    try:
        return normalize_newlines(code_path.read_text(encoding="utf-8", errors="replace"))
    except FileNotFoundError:
        return f"[file not found under repo root: {rel}]"
    except Exception as e:
        return f"[error reading file: {rel} - {e}]"


# ---------- Context helpers ----------

FUNC_DEF_RE = re.compile(
    r'^(?P<indent>\s*)(?:static\s+)?(?:inline\s+)?(?:[\w\*\s]+\s+)?(?P<name>[A-Za-z_]\w*)\s*\([^;]*\)\s*\{',
    re.MULTILINE,
)

SINK_PATTERNS = [
    r'\bstrcpy\s*\(',
    r'\bstrcat\s*\(',
    r'\bsprintf\s*\(',
    r'\bsnprintf\s*\(',
    r'\bvsprintf\s*\(',
    r'\bmemcpy\s*\(',
    r'\bmemmove\s*\(',
    r'\bmemset\s*\(',
    r'\brealloc\s*\(',
    r'\bmalloc\s*\(',
    r'\bcalloc\s*\(',
    r'\bgets\s*\(',
    r'\bscanf\s*\(',
    r'\bfscanf\s*\(',
    r'\bread\s*\(',
    r'\bwrite\s*\(',
]
SINK_RE = re.compile("|".join(SINK_PATTERNS))


def number_code(code: str) -> str:
    lines = code.split("\n")
    width = max(4, len(str(len(lines))))
    return "\n".join(f"{i+1:>{width}} | {lines[i]}" for i in range(len(lines)))


def extract_functions_with_ranges(code: str) -> List[Tuple[str, int, int]]:
    """
    Best-effort: find function names and approximate start/end lines by brace depth.
    """
    text = code
    results: List[Tuple[str, int, int]] = []
    for m in FUNC_DEF_RE.finditer(text):
        name = m.group("name")
        start_line = text.count("\n", 0, m.start()) + 1
        brace_pos = text.find("{", m.end() - 1)
        if brace_pos == -1:
            end_line = start_line
        else:
            depth = 1
            i = brace_pos + 1
            while i < len(text) and depth > 0:
                ch = text[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                i += 1
            end_line = text.count("\n", 0, i) + 1
        results.append((name, start_line, end_line))
    return results


def strip_comments_preserve_lines(src: str) -> str:
    """
    Remove // and /* */ comments while preserving newlines and non-comment content.
    Keeps string literals intact to avoid stripping comment-like sequences within strings.
    """
    out = []
    i = 0
    n = len(src)
    in_sl = False      # // ...
    in_ml = False      # /* ... */
    in_sq = False      # '...'
    in_dq = False      # "..."
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        # end of single-line comment
        if in_sl:
            if ch == "\n":
                in_sl = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue

        # end of multi-line comment
        if in_ml:
            if ch == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_ml = False
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
            continue

        # strings
        if in_sq:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if ch == "'":
                in_sq = False
            i += 1
            continue

        if in_dq:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if ch == '"':
                in_dq = False
            i += 1
            continue

        # entering comments?
        if ch == "/" and nxt == "/":
            out.append("  ")
            i += 2
            in_sl = True
            continue
        if ch == "/" and nxt == "*":
            out.append("  ")
            i += 2
            in_ml = True
            continue

        # entering strings?
        if ch == "'":
            in_sq = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_dq = True
            out.append(ch)
            i += 1
            continue

        # normal char
        out.append(ch)
        i += 1

    return "".join(out)


def scan_sinks(code: str) -> List[Tuple[int, str, str]]:
    """Return list of (line, api, snippet) for lines matching common sink patterns (skip comments)."""
    hits: List[Tuple[int, str, str]] = []
    original_lines = code.split("\n")
    code_no_comments = strip_comments_preserve_lines(code)
    for idx, (line_nc, line_orig) in enumerate(zip(code_no_comments.split("\n"), original_lines), start=1):
        m = SINK_RE.search(line_nc)
        if m:
            api = m.group(0).split("(")[0].strip()
            hits.append((idx, api, line_orig.strip()))
    return hits


# ---------- Markdown rendering ----------

def guess_lang_from_uri(uri: str) -> str:
    ext = Path(uri).suffix.lower()
    return {
        ".c": "c",
        ".h": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".hpp": "cpp",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "tsx",
        ".jsx": "jsx",
        ".py": "python",
        ".go": "go",
        ".java": "java",
        ".rb": "ruby",
        ".rs": "rust",
        ".cs": "csharp",
        ".php": "php",
        ".sh": "bash",
        ".bash": "bash",
        ".zsh": "zsh",
    }.get(ext, "")


def md_inline_code(s: str) -> str:
    """
    Safely wrap `s` as inline code inside a Markdown table:
    - escape pipe characters
    - choose a backtick fence length not present in s
    - fallback to <code> for pathological cases
    """
    content = s.replace("|", r"\|")
    for n in (1, 2, 3, 4):
        fence = "`" * n
        if fence not in content:
            return f"{fence}{content}{fence}"
    # Fallback: HTML-escape minimal chars
    esc = (content.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;"))
    return f"<code>{esc}</code>"


def render_issue_md(index: int, title: str, content: str) -> str:
    # Use only the first line of the title; sanitize heading markers/backticks.
    header = (title or "").strip().splitlines()[0] if title else ""
    header = re.sub(r'[#`]+', '', header).strip()
    if not header:
        header = f"Issue {index}"
    return f"### {header}\n\n{content.strip()}\n"


def write_reports(
    by_uri: Dict[str, List[Tuple[str, str]]],
    out_dir: Path,
    repo_root: Optional[Path],
    numbered_code: bool,
    function_index: bool,
    defines_from: Optional[Path],
    scan_sinks_flag: bool,
) -> List[Path]:
    """Write a Markdown file per URI to out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    defines_cache: Optional[List[str]] = None
    if defines_from:
        defines_cache = parse_defines_from_file(defines_from)

    for uri in sorted(by_uri.keys()):
        issues = by_uri[uri]
        report_name = uri_to_report_name(uri)
        out_path = out_dir / report_name

        parts: List[str] = [f"# {uri}\n", "## Issues\n"]
        for i, (title, content) in enumerate(issues, 1):
            parts.append(render_issue_md(i, title, content))

        code_text = read_repo_file(repo_root, uri)
        if code_text is not None:
            parts.append("## Source\n")
            if numbered_code:
                parts.append("```text")
                parts.append(number_code(code_text))
                parts.append("```")
            else:
                lang = guess_lang_from_uri(uri)
                parts.append(f"```{lang}".rstrip())
                parts.append(code_text.rstrip())
                parts.append("```")

            if function_index:
                funcs = extract_functions_with_ranges(code_text)
                parts.append("\n## Function index\n")
                if funcs:
                    table = ["| Name | Lines |", "|---|---|"]
                    table += [f"| {name} | {start}–{end} |" for name, start, end in funcs]
                    parts.append("\n".join(table))
                else:
                    parts.append("_No functions found._")

            if scan_sinks_flag:
                sinks = scan_sinks(code_text)
                parts.append("\n## Potentially risky calls\n")
                if sinks:
                    table = ["| Line | API | Snippet |", "|---:|---|---|"]
                    table += [f"| {ln} | {md_inline_code(api)} | {md_inline_code(snippet)} |"
                              for ln, api, snippet in sinks]
                    parts.append("\n".join(table))
                else:
                    parts.append("_No sink-pattern matches._")

        if defines_cache is not None:
            parts.append("\n## Defines\n")
            parts.append("```c")
            parts.append("\n".join(defines_cache))
            parts.append("```")

        content = "\n".join(parts).rstrip() + "\n"
        out_path.write_text(content, encoding="utf-8")
        written.append(out_path)

    return written


def parse_defines_from_file(path: Path) -> List[str]:
    try:
        text = normalize_newlines(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        return [f"[error reading defines file: {e}]"]
    lines = [ln.strip() for ln in text.split("\n") if ln.strip().startswith("#define")]
    return lines or ["[no #define entries found]"]


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate per-file Markdown reports from SARIF findings.")
    parser.add_argument("sarif_paths", nargs="+", help="Path(s) to SARIF file(s) to ingest.")
    parser.add_argument("-o", "--out-dir", default="findings", help="Output directory (default: findings)")
    parser.add_argument("-r", "--repo-root", default=None, help="Repository root for reading source files (optional)")
    parser.add_argument("--numbered-code", action="store_true", help="Append the source as a numbered text block")
    parser.add_argument("--function-index", action="store_true", help="Append a best-effort function index table")
    parser.add_argument("--defines-from", default=None, help="Path to a header (e.g., config.h) to pull #define entries from")
    parser.add_argument("--scan-sinks", action="store_true", help="Append a table of common risky API calls")
    args = parser.parse_args(argv)

    sarif_files = [Path(p) for p in args.sarif_paths]
    for p in sarif_files:
        if not p.exists():
            print(f"[ERROR] File not found: {p}", file=sys.stderr)
            return 2
        if p.is_dir():
            print(f"[ERROR] Expected a file, got a directory: {p}", file=sys.stderr)
            return 2

    repo_root = Path(args.repo_root).resolve() if args.repo_root else None
    defines_from = Path(args.defines_from).resolve() if args.defines_from else None

    by_uri = collect_issues_by_uri(sarif_files)
    # FIX: avoid walrus operator for broader Python compatibility
    function_index = args.function_index
    written = write_reports(
        by_uri,
        Path(args.out_dir),
        repo_root,
        args.numbered_code,
        function_index,
        defines_from,
        args.scan_sinks,
    )

    print(f"Wrote {len(written)} Markdown report(s) to: {Path(args.out_dir).resolve()}")
    for w in sorted(written):
        print(f" - {w}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
