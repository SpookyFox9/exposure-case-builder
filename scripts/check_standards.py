"""Check the written engineering standards that linters do not cover.

Rules (from the project's coding-style standards): files stay under 800 lines (a warning above 400),
functions under 50 lines, control-flow nesting no deeper than 4, no print() in library or script code
(use logging), and dataclasses are frozen (immutability).

Usage:
    python scripts/check_standards.py [DIR ...]      # defaults to src and scripts
Exit status is 1 when any error is found.
"""

from __future__ import annotations

import ast
import logging
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_LINES = 800
WARN_FILE_LINES = 400
MAX_FUNCTION_LINES = 50
MAX_NESTING = 4
SKIP_DIRS = frozenset({".venv", "__pycache__", ".git", "node_modules"})
_NESTING_NODES = (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.AsyncFor, ast.AsyncWith)

log = logging.getLogger("check_standards")


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    rule: str
    message: str
    severity: str = "error"


def _nesting(node: ast.AST, depth: int = 0) -> int:
    deepest = depth
    for child in ast.iter_child_nodes(node):
        step = 1 if isinstance(child, _NESTING_NODES) else 0
        deepest = max(deepest, _nesting(child, depth + step))
    return deepest


def _is_dataclass_decorator(node: ast.expr) -> tuple[bool, bool]:
    """(is a dataclass decorator, is frozen)."""
    target = node.func if isinstance(node, ast.Call) else node
    name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
    if name != "dataclass":
        return False, False
    frozen = isinstance(node, ast.Call) and any(
        kw.arg == "frozen" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords
    )
    return True, frozen


def _check_node(path: Path, node: ast.AST) -> Iterable[Violation]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        length = (node.end_lineno or node.lineno) - node.lineno + 1
        if length > MAX_FUNCTION_LINES:
            msg = f"{node.name} is {length} lines (limit {MAX_FUNCTION_LINES})"
            yield Violation(path, node.lineno, "function-length", msg)
        depth = _nesting(node)
        if depth > MAX_NESTING:
            yield Violation(path, node.lineno, "nesting", f"{node.name} nests {depth} levels (limit {MAX_NESTING})")
    elif isinstance(node, ast.ClassDef):
        for decorator in node.decorator_list:
            is_dc, frozen = _is_dataclass_decorator(decorator)
            if is_dc and not frozen:
                yield Violation(path, node.lineno, "frozen-dataclass", f"{node.name} must be @dataclass(frozen=True)")
    elif isinstance(node, ast.Call) and getattr(node.func, "id", "") == "print":
        yield Violation(path, node.lineno, "no-print", "use logging instead of print()")


def check_source(path: Path, text: str) -> list[Violation]:
    """All violations in one file's source text."""
    lines = len(text.splitlines())
    found: list[Violation] = []
    if lines > MAX_FILE_LINES:
        found.append(Violation(path, 1, "file-length", f"{lines} lines (limit {MAX_FILE_LINES})"))
    elif lines > WARN_FILE_LINES:
        found.append(Violation(path, 1, "file-length", f"{lines} lines (typical {WARN_FILE_LINES})", "warning"))
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return [*found, Violation(path, exc.lineno or 1, "syntax", f"cannot parse: {exc.msg}")]
    for node in ast.walk(tree):
        found.extend(_check_node(path, node))
    return sorted(found, key=lambda v: (v.line, v.rule))


def run(roots: Sequence[Path]) -> list[Violation]:
    found: list[Violation] = []
    for root in roots:
        for path in sorted(Path(root).rglob("*.py")):
            if SKIP_DIRS & set(path.parts):
                continue
            found.extend(check_source(path, path.read_text(encoding="utf-8")))
    return found


def main(argv: list[str] | None = None) -> int:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.handlers[:] = [handler]
    log.setLevel(logging.INFO)
    log.propagate = False
    roots = [Path(a) for a in (argv or ["src", "scripts"])]
    violations = run(roots)
    for v in violations:
        log.warning("%s:%s [%s] %s: %s", v.path, v.line, v.rule, v.severity, v.message)
    errors = sum(v.severity == "error" for v in violations)
    log.info("standards check: %d error(s), %d warning(s)", errors, len(violations) - errors)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
