"""The Mermaid diagrams in docs/architecture.md must match the real server and the real modules.

Naming rule (the test depends on it): a tool node is ``tool_<name>``, a module node is ``mod_<name>``, a write tool
carries ``:::write`` on its definition line, and in a flowchart every edge sits on its own line as ``a --> b``
(``-.->`` and ``-->|label|`` allowed) with nodes defined elsewhere. ``test_every_flowchart_arrow_is_parsed`` fails
if an edge is written any other way, so no edge is silently skipped.

What is checked: tool names, write tools, the module list, tool -> service edges, that tool -> module edges point
only at modules ``service`` imports, the ``text_safety`` importers and the disposition-log tools. Pipeline arrows
and wording are checked by review.
"""

import ast
import asyncio
import inspect
import re
from functools import cache
from pathlib import Path

import pytest
from mcp.types import Tool

from exposure_case.server import build_server
from exposure_case.service import Workspace

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "architecture.md"
PACKAGE = ROOT / "src" / "exposure_case"
NODE = re.compile(r"\b(tool|mod)_([a-z0-9_]*[a-z0-9])\b")
WRITE_NODE = re.compile(r"\btool_([a-z0-9_]*[a-z0-9])\b[^\n]*?:::write\b")
EDGE = re.compile(r"^\s*(\w+)\s*(?:-->|-\.->)(?:\|[^|\n]*\|)?\s*(\w+)\s*$", re.MULTILINE)
ARROW = re.compile(r"-->|-\.->")
# Source-text markers for "this Workspace method touches the disposition log"; a new helper that reads the log
# must be added here, or the test fails loudly (the diagram would claim a read the markers do not see).
LOG_MARKERS = ("self._latest(", "self._log_state(", "dlog.record_disposition(")


@cache
def mermaid_blocks() -> tuple[str, ...]:
    """Every ```mermaid block in the architecture doc."""
    return tuple(re.findall(r"```mermaid\n(.*?)```", DOC.read_text(encoding="utf-8"), re.DOTALL))


@cache
def diagram_text() -> str:
    blocks = mermaid_blocks()
    assert blocks, "docs/architecture.md has no mermaid diagrams"
    return "\n".join(blocks)


def nodes(kind: str) -> frozenset[str]:
    return frozenset(name for k, name in NODE.findall(diagram_text()) if k == kind)


@cache
def edges() -> frozenset[tuple[str, str]]:
    return frozenset(EDGE.findall(diagram_text()))


def edges_into(target: str) -> frozenset[str]:
    return frozenset(a for a, b in edges() if b == target)


@cache
def modules() -> frozenset[str]:
    return frozenset(p.stem for p in PACKAGE.glob("*.py") if p.stem != "__init__")


@cache
def local_imports(module: str) -> frozenset[str]:
    """Modules imported with ``from .x import`` or ``from . import x`` anywhere in the module."""
    tree = ast.parse((PACKAGE / f"{module}.py").read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ImportFrom) and node.level == 1):
            continue
        if node.module:
            found.add(node.module)
        else:
            found.update(alias.name for alias in node.names)
    return frozenset(found)


@pytest.fixture(scope="module")
def real_tools(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Tool]:
    tmp = tmp_path_factory.mktemp("diagram")
    ws = Workspace.load(ROOT / "data" / "sample", exports_dir=tmp / "e", dispositions_path=tmp / "d.jsonl")
    tools = {t.name: t for t in asyncio.run(build_server(ws).list_tools())}
    assert tools, "the server lists no tools"
    return tools


def test_every_flowchart_arrow_is_parsed() -> None:
    flowcharts = [b for b in mermaid_blocks() if b.lstrip().startswith("flowchart")]
    assert flowcharts
    unparsed = [
        line.strip()
        for block in flowcharts
        for line in block.splitlines()
        if ARROW.search(line) and not EDGE.fullmatch(line)
    ]
    assert not unparsed, f"edges must be bare 'a --> b' lines: {unparsed}"


def test_diagram_tools_match_the_real_server(real_tools: dict[str, Tool]) -> None:
    assert nodes("tool") == set(real_tools)


def test_write_style_marks_exactly_the_tools_that_are_not_read_only(real_tools: dict[str, Tool]) -> None:
    writers = {
        name for name, tool in real_tools.items() if tool.annotations is None or not tool.annotations.read_only_hint
    }
    assert writers, "expected at least one write tool"
    assert set(WRITE_NODE.findall(diagram_text())) == writers
    assert re.search(r"^\s*classDef write\b", diagram_text(), re.MULTILINE)


def test_diagram_modules_are_exactly_the_package_modules() -> None:
    assert nodes("mod") == modules()


def test_every_tool_reaches_the_workspace(real_tools: dict[str, Tool]) -> None:
    assert {f"tool_{name}" for name in real_tools} <= edges_into("mod_service")


def test_tool_to_module_edges_point_only_at_modules_the_service_imports() -> None:
    """A loose check: each target is a module service imports, not proof the tool uses it."""
    allowed = {f"mod_{m}" for m in local_imports("service") | {"service"}}
    targets = {b for a, b in edges() if a.startswith("tool_") and b.startswith("mod_")}
    assert targets - {"mod_service"}, "no tool-to-module edges were parsed"
    assert targets <= allowed


def test_text_safety_edges_match_the_modules_that_import_it() -> None:
    users = {m for m in modules() if "text_safety" in local_imports(m)}
    assert users
    assert {a.removeprefix("mod_") for a in edges_into("mod_text_safety")} == users


def test_disposition_log_edges_match_the_tools_that_read_or_write_it(real_tools: dict[str, Tool]) -> None:
    missing = [name for name in real_tools if not hasattr(Workspace, name)]
    assert not missing, f"tools with no Workspace method of the same name: {missing}"
    source = {name: inspect.getsource(getattr(Workspace, name)) for name in real_tools}
    users = {name for name, text in source.items() if any(marker in text for marker in LOG_MARKERS)}
    assert users
    drawn = {a.removeprefix("tool_") for a in edges_into("store_log") if a.startswith("tool_")}
    assert drawn == users
