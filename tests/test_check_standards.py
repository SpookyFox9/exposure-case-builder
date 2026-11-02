"""The engineering-standards checker: file size, function length, nesting, print(), frozen dataclasses."""

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("check_standards", ROOT / "scripts" / "check_standards.py")
cs = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cs  # dataclasses resolve their module through sys.modules
spec.loader.exec_module(cs)


def function_with(lines: int) -> str:
    body = "\n".join("    x = 1" for _ in range(lines - 1))
    return f"def f():\n{body}\n"


def check(text: str, name: str = "mod.py"):
    return cs.check_source(Path(name), text)


def rules(violations) -> set[str]:
    return {v.rule for v in violations}


def test_function_of_exactly_fifty_lines_passes_and_fifty_one_fails():
    assert "function-length" not in rules(check(function_with(50)))
    assert "function-length" in rules(check(function_with(51)))


def test_methods_and_async_functions_are_measured_too():
    body = "\n".join("        x = 1" for _ in range(60))
    assert "function-length" in rules(check(f"class A:\n    def m(self):\n{body}\n"))
    assert "function-length" in rules(check(f"async def m():\n{body}\n"))


def test_nesting_deeper_than_four_fails():
    deep = "def f(a):\n" + "".join(f"{'    ' * (i + 1)}if a:\n" for i in range(5)) + f"{'    ' * 6}pass\n"
    shallow = "def f(a):\n" + "".join(f"{'    ' * (i + 1)}if a:\n" for i in range(4)) + f"{'    ' * 5}pass\n"
    assert "nesting" in rules(check(deep))
    assert "nesting" not in rules(check(shallow))


def test_print_calls_are_flagged():
    assert "no-print" in rules(check("print('hi')\n"))
    assert "no-print" not in rules(check("log.info('hi')\n"))


def test_dataclasses_must_be_frozen():
    assert "frozen-dataclass" in rules(check("@dataclass\nclass A:\n    x: int\n"))
    assert "frozen-dataclass" in rules(check("@dataclass(slots=True)\nclass A:\n    x: int\n"))
    assert "frozen-dataclass" not in rules(check("@dataclass(frozen=True)\nclass A:\n    x: int\n"))
    assert "frozen-dataclass" not in rules(
        check("@dataclasses.dataclass(frozen=True, slots=True)\nclass A:\n    x: int\n")
    )


def test_file_length_limits():
    long_file = "\n".join("x = 1" for _ in range(801)) + "\n"
    medium = "\n".join("x = 1" for _ in range(401)) + "\n"
    assert "file-length" in rules(check(long_file))
    findings = check(medium)
    assert [v.severity for v in findings if v.rule == "file-length"] == ["warning"]


def test_a_syntax_error_is_reported_not_raised():
    assert "syntax" in rules(check("def broken(:\n"))


def test_violations_carry_location_and_message():
    v = check("print('x')\n", "pkg/mod.py")[0]
    assert (v.path, v.line, v.rule) == (Path("pkg/mod.py"), 1, "no-print") and v.message


def test_run_checks_every_python_file_under_the_roots(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("print('x')\n", encoding="utf-8")
    assert [v.path.name for v in cs.run([tmp_path]) if v.severity == "error"] == ["bad.py"]


def test_main_exit_codes(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    assert cs.main([str(tmp_path)]) == 0
    (tmp_path / "bad.py").write_text("print('x')\n", encoding="utf-8")
    assert cs.main([str(tmp_path)]) == 1


def test_this_repository_meets_its_own_standards():
    errors = [v for v in cs.run([ROOT / "src", ROOT / "scripts"]) if v.severity == "error"]
    assert not errors, "\n".join(f"{v.path}:{v.line} [{v.rule}] {v.message}" for v in errors)
