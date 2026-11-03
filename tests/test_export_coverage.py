import json

from test_export import NOW, package_view, world  # noqa: F401  (world is a fixture)

from exposure_case.case import build_package_view
from exposure_case.coverage import CoverageStep
from exposure_case.export import package_json, package_markdown

STEP = CoverageStep(
    step=2,
    package_id="fix:v-p:patch",
    hosts_cleared=3,
    cumulative_hosts_cleared=8,
    urgent_hosts_total=20,
    urgent_findings=5,
    actions=1,
)


def with_coverage(world, step):  # noqa: F811
    _, _, packages, links = world
    ranked = next(r for r in packages if r.package.package_id == "fix:v-p:patch")
    return build_package_view(ranked, links, NOW, step)


def test_markdown_states_the_coverage_step_and_its_assumptions(world):  # noqa: F811
    text = package_markdown(with_coverage(world, STEP))
    assert "**Coverage order:** step 2" in text
    assert "3 more hosts" in text and "8 of 20" in text
    assert "every listed action" in text and "earlier step" in text
    assert "heuristic" in text and "not the shortest plan" in text


def test_markdown_without_coverage_has_no_coverage_line(world):  # noqa: F811
    assert "Coverage order" not in package_markdown(package_view(world))


def test_json_carries_the_coverage_object_or_null(world):  # noqa: F811
    with_step = json.loads(package_json(with_coverage(world, STEP)))
    assert with_step["coverage"] == STEP.to_dict()
    assert json.loads(package_json(package_view(world)))["coverage"] is None
