import dataclasses
import random

import pytest
from test_fixes import fx

from exposure_case.coverage import CoverageStep, coverage_order, is_urgent
from exposure_case.fixes import build_fix_packages

OPENSSH = "cpe:/a:openbsd:openssh"
APACHE = "cpe:/a:apache:http_server"
NGINX = "cpe:/a:nginx:nginx"
SOL_A = "Upgrade to OpenSSH 9.6 or later."
SOL_B = "Upgrade to OpenSSH 9.8 or later."


def hot(fid, asset="a1", plugin=1, cpe=OPENSSH, **extra):
    """An urgent finding: critical severity."""
    return fx(fid, asset=asset, plugin=plugin, cpe=cpe, severity="critical", exploit_available=False, **extra)


def quiet(fid, asset="a1", plugin=1, cpe=OPENSSH, **extra):
    """A finding that is not urgent: high severity, no exploitation signal."""
    return fx(fid, asset=asset, plugin=plugin, cpe=cpe, severity="high", exploit_available=False, **extra)


def order(records):
    return coverage_order(build_fix_packages(records))


def ids(steps):
    return [s.package_id for s in steps]


@pytest.mark.parametrize(
    "record,expected",
    [
        (hot("f"), True),
        (quiet("f"), False),
        (fx("f", severity="high", exploit_available=True), True),
        (quiet("f", exploited_by_malware=True), True),
        (quiet("f", vpr={"on_cisa_kev": True}), True),
        (fx("f", severity="medium", exploit_available=False), False),
        (fx("f", severity="info", exploit_available=True), False),
        (fx("f", severity="critical", state="FIXED"), False),
    ],
)
def test_is_urgent(record, expected):
    assert is_urgent(record) is expected


def test_empty_input_gives_no_steps():
    assert coverage_order([]) == ()


def test_single_package_is_one_step_that_clears_its_urgent_host():
    steps = order([hot("f1", asset="a1"), hot("f2", asset="a2", plugin=2)])
    assert len(steps) == 1
    s = steps[0]
    assert (s.step, s.hosts_cleared, s.cumulative_hosts_cleared, s.urgent_hosts_total) == (1, 2, 2, 2)
    assert s.urgent_findings == 2 and s.actions == 1


def test_a_host_with_urgent_findings_in_two_packages_clears_only_on_the_second():
    # P has 2 urgent findings on a1, Q has 1 on a1: P is first (more urgent findings) but clears nothing.
    steps = order(
        [
            hot("p1", plugin=1, cpe=OPENSSH),
            hot("p2", plugin=2, cpe=OPENSSH),
            hot("q1", plugin=3, cpe=APACHE, solution="Upgrade Apache to 2.4.60."),
        ]
    )
    assert ids(steps) == ["fix:openbsd-openssh:patch", "fix:apache-http-server:patch"]
    assert [s.hosts_cleared for s in steps] == [0, 1]
    assert [s.cumulative_hosts_cleared for s in steps] == [0, 1]


def test_a_package_that_clears_a_host_alone_goes_before_a_larger_one_that_clears_none():
    steps = order(
        [
            hot("b1", asset="a1", plugin=1, cpe=OPENSSH),
            hot("b2", asset="a1", plugin=2, cpe=OPENSSH),
            hot("b3", asset="a1", plugin=3, cpe=OPENSSH),
            hot("o1", asset="a1", plugin=4, cpe=APACHE, solution="Upgrade Apache to 2.4.60."),
            hot("s1", asset="a9", plugin=5, cpe=NGINX, solution="Upgrade nginx to 1.27."),
        ]
    )
    assert steps[0].package_id == "fix:nginx-nginx:patch" and steps[0].hosts_cleared == 1


def test_ties_prefer_fewer_actions_then_package_id():
    fewer = [
        hot("y1", asset="a2", plugin=1, cpe=NGINX, solution="Upgrade nginx to 1.27."),
        hot("y2", asset="a2", plugin=2, cpe=NGINX, solution="Upgrade nginx to 1.27."),
    ]
    more = [
        hot("x1", asset="a1", plugin=3, cpe=OPENSSH, solution=SOL_A),
        hot("x2", asset="a1", plugin=4, cpe=OPENSSH, solution=SOL_B),
    ]
    steps = order(more + fewer)
    assert [s.actions for s in steps] == [1, 2]
    assert ids(steps) == ["fix:nginx-nginx:patch", "fix:openbsd-openssh:patch"]

    twin_a = [hot("a1f", asset="h1", plugin=5, cpe=APACHE, solution="Upgrade Apache to 2.4.60.")]
    twin_b = [hot("b1f", asset="h2", plugin=6, cpe=NGINX, solution="Upgrade nginx to 1.27.")]
    assert ids(order(twin_b + twin_a)) == ["fix:apache-http-server:patch", "fix:nginx-nginx:patch"]


def test_order_does_not_depend_on_input_order():
    records = [
        hot("p1", plugin=1, cpe=OPENSSH),
        hot("p2", asset="a2", plugin=2, cpe=OPENSSH),
        hot("q1", plugin=3, cpe=APACHE, solution="Upgrade Apache to 2.4.60."),
        hot("r1", asset="a3", plugin=4, cpe=NGINX, solution="Upgrade nginx to 1.27."),
        quiet("z1", asset="a4", plugin=5, cpe="cpe:/a:vim:vim", solution="Upgrade vim."),
    ]
    expected = order(records)
    for seed in range(5):
        shuffled = records[:]
        random.Random(seed).shuffle(shuffled)
        assert order(shuffled) == expected


def test_packages_without_urgent_findings_get_no_step():
    steps = order([quiet("f1", cpe=OPENSSH), hot("f2", asset="a2", plugin=2, cpe=APACHE, solution="Upgrade it.")])
    assert ids(steps) == ["fix:apache-http-server:patch"]


def test_fixed_and_info_findings_are_ignored():
    records = [
        fx("fx1", asset="a1", severity="critical", state="FIXED", cpe=OPENSSH),
        fx("in1", asset="a2", plugin=2, severity="info", exploit_available=True, cpe=APACHE),
        hot("live", asset="a3", plugin=3, cpe=NGINX, solution="Upgrade nginx to 1.27."),
    ]
    steps = order(records)
    assert ids(steps) == ["fix:nginx-nginx:patch"] and steps[0].urgent_hosts_total == 1


def test_a_non_urgent_finding_on_a_host_does_not_block_clearing_it():
    steps = order([hot("p1", asset="a1", plugin=1, cpe=OPENSSH), quiet("q1", asset="a1", plugin=2, cpe=APACHE)])
    assert ids(steps) == ["fix:openbsd-openssh:patch"] and steps[0].hosts_cleared == 1


def test_kev_and_public_exploit_hosts_count_as_urgent():
    steps = order(
        [
            quiet("k1", asset="a1", plugin=1, cpe=OPENSSH, vpr={"on_cisa_kev": True}),
            fx(
                "e1",
                asset="a2",
                plugin=2,
                cpe=APACHE,
                severity="high",
                exploit_available=True,
                solution="Upgrade Apache to 2.4.60.",
            ),
        ]
    )
    assert steps[-1].urgent_hosts_total == 2 and steps[-1].cumulative_hosts_cleared == 2


def test_cleared_hosts_add_up_to_the_urgent_hosts():
    steps = order(
        [
            hot("p1", asset="a1", plugin=1, cpe=OPENSSH),
            hot("p2", asset="a2", plugin=2, cpe=OPENSSH),
            hot("q1", asset="a2", plugin=3, cpe=APACHE, solution="Upgrade Apache to 2.4.60."),
            hot("q2", asset="a3", plugin=4, cpe=APACHE, solution="Upgrade Apache to 2.4.60."),
            hot("r1", asset="a1", plugin=5, cpe=NGINX, solution="Upgrade nginx to 1.27."),
        ]
    )
    assert sum(s.hosts_cleared for s in steps) == steps[0].urgent_hosts_total == steps[-1].cumulative_hosts_cleared == 3
    assert [s.step for s in steps] == [1, 2, 3]


def test_a_step_is_frozen_and_serializes():
    step = order([hot("f1")])[0]
    assert isinstance(step, CoverageStep)
    with pytest.raises(dataclasses.FrozenInstanceError):
        step.step = 9  # type: ignore[misc]
    assert set(step.to_dict()) == {
        "step",
        "package_id",
        "hosts_cleared",
        "cumulative_hosts_cleared",
        "urgent_hosts_total",
        "urgent_findings",
        "actions",
    }


def test_the_input_packages_are_not_modified():
    packages = build_fix_packages([hot("f1"), hot("f2", asset="a2", plugin=2)])
    before = [p.to_dict() for p in packages]
    coverage_order(packages)
    assert [p.to_dict() for p in packages] == before
