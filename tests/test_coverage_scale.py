import random
import time
from types import SimpleNamespace

from test_coverage import hot, order, quiet  # noqa: F401  (shared fixtures)

from exposure_case.coverage import coverage_order

SCALE_PACKAGES = 1000
SCALE_HOSTS = 3000
SCALE_PER_PACKAGE = 200
# Guards against a quadratic blow-up (minutes), not micro-timing: about 1 s on a laptop, 7 s on a shared CI runner.
TIME_LIMIT_SECONDS = 20.0


def _stub_package(pid, hosts):
    records = [
        SimpleNamespace(
            asset_uuid=h,
            severity="critical",
            state="OPEN",
            on_cisa_kev=False,
            exploited_by_malware=False,
            exploit_available=False,
        )
        for h in hosts
    ]
    return SimpleNamespace(package_id=pid, active=tuple(records), impact=SimpleNamespace(actions=1))


def test_a_large_export_is_ordered_within_the_time_limit():
    rng = random.Random(7)
    packages = [
        _stub_package(f"fix:p{i:04d}:patch", [f"h{n}" for n in rng.sample(range(SCALE_HOSTS), SCALE_PER_PACKAGE)])
        for i in range(SCALE_PACKAGES)
    ]
    started = time.perf_counter()
    steps = coverage_order(packages)  # type: ignore[arg-type]
    elapsed = time.perf_counter() - started
    assert len(steps) == SCALE_PACKAGES
    assert steps[-1].cumulative_hosts_cleared == steps[0].urgent_hosts_total
    assert elapsed < TIME_LIMIT_SECONDS, f"took {elapsed:.1f}s"


def test_a_package_can_gain_value_after_another_is_applied():
    # Both packages share hosts a1 and a2. The vim package has two urgent findings per host, bash has one, so
    # vim goes first and clears nothing; bash then clears both hosts at once. A package's gain can therefore
    # rise after another is applied, which rules out a lazy "gains only shrink" shortcut.
    vim = [
        hot(f"v{i}{h}", asset=h, plugin=i, cpe="cpe:/a:vim:vim", solution="Upgrade vim.")
        for i in (1, 2)
        for h in ("a1", "a2")
    ]
    bash = [hot(f"b{h}", asset=h, plugin=3, cpe="cpe:/a:gnu:bash", solution="Upgrade bash.") for h in ("a1", "a2")]
    steps = order(vim + bash)
    assert [s.package_id for s in steps] == ["fix:vim-vim:patch", "fix:gnu-bash:patch"]
    assert [s.hosts_cleared for s in steps] == [0, 2]


def test_a_host_with_urgent_findings_in_three_packages_clears_on_the_last():
    records = [
        hot("a", plugin=1, cpe="cpe:/a:vim:vim", solution="Upgrade vim."),
        hot("b", plugin=2, cpe="cpe:/a:gnu:bash", solution="Upgrade bash."),
        hot("c", plugin=3, cpe="cpe:/a:nginx:nginx", solution="Upgrade nginx."),
    ]
    steps = order(records)
    assert [s.hosts_cleared for s in steps] == [0, 0, 1]


def test_repeated_urgent_findings_of_one_plugin_on_a_host_count_toward_the_package():
    records = [
        hot("a1", plugin=1, cpe="cpe:/a:vim:vim", solution="Upgrade vim."),
        hot("a2", plugin=1, cpe="cpe:/a:vim:vim", solution="Upgrade vim.", asset="a1"),
    ]
    steps = order(records)
    assert len(steps) == 1 and steps[0].hosts_cleared == 1


def _naive_order(packages):
    """Reference: recompute every gain from scratch at each step (slow, obviously right)."""
    left = {p.package_id: {} for p in packages}
    for p in packages:
        for r in p.active:
            left[p.package_id][r.asset_uuid] = left[p.package_id].get(r.asset_uuid, 0) + 1
    remaining = {}
    for per_host in left.values():
        for host, n in per_host.items():
            remaining[host] = remaining.get(host, 0) + n
    order = []
    while left:

        def key(pid):
            gain = sum(1 for h, n in left[pid].items() if remaining[h] == n)
            return -gain, -sum(left[pid].values()), 1, pid

        best = min(left, key=key)
        order.append((best, -key(best)[0]))
        for host, n in left.pop(best).items():
            remaining[host] -= n
    return order


def test_the_incremental_order_matches_a_from_scratch_recomputation():
    rng = random.Random(11)
    for trial in range(200):
        n_hosts = rng.randint(1, 12)
        packages = [
            _stub_package(f"fix:p{i:02d}:patch", [f"h{rng.randrange(n_hosts)}" for _ in range(rng.randint(1, 6))])
            for i in range(rng.randint(1, 10))
        ]
        got = [(s.package_id, s.hosts_cleared) for s in coverage_order(packages)]  # type: ignore[arg-type]
        assert got == _naive_order(packages), f"trial {trial}"
