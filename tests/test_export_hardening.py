"""Regressions from the security review of the exporters (commit 467158b)."""

import csv
import dataclasses
import io
import os
from datetime import datetime, timedelta, timezone

import pytest
from test_export import NOW, build, case_file, fx, package_view, world  # noqa: F401  (world is a fixture)

from exposure_case.case import build_case_file, build_package_view
from exposure_case.export import (
    ExportError,
    _pct,
    case_markdown,
    csv_cell,
    md_cell,
    md_code,
    md_text,
    package_hosts_csv,
    package_markdown,
    write_case_export,
    write_package_export,
)
from exposure_case.ingest import IngestError, parse_record


def unescaped(text: str, chars: str) -> list[str]:
    """Characters from ``chars`` that a CommonMark parser would treat as markup (not backslash-escaped)."""
    found, i = [], 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] in chars:
            found.append(text[i])
        i += 1
    return found


# --- markdown injection ---


@pytest.mark.parametrize(
    "payload",
    [
        "\\<img src=x onerror=1>",
        "\\\\<b>",
        "a\\",
        "<script>x</script>",
        "\\\\\\<i>",
    ],
)
def test_backslashes_cannot_defeat_the_angle_bracket_escape(payload):
    assert unescaped(md_text(payload), "<>") == []


def test_trailing_backslash_cannot_escape_the_next_cell_boundary():
    row = "| " + md_cell("abc\\") + " | next |"
    assert row.count("|") - row.count("\\|") == 3  # the cell separator stays unescaped


def test_backslash_pipe_cannot_split_a_table_row():
    cell = md_cell("a\\|b")
    assert unescaped(cell, "|") == []


@pytest.mark.parametrize(
    "payload",
    [
        "[Apply patch](javascript:alert(1))",
        "![](https://tracker.test/x.png)",
        "[KB](https://evil.test)",
        "]( x",
    ],
)
def test_links_and_images_are_defused(payload):
    out = md_text(payload)
    assert unescaped(out, "[]") == []


def test_invisible_and_bidi_characters_are_removed():
    out = md_text("evil\u202eexe.txt\u200b\u2028zero\ufeffwidth\u2066x")
    assert all(ch not in out for ch in "\u202e\u200b\u2028\ufeff\u2066") and "evil" in out


def test_md_code_cannot_be_broken_out_of():
    assert md_code("a`b `` c") == "`a'b '' c`"
    assert md_code("plain") == "`plain`"


def test_advisory_urls_are_code_spans_not_links(world):  # noqa: F811
    recs = [fx("f1", see_also=["javascript:alert(1)", "https://example.test/adv1"])]
    _, packages, links = build(recs)
    md = package_markdown(build_package_view(packages[0], links, NOW))
    assert "`javascript:alert(1)`" in md and "`https://example.test/adv1`" in md


def test_identifiers_with_backticks_cannot_break_out_of_code_spans():
    from exposure_case.links import Link

    view_md = md_code(Link("plugin:1`; <b>", "t", 1, 1.0).other_id)
    assert view_md.count("`") == 2


# --- csv ---


@pytest.mark.parametrize("bad", [" =1+1", "\x00=1", "\u200b=1", "\u202e=1", "\n=1", "  @SUM(A1)", " \t-2+3"])
def test_csv_formulas_are_neutralized_after_cleaning(bad):
    assert csv_cell(bad).startswith("'")


def test_csv_cell_removes_invisible_characters_but_keeps_newlines():
    out = csv_cell("a\u200bb\u202ec\u2028d\ne")
    assert out == "abc" + "d\ne"


def test_csv_files_are_written_with_a_bom_so_excel_reads_unicode(world, tmp_path):  # noqa: F811
    paths = write_package_export(package_view(world), tmp_path, confirm=True)
    for p in paths:
        starts_with_bom = p.read_bytes().startswith(b"\xef\xbb\xbf")
        assert starts_with_bom == (p.suffix == ".csv")


def test_csv_round_trips_non_ascii(world, tmp_path):  # noqa: F811
    recs = [dataclasses.replace(fx("f1"), hostname="srv-é-日本")]
    _, packages, links = build(recs)
    text = package_hosts_csv(build_package_view(packages[0], links, NOW))
    assert "srv-é-日本" in [cell for row in csv.reader(io.StringIO(text)) for cell in row]


# --- percentages ---


@pytest.mark.parametrize(
    "share,expected",
    [
        (0.0, "0.0%"),
        (1.0, "100.0%"),
        (0.9996, "99.9%"),
        (0.0004, "under 0.1%"),
        (0.5, "50.0%"),
        (0.0015, "0.1%"),
    ],
)
def test_percentages_never_round_up_to_a_full_clear(share, expected):
    assert _pct(share) == expected


# --- writing files ---


def test_file_names_carry_a_hash_so_lossy_slugs_cannot_collide(world, tmp_path):  # noqa: F811
    view = package_view(world)
    a = dataclasses.replace(view, package=dataclasses.replace(view.package, package_id="fix:a/b:patch"))
    b = dataclasses.replace(view, package=dataclasses.replace(view.package, package_id="fix:a-b:patch"))
    names_a = {p.name for p in write_package_export(a, tmp_path, confirm=True)}
    names_b = {p.name for p in write_package_export(b, tmp_path, confirm=True)}
    assert names_a.isdisjoint(names_b)


def test_reserved_and_long_names_are_safe(world, tmp_path):  # noqa: F811
    view = package_view(world)
    for pid in ("con", "NUL", "x" * 500, "日本語"):
        v = dataclasses.replace(view, package=dataclasses.replace(view.package, package_id=pid))
        for p in write_package_export(v, tmp_path, confirm=True):
            assert len(p.name) <= 100 and p.stem.lower() not in ("con", "nul", "aux")


def test_existing_symlink_target_is_replaced_not_followed(world, tmp_path):  # noqa: F811
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me", encoding="utf-8")
    out = tmp_path / "out"
    first = write_package_export(package_view(world), out, confirm=True)
    link = first[0]
    link.unlink()
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    write_package_export(package_view(world), out, confirm=True)
    assert outside.read_text(encoding="utf-8") == "keep me" and not link.is_symlink()


def test_failed_write_leaves_no_temp_files(world, tmp_path, monkeypatch):  # noqa: F811
    calls = {"n": 0}
    real = os.replace

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        return real(src, dst)

    monkeypatch.setattr(os, "replace", flaky)
    with pytest.raises(ExportError):
        write_package_export(package_view(world), tmp_path, confirm=True)
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_unwritable_directory_is_an_export_error(world, tmp_path):  # noqa: F811
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(ExportError):
        write_package_export(package_view(world), blocker / "sub", confirm=True)


def test_case_and_package_with_the_same_stem_do_not_share_files(world, tmp_path):  # noqa: F811
    cf = case_file(world)
    view = package_view(world)
    a = {p.name for p in write_case_export(cf, tmp_path, confirm=True)}
    b = {p.name for p in write_package_export(view, tmp_path, confirm=True)}
    assert a.isdisjoint(b)


# --- case wording and robustness ---


def test_wording_does_not_overstate_what_a_package_clears(world):  # noqa: F811
    md = case_markdown(case_file(world))
    assert "## Fix packages that address this case" in md and "clear this case" not in md
    pkg = package_markdown(package_view(world))
    assert "Clears this share" not in pkg and "alone clears" in pkg


def test_one_day_is_singular():
    f = dataclasses.replace(fx("f1"), first_found=NOW - timedelta(days=1))
    cases, _, links = build([f])
    cf = build_case_file(cases[0], links, NOW)
    assert any("first seen 1 day before" in line for line in cf.facts_summary)


def test_naive_as_of_is_rejected(world):  # noqa: F811
    _, cases, _, links = world
    with pytest.raises(ValueError, match="timezone"):
        build_case_file(cases[0], links, datetime(2026, 11, 2))


def test_unknown_severity_is_an_ingest_error():
    from test_ingest import raw_record

    with pytest.raises(IngestError, match="severity"):
        parse_record(raw_record(severity="catastrophic"))


def test_timeline_cap_keeps_the_most_recent_events():
    recs = []
    for i in range(50):
        f = fx(f"f{i:02d}", asset=f"a{i}")
        recs.append(dataclasses.replace(f, first_found=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=i)))
    cases, _, links = build(recs)[0], None, build(recs)[2]
    cf = build_case_file(cases[0], links, NOW)
    md = case_markdown(cf, max_events=40)
    timeline = md.split("## Timeline")[1].split("## Limitations")[0]
    assert "2026-02-19" in timeline  # the 50th event (Jan 1 + 49 days)
    assert "| 2026-01-01 |" not in timeline and "10 earlier events are in the JSON" in timeline


def test_cves_are_the_union_across_a_plugins_findings():
    recs = [fx("f1", asset="a1", cve=["CVE-1"]), fx("f2", asset="a2", cve=["CVE-2"])]
    cases, _, links = build(recs)[0], None, build(recs)[2]
    cf = build_case_file(cases[0], links, NOW)
    assert cf.vulnerabilities[0].cves == ("CVE-1", "CVE-2")
