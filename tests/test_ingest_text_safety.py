"""Quality review 2026-11-03: invisible and bidi characters in Tenable text reached the model unchanged in tool
answers (exports already stripped them), and the OS list skipped the documented 4,096-character field cap."""

import pytest
from test_ingest import raw_record

from exposure_case.ingest import MAX_TEXT_CHARS, parse_record
from exposure_case.text_safety import md_text

pytestmark = pytest.mark.unit

RLO, ZWSP = "\u202e", "\u200b"


def test_invisible_and_bidi_characters_are_removed_at_ingest():
    raw = raw_record()
    raw["plugin"]["name"] = f"Bash{RLO} RCE{ZWSP}"
    raw["asset"]["hostname"] = f"host{ZWSP}01"
    raw["plugin"]["cve"] = [f"CVE-2014-6271{RLO}"]
    raw["asset"]["operating_system"] = [f"Linux{RLO}"]
    r = parse_record(raw)
    assert r.plugin_name == "Bash RCE" and r.hostname == "host01"
    assert r.cves == ("CVE-2014-6271",) and r.operating_system == ("Linux",)


def test_the_os_list_is_capped_like_every_other_text_field():
    raw = raw_record()
    raw["asset"]["operating_system"] = ["x" * 100_000] + ["y"] * 500
    r = parse_record(raw)
    assert len(r.operating_system) <= 100 and all(len(o) <= MAX_TEXT_CHARS for o in r.operating_system)


@pytest.mark.parametrize("text", ["HTTPS://evil.example/x", "Www.evil.example", "mail a@b.example now"])
def test_no_link_can_form_from_uppercase_urls_or_emails(text):
    out = md_text(text)
    assert "`" in out, out  # rendered as an inert code span


@pytest.mark.parametrize("keep_newline", [False, True])
def test_the_fast_path_matches_the_character_by_character_rule(keep_newline):
    import unicodedata

    from exposure_case.text_safety import STRIPPED_CATEGORIES, strip_invisible

    samples = [
        "plain text",
        "line one\nline two",
        "tab\there",
        "cr\r\nlf",
        "nbsp\u00a0x",
        "é ü 漢字",
        RLO + "x",
        ZWSP,
        "\u2028sep",
        "\x00nul",
        "",
        "emoji \U0001f600",
        "\u3000ideographic space",
    ]
    for s in samples:
        text = s.replace("\t", " ").replace("\r", "")
        slow = "".join(
            ch for ch in text if (keep_newline and ch == "\n") or unicodedata.category(ch) not in STRIPPED_CATEGORIES
        )
        assert strip_invisible(s, keep_newline) == slow, repr(s)


@pytest.mark.parametrize("field", ["finding_id", "asset"])
def test_ids_with_hidden_characters_are_rejected_not_silently_changed(field):
    # Stripping would break the trace to the source record, so a hidden character in an id is an error.
    from exposure_case.ingest import IngestError

    raw = raw_record()
    if field == "asset":
        raw["asset"]["uuid"] = raw["asset"]["uuid"] + ZWSP
    else:
        raw["finding_id"] = raw["finding_id"] + RLO
    with pytest.raises(IngestError, match="hidden or control"):
        parse_record(raw)


def test_the_email_pattern_stays_fast_on_long_words():
    import time

    start = time.perf_counter()
    md_text("a" * 20_000)
    assert time.perf_counter() - start < 0.2
