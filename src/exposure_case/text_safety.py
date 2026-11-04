"""Neutralize untrusted text (Tenable plugin names, solutions, hostnames, advisory links) on its way out.

* Markdown is the supported target: backslashes are escaped first, then ``< > [ ]``, so no tag, link or image
  can form; bare URLs become inert code spans; advisory URLs and ids are rendered as code spans.
* CSV: formula-looking cells get a leading apostrophe.
* Invisible and bidirectional-override characters are removed everywhere.
"""

from __future__ import annotations

import re
import unicodedata

# control, format (bidi, zero-width), line separator, paragraph separator
STRIPPED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})
_FORMULA_START = ("=", "+", "-", "@")
_MARKDOWN_ESCAPES = "<>[]"
# Bare URLs are auto-linked by GitHub-flavoured renderers, so they are shown as code spans instead.
_URL = re.compile(
    r"\b(?:(?:https?|ftp)://|www\.)[^\s<>\[\]()`]*"  # URLs, any letter case
    r"|(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+",  # e-mail addresses (GitHub links them); anchored, so linear
    re.IGNORECASE,
)


def strip_invisible(value: object, keep_newline: bool = False) -> str:
    """Text without control, format (bidi / zero-width) or line-separator characters."""
    text = str(value).replace("\t", " ").replace("\r", "")
    # Fast path: isprintable() is False for every stripped category (and for "\n"), so clean text skips the loop.
    if text.isprintable() or (keep_newline and text.replace("\n", "").isprintable()):
        return text
    return "".join(
        ch for ch in text if (keep_newline and ch == "\n") or unicodedata.category(ch) not in STRIPPED_CATEGORIES
    )


def single_line(value: object) -> str:
    """Invisible characters removed and all whitespace collapsed to single spaces."""
    return " ".join(strip_invisible(str(value).replace("\n", " ")).split())


def _escape_plain(text: str) -> str:
    text = text.replace("\\", "\\\\")  # escape backslashes FIRST, or they can cancel our escapes
    for ch in _MARKDOWN_ESCAPES:
        text = text.replace(ch, "\\" + ch)
    return text.replace("`", "'")


def md_text(value: object) -> str:
    """Single-line Markdown text in which no tag, link or image can form and no URL is clickable."""
    cleaned = strip_invisible(value)
    pieces: list[str] = []
    position = 0
    for match in _URL.finditer(cleaned):
        pieces.append(_escape_plain(cleaned[position : match.start()]))
        pieces.append("`" + match.group().replace("`", "'") + "`")
        position = match.end()
    pieces.append(_escape_plain(cleaned[position:]))
    return " ".join("".join(pieces).split())


def md_cell(value: object) -> str:
    """``md_text`` that is also safe inside a Markdown table cell."""
    return md_text(value).replace("|", "\\|")


def md_code(value: object) -> str:
    """A code span: literal text, never a link, and it cannot be closed early by the text itself."""
    return "`" + " ".join(strip_invisible(value).replace("`", "'").split()) + "`"


def csv_cell(value: object) -> object:
    """Numbers pass through; strings a spreadsheet would run as a formula get a leading apostrophe."""
    if not isinstance(value, str):
        return value
    text = strip_invisible(value, keep_newline=True)
    return f"'{text}" if text.lstrip().startswith(_FORMULA_START) else text
