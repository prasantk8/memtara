"""Structural tests for `scripts/pdf.py`.

These do not check that the API exists — they check the three properties the
Canonical Case File actually depends on, because those are the ones that fail
silently:

1.  **The cross-reference table is true.** Every recorded offset is read back
    out of the produced bytes and must land exactly on `N 0 obj`. A wrong xref
    is the signature bug of a hand-rolled PDF writer: the file still greps
    fine, still ends in %%EOF, and still refuses to open in Acrobat. Nothing
    else here matters if this fails.

2.  **Nothing is drawn past the right margin.** Every `Td`/`Tj` pair is parsed
    back out of the content streams and re-measured with Courier's uniform
    600/1000 em advance. This is the only way to prove the wrapper works,
    since a PDF renders overflowing text perfectly happily and simply pushes
    it off the page.

3.  **The bytes are reproducible.** The exporter publishes a SHA-256 over
    them as a tamper-evident seal; two renders of the same document with the
    same `created_at` that differ by one byte would make that seal a lie.

The parsing here is deliberately naive — regexes over uncompressed streams —
and that is a feature of the writer, not a shortcut in the test. If someone
turns on /FlateDecode, these tests break loudly rather than stop checking.

Run:
    .venv/bin/python -m pytest tests/test_pdf_writer.py -v
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.pdf import A4, MARGIN, Document, sanitise  # noqa: E402

FIXED = datetime(2026, 9, 16, 9, 0, 0, tzinfo=timezone.utc)
CHAR_EM = 0.6

DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

TEXT_OP = re.compile(
    rb"BT /(F\d) ([\d.]+) Tf (-?[\d.]+) (-?[\d.]+) Td \((.*)\) Tj ET"
)
STREAM = re.compile(rb"stream\n(.*?)\nendstream", re.DOTALL)


# ---------------------------------------------------------------------------
# Helpers: read a PDF back the way a viewer would, not the way we wrote it.
# ---------------------------------------------------------------------------


def xref_offsets(data: bytes) -> list[int]:
    """Follow `startxref` to the table and return the offsets it records, in
    object-number order starting at object 1."""
    marker = data.rfind(b"startxref")
    assert marker != -1, "no startxref"
    start = int(data[marker + len(b"startxref"):].split()[0])
    assert data[start:start + 4] == b"xref", "startxref does not point at the table"

    header, _, body = data[start:].partition(b"\n")[2].partition(b"\n")
    first, count = (int(n) for n in header.split())
    assert first == 0, "subsection does not start at object 0"

    offsets = []
    for i in range(count):
        entry = body[i * 20:(i + 1) * 20]
        assert len(entry) == 20, f"xref entry {i} is not 20 bytes"
        offset, _generation, kind = entry.split()[:3]
        if kind == b"f":
            continue
        offsets.append(int(offset))
    return offsets


def content_streams(data: bytes) -> list[bytes]:
    """Content streams in page order — page objects and their streams are
    emitted in the order the pages were laid out."""
    return [s for s in STREAM.findall(data) if b"BT " in s or b" l S" in s]


def drawn_text(stream: bytes) -> list[tuple[float, float, float, str]]:
    """(x, y, size, text) for every string drawn in a stream, with PDF string
    escapes undone so the measured length is the glyph count."""
    out = []
    for _font, size, x, y, raw in TEXT_OP.findall(stream):
        text = raw.decode("latin-1")
        text = re.sub(r"\\([\\()])", r"\1", text)
        out.append((float(x), float(y), float(size), text))
    return out


def long_document(paragraphs: int = 40) -> Document:
    doc = Document(
        "Canonical Case File",
        "Case 2026-0417 / DFSA",
        created_at=FIXED,
        running_header="Memtara - Canonical Case File - Case 2026-0417",
    )
    for i in range(paragraphs):
        doc.heading(f"Section {i}", level=2)
        doc.paragraph(
            f"Finding {i}. The holder satisfied the predicate without disclosing "
            "the underlying figures to the bank, the issuer or any intermediary, "
            "which is the property the attestation is about."
        )
        doc.bullet(f"Proof digest {DIGEST}")
    return doc


# ---------------------------------------------------------------------------
# File structure
# ---------------------------------------------------------------------------


def test_starts_and_ends_like_a_pdf():
    data = long_document(4).render()
    assert data.startswith(b"%PDF-")
    assert data.endswith(b"%%EOF")


def test_xref_offsets_point_at_their_objects():
    """The one test that decides whether the file opens at all."""
    data = long_document(30).render()
    offsets = xref_offsets(data)
    assert offsets, "xref recorded no objects"

    for number, offset in enumerate(offsets, start=1):
        expected = f"{number} 0 obj".encode()
        assert data[offset:offset + len(expected)] == expected, (
            f"xref entry for object {number} points at "
            f"{data[offset:offset + 24]!r}, not {expected!r}"
        )

    # And the table accounts for every object in the file, so nothing is
    # written that a viewer cannot reach.
    assert len(re.findall(rb"^\d+ 0 obj$", data, re.MULTILINE)) == len(offsets)
    size = int(re.search(rb"/Size (\d+)", data).group(1))
    assert size == len(offsets) + 1  # +1 for the free object 0


def test_page_count_matches_the_pages_node():
    data = long_document(30).render()
    declared = int(re.search(rb"/Count (\d+)", data).group(1))
    actual = len(re.findall(rb"/Type /Page[^s]", data))
    assert declared == actual >= 3
    kids = re.search(rb"/Kids \[(.*?)\]", data).group(1)
    assert len(re.findall(rb"\d+ 0 R", kids)) == declared


def test_trailer_names_a_root_and_an_info_dictionary():
    data = long_document(2).render()
    assert re.search(rb"trailer\n<< /Size \d+ /Root 1 0 R /Info 6 0 R >>", data)
    assert b"/Producer (" in data
    assert b"/CreationDate (D:20260916090000+00'00')" in data


# ---------------------------------------------------------------------------
# Determinism — the reason this module exists
# ---------------------------------------------------------------------------


def test_same_created_at_renders_identical_bytes():
    assert long_document(25).render() == long_document(25).render()


def test_render_is_idempotent():
    doc = long_document(10)
    assert doc.render() == doc.render()


def test_created_at_is_the_only_thing_that_moves():
    a = long_document(6)
    b = long_document(6)
    b.created_at = datetime(2026, 9, 17, 9, 0, 0, tzinfo=timezone.utc)
    assert a.render() != b.render()
    # ...and only in the Info dictionary, not in the drawn content.
    assert content_streams(a.render()) == content_streams(b.render())


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def test_long_document_paginates_and_every_footer_knows_the_total():
    data = long_document(40).render()
    streams = content_streams(data)
    assert len(streams) >= 3

    total = len(streams)
    for index, stream in enumerate(streams, start=1):
        expected = f"Page {index} of {total}".encode()
        assert expected in stream, f"page {index} footer is not {expected!r}"


def test_running_header_appears_after_the_first_page_only():
    data = long_document(40).render()
    streams = content_streams(data)
    header = b"Memtara - Canonical Case File - Case 2026-0417"
    assert header not in streams[0], "page 1 carries the title block, not the header"
    for stream in streams[1:]:
        assert header in stream


def test_page_break_does_not_manufacture_blank_pages():
    doc = Document("T", created_at=FIXED)
    doc.page_break()          # before any content
    doc.paragraph("one")
    doc.page_break()
    doc.page_break()          # twice in a row
    doc.paragraph("two")
    assert len(content_streams(doc.render())) == 2


def test_a_heading_is_never_orphaned_at_the_foot_of_a_page():
    """A heading with no room for content under it must move to the next page.
    Checked geometrically: every bold heading baseline must have at least
    three body lines of page left below it."""
    doc = Document("T", created_at=FIXED)
    for i in range(60):
        doc.paragraph(f"Filler paragraph number {i} for pagination pressure.")
        doc.heading(f"Heading {i}", level=2)
        doc.paragraph("Body text belonging to the heading above it.")
    data = doc.render()
    for stream in content_streams(data):
        for _font, size, _x, y, _raw in TEXT_OP.findall(stream):
            if float(size) == 12.5:  # level-2 heading
                assert float(y) - 3 * 13.0 >= MARGIN - 1e-6, "orphaned heading"


def test_empty_document_still_renders_one_valid_page():
    data = Document("Nothing to report", created_at=FIXED).render()
    assert len(content_streams(data)) == 1
    assert b"Page 1 of 1" in data


# ---------------------------------------------------------------------------
# Layout: nothing may cross the right margin
# ---------------------------------------------------------------------------


def _assert_within_margins(data: bytes) -> int:
    limit = A4[0] - MARGIN
    checked = 0
    for stream in content_streams(data):
        for x, _y, size, text in drawn_text(stream):
            end = x + len(text) * CHAR_EM * size
            assert end <= limit + 1e-6, (
                f"{text!r} at x={x} size={size} ends at {end:.2f}, "
                f"past the right margin at {limit:.2f}"
            )
            assert x >= MARGIN - 1e-6 or _y < MARGIN, f"{text!r} starts left of the margin"
            checked += 1
    return checked


def test_nothing_is_drawn_past_the_right_margin():
    doc = long_document(20)
    doc.heading("A heading long enough to need wrapping at sixteen point across A4")
    doc.key_values(
        [
            ("Predicate", "income_gte_threshold"),
            ("Proof digest", DIGEST),
            ("A pathologically long key that wants the whole line to itself", DIGEST),
        ]
    )
    doc.table(
        ["#", "Artefact", "SHA-256", "Notes"],
        [
            ["1", "proof.bin", DIGEST, "Barretenberg UltraHonk over tax_session"],
            ["2", "vk.bin", DIGEST, "Committed verification key"],
        ],
    )
    doc.preformatted(["x" * 200, '{"predicate": "income_gte_threshold"}'])
    assert _assert_within_margins(doc.render()) > 100


def test_an_unbreakable_token_hard_breaks_instead_of_overflowing():
    """A 64-character digest fits on a body line (80 columns at 10 pt), so
    wrapping must move it whole onto its own line. Anything wider than the
    column — a base64url proof token, or that same digest inside the narrower
    value column of `key_values` — has to be split at the column boundary,
    and split without losing or duplicating a character."""
    doc = Document("T", created_at=FIXED)
    doc.paragraph(f"The proof digest is {DIGEST} as recorded.")
    token = "eyJhbGciOiJFZERTQSJ9." + "Qk4yNTRfcHJvb2ZfYnl0ZXM" * 12
    doc.paragraph(f"Token: {token}")
    doc.key_values(
        [("Verification key commitment", "committed at genesis"), ("Proof digest", DIGEST)]
    )
    data = doc.render()
    _assert_within_margins(data)

    body = [text for _x, _y, size, text in drawn_text(content_streams(data)[0]) if size == 10.0]
    assert any(DIGEST in line for line in body), "a digest that fits a line was broken anyway"
    assert not any(token in line for line in body), "the long token did not break at all"
    assert token in "".join(body).replace(" ", ""), "the token was mangled, not merely broken"

    # The value column of key_values is narrower than 64 characters here, so
    # the same digest does have to split — and must still reassemble exactly.
    fragments = [line for line in body if line and set(line) <= set("0123456789abcdef")]
    assert len(fragments) > 1, "the digest never hard-broke in the value column"
    assert "".join(fragments) == DIGEST


def test_preformatted_fits_a_hundred_columns_and_clips_beyond():
    doc = Document("T", created_at=FIXED)
    doc.preformatted(["c" * 100, "d" * 140])
    data = doc.render()
    _assert_within_margins(data)
    lines = [text for _x, _y, size, text in drawn_text(content_streams(data)[0]) if size == 8.0]
    assert lines[0] == "c" * 100, "a 100-column line must survive intact"
    assert len(lines[1]) == 100 and lines[1].endswith(">"), "over-long lines clip with a marker"


def test_table_draws_a_rule_under_the_header():
    doc = Document("T", created_at=FIXED)
    doc.table(["A", "B"], [["1", "2"]])
    stream = content_streams(doc.render())[0]
    rules = re.findall(rb"[\d.]+ G [\d.]+ w [\d.]+ ([\d.]+) m", stream)
    # Title-block rule, header rule, footer rule.
    assert len(rules) >= 3


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def test_non_latin1_input_renders_without_raising_and_stays_in_range():
    doc = Document(
        "Case file — DFSA §5(c)",
        "Status ✅",
        created_at=FIXED,
        running_header="… continued",
    )
    doc.paragraph("Threshold ≥ 100 000 AED and ≤ 250 000 AED — a 2 × margin. 🚀")
    doc.bullet("Holder’s “consent” recorded")
    doc.table(["Clause", "Status"], [["§5(c)", "✅"]])
    doc.preformatted(["{'flag': '✅'}"])
    data = doc.render()

    for stream in content_streams(data):
        assert all(byte < 0x80 for byte in stream), "content stream left the ASCII range"
        for _x, _y, _size, text in drawn_text(stream):
            assert all(ord(ch) <= 0xFF for ch in text)

    # The substitutions actually happened, rather than the characters being
    # dropped on the floor.
    joined = "\n".join(
        text for stream in content_streams(data) for _x, _y, _s, text in drawn_text(stream)
    )
    assert "Case file - DFSA S.5(c)" in joined
    assert "Status [OK]" in joined
    assert "Threshold >= 100 000 AED and <= 250 000 AED - a 2 x margin. ?" in joined
    assert '- Holder\'s "consent" recorded' in joined
    assert "... continued" in joined or len(content_streams(data)) == 1
    # Nothing from the source survived as raw UTF-8.
    for utf8 in ("—", "✅", "🚀", "≥", "§"):
        assert utf8.encode("utf-8") not in data


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("—", "-"),
        ("…", "..."),
        ("✅", "[OK]"),
        ("≥", ">="),
        ("≤", "<="),
        ("×", "x"),
        ("§", "S."),
        ("“q”", '"q"'),
        ("’", "'"),
        ("é", "é"),          # already representable; must pass through
        ("🇦🇪", "??"),        # regional indicators, one "?" each
        ("\u0000", "?"),
    ],
)
def test_substitution_table(raw, expected):
    assert sanitise(raw) == expected


def test_parentheses_and_backslashes_are_escaped():
    doc = Document("T", created_at=FIXED)
    doc.paragraph(r"path C:\vault\(v2) and a lone ) brace")
    stream = content_streams(doc.render())[0]
    assert rb"C:\\vault\\\(v2\)" in stream
    # The escaping must round-trip: unescaped text is what the reader sees.
    texts = [t for _x, _y, _s, t in drawn_text(stream)]
    assert any(r"C:\vault\(v2) and a lone ) brace" in t for t in texts)
