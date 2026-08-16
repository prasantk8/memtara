#!/usr/bin/env python3
"""A small, deterministic, dependency-free PDF writer.

Written for `scripts/export_audit_evidence.py`, which renders the Canonical
Case File — the evidence document a bank's CRO hands to the DFSA or the CBUAE
— and then publishes a SHA-256 over the rendered bytes as a tamper-evident
seal. That seal is the whole design constraint. It means:

  * the same document plus the same `created_at` must produce byte-identical
    output, forever, on any machine; and
  * nothing may enter the file that the caller did not put there — no build
    timestamps, no object IDs derived from memory addresses, no dictionary
    iteration order that depends on insertion history.

That is also why this exists instead of `reportlab`. A seal over bytes we do
not fully control is a seal over someone else's release notes, and this repo
already declines dependencies it can do without (see requirements-dev.txt).

Deliberate non-features, so nobody mistakes them for oversights:

  * **Streams are not compressed.** `zlib` is in the standard library and the
    /Filter plumbing would be four lines, but an uncompressed content stream
    is greppable and diffable. When two runs of the exporter disagree, the
    person debugging it wants to see which line of text moved, not two blobs
    of DEFLATE. Reproducibility is worth more here than file size.
  * **No font embedding.** Base-14 only, so the file has no font program in
    it and cannot drift when a system font is upgraded.
  * **No /ID in the trailer.** It is optional for an unencrypted PDF 1.4, and
    every sensible way to generate one is either random or a hash of the file
    we are still writing.

Usage::

    from scripts.pdf import Document, A4

    doc = Document("Canonical Case File", "Case 2026-0417", created_at=AS_OF)
    doc.heading("A. Attestation")
    doc.key_values([("Predicate", "income_gte_threshold"), ("Circuit", "tax_session")])
    Path("case.pdf").write_bytes(doc.render())
"""

from __future__ import annotations

from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Why every font here is Courier
#
# Courier's base-14 metrics are uniform: *every* glyph, including the space
# and the period, is exactly 600/1000 em. So the width of a string is
#
#     len(s) * 0.6 * font_size
#
# exactly, with no font metric table, no AFM parsing, and no per-character
# lookup. That single fact is what lets this module wrap paragraphs, size
# table columns and clip preformatted blocks with integer character counts
# and still guarantee nothing crosses the right margin.
#
# Do NOT "improve" this to Helvetica. Helvetica is proportional; `len(s)`
# stops predicting width, every width calculation below silently becomes
# wrong, and the failure mode is text running off the page in a document that
# has already been sealed and sent to a regulator. If proportional fonts are
# ever genuinely needed, the AFM widths have to come with them.
# ---------------------------------------------------------------------------

A4 = (595.28, 841.89)

MARGIN = 56.0

BODY_SIZE, BODY_LEAD = 10.0, 13.0          # 80 columns of text at A4 width
TABLE_SIZE, TABLE_LEAD = 9.0, 11.5         # 89 columns; tables want the room
PRE_SIZE, PRE_LEAD = 8.0, 9.5              # see `preformatted` for the arithmetic
TITLE_SIZE = 18.0
SUBTITLE_SIZE = 10.0
FOOTER_SIZE = 8.0
HEADER_SIZE = 8.0
HEADING_SIZES = {1: 16.0, 2: 12.5, 3: 10.5}

CHAR_EM = 0.6                              # Courier, every glyph, always

FONT_REGULAR = "F1"
FONT_BOLD = "F2"
FONT_OBLIQUE = "F3"

PRODUCER = "memtara-zkp scripts/pdf.py"

RULE_GRAY = 0.55
RULE_WIDTH = 0.6


# ---------------------------------------------------------------------------
# Text encoding
#
# The fonts declare /WinAnsiEncoding, which agrees with Latin-1 across
# 0x20-0x7E and 0xA0-0xFF and disagrees in 0x80-0x9F (where Latin-1 has C1
# controls and WinAnsi has typographic punctuation). Rather than build a
# WinAnsi table, we only ever emit bytes from the ranges where the two agree,
# and route everything else through the substitution table below. That keeps
# `bytes.decode("latin-1")` a faithful reading of the file, which is what the
# tests and any future debugging rely on.
#
# Substitution happens at the API boundary, before a single width is computed
# — "✅" is one character but four columns once it becomes "[OK]", and a
# wrapper that measured before substituting would overflow the margin by three
# characters. Anything unrecognised becomes "?" rather than vanishing: a
# regulator's copy of an evidence document must never quietly lose a
# character, and a visible "?" is a bug report.
# ---------------------------------------------------------------------------

_SUBSTITUTIONS = {
    "—": "-",      # em dash
    "–": "-",      # en dash
    "‘": "'",      # left single quote
    "’": "'",      # right single quote / apostrophe
    "“": '"',      # left double quote
    "”": '"',      # right double quote
    "…": "...",    # ellipsis
    "✅": "[OK]",   # white heavy check mark
    "≥": ">=",
    "≤": "<=",
    "×": "x",      # multiplication sign
    "§": "S.",     # section sign
    " ": " ",      # non-breaking space; must not survive into wrapping
    "\t": "    ",
}


def sanitise(text: str) -> str:
    """Fold `text` into the byte range WinAnsi and Latin-1 agree on.

    `×` and `§` are representable in WinAnsi and are still folded to ASCII:
    the substitution table is the documented contract, and an all-ASCII
    content stream is easier to eyeball in a hex dump than one with stray
    high bytes.
    """
    out = []
    for ch in str(text):
        if ch in _SUBSTITUTIONS:
            out.append(_SUBSTITUTIONS[ch])
            continue
        code = ord(ch)
        if ch == "\n" or 0x20 <= code <= 0x7E or 0xA0 <= code <= 0xFF:
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)


def _escape(text: str) -> str:
    """Escape a PDF literal string. Backslash first, or we escape our own
    escapes."""
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _num(value: float) -> str:
    """Format a coordinate. Two decimals is well past the resolution of any
    output device, and the fixed rounding keeps the bytes stable against
    platform float repr differences."""
    rounded = round(float(value), 2)
    if rounded == int(rounded):
        return str(int(rounded))
    return f"{rounded:.2f}".rstrip("0")


def _wrap(text: str, width: int) -> list[str]:
    """Word-wrap to `width` characters, hard-breaking any token that cannot
    fit on a line by itself.

    That last clause is not a corner case here: this document is full of
    64-character SHA-256 digests and base64url proof tokens, none of which
    contain a space. Without the hard break they would run past the right
    margin of a sealed PDF. They are broken at the column boundary rather
    than hyphenated, because a hyphen inserted into a digest is a digest a
    reader will copy out wrong.

    Runs of whitespace collapse (this is prose, not `preformatted`), but
    explicit newlines are honoured as paragraph breaks.
    """
    width = max(1, width)
    out: list[str] = []
    for para in text.split("\n"):
        line = ""
        emitted = False
        for word in para.split():
            while len(word) > width:
                if line:
                    out.append(line)
                    line = ""
                    emitted = True
                out.append(word[:width])
                emitted = True
                word = word[width:]
            if not word:
                continue
            if not line:
                line = word
            elif len(line) + 1 + len(word) <= width:
                line += " " + word
            else:
                out.append(line)
                emitted = True
                line = word
        if line or not emitted:
            out.append(line)
    return out


def _fit_columns(natural: list[int], available: int) -> list[int]:
    """Distribute `available` character cells across columns that want
    `natural`.

    Water-filling rather than proportional scaling: a column of two-character
    flags next to a column of 64-character digests should keep its two
    characters and give the rest away, whereas proportional scaling would
    shave the narrow column to nothing and still leave the wide one wrapping.
    Columns that fit under the fair share are settled first, and the freed
    space is re-shared among the rest until nothing else fits.
    """
    n = len(natural)
    if n == 0:
        return []
    widths = [0] * n
    pending = list(range(n))
    remaining = available
    while pending:
        fair = max(1, remaining // len(pending))
        settled = [i for i in pending if natural[i] <= fair]
        if not settled:
            break
        for i in settled:
            widths[i] = natural[i]
            remaining -= natural[i]
            pending.remove(i)
    if pending:
        share, extra = divmod(max(0, remaining), len(pending))
        for rank, i in enumerate(pending):
            widths[i] = max(1, share + (1 if rank < extra else 0))
    return widths


class Document:
    """A flowing, paginated text document.

    Content is laid out as it is added; `render()` only serialises. The one
    thing layout cannot know while it runs is the total page count needed by
    the "Page N of M" footer — so footers are not part of the flow at all.
    They are drawn into the bottom margin at serialisation time, once M is
    known, which makes this a genuine two-pass render without a second layout
    pass and without patching bytes after the fact. Nothing in the margins can
    push content around, so the two passes cannot disagree.
    """

    def __init__(
        self,
        title: str,
        subtitle: str = "",
        created_at: datetime | None = None,
        page_size: tuple[float, float] = A4,
        running_header: str = "",
    ) -> None:
        self.title = sanitise(title)
        self.subtitle = sanitise(subtitle)
        self.running_header = sanitise(running_header)
        self.page_width, self.page_height = float(page_size[0]), float(page_size[1])
        self.margin = MARGIN

        # The only time-varying input in the whole module. Callers that want a
        # reproducible seal pin it; callers that do not get wall-clock UTC,
        # truncated to the second because the PDF date format has no room for
        # anything finer.
        moment = created_at or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        self.created_at = moment.astimezone(timezone.utc).replace(microsecond=0)

        self._pages: list[list[tuple]] = []
        self._page: list[tuple] | None = None
        self._y = 0.0
        self._pending_break = False

    # -- geometry ----------------------------------------------------------

    @property
    def text_width(self) -> float:
        return self.page_width - 2 * self.margin

    @property
    def right_margin(self) -> float:
        return self.page_width - self.margin

    def _columns(self, size: float) -> int:
        """How many Courier characters of `size` fit across the text width."""
        return max(1, int(self.text_width // (CHAR_EM * size)))

    # -- page machinery ----------------------------------------------------

    def _new_page(self) -> None:
        self._page = []
        self._pages.append(self._page)
        self._y = self.page_height - self.margin
        if len(self._pages) == 1:
            self._draw_title_block()
        elif self.running_header:
            self._draw_running_header()

    def _ensure(self, height: float) -> None:
        """Guarantee `height` points of room below the cursor, breaking the
        page if there is not."""
        if self._page is None or self._pending_break:
            self._pending_break = False
            self._new_page()
        elif self._y - height < self.margin:
            self._new_page()

    def _draw_title_block(self) -> None:
        if not self.title:
            return
        for line in _wrap(self.title, self._columns(TITLE_SIZE)):
            self._line(line, TITLE_SIZE, TITLE_SIZE * 1.3, font=FONT_BOLD)
        if self.subtitle:
            self._y -= 2
            for line in _wrap(self.subtitle, self._columns(SUBTITLE_SIZE)):
                self._line(line, SUBTITLE_SIZE, SUBTITLE_SIZE * 1.3, font=FONT_OBLIQUE)
        self._y -= 6
        self._rule_at(self._y)
        self._y -= 14

    def _draw_running_header(self) -> None:
        # Lives in the top margin, above the text frame, so it never displaces
        # content and never changes where a page breaks.
        text = self.running_header[: self._columns(HEADER_SIZE)]
        assert self._page is not None
        self._page.append(
            ("text", self.margin, self.page_height - self.margin + 16, HEADER_SIZE, FONT_OBLIQUE, text)
        )
        self._page.append(
            (
                "line",
                self.margin,
                self.page_height - self.margin + 10,
                self.right_margin,
                self.page_height - self.margin + 10,
            )
        )

    def _footer_ops(self, index: int, total: int) -> list[tuple]:
        label = f"Page {index + 1} of {total}"
        width = len(label) * CHAR_EM * FOOTER_SIZE
        return [
            ("line", self.margin, self.margin - 14, self.right_margin, self.margin - 14),
            ("text", (self.page_width - width) / 2, self.margin - 26, FOOTER_SIZE, FONT_REGULAR, label),
        ]

    # -- primitives --------------------------------------------------------

    def _line(self, text: str, size: float, leading: float, font: str = FONT_REGULAR, indent: float = 0.0) -> None:
        """Draw one already-wrapped line at the cursor and advance it."""
        self._ensure(leading)
        assert self._page is not None
        if text:
            # Baseline sits 0.75 em below the top of the line box: Courier's
            # ascender is ~0.63 em and this leaves the descender of the line
            # above clear of it.
            self._page.append(
                ("text", self.margin + indent, self._y - size * 0.75, size, font, text)
            )
        self._y -= leading

    def _rule_at(self, y: float) -> None:
        assert self._page is not None
        self._page.append(("line", self.margin, y, self.right_margin, y))

    # -- public API --------------------------------------------------------

    def heading(self, text: str, level: int = 1) -> None:
        size = HEADING_SIZES.get(level, HEADING_SIZES[3])
        leading = size * 1.3
        lines = _wrap(sanitise(text), self._columns(size))
        space_before = 14.0 if level == 1 else 10.0

        # Orphan control: a heading alone at the foot of a page reads as a
        # section with no content, which in an evidence document looks like
        # something was removed. Demand room for the heading plus three body
        # lines, or start the section on the next page.
        needed = space_before + leading * len(lines) + BODY_LEAD * 3
        self._ensure(needed)
        self._y -= space_before
        for line in lines:
            self._line(line, size, leading, font=FONT_BOLD)
        self._y -= 3

    def paragraph(self, text: str) -> None:
        for line in _wrap(sanitise(text), self._columns(BODY_SIZE)):
            self._line(line, BODY_SIZE, BODY_LEAD)
        self._y -= 4

    def bullet(self, text: str) -> None:
        width = self._columns(BODY_SIZE) - 2
        lines = _wrap(sanitise(text), width)
        for i, line in enumerate(lines):
            self._line(("- " if i == 0 else "  ") + line, BODY_SIZE, BODY_LEAD)
        self._y -= 2

    def key_values(self, rows: list[tuple[str, str]]) -> None:
        """Two aligned columns. The key column is sized from the widest key
        and capped, so one pathological key cannot squeeze every value into a
        four-character gutter."""
        pairs = [(sanitise(k), sanitise(v)) for k, v in rows]
        if not pairs:
            return
        total = self._columns(BODY_SIZE)
        key_width = min(max(len(k) for k, _ in pairs), max(8, total // 3))
        value_width = max(4, total - key_width - 2)
        indent = (key_width + 2) * CHAR_EM * BODY_SIZE

        for key, value in pairs:
            key_lines = _wrap(key, key_width)
            value_lines = _wrap(value, value_width) or [""]
            self._ensure(BODY_LEAD * max(len(key_lines), len(value_lines)))
            top = self._y
            for line in key_lines:
                self._line(line, BODY_SIZE, BODY_LEAD, font=FONT_BOLD)
            key_bottom = self._y
            self._y = top
            for line in value_lines:
                self._line(line, BODY_SIZE, BODY_LEAD, indent=indent)
            self._y = min(self._y, key_bottom)
        self._y -= 4

    def table(self, headers: list[str], rows: list[list[str]]) -> None:
        """A plain text table: columns sized from their widest cell, a rule
        under the header, and the header repeated when a table spans pages —
        an unlabelled continuation of a table of digests is unreadable."""
        head = [sanitise(h) for h in headers]
        body = [[sanitise(c) for c in row] for row in rows]
        ncols = max(len(head), max((len(r) for r in body), default=0))
        if ncols == 0:
            return

        capacity = self._columns(TABLE_SIZE)
        gutter = 2 if ncols * 3 + 2 * (ncols - 1) <= capacity else 1

        # More columns than the page has character cells is not a layout
        # problem with a good answer; drop the overflow rather than draw past
        # the right margin, which would break the seal's readability silently.
        max_cols = max(1, (capacity + gutter) // (1 + gutter))
        ncols = min(ncols, max_cols)

        head = (head + [""] * ncols)[:ncols]
        body = [(row + [""] * ncols)[:ncols] for row in body]

        natural = [
            max(1, len(head[i]), max((len(row[i]) for row in body), default=0))
            for i in range(ncols)
        ]
        available = capacity - gutter * (ncols - 1)
        widths = natural if sum(natural) <= available else _fit_columns(natural, available)

        char = CHAR_EM * TABLE_SIZE
        offsets = []
        cursor = 0
        for width in widths:
            offsets.append(cursor * char)
            cursor += width + gutter

        def row_lines(cells: list[str]) -> list[list[str]]:
            return [_wrap(cells[i], widths[i]) for i in range(ncols)]

        def draw(cells: list[str], font: str) -> None:
            wrapped = row_lines(cells)
            top = self._y
            for i, lines in enumerate(wrapped):
                self._y = top
                for line in lines:
                    self._line(line, TABLE_SIZE, TABLE_LEAD, font=font, indent=offsets[i])
            self._y = top - TABLE_LEAD * max(len(w) for w in wrapped)

        def draw_header() -> None:
            draw(head, FONT_BOLD)
            self._y -= 2
            self._rule_at(self._y)
            self._y -= 5

        header_height = TABLE_LEAD * max(len(w) for w in row_lines(head)) + 7
        first_height = TABLE_LEAD * max((len(w) for w in row_lines(body[0])), default=1) if body else 0
        self._ensure(header_height + first_height)
        draw_header()

        for row in body:
            height = TABLE_LEAD * max(len(w) for w in row_lines(row))
            if self._y - height < self.margin:
                self._new_page()
                draw_header()
            draw(row, FONT_REGULAR)
        self._y -= 6

    def preformatted(self, lines: list[str]) -> None:
        """Verbatim lines — JSON, hex dumps, circuit output — with no wrapping.

        8 pt was chosen so that a 100-column line fits exactly: 100 glyphs at
        0.6 em is 480 pt against 483.28 pt of A4 text width. Anything longer
        is *clipped*, not wrapped, with the last visible character replaced by
        ">" to mark the truncation. Wrapping was rejected because these blocks
        are copy-paste sources — a silently re-flowed JSON body or proof hex
        is worse than a visibly cut one.
        """
        limit = self._columns(PRE_SIZE)
        for raw in lines:
            text = sanitise(raw).replace("\n", " ")
            if len(text) > limit:
                text = text[: limit - 1] + ">"
            self._line(text, PRE_SIZE, PRE_LEAD)
        self._y -= 4

    def rule(self) -> None:
        self._ensure(10)
        self._y -= 4
        self._rule_at(self._y)
        self._y -= 8

    def spacer(self, points: float = 8.0) -> None:
        self._ensure(0)
        self._y -= points

    def page_break(self) -> None:
        """Deferred, so a break before the first content or two in a row do
        not leave a blank page in a document that will be page-counted."""
        if self._page is not None:
            self._pending_break = True

    # -- serialisation -----------------------------------------------------

    def render(self) -> bytes:
        if not self._pages:
            self._new_page()
        total = len(self._pages)

        objects: list[bytes] = [b""] * 6
        first_page_obj = 7
        page_refs = []
        for index, ops in enumerate(self._pages):
            page_obj = first_page_obj + index * 2
            content_obj = page_obj + 1
            page_refs.append(page_obj)
            objects.append(
                (
                    f"<< /Type /Page /Parent 2 0 R "
                    f"/MediaBox [0 0 {_num(self.page_width)} {_num(self.page_height)}] "
                    f"/Resources << /Font << /{FONT_REGULAR} 3 0 R /{FONT_BOLD} 4 0 R "
                    f"/{FONT_OBLIQUE} 5 0 R >> >> "
                    f"/Contents {content_obj} 0 R >>"
                ).encode("latin-1")
            )
            stream = _content_stream(ops + self._footer_ops(index, total))
            objects.append(
                b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"
            )

        kids = " ".join(f"{ref} 0 R" for ref in page_refs)
        objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
        objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {total} >>".encode("latin-1")
        objects[2] = _font_object("Courier")
        objects[3] = _font_object("Courier-Bold")
        objects[4] = _font_object("Courier-Oblique")
        objects[5] = self._info_object()

        return _assemble(objects)

    def _info_object(self) -> bytes:
        stamp = self.created_at.strftime("D:%Y%m%d%H%M%S+00'00'")
        fields = [
            f"/Producer ({_escape(PRODUCER)})",
            f"/CreationDate ({stamp})",
            f"/ModDate ({stamp})",
        ]
        if self.title:
            fields.insert(0, f"/Title ({_escape(self.title)})")
        if self.subtitle:
            fields.insert(1, f"/Subject ({_escape(self.subtitle)})")
        return ("<< " + " ".join(fields) + " >>").encode("latin-1")


def _font_object(base_font: str) -> bytes:
    return (
        f"<< /Type /Font /Subtype /Type1 /BaseFont /{base_font} "
        f"/Encoding /WinAnsiEncoding >>"
    ).encode("latin-1")


def _content_stream(ops: list[tuple]) -> bytes:
    """One operator group per line. The line-per-op layout is not cosmetic:
    it is what makes `diff` on two renders point at the paragraph that moved,
    and what lets the tests parse positions back out with a regex."""
    out = []
    for op in ops:
        if op[0] == "text":
            _, x, y, size, font, text = op
            out.append(
                f"BT /{font} {_num(size)} Tf {_num(x)} {_num(y)} Td ({_escape(text)}) Tj ET"
            )
        else:
            _, x1, y1, x2, y2 = op
            out.append(
                f"{_num(RULE_GRAY)} G {_num(RULE_WIDTH)} w "
                f"{_num(x1)} {_num(y1)} m {_num(x2)} {_num(y2)} l S"
            )
    return "\n".join(out).encode("latin-1")


def _assemble(objects: list[bytes]) -> bytes:
    """Write the file body, recording where each object actually started, and
    build the xref from those recorded positions.

    The offsets are measured, never predicted. A hand-rolled PDF whose xref
    was computed from assumed object lengths is the classic way to produce a
    file that looks fine in a text editor and refuses to open in Acrobat, and
    `test_xref_offsets_point_at_their_objects` exists to keep it that way.
    """
    # The binary comment on line 2 is the conventional signal to tools that
    # this file is binary and must not be transferred as text.
    buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(buf))
        buf += f"{number} 0 obj\n".encode("latin-1")
        buf += body
        buf += b"\nendobj\n"

    xref_offset = len(buf)
    size = len(objects) + 1
    buf += f"xref\n0 {size}\n".encode("latin-1")
    buf += b"0000000000 65535 f \n"          # each entry is exactly 20 bytes
    for offset in offsets:
        buf += f"{offset:010d} 00000 n \n".encode("latin-1")
    buf += (
        f"trailer\n<< /Size {size} /Root 1 0 R /Info 6 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF"
    ).encode("latin-1")
    return bytes(buf)


if __name__ == "__main__":  # pragma: no cover - specimen for eyeballing
    import pathlib

    doc = Document(
        "Canonical Case File - specimen",
        "Rendered by scripts/pdf.py; not evidence of anything",
        created_at=datetime(2026, 9, 16, 9, 0, 0, tzinfo=timezone.utc),
        running_header="Memtara - specimen - not for circulation",
    )
    doc.heading("A. Attestation")
    doc.paragraph(
        "The bank asserts the predicate below was satisfied without any party "
        "other than the holder observing the underlying figures — see §5(c)."
    )
    doc.key_values(
        [
            ("Predicate", "income_gte_threshold"),
            ("Circuit", "tax_session"),
            ("Proof digest", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ]
    )
    doc.heading("B. Evidence", level=2)
    doc.table(
        ["#", "Artefact", "SHA-256"],
        [["1", "proof.bin", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]],
    )
    doc.preformatted(['{"predicate": "income_gte_threshold", "satisfied": true}'])
    pathlib.Path("/tmp/pdf_specimen.pdf").write_bytes(doc.render())
    print("wrote /tmp/pdf_specimen.pdf")
