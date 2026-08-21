"""`docs/openapi.yaml` is a test that happens to be readable, not documentation
that happens to be wrong.

WHAT THIS CHECKS, AND WHY IT DOES NOT TRUST A HAND-MAINTAINED LIST
---------------------------------------------------------------------
A drift check that compares the router against a second list someone typed by
hand is not a check on the router — it is a check that two humans remembered
to update the same fact twice, which is exactly the discipline that produced
the gap this test now closes: before this stage, `/review`,
`/decision-evidence`, `/model-corrections` and every route workstreams A and B
added were simply absent from `docs/openapi.yaml`, silently, for as long as
nobody happened to notice.

So this test does not maintain its own route list. It DERIVES the real route
set straight from `backend/api/src/**/*.rs` by parsing every `.route(path,
methods)` call reachable from `main.rs`'s `Router` — the exact same source
text `cargo build` compiles into the server that will exist in CI, the CI
image, and prod. There is no second copy for the two to drift apart from; the
extraction re-derives its answer from source on every run. This is a real,
mechanical introspection of the router-assembly code, not a fixture: add a
route anywhere in `backend/api/src/`, and the very next run of this test sees
it, with no edit to this file required.

Axum 0.7 has no public API to list a live `Router`'s registered paths (there
is no `.routes()` — the match table is internal to `matchit`), which is why
this reads source rather than booting a server and introspecting it at
runtime. What IS read is exhaustive: every `.rs` file under
`backend/api/src/`, with each file's `#[cfg(test)] mod tests { ... }` block
(the house convention for where unit tests live, confirmed against every
module in this crate) truncated away first, so a route registered only inside
a test double is never credited as something the real server serves.

THE CHECK IS BIDIRECTIONAL, ON PURPOSE
---------------------------------------------------------------------
A route with no spec entry is undocumented — an integrator reading the spec
does not know it exists. A spec entry with no route is a LIE — it promises an
endpoint nobody implements, which is worse than silence because a caller who
trusts it fails at the worst possible time. Both directions raise on this
test; neither is a warning.

Method-and-path SHAPE is compared, not parameter names: axum spells a path
parameter `:id`, OpenAPI spells the same thing `{id}` (or `{request_id}`, or
whatever name a spec author chose) — both are normalised to the single token
`{param}` before comparison, so a cosmetic naming choice on either side is
never mistaken for drift. What is NOT normalised away, and therefore DOES
count as drift, is the number and order of segments and which HTTP method is
registered — `GET /foo/{a}/{b}` and `GET /foo/{a}` are different shapes, and a
mismatch between them is exactly the kind of thing a hand-maintained doc can
paper over and this test cannot.

A TEST THAT CANNOT INTROSPECT MUST FAIL LOUDLY, NOT SKIP
---------------------------------------------------------------------
Trap #7 in `docs/STAGE_PLAN_CONSENT_AND_WITNESS.md` §7: a test that quietly
skips when its precondition is missing is indistinguishable, from a green CI
run, from a test that verified something. If `backend/api/src/` cannot be
found, if not a single `.route(` call is extracted, or if `docs/openapi.yaml`
fails to parse, this test raises — loudly, with the reason — rather than
reporting 0 findings as though that were a clean result.

Run:
    .venv/bin/python -m pytest tests/test_openapi_drift.py -v
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_SRC = REPO_ROOT / "backend" / "api" / "src"
OPENAPI_PATH = REPO_ROOT / "docs" / "openapi.yaml"

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

# Every `.rs` file's own `#[cfg(test)] mod tests { ... }` block is dropped
# before scanning, so a route wired up only for a unit-test double (there are
# none of these in this crate today, and this test must not silently start
# crediting one if that ever changes) is never counted as part of the real
# router. Matches the block header; the truncation below drops everything
# from that point in the file onward, which is safe because every module in
# this crate follows the house convention of putting `mod tests` last.
_CFG_TEST_MOD = re.compile(r"#\[cfg\(test\)\]\s*\r?\n\s*mod\s+tests\b")


class RouteKey(NamedTuple):
    method: str  # lower-case HTTP verb
    shape: str  # path with every `:param`/`{param}` segment normalised to `{param}`


def _normalise_path(path: str) -> str:
    """`:id` (axum) and `{id}` / `{request_id}` (OpenAPI) all become `{param}`.

    Comparing shapes, not names, is the deliberate choice explained in the
    module docstring: a spec author is free to call a path parameter whatever
    reads best to an integrator, and that freedom must not register as drift.
    """
    segments = path.split("/")
    normalised = []
    for seg in segments:
        if seg.startswith(":") or (seg.startswith("{") and seg.endswith("}")):
            normalised.append("{param}")
        else:
            normalised.append(seg)
    return "/".join(normalised)


def _extract_route_call_args(text: str, start: int) -> str:
    """Given `text` and the index just after `.route(`, return the raw text of
    the call's arguments up to (not including) the matching close paren.

    A regex cannot do this correctly by itself — `.route("/vault", get(a).put(b))`
    has parens nested inside the very argument list a regex would need to stop
    at — so this walks characters, tracking paren depth and skipping over the
    contents of string literals (so a `)` or `"` inside a path string, e.g. a
    future path containing a literal quote, cannot desynchronise the count).
    """
    depth = 1
    i = start
    in_string = False
    out = []
    while i < len(text):
        c = text[i]
        if in_string:
            if c == "\\" and i + 1 < len(text):
                out.append(c)
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            out.append(c)
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return "".join(out)
        out.append(c)
        i += 1
    raise ValueError(
        f"unbalanced parentheses while scanning a `.route(` call starting at byte {start} — "
        "the extractor could not find a matching close paren, which means either the source "
        "has a syntax error or this parser's assumptions about Rust call syntax no longer hold"
    )


_ROUTE_CALL = re.compile(r"\.route\s*\(")
_LEADING_PATH_LITERAL = re.compile(r'^\s*"([^"]*)"')
_METHOD_CALL = re.compile(r"\b(" + "|".join(HTTP_METHODS) + r")\s*\(")


def extract_routes_from_source(text: str, *, source_name: str) -> set[RouteKey]:
    """Every `(method, path-shape)` pair this one file's `.route(...)` calls
    register, after truncating any `#[cfg(test)] mod tests { ... }` block.
    """
    m = _CFG_TEST_MOD.search(text)
    if m:
        text = text[: m.start()]

    routes: set[RouteKey] = set()
    for call in _ROUTE_CALL.finditer(text):
        args = _extract_route_call_args(text, call.end())
        path_match = _LEADING_PATH_LITERAL.match(args)
        if not path_match:
            raise ValueError(
                f"{source_name}: a `.route(` call's first argument is not a string literal "
                f"(got {args[:80]!r}...) — this extractor only understands the literal-path "
                "style this codebase uses everywhere today; if a route is now built from a "
                "non-literal expression, this parser needs to learn that shape rather than "
                "silently miss the route"
            )
        raw_path = path_match.group(1)
        after_path = args[path_match.end() :]
        methods = sorted(set(_METHOD_CALL.findall(after_path)))
        if not methods:
            raise ValueError(
                f"{source_name}: `.route(\"{raw_path}\", ...)` names no recognised HTTP method "
                f"call ({', '.join(HTTP_METHODS)}) in its handler argument ({after_path[:80]!r}) "
                "— either this route is unreachable or this parser does not understand how its "
                "handler is being registered; either way, silently skipping it would be worse "
                "than failing loudly here"
            )
        shape = _normalise_path(raw_path)
        for method in methods:
            routes.add(RouteKey(method=method, shape=shape))
    return routes


def real_router_routes() -> set[RouteKey]:
    """The full set of routes the compiled server actually registers, derived
    from every `.rs` file under `backend/api/src/` — see the module docstring
    for why this is exhaustive-scan rather than a hand-tracked merge tree.
    """
    if not BACKEND_SRC.is_dir():
        raise RuntimeError(
            f"{BACKEND_SRC} does not exist — this test cannot introspect a router it cannot "
            "find. Failing loudly rather than reporting an empty (and therefore falsely clean) "
            "route set."
        )
    rs_files = sorted(BACKEND_SRC.rglob("*.rs"))
    if not rs_files:
        raise RuntimeError(f"no .rs files found under {BACKEND_SRC} — cannot introspect the router")

    routes: set[RouteKey] = set()
    for path in rs_files:
        text = path.read_text(encoding="utf-8")
        if ".route(" not in text:
            continue
        routes |= extract_routes_from_source(text, source_name=str(path.relative_to(REPO_ROOT)))

    if not routes:
        raise RuntimeError(
            f"scanned {len(rs_files)} .rs file(s) under {BACKEND_SRC} and extracted zero routes — "
            "either the router has genuinely been emptied (unlikely) or this parser's assumptions "
            "about `.route(` call syntax no longer match the source. Either way, a silent empty "
            "set would make every downstream assertion in this test vacuously pass, which is "
            "exactly the 'a test can pass while lying' failure trap #7 exists to name."
        )
    return routes


def spec_routes() -> set[RouteKey]:
    """The full set of (method, path-shape) pairs `docs/openapi.yaml` declares."""
    if not OPENAPI_PATH.is_file():
        raise RuntimeError(f"{OPENAPI_PATH} does not exist")
    spec = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    if not isinstance(spec, dict) or "paths" not in spec:
        raise RuntimeError(
            f"{OPENAPI_PATH} parsed but carries no top-level `paths` key — this is not a "
            "readable OpenAPI document, and a diff against nothing would silently pass every "
            "route in the router as 'undocumented' without saying why."
        )

    routes: set[RouteKey] = set()
    for raw_path, path_item in spec["paths"].items():
        if not isinstance(path_item, dict):
            continue
        shape = _normalise_path(raw_path)
        for key in path_item:
            if key.lower() in HTTP_METHODS:
                routes.add(RouteKey(method=key.lower(), shape=shape))
    if not routes:
        raise RuntimeError(
            f"{OPENAPI_PATH} carries a `paths` key but it named zero (method, path) operations — "
            "failing loudly rather than reporting a false-clean diff against nothing."
        )
    return routes


def _fmt(routes: set[RouteKey]) -> str:
    return "\n".join(f"  {r.method.upper():7s} {r.shape}" for r in sorted(routes, key=lambda r: (r.shape, r.method)))


def test_every_real_route_has_a_spec_entry():
    """A route with no spec entry is undocumented — see the module docstring."""
    router = real_router_routes()
    spec = spec_routes()
    undocumented = router - spec
    assert not undocumented, (
        f"{len(undocumented)} route(s) exist in the real router (backend/api/src/) but have no "
        f"entry in docs/openapi.yaml:\n{_fmt(undocumented)}\n\n"
        "Add each one to docs/openapi.yaml — the router is the source of truth here, not this "
        "test and not the spec."
    )


def test_no_spec_entry_promises_a_route_that_does_not_exist():
    """A spec entry with no route is a lie — see the module docstring."""
    router = real_router_routes()
    spec = spec_routes()
    fictional = spec - router
    assert not fictional, (
        f"{len(fictional)} entr(y/ies) in docs/openapi.yaml promise a route the real router "
        f"(backend/api/src/) does not register:\n{_fmt(fictional)}\n\n"
        "Either the route was removed from the code and the spec was not updated, or the spec "
        "was written ahead of the implementation landing. Fix whichever is actually true — do "
        "not delete the mismatch without knowing which side is wrong."
    )


def test_the_extractor_itself_is_not_silently_empty():
    """Trap #7, made explicit as its own assertion rather than left implicit in
    the two tests above: if either extractor ever starts returning an empty
    set (a refactor that breaks the regex, a path that moves), the two tests
    above would both go vacuously green — 'nothing here differs from
    nothing'. This pins a floor under both counts so that failure mode itself
    fails loudly instead of quietly passing everything.
    """
    router = real_router_routes()
    spec = spec_routes()
    # Both counts as of this stage; either shrinking sharply is itself a
    # signal something broke in extraction rather than routes being removed
    # in bulk — a handful of routes retiring in a normal change is plausible,
    # the router or the spec losing MOST of its routes in one commit is not.
    assert len(router) >= 30, f"only {len(router)} route(s) extracted from the router — extractor likely broken"
    assert len(spec) >= 30, f"only {len(spec)} route(s) extracted from the spec — extractor likely broken"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
