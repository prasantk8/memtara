# The AIHOOTS marketing site, and a patch for the gateway repo

This directory now does two separate jobs. It used to do one, and the split
happened because a question that was open when it was written has since been
answered by evidence.

| Job | Files | Destination |
|---|---|---|
| **The marketing site** | `wrangler.toml`, `public/`, `DEPLOY.md` | Cloudflare Pages → `aihoots.com` |
| **A patch for the gateway repo** | `README_PATCH.md`, `PR_DESCRIPTION.md` | `prasantk8/aihoots-e1-audit-gateway` |

## The open question is closed: the marketing site is not served by the gateway

The earlier version of this file said we had to determine whether
`ai.aihoots.com` was served from the FastAPI gateway repository or maintained
separately, because `public/memtara.html` would 404 in the first case without a
`StaticFiles` mount. That is now settled by observation rather than inference:

```
$ curl -sSI https://ai.aihoots.com/
HTTP/2 200
content-type: text/html
cf-cache-status: HIT

$ for p in /v1 /v1/models /docs /health; do curl -s -o /dev/null -w "$p %{http_code}\n" https://ai.aihoots.com$p; done
/v1        404
/v1/models 404
/docs      404
/health    404
```

A cached static HTML page with no API surface at all. `ai.aihoots.com` is a
**marketing site**, not the audit gateway — the gateway is self-hosted and only
ever answers on `localhost:8000/v1` after `docker compose up`.

So no `StaticFiles` mount is needed, no HTML goes into the gateway repository,
and the pull request there shrinks to **the README change only**.

## Job 1 — the marketing site

Read **`DEPLOY.md`**. It contains the commands, verified against wrangler
4.123.0, and one blocker you must clear first: `aihoots.com` currently serves an
infinite redirect loop, and deploying Pages will not fix it on its own.

```
public/
  index.html      the AIHOOTS platform page — the new root
  memtara.html    the Memtara engine detail page, linked from it as /memtara
  _headers        security headers, mirroring what ai.aihoots.com returns
wrangler.toml     Pages config (and why there is deliberately no src/worker.js)
DEPLOY.md         the actual procedure
```

`index.html` uses the design tokens lifted verbatim from the live
`ai.aihoots.com` stylesheet, with one rule added on top: **green is AIHOOTS, the
governance platform; amber is Memtara, the ZK engine.** Hue carries the
platform/engine distinction wherever it appears, so the architecture is legible
before a word of it is read. If you change those tokens, change them on the live
site first, then here — two properties drifting apart is how an umbrella brand
stops looking like one.

The use-case tabs are CSS `:checked` selectors with no JavaScript. That is not
minimalism for its own sake: it lets `_headers` ship `script-src 'none'`, which
is a defensible thing for a governance vendor's own site to claim.

## Job 2 — the patch for the gateway repository

Still staged, still not sent. Opening a pull request against a repository writes
to a service outside this machine and puts your name on the result; the files
are ready and sending them is your call.

The AIHOOTS working tree in `tests/aihoots_reference/` was **not** modified — it
is a submodule pinned to a commit, and editing it in place would leave this
repository holding a dirty submodule pointer that neither repo could resolve
cleanly.

```bash
# from wherever you keep the AIHOOTS checkout — NOT the submodule in this repo
cd /path/to/aihoots-e1-audit-gateway
git checkout -b memtara-companion

# hand-apply the two blocks in README_PATCH.md
$EDITOR README.md

git add README.md
git commit -m "Link Memtara, the ZK engine behind the AIHOOTS platform"
git push -u origin memtara-companion
gh pr create --title "Link the Memtara companion" --body-file \
    /path/to/memtara/marketing/aihoots-pr/PR_DESCRIPTION.md
```

## Still needs a real value before launch

1. **`REPLACE-WITH-CONTACT@aihoots.com`** in `public/memtara.html` — the "Book
   15 minutes" mailto. `index.html` deliberately has no placeholder contact at
   all: a dead mailto on the root page is worse than sending people to GitHub,
   which is where the checkable material lives anyway. Add a real address to
   both when you have one.
2. **`github.com/prasantk8/memtara` must be public.** Both pages and the
   badge link there repeatedly. If it is private, every link is a 404 for the
   reader, which is worse than not linking at all — and the entire argument of
   the page is "go and check it yourself".
3. **The apex redirect loop.** See `DEPLOY.md`. Until it is cleared, every link
   in the LinkedIn campaign and the outreach script is dead.
