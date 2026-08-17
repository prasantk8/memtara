# Infrastructure cleanup — the `aihoots.com` zone

What is actually deployed, what is broken, and the exact clicks to fix it.

Everything below was **measured, not assumed**, on **17 August 2026, 06:12 UTC**,
with `curl` and `dig` against public DNS. Three things the brief for this
document described turned out to be out of date, and one problem nobody had
listed turned out to be worse than all of them. Re-measure before acting — the
commands are in [Verify first](#verify-first) and take about ten seconds.

Related: [`marketing/aihoots-pr/DEPLOY.md`](../marketing/aihoots-pr/DEPLOY.md)
covers deploying the site itself. This document covers the DNS and routing
around it.

---

## Verify first

```bash
for h in aihoots.com www.aihoots.com ai.aihoots.com; do
  printf '%-20s ' "$h"
  curl -sS -o /dev/null -w '%{http_code}\n' --max-time 10 "https://$h/" || true
done

dig +short ai.aihoots.com A ai.aihoots.com CNAME     # empty output = no record at all
```

### What that returned on 17 Aug 2026

| Host | Measured | Brief said | Reality |
|---|---|---|---|
| `aihoots.com` | **200** — `AIHOOTS — Verifiable AI Governance \| Powered by Memtara ZK` | live | ✅ Correct. The redirect loop documented in `DEPLOY.md` on 15 Aug is **cleared**. |
| `www.aihoots.com` | **522** | not mentioned | ❌ **Broken right now.** See [Section C](#section-c--wwwaihootscom-is-returning-522-fix-this-first). |
| `ai.aihoots.com` | **NXDOMAIN** — does not resolve | "points to a dead Worker" | ⚠️ There is no DNS record. Nothing to unroute. See [Section A](#section-a--the-late-cloud-53ba-worker). |

One more measurement worth recording, because it looks like a fault and is not:
`https://aihoots.com/memtara.html` returns **308 → `/memtara`** → 200. That is
Cloudflare Pages canonicalising `.html` URLs, which it does by default. The page
is fine; only its URL changed shape. Any hard-coded `…/memtara.html` link still
works, at the cost of one redirect hop.

---

## Section A — the `late-cloud-53ba` Worker

**The premise has already resolved itself.** `ai.aihoots.com` has no `A` record
and no `CNAME`; it fails at DNS resolution, before any Worker route could be
consulted. So there is no route to remove and no live traffic reaching that
Worker. Deleting it is housekeeping, not a fix — do it so the next person
reading the dashboard is not misled, but do not expect anything to change.

Confirm it still exists before hunting for it:

```
https://dash.cloudflare.com/?to=/:account/workers-and-pages
```

(`:account` is a literal placeholder — Cloudflare substitutes your account ID.)

Look for `late-cloud-53ba` in the list. Cloudflare auto-generates names in that
`adjective-noun-hex` shape, which is a reliable sign the Worker was created by a
"deploy a starter" flow and never renamed.

**If it is there:**

1. Open it → **Settings** → scroll to the bottom → **Delete**.
2. Cloudflare asks you to type the Worker's name to confirm. That prompt is the
   only safeguard, so read the name in the dialog rather than the one in your
   head — it is easy to have two auto-named Workers open.
3. Before deleting, check **Settings → Domains & Routes**. If it lists any route
   other than a `*.workers.dev` subdomain, something *is* pointing at it and
   Section A does not apply to your zone as measured. Stop and re-measure.

**If it is not there**, it has already been deleted. Move on.

### Then check DNS for a leftover record

```
https://dash.cloudflare.com/?to=/:zone/dns/records
```

Filter for `ai`. As measured there is **no** `ai` record, so expect to find
nothing. If one appears, it was added between this measurement and your reading,
and you should decide [Section B](#section-b--what-ai-aihootscom-should-be) first
rather than deleting it reflexively.

---

## Section B — what `ai.aihoots.com` should be

Do not point it anywhere until you have decided what it is *for*, because the
repository currently makes a factual claim about it that is false:

- [`README.md:16`](../README.md) links
  "[AIHOOTS E1 audit gateway](https://ai.aihoots.com)" — **a hostname that does
  not resolve.** This sits inside the repository's most prominent claim block,
  the one a Chief Risk Officer reads first.
- [`docs/REGULATORY_MATRIX.md:16`](./REGULATORY_MATRIX.md) describes AIHOOTS E1
  as "live at `ai.aihoots.com`" — also false as measured.
- [`docs/REGULATORY_DEMO_REPORT.md`](./REGULATORY_DEMO_REPORT.md) shows
  `POST https://ai.aihoots.com/v1/chat/completions` in five worked journeys. That
  one is *illustrative* rather than a claim of live service, and it is generated
  by [`scripts/generate_regulatory_demo.py:1315`](../scripts/generate_regulatory_demo.py),
  so changing it means editing the generator and regenerating — CI fails
  otherwise (see the "Regenerate the compliance demonstration" step in
  [`ci.yml`](../.github/workflows/ci.yml)).

A prospect who clicks that README link gets a DNS error. That is worse than a
404, because a 404 reads as "moved" and a DNS failure reads as "was never there".

`DEPLOY.md` already framed the choice as A/B/C. With `ai.` now gone from DNS
entirely, the options collapse to two:

| Option | Do this | Consequence |
|---|---|---|
| **A — retire the subdomain** (recommended) | Leave DNS empty. Fix the three references above to point at `aihoots.com` or at the repository. | One canonical site. No dead link. The `ai.` name stays free for an actual gateway later, which is what it was named for. |
| **B — make it a redirect to the apex** | Add the custom domain to Pages (below), then a Redirect Rule `ai.aihoots.com/*` → `https://aihoots.com/$1` (301). | Old inbound links and any cached LinkedIn preview resolve instead of erroring. Costs you the `ai.` name for a future gateway. |

**Option A is the recommendation** and it requires no Cloudflare work at all —
only three text edits. Choose B only if you know of published links to `ai.` in
the wild that you cannot retract.

Note what neither option does: **it does not make the gateway public.** The
AIHOOTS E1 audit gateway is self-hosted (`docker compose up`, then
`localhost:8000/v1`). Pointing a DNS name at a static marketing page does not
change that, and copy implying otherwise would be the exact kind of claim
[`marketing/README.md`](../marketing/README.md) forbids.

### If you chose B — attaching the domain to Pages

```
https://dash.cloudflare.com/?to=/:account/pages/view/aihoots-landing
```

→ **Custom domains** tab → **Set up a custom domain** → `ai.aihoots.com` →
**Continue** → **Activate domain**.

Because the zone is already on Cloudflare, the DNS record is created for you;
you do not add it by hand, and adding one first will make this step conflict.

There is no `wrangler` command for this. `wrangler pages project` supports
exactly `list`, `create` and `delete` — verified against wrangler 4.123.0. If
you need it scripted, use the REST API form in
[`DEPLOY.md`](../marketing/aihoots-pr/DEPLOY.md#attaching-the-custom-domain).

Then add the Redirect Rule:

```
https://dash.cloudflare.com/?to=/:zone/rules/redirect-rules
```

→ **Create rule** → *If* `Hostname equals ai.aihoots.com` → *Then* **Dynamic**,
expression `concat("https://aihoots.com", http.request.uri.path)`, status **301**,
**preserve query string** on.

Use a **hostname condition**, not a path-only match. A redirect rule written
without one is precisely what produced the apex-redirects-to-itself loop this
zone was serving on 15 August.

---

## Section C — `www.aihoots.com` is returning 522. Fix this first.

This was not in the brief and it is the only thing here actively costing you
visitors.

```
$ curl -sSI https://www.aihoots.com/
HTTP/2 522
error code: 522

$ dig +short www.aihoots.com
188.114.96.6
188.114.97.6      # same Cloudflare proxy IPs as the apex
```

**What 522 means:** Cloudflare accepted the connection and then timed out
reaching an origin. So `www` is proxied (orange cloud) and pointed at something
that is not answering. It is *not* attached to the `aihoots-landing` Pages
project — a Pages custom domain never 522s, it serves the site.

This is worse than it looks for three reasons. Browsers and mail clients
autocomplete `www.`; the redirect loop `DEPLOY.md` documented on 15 August ran
`www → 301 → http://aihoots.com`, so anything that cached `www` as the entry
point still starts there; and a 522 renders as Cloudflare's grey error page with
your domain on it, which reads to a bank's risk officer as an operational
failure rather than a DNS misconfiguration.

**The fix — attach `www` to Pages and let Cloudflare own the record:**

1. Delete the stale record first, or step 2 will conflict with it:
   ```
   https://dash.cloudflare.com/?to=/:zone/dns/records
   ```
   Find the `www` record, note what it points at (worth knowing — it is the
   origin that stopped answering), then **Delete**.
2. ```
   https://dash.cloudflare.com/?to=/:account/pages/view/aihoots-landing
   ```
   → **Custom domains** → **Set up a custom domain** → `www.aihoots.com` →
   **Activate domain**. Cloudflare recreates the DNS record correctly.
3. Decide which host is canonical. The site's `og:url` is `https://aihoots.com/`,
   so the apex is canonical and `www` should redirect to it. Add a Redirect Rule
   exactly as in Section B, with `Hostname equals www.aihoots.com` →
   `concat("https://aihoots.com", http.request.uri.path)`, **301**.

Serving the same site on both hosts without a redirect is the alternative, and
it splits your SEO and your analytics for no gain. Pick the redirect.

---

## Section D — every "Read the code" button on the live site is a 404

Not in the brief, found while checking the links the campaign depends on. For an
outreach programme whose stated advantage is *"everything claimed here is
verifiable by the reader, today"*, this is the most damaging defect in this
document.

```
$ curl -sS -o /dev/null -w '%{http_code}\n' https://github.com/prasantk8/memtara-zkp
404
$ curl -sS -o /dev/null -w '%{http_code}\n' https://github.com/prasantk8/memtara
200
```

Confirmed against the GitHub API: `prasantk8/memtara` exists, is **public**,
default branch `main`. **`prasantk8/memtara-zkp` does not exist.** The local git
remote agrees — `origin` is `https://github.com/prasantk8/memtara.git`.

`memtara-zkp` was hard-coded in **18 places**, none of which had ever resolved.

### Resolved on 18 Aug 2026 — option 2

The repository keeps its name, `prasantk8/memtara`, and **every reference in
this repository has been rewritten to match it**. Renaming the GitHub
repository to `memtara-zkp` was rejected: it would have made 18 stale strings
correct at the cost of invalidating the name that is already public, already in
`origin`, and already the one that works.

Corrected: `README_PATCH.md` (badge target, prose link, clone command, `cd`,
matrix link), `marketing/aihoots-pr/README.md`, `PR_DESCRIPTION.md`,
`marketing/outreach/LINKEDIN_POST.md`, `marketing/outreach/PILOT_EMAIL.md`,
`scripts/quickstart.sh:111`, `scripts/pdf.py` (the `/Producer` string stamped
into every generated PDF), and the project tree in `README.md`.
`public/index.html` and `public/memtara.html` were corrected earlier in the
same effort.

`LINKEDIN_POST.md` and `PILOT_EMAIL.md` each carried a "do not publish, the
link 404s" blocker. Those blockers are now false. They have been rewritten
rather than deleted, so anyone working from an older copy of that text still
learns which of the two names is the wrong one.

**What this does not fix.** Editing HTML in this repository changes nothing at
`aihoots.com`. The live site keeps serving whatever was last deployed until
`wrangler pages deploy` runs again — see
[`DEPLOY.md`](../marketing/aihoots-pr/DEPLOY.md#deploy). Until that runs, the
buttons named in the heading above are still 404s **for readers**, however
green this repository looks.

---

## Verify when finished

```bash
# 1. All three hostnames resolve and answer.
for h in aihoots.com www.aihoots.com; do
  printf '%-20s ' "$h"
  curl -sS -o /dev/null -w '%{http_code} -> %{redirect_url}\n' --max-time 10 "https://$h/"
done
# want: aihoots.com 200
#       www.aihoots.com 301 -> https://aihoots.com/

# 2. The repository link the whole campaign rests on. `memtara` is the name;
#    `memtara-zkp` has never existed and should stay a 404 — if it ever answers
#    200, somebody renamed the repo and every link in this project needs
#    revisiting.
curl -sSL -o /dev/null -w 'memtara      %{http_code}\n' https://github.com/prasantk8/memtara
curl -sSL -o /dev/null -w 'memtara-zkp  %{http_code}\n' https://github.com/prasantk8/memtara-zkp

# 3. Security headers from public/_headers still applied.
curl -sSI https://aihoots.com/ | grep -i 'content-security-policy\|x-frame-options'

# 4. No loop anywhere.
curl -sSL -o /dev/null -w '%{num_redirects} hops -> %{url_effective}\n' https://www.aihoots.com/
```

Then re-scrape the social preview with the
[LinkedIn Post Inspector](https://www.linkedin.com/post-inspector/). It caches
aggressively and has been caching this zone's failures since 15 August — a post
published without clearing it will render the old error.

---

## Priority

1. **Section D** — the repository link. Cheapest fix, largest blast radius, and
   the campaign cannot launch around it.
2. **Section C** — `www` returning 522. Actively serving an error page under
   your brand.
3. **Section B** — decide `ai.aihoots.com`, then fix the three false references
   to it in `README.md` and `REGULATORY_MATRIX.md`.
4. **Section A** — delete the orphaned Worker. Housekeeping; nothing depends
   on it.
