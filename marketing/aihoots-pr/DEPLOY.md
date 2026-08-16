# Deploying the AIHOOTS marketing site to Cloudflare Pages

Static site, one directory, no build step. The deploy itself is about ninety
seconds. **Read the blocker first** — the deploy will appear to succeed and the
site will still be unreachable if you skip it.

Commands below were verified against **wrangler 4.123.0** on 16 Aug 2026.

---

## Blocker: `aihoots.com` is currently an infinite redirect loop

This is not a prediction. As of 15 Aug 2026, 23:02 UTC:

```
$ curl -sSI https://aihoots.com/
HTTP/2 308
location: https://aihoots.com/          <-- redirects to itself
server: cloudflare
x-siteid: ap-south-1
x-version: 03d6711

$ curl -sS -o /dev/null -L https://aihoots.com/
curl: (47) Maximum (5) redirects followed
```

`www.aihoots.com` → `301` → `http://aihoots.com/` → `308` → `https://aihoots.com/`
→ `308` → itself, forever. In a browser this is `ERR_TOO_MANY_REDIRECTS`. **The
apex domain is down right now**, and has been serving nothing but a loop to
every visitor, crawler and LinkedIn preview scraper that has tried it.

Two things follow, and the second one is the one people get wrong:

1. Every link to `aihoots.com` in the LinkedIn campaign, the outreach script and
   the `README_PATCH.md` badge is currently a dead link.

2. **Deploying Pages will not, on its own, fix this.** The `x-siteid` /
   `x-version` headers are not Pages headers — something else is answering for
   the apex, either a Cloudflare Redirect Rule / Bulk Redirect or a third-party
   host still holding the DNS record. Redirect Rules execute at the edge
   *before* Pages routing, so a rule matching `aihoots.com/*` will keep
   shadowing your new site after a completely successful deploy. You will see a
   green checkmark in the terminal and a redirect loop in the browser, and lose
   an hour to it.

### Clear it before deploying

In the Cloudflare dashboard for the `aihoots.com` zone:

- **Rules → Redirect Rules** and **Rules → Bulk Redirects** — find and disable
  any rule whose target is `aihoots.com`. A rule that redirects the apex to
  itself is the classic symptom of a "redirect www to apex" rule written
  without a hostname condition, so it matches the apex too.
- **DNS** — the apex `A`/`CNAME` records currently point at Cloudflare proxy
  IPs (`104.21.26.34`, `172.67.135.86`). Once the Pages custom domain is
  attached, Cloudflare manages this record itself. Remove any stale record
  pointing at a previous host.
- **Rules → Page Rules** — legacy forwarding rules live here and are easy to
  miss because they are in a different part of the dashboard.

Confirm it is clear before you deploy:

```bash
curl -sSI https://aihoots.com/ | head -3
# want: HTTP/2 200 (or 404 while nothing is deployed yet)
# not:  308 with location: https://aihoots.com/
```

---

## Decide this before deploying: what happens to `ai.aihoots.com`

The brief described `ai.aihoots.com` as "the AIHOOTS gateway". It is not.
`https://ai.aihoots.com/` currently serves a **static marketing page** titled
*"AIHOOTS — AI governance, built in the open"* from Cloudflare (`cf-cache-status: HIT`).
There is no API behind it — `/v1`, `/v1/models`, `/docs` and `/health` all
return `404`. The actual audit gateway is self-hosted (`docker compose up`,
then `localhost:8000/v1`); there is no public proxy anywhere.

So deploying this site to the apex gives you **two marketing sites for one
brand**, which splits your SEO, your inbound links and your analytics, and
guarantees that one of them goes stale. Pick one:

| Option | What you do | Consequence |
|---|---|---|
| **A — apex is the brand** (recommended) | Deploy here to `aihoots.com`. Make `ai.aihoots.com` redirect to it, or retire it. | One canonical site. The `ai.` subdomain is freed for the gateway it is named after, if you ever host one. |
| **B — keep both** | Deploy to the apex, leave `ai.aihoots.com` as the lab/personal-narrative site. | Defensible only if the two have genuinely different audiences — the lab site is first-person and voice-driven, this one is a product page. Cross-link them explicitly and pick a canonical. |
| **C — replace in place** | Point the existing `ai.aihoots.com` Pages project at this directory instead. | No apex work needed, but the redirect loop on `aihoots.com` stays broken and every campaign link stays dead. |

The page as written assumes **A**: `og:url` is `https://aihoots.com/`, and the
footer links to `ai.aihoots.com` as "the lab". If you choose B or C, change
`og:url` in `public/index.html` to match, or social previews will point at the
wrong host.

---

## Deploy

```bash
# 1. Wrangler. A project-local install is better than -g: the version that
#    deploys your site is then recorded in a lockfile rather than being
#    whatever your laptop happened to have.
npm install --save-dev wrangler

# 2. Authenticate (opens a browser).
npx wrangler login

# 3. From this directory — marketing/aihoots-pr/
cd marketing/aihoots-pr

# 4. Create the project once. Skip if it already exists.
npx wrangler pages project create aihoots-landing \
  --production-branch main

# 5. Deploy the directory.
npx wrangler pages deploy ./public --project-name aihoots-landing
```

That prints a `https://<hash>.aihoots-landing.pages.dev` URL. **Open it and
check the page before touching the custom domain** — this preview URL is the
entire reason a bad deploy never has to be visible on your brand domain.

### Attaching the custom domain

The brief specified:

```bash
wrangler pages project add-domain aihoots-landing aihoots.com   # does not exist
```

There is no such command. `wrangler pages project` supports exactly `list`,
`create` and `delete` — checked against wrangler 4.123.0, not from memory.
Custom domains are attached one of two ways:

**Dashboard** (30 seconds, and the one to use):
Workers & Pages → `aihoots-landing` → **Custom domains** → *Set up a custom
domain* → `aihoots.com`. Because the zone is already on Cloudflare, the DNS
record is created for you.

**REST API** (for CI):

```bash
curl -X POST \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/pages/projects/aihoots-landing/domains" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"aihoots.com"}'
```

The token needs **Account → Cloudflare Pages → Edit** and **Zone → DNS → Edit**
on the `aihoots.com` zone. Do not reuse a Global API Key here.

Add `www.aihoots.com` as a second custom domain in the same place, or it keeps
301-ing into the loop described above.

---

## Verify

```bash
# 1. Serving, not looping
curl -sSI https://aihoots.com/ | head -3          # expect HTTP/2 200

# 2. The security headers from public/_headers actually applied
curl -sSI https://aihoots.com/ | grep -i "content-security-policy\|x-frame-options"

# 3. The engine detail page came along
curl -sS -o /dev/null -w "%{http_code}\n" https://aihoots.com/memtara.html   # 200

# 4. No mixed content or blocked font (open devtools console; should be empty)
```

Then check the LinkedIn post preview with the
[Post Inspector](https://www.linkedin.com/post-inspector/) — it caches
aggressively, and it has been caching the redirect loop.

---

## Rollback

Pages keeps every deployment. Rolling back is a dashboard action, not a
re-deploy:

Workers & Pages → `aihoots-landing` → **Deployments** → the previous one →
*Rollback to this deployment*.

To list them from the terminal:

```bash
npx wrangler pages deployment list --project-name aihoots-landing
```

Removing the custom domain in the dashboard reverts the apex to whatever DNS
you leave behind — which, if you have not cleared the redirect rules, is the
loop. Clear the rules regardless of which option you pick.

---

## What this does not touch

- **The audit gateway.** It is self-hosted and this deploy has no relationship
  to it. Nothing in `aihoots-e1-audit-gateway` changes.
- **`ai.aihoots.com`**, unless you choose option B or C above. Deploying to a
  new Pages project and attaching the apex leaves the subdomain exactly as it is.
- **Any DNS record other than the apex** (and `www`, if you add it).

## Files

| Path | Purpose |
|---|---|
| `wrangler.toml` | Pages project config. Explains why there is no `src/worker.js`. |
| `public/index.html` | The AIHOOTS platform page. Self-contained apart from Google Fonts. |
| `public/memtara.html` | The Memtara engine detail page, linked from the platform page. |
| `public/_headers` | Security headers, mirroring what `ai.aihoots.com` already returns. |
