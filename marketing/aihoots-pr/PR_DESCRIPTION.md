Link Memtara, the ZK engine behind the AIHOOTS platform

## What this adds

A "Memtara Companion" badge and a short section in `README.md` explaining the
division of labour between the two projects. Nothing else — no `src/` changes,
no new dependencies, no behaviour change to the gateway.

## Why

This gateway makes what a model was told auditable. It does not make it true.
A prompt asserting "this client qualifies for the note" gets chained faithfully
and is still prompt text, which is attacker-controlled.

Memtara closes that half: the client's own device proves, against terms the bank
registered in advance, that it meets a product's suitability thresholds. This
gateway already validates the resulting Ed25519 attestation locally against a
published JWKS and appends the proof hash to the chain — that integration exists
and is tested on the Memtara side. What has been missing is anywhere in this
repository that says so.

## Why there is no HTML in this PR

An earlier draft of this change added `public/memtara.html` here. That was
wrong, and checking rather than assuming is what caught it: `ai.aihoots.com`
returns a cached static page with `404` on `/v1`, `/v1/models`, `/docs` and
`/health`. It is a marketing site, not this application. This repository is a
FastAPI app with no `StaticFiles` mount, so an HTML file dropped in the tree
here would have shipped and then 404'd in the browser.

The marketing pages are deployed separately to Cloudflare Pages, and the
positioning they carry is: **AIHOOTS is the governance platform, Memtara is the
zero-knowledge engine underneath it.** This PR is the part of that which belongs
in the gateway's own README.

## Before merging

- [ ] Confirm `github.com/prasantk8/memtara-zkp` is public. Every link in the
      new section and both badges point there.
- [ ] Confirm `aihoots.com/memtara` resolves. It currently does not — the apex
      domain is serving an infinite redirect loop, tracked separately. If the
      marketing deploy has not happened when this merges, point the two
      `aihoots.com/memtara` links at the GitHub repository instead and switch
      them back later.
