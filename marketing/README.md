# marketing/

Awareness-campaign assets for Memtara — the structured-product suitability
platform in this repository — and for AIHOOTS, the audit gateway it ships
alongside.

## What is here

| File | What it is | Who uses it |
| --- | --- | --- |
| `LINKEDIN_SERIES.md` | A five-post LinkedIn series, ready to paste, plus graphic specs and two Mermaid diagrams | The founder, posting under their own name |
| `LEAD_LIST.md` | The outreach playbook: a blank tracking table, UAE segmentation, buyer roles, the cold-email script and its variants, and a practical compliance note | The founder, doing the outreach |
| `outreach/LINKEDIN_POST.md` | The five-post launch *sequence* and publishing schedule. Two posts drafted in full here — architecture, and the open-source ethos; the other three point at `LINKEDIN_SERIES.md` rather than duplicating it | The founder, scheduling the launch |
| `outreach/PILOT_EMAIL.md` | The cold email aimed at a Head of Wealth, paste-ready, with the reasoning for each line and a two-step follow-up cadence | The founder, doing the outreach |
| `outreach/OBJECTION_HANDLER.md` | The five *procurement* objections — SOC 2, vendor thresholds, price, contract terms, support — and which document answers each | Whoever is handling vendor onboarding |

`LINKEDIN_SERIES.md` and `LEAD_LIST.md` are the long-form source; `outreach/` is
the paste-ready layer over them. Where the two could disagree, `outreach/` links
rather than restates — deliberately, because two copies of one post is how the
stale copy gets published. The deep technical objections live in
[`docs/SALES_OBJECTION_HANDLER.md`](../docs/SALES_OBJECTION_HANDLER.md).

Everything in this folder is written to be checked. Before editing any of it,
read the repository's [`README.md`](../README.md) — particularly the
**Honest limits** section — and keep the copy consistent with it. If a claim
here and a claim there ever disagree, the repository is right and the marketing
copy is wrong.

Source material worth citing in outreach, because it is in the repo and a
prospect's technology team can open it:
[`docs/REGULATORY_MATRIX.md`](../docs/REGULATORY_MATRIX.md),
[`docs/REGULATORY_DEMO_REPORT.md`](../docs/REGULATORY_DEMO_REPORT.md),
[`scripts/demo_cro_workflow.py`](../scripts/demo_cro_workflow.py),
[`clients/prover/README.md`](../clients/prover/README.md),
and [`docs/openapi.yaml`](../docs/openapi.yaml).

## Campaign posture

This is founder-led outreach with zero customers. There is no logo wall, no
case study, no analyst mention, and nothing that a buyer would recognise as
social proof. Pretending otherwise is not an option, because the audience — a
Chief Risk Officer, a Head of Digital Wealth, and the architect they will
forward the email to — is unusually well equipped to check. That leaves exactly
one durable advantage: everything claimed here is verifiable by the reader,
today, without asking us for permission. The demo runs from a public
repository in about forty seconds. The attestation JWT validates against a
published JWKS. The sealed case file re-verifies from a committed key, and
fails on a single flipped byte. The regulatory matrix names four genuine gaps
on its first page.

So the copy's job is to make checking easy, not to make checking unnecessary.
Name the cryptography precisely rather than saying "advanced". Name the known
limits before the prospect finds them, because a CRO who discovers a limit
themselves stops believing the strengths. Where the honest answer is
unflattering — zero pilots, no container image, org self-registration still
unauthenticated, bias testing not measured — say it in the same plain register
as everything else. The conversion event we are optimising for is not a like;
it is a technically literate person cloning the repo and finding that it does
what the post said. Every post and every email should be written so that this
is the cheapest next step available to them.

## What not to do

No fabricated traction. There are zero pilots, zero paying customers, no
revenue and no waiting list, and no message may imply otherwise — including by
omission, phrasing like "our current deployments", or a pilot described in the
present tense before one exists. No name-dropping. Do not mention a bank,
family office or wealth manager we have not actually spoken to, do not use
anyone's logo, and do not describe an exploratory call as a pilot, an
evaluation or a relationship. No implied regulatory endorsement. We have no
DFSA or CBUAE approval, no sandbox admission, and no Innovation Testing Licence
or RegLab place; mapping our behaviour to a published rule is not the same as a
regulator agreeing that we satisfy it, and the copy must never blur the two.
Separately, and just as firmly: do not claim SOC 2, ISO 27001, penetration
testing or an SLA track record; do not say "bank-grade", "military-grade",
"unhackable" or "immutable"; do not invent a mis-selling fine figure or an
industry benchmark; do not claim legal admissibility, which is a question for
counsel; and do not describe the case file's seal as a digital signature a PDF
viewer will validate, because it is not one.
