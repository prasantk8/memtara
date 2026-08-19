# Pricing position — confronting the 16.4-month payback

`docs/PRICING_MODEL.md` already does the honest arithmetic and does not hide
from it: at Tier 2S ($12,000/month), a mid-size DIFC wealth desk doing
2,500 recommendations/year clears break-even, but only just — net positive
about $18k/year, payback about 16.4 months. That is our own beachhead
customer's own numbers, not a worst case. This document does not route
around that; it sets out the options and gives a recommendation that has to
survive being shown to the first real prospect.

**Why this matters commercially, stated plainly:** a 16.4-month payback on
a 12-month contract term means the licence has not paid for itself, on
labour savings alone, by the time the first renewal decision is made. That
is a fragile renewal, not a bad pilot — but it is exactly the situation
`docs/PRICING_MODEL.md` itself names as worse than not selling: "a customer
who cannot justify the renewal."

---

## The four options, honestly

### A. Price on risk/evidence value, not per-decision cost

`docs/PRICING_MODEL.md` already does this in part — the basis-point framing
(2.3 bp of distributed volume for Tier 2S at the mid-size desk) reframes the
same $144k/year as a small fraction of what flows through the control,
rather than a cost per suitability check. This is not a new price; it is a
different sentence describing the existing price, and it is real: a Head of
Wealth approving 2–3 bp of distribution does not need an operations study.

**What it doesn't fix:** the CFO or Internal Audit will still ask for the
labour-based case at some point in diligence (see `docs/PRICING_MODEL.md`'s
own note that this is "what you show the CFO when they ask you to prove the
number"), and at that point the 16.4-month number resurfaces regardless of
how the first conversation was framed. Basis-point framing changes who
objects, not whether the underlying math is thin.

### B. Change the tier structure

Options within this: lower Tier 2S's price to shorten payback; add a fifth,
narrower tier between 2S and pilot; or introduce usage-based pricing above
an included volume so a desk below break-even pays less and a desk above it
pays for what it actually uses.

**What it doesn't fix, and what it risks:** `docs/PRICING_MODEL.md` already
warns against discounting price first — "the worst thing to concede first,
because it resets the reference point for every subsequent deal and for the
bank's own renewal." A new, cheaper tier built specifically because the
current one is uncomfortable is a price cut wearing a different name, and
it invites the next prospect to negotiate down from wherever the new floor
lands. Usage-based pricing is more defensible in principle but adds billing
and metering complexity this pre-revenue company has not built, for a
customer count of approximately zero — solving an implementation problem to
fix a story problem.

### C. Target higher-volume decision types

`/private/tmp/.../scratchpad/beachhead_pressure_test.md` already ran this
analysis: AML/STR alert disposition scores higher than suitability on raw
decision frequency (a bank's alert queue runs into the thousands per
month, versus suitability's own stated ~208/month assumption), and that
volume would clear Tier 2S's break-even comfortably rather than marginally.
The same document's verdict was explicitly **not** to switch — "keep
suitability, name AML/STR as a second shot" — because AML/STR currently has
one paragraph of design work behind it versus suitability's full pricing
model, objection handler, and pilot template, and because a wrong or
incomplete zero-knowledge predicate about PEP/sanctions status is a
qualitatively worse failure mode for a zero-track-record vendor than a
suitability miss.

**What it doesn't fix, on this timeline:** it isn't available for the
pilot in front of us today. It is the correct medium-term fix for the
frequency problem specifically, not a lever available in the next
discovery call.

### D. Accept a longer payback in exchange for a reference customer

`docs/PRICING_MODEL.md`'s own trade table already prices this: a reference
commitment (named logo, joint case study, reference call) is "worth a
genuine 20–30% to us" `[ASSUMPTION — the pricing doc's own estimate, not a
measured figure; no reference customer exists yet to calibrate against]`.
Applied to the 2,500-rec/year Tier 2S case: $18k/year net, uncomfortable
alone, stops being the whole story once a first-reference discount on
customer-acquisition cost and the compounding value of "a named DIFC bank
runs this" for every subsequent deal are counted. This does not change the
Bank's own renewal math — they still see 16.4 months — but it changes
whether *we* should be willing to sign that deal.

**What it doesn't fix:** it does not make the Bank's own internal
business case any stronger. If their renewal decision is judged purely on
labour-displacement math, the reference trade is invisible to them and the
deal still risks non-renewal on schedule.

---

## Recommendation

**Lead every conversation with basis points (A), do not touch the tier
structure to fix this (reject B), keep AML/STR moving as a named second
shot rather than switching to it now (C stays parallel, not primary), and
explicitly price the first 1–2 deals as reference trades (D) rather than
pretending the labour math is stronger than it is.**

Concretely: for a prospect at or near the Tier 2S break-even (the likely
shape of our actual near-term prospects, per the beachhead volume
analysis), do not discount price to improve their payback number. Instead,
trade term and reference commitment exactly as `docs/PRICING_MODEL.md`
already prescribes — 24 months at the 12-month price, plus a named
reference or case study — and be explicit internally that the deal's value
to us is not fully captured by its 16-month payback on their side. Say the
16.4-month number out loud in the room before they compute it themselves;
a vendor who leads with the honest number and the reference-value argument
is more credible than one who waits to be caught.

Simultaneously, treat every discovery call as a live test of C: ask the
volume question the beachhead document specifies, and if 3 of the first 5
calls independently surface AML/STR (or any higher-frequency decision
type) as the sharper, better-funded pain, that is the trigger to
re-open this pricing question with a different volume assumption entirely
— not a full pivot, but a second track worth resourcing.

## What would falsify this recommendation

1. **A prospect's actual suitability volume comes in materially below the
   2,500/year assumption**, not just near Tier-2S break-even but below the
   Tier-1 pilot's own break-even (~980/year). At that point the labour case
   isn't thin, it's absent, and no amount of reference-trade reasoning
   rescues a deal with no revenue floor — pricing would need to shift to a
   flat evidence-retainer model decoupled from volume, not a discount.
2. **Reference commitments turn out to have near-zero real value to the
   banks we're actually pursuing** — e.g. UAE/DIFC institutions
   systematically refuse to be named or give reference calls even in
   exchange for a discount, which would mean the 20–30% figure this
   recommendation leans on is not just unmeasured but wrong for this
   market. If that happens twice, stop offering the reference trade and
   price purely on basis points and risk value instead.
3. **A prospect explicitly states price, not payback period, is the
   objection** — i.e., they accept the ROI story but the absolute number is
   too large for their approval threshold regardless of payback. That is a
   different problem (deal size, not deal shape) and this document's
   recommendation does not address it; it would argue for option B after
   all, in a form scoped to that specific finding rather than a general
   tier redesign.

`[ASSUMPTION]` markers above follow `docs/PRICING_MODEL.md`'s own
convention: every number sourced from the ROI calculator's stated defaults
or the pricing doc's own trade-value estimates, not from a completed deal —
because there isn't one yet.
