# Objection handler — the procurement desk

The five objections that come from **vendor onboarding**, not from the buyer.

## Which document you want

There are two, and picking the wrong one wastes a meeting.

| You are talking to | Use |
|---|---|
| A CRO, Head of Compliance, or the architect they forwarded you to | [`docs/SALES_OBJECTION_HANDLER.md`](../../docs/SALES_OBJECTION_HANDLER.md) — eight technical objections in depth, plus a due-diligence answer sheet |
| Procurement, vendor risk, legal, or anyone sending you a questionnaire | **This file** |

The technical document answers *does it work*. This one answers *can we buy it*,
which is a different question with a different failure mode: the buyer is
convinced and the vendor-risk form still says no. Every objection below is one
you cannot argue your way out of — you can only answer it accurately, offer the
compensating control, and let them decide.

**The two rules from the technical document apply here unchanged.** Never bluff:
everything below is traceable to a file in this repository, and a bank's vendor
risk team will check. Say the honest numbers out loud: zero pilots, zero paying
customers, no CBUAE or DFSA approval, no sandbox place, no SOC 2, no ISO 27001,
no penetration test. Naming those first is what buys you the right to be believed
about anything else.

---

## 1. "Send us your SOC 2 Type II and your latest penetration test."

**What they mean:** this is a form field, and an empty one usually ends the
process automatically. They are not asking you to argue; they are asking whether
they can tick the box.

**Answer:**

> We have neither, and I'd rather say that in the first email than the third.
> No SOC 2, no ISO 27001, no third-party penetration test. We are pre-revenue
> and those cost more than we have.
>
> What we can put in front of your security team instead is the system itself.
> The code is public, the cryptography is named rather than described, and the
> security measures we do operate are written down as contractual commitments
> rather than marketing claims — Schedule 3 of our pilot agreement.
>
> For a pilot, the compensating control is scope: synthetic clients only, no
> production client data, one instrument. There is nothing in the pilot for a
> breach to expose.

**Send them:** [`docs/PILOT_AGREEMENT_TEMPLATE.md` § Schedule 3 — Security
measures](../../docs/PILOT_AGREEMENT_TEMPLATE.md), and
[§ 3.2 — What Memtara actually receives](../../docs/PILOT_AGREEMENT_TEMPLATE.md),
which inventories the personal data precisely rather than gesturing at it. The
inventory does more for a vendor-risk reader than any certificate summary would.

**When it is fatal:** a bank with a hard policy that no vendor touches any
environment without SOC 2. That policy exists and it is not irrational. Ask
whether a fully air-gapped evaluation — their laptop, their data, our source,
no connection to us — sits outside the policy's scope. If it does not, walk, and
ask them what the smallest certification would be that changes the answer.

---

## 2. "You're pre-revenue. You won't clear our vendor risk threshold."

**What they mean:** audited accounts, minimum trading history, professional
indemnity and cyber liability cover at a stated limit, and often a rule about
concentration risk on single-founder suppliers.

**Answer:**

> That is a fair objection and I am not going to talk you out of a threshold.
> Two things worth putting on the table before you close it out.
>
> First, a pilot as we scope it is not a supplier relationship. No production
> data, no integration into a live advice journey, no dependency you would have
> to unwind. It is closer to an evaluation than a deployment, and it is worth
> checking which of the two your policy is actually written against.
>
> Second, the exit risk that thresholds exist to manage is the one place we are
> genuinely unusual. The verification key is committed to a public repository.
> A case file issued during the pilot re-verifies from that published key with
> the vendor gone — not "we would hand over an escrow copy", but *already
> published, today, verifiable by you without us.*

**Send them:** [`docs/PILOT_AGREEMENT_TEMPLATE.md` § 9 — Termination and
exit](../../docs/PILOT_AGREEMENT_TEMPLATE.md), and
[`docs/SALES_OBJECTION_HANDLER.md` § 7 — "What happens to us if your company
disappears?"](../../docs/SALES_OBJECTION_HANDLER.md) for the long-form version.

**When it is fatal:** insurance minimums. A PI/cyber requirement is a number you
either carry or do not, and no argument moves it. Find out the limit and what it
would cost to carry — for two named pilots it may be cheaper than the sales cycle
you are about to lose.

---

## 3. "We need a price and a budget line before this goes anywhere."

**What they mean:** they cannot raise a purchase order against "let's talk about
it", and an unpriced pilot stalls in a queue rather than being rejected.

**Answer:**

> Priced, and priced in basis points of the product flow it governs rather than
> per seat — a suitability check is worth what the recommendation is worth, not
> what a login is worth. Tiers and the reasoning behind them are written down.
>
> For the first two pilots the number that matters is the pilot fee, and I'd
> rather agree it in the first conversation than discover in week six that it
> was the blocker. There is also a list of what is deliberately *not* in the
> price, so nothing arrives as a surprise line item later.

**Send them:** [`docs/PRICING_MODEL.md`](../../docs/PRICING_MODEL.md) — the tier
table, `§ Price it in basis points, not headcount`, and `§ What is not in the
price`. Pilot fees specifically:
[`PILOT_AGREEMENT_TEMPLATE.md` § 2 — Term and fees](../../docs/PILOT_AGREEMENT_TEMPLATE.md)
and `Schedule 2 — Fees`.

**Do not** discount to unblock this. `PRICING_MODEL.md § Discounting, and what to
trade instead of price` lists what to give away instead; read it before the call,
because the concession you improvise under pressure is the one that sets the
reference price for every deal after it.

**When it is fatal:** it is not. If a price is genuinely the obstacle, you have
found a real buyer and a solvable problem. Treat this objection as the good news
it usually is.

---

## 4. "Our contract terms are non-negotiable — DPA, liability cap, indemnities."

**What they mean:** their paper, their caps, and a data-protection addendum that
assumes you are a processor of client financial data.

**Answer:**

> Happy to work from your paper. One correction to make early, because it
> changes the DPA rather than being a detail inside it: we do not receive the
> client's income, liquid assets, risk tolerance or holdings. Those never leave
> the client's device. What we hold is inventoried line by line — a phone
> number, optionally an email, device names, session records, a persistent user
> ID, and an encrypted vault blob we cannot decrypt.
>
> Two clauses usually need real discussion rather than redlining. Data residency
> and transfers, because the honest answer depends on where you host the
> pilot. And retention versus deletion, because an append-only audit chain and a
> deletion right are in genuine tension — we have written up that tension rather
> than pretending it resolves cleanly.

**Send them:** [`docs/PILOT_AGREEMENT_TEMPLATE.md`](../../docs/PILOT_AGREEMENT_TEMPLATE.md),
specifically `§ 3.1 Roles`, `§ 3.2` (the inventory), `§ 3.4 Location and
transfers`, `§ 3.6 Retention, deletion, and the honest tension with the audit
chain`, and `§ 7 Indemnities and liability`. For UAE data residency as a
substantive question rather than a clause, see
[`SALES_OBJECTION_HANDLER.md` § 8](../../docs/SALES_OBJECTION_HANDLER.md).

**Raise § 3.6 yourself, before their legal team finds it.** A tension you
disclose is a design decision; the same tension discovered in review is a
concealment, and it costs you the clause *and* the credibility.

**When it is fatal:** an uncapped indemnity, or a liability cap set as a multiple
of fees that a pre-revenue company cannot carry. That is a solvency question, not
a negotiation. Say so plainly and ask whether the cap can be scoped to the pilot.

---

## 5. "Who supports this at 2am? What's the SLA?"

**What they mean:** they are imagining a production incident during a live advice
session, and they want to know who answers.

**Answer:**

> Today: me, and no SLA. There is no 24/7 rota, no support tier and no
> container image yet — you would run it from source alongside your
> environment. I would rather you hear that now than read it in a schedule.
>
> What makes that survivable for a pilot is that nothing in the pilot is in a
> client's path. Synthetic clients, one instrument, no live advice journey. The
> failure mode of an outage is that an evaluation pauses, not that an advisor
> cannot advise.
>
> Known operational limits, so you are not discovering them: rate limiting is
> per process rather than shared across instances, and organisation
> self-registration is not yet authenticated. Both are listed with everything
> else we have not closed.

**Send them:** the honest-limits section of the repository
[`README.md`](../../README.md), and
[`docs/REGULATORY_MATRIX.md`](../../docs/REGULATORY_MATRIX.md), which names four
genuine gaps on its first page. `PILOT_AGREEMENT_TEMPLATE.md § 6 — What Memtara
promises, and what it does not` is the contractual version of the same answer.

**When it is fatal:** if they are scoping production rather than a pilot, this
objection is correct and you should say so. Production support is a real gap.
Trying to talk past it buys you a deployment you cannot service, which is worse
for you than the lost deal.

---

## The pattern underneath all five

Every answer above has the same shape: **name the gap first, then the
compensating control, then what they can check without you.** That ordering is
not modesty. The audience for this campaign — a vendor risk analyst with a
questionnaire — is paid to find the gap, and finding it after you claimed
otherwise ends the conversation permanently. Finding it *in your own first
sentence* is the only version where the strengths still get read.

Two things follow. Put the honest numbers in the first email, not the third, and
never bluff a certification, an SLA, an insurance limit or a customer.

And when an objection arrives that is not covered here or in
[`SALES_OBJECTION_HANDLER.md`](../../docs/SALES_OBJECTION_HANDLER.md), say you
will find out — then add it to whichever of the two files it belongs in. A
procurement desk asks the same five questions of every vendor; the sixth one you
hear is worth writing down.
