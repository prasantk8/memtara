# Memtara — pricing

Companion to `scripts/roi_calculator.py`. Every number in the tier table is a
list price we set; every number in the justification came out of that
calculator, and you can reproduce all of them from this document.

---

## Read this before the tier table

The tiers below started as a brief: $5k pilot, $25k production, $50k+
enterprise. Then the ROI calculator was built and run against them, and it said
something the brief did not anticipate:

> **At $25,000/month, displaced compliance labour alone does not pay for
> Memtara until a bank is writing roughly 4,900 structured-product
> recommendations a year.**

That is not a small institution. A DIFC boutique doing 800 a year, or a
mid-sized wealth desk doing 2,500, cannot build a labour-based business case at
that price — and a labour-based case is the only one procurement can verify
without trusting us.

Two consequences, both of which changed the model:

1. **A fourth tier exists now** — Tier 2S, $12,000/month — because the jump from
   $5,000 to $25,000 is 5x, and a 5x cliff between "pilot worked" and "production
   contract" is where pilots go to die. A bank that has just proven the thing
   works should be able to buy it without a new budget cycle.
2. **The tiers are now stated with the volume band each is honestly priced
   for.** Selling Tier 2 to a 2,000-recommendation bank produces a customer who
   cannot justify the renewal, which is a worse outcome than not selling.

Reproduce the finding:

```bash
python3 scripts/roi_calculator.py --tier production --products-per-year 2500
```

---

## The tiers

| | **Tier 1 — Pilot** | **Tier 2S — Single desk** | **Tier 2 — Production** | **Tier 3 — Enterprise** |
|---|---|---|---|---|
| **Price** | $5,000 / month | $12,000 / month | $25,000 / month | From $50,000 / month |
| **Setup** | $0 | $0 | $0 | Scoped |
| **Term** | 3 months | 12 months | 12 months | 24–36 months |
| **Honest volume band** | any — this tier is not sold on volume | ~1,500–5,000 recs/yr | ~5,000–12,000 recs/yr | 10,000+ recs/yr, or multi-entity |
| **Break-even on labour alone** | ~980 recs/yr | ~2,100 recs/yr | ~4,900 recs/yr | ~9,800 recs/yr |
| **Products** | One product family | Unlimited | Unlimited | Unlimited |
| **Named users** | 10 | 25 | 100 | Unlimited |
| **Organisations (`org_id`)** | 1 | 1 | 1 | Multiple, isolated |
| **API access** | Read-only + demo endpoints | Full | Full | Full |
| **Case file export** | Manual (`memtara-export` CLI) | Automated + CLI | Automated + CLI + webhook | As Tier 2, plus scheduled bulk |
| **Deployment** | Our infrastructure | Our infrastructure | Our infrastructure or yours | On-premise, air-gapped supported |
| **Verification key** | Shared | Shared | Shared | Dedicated vkey, published under your name |
| **Support** | Email, next business day | Email, 8h | 8×5 with escalation | 24×7 with named engineer |
| **Availability commitment** | None — it is a pilot | 99.5% | 99.9% | 99.95% |
| **Compliance consulting** | — | — | 2 days / quarter | Included, scoped |

Prices are USD, exclusive of UAE VAT, billed monthly in advance.

### What "break-even on labour alone" means

The volume at which the hours Memtara displaces — the per-recommendation
suitability check plus the reconstruction of a file when audit or a complaint
asks for one — cover the licence, **with the entire regulatory-risk benefit set
to zero**. It is the floor of the business case, not the case.

Below that volume the tier can still be the right purchase. It is simply a
different argument: defensibility on a small number of large tickets, not
operational saving. Make that argument explicitly rather than stretching the
labour numbers, because the operations team will be asked to confirm them.

---

## What the ROI calculator says, by institution shape

Run at the calculator's default assumptions (45 min per manual check, $95/hr
loaded, 60% of that time displaced, 6 hours to reconstruct a file, $250k average
ticket). Your numbers will differ; that is the point of the tool.

| Institution | Recs/yr | Tier | Licence/yr | Displaced labour/yr | Net | Payback | Licence as bp of distribution |
|---|---:|---|---:|---:|---:|---:|---:|
| Boutique DIFC manager | 800 | Pilot | $60k | $52k | −$8k | never* | 3.00 bp |
| Mid-size wealth desk | 2,500 | **2S** | $144k | $162k | +$18k | 16.4 mo | 2.30 bp |
| Mid-size wealth desk | 2,500 | 2 | $300k | $162k | −$138k | never | 4.80 bp |
| Large private bank | 6,000 | 2 | $300k | $348k | +$48k | 6.0 mo | 2.00 bp |
| Universal bank | 15,000 | 3 | $600k | $824k | +$224k | 1.3 mo | 1.60 bp |

\* On labour alone. The boutique buys this for defensibility on large tickets,
and the pilot price is set so that argument does not have to clear a big number.

**On the brief's "payback in under 3 months."** It is achievable, and the
universal-bank row shows it — but only when volume is comfortably above the
tier's break-even, or when the bank's own risk term carries the case. Near the
break-even point payback is measured in years, not months. Quoting "under three
months" as a general claim gets it checked and then disbelieved. Quote the
calculator's output for *their* numbers instead; it takes ninety seconds in the
meeting and it is far more persuasive because it is theirs.

---

## Price it in basis points, not headcount

The right-hand column above is the one to lead with. A bank distributing $625m
of structured product a year pays 4.8 bp for Tier 2, and 2.3 bp for Tier 2S.
Risk infrastructure is bought in basis points of what flows through it, and a
Head of Wealth can approve a two-basis-point line without commissioning an
operations study into how many minutes a suitability check takes.

The labour model is what you show the CFO when they ask you to prove the number.
The basis-point framing is what you show the buyer.

---

## What is not in the price

Say these out loud in the first pricing conversation. Every one of them is
something the bank will otherwise discover during implementation and treat as a
surprise cost, which is the most expensive kind.

- **Their integration engineering.** The calculator defaults to 20 days at their
  blended rate. Embedding the prover in an existing mobile app, or standing up
  advisor terminals, is their build. `clients/prover/README.md` describes exactly
  what it involves, including the parts that are genuinely awkward.
- **On-premise deployment.** There is no container image yet. On-prem today is a
  scoped engagement, priced separately, not a config flag.
- **Their product registry data.** Someone at the bank has to decide what the
  suitability thresholds for each instrument actually are, and get the risk
  committee to approve them. Memtara enforces that decision; it cannot make it.
  In practice this is the single largest hidden cost of adoption and the thing
  most likely to slip a go-live date.
- **Bias and disparate-impact testing.** CBUAE §3(a). Neither Memtara nor
  AIHOOTS measures it. See `docs/REGULATORY_MATRIX.md`.
- **Arabic-language disclosure.** Specified in `docs/journeys.md`, not built.

---

## Discounting, and what to trade instead of price

Founder-led sales with no reference customers will meet price pressure. Price is
the worst thing to concede first, because it resets the reference point for every
subsequent deal and for the bank's own renewal.

Trade these instead, roughly in the order you should be willing to give them:

1. **Term length** — 24 months at the 12-month price. Costs nothing now, and
   duration is worth more than margin at this stage.
2. **A reference commitment** — a named logo, a joint case study, or a
   willingness to take a reference call. Worth a genuine 20–30% to us, and it is
   the one thing a first customer can give that a tenth customer cannot.
3. **Roadmap influence** — a written commitment to two of their requirements in
   the next two quarters. Nearly free if their requirements are ones we wanted
   anyway, and it should be nearly free, because it usually is.
4. **Pilot credit** — the full pilot fee credited against the first production
   invoice. Makes the pilot decision almost costless and pulls the production
   conversation forward.
5. **Price**, last, and only against a signed term.

**Do not discount the pilot below $5,000/month.** A free pilot is not evaluated;
it is scheduled around. The fee is not really revenue at this stage — it is the
mechanism that gets someone at the bank assigned to the project.

---

## How a deal is expected to progress

| Stage | What happens | Typical duration |
|---|---|---|
| First call | 15 minutes. The demo runs live, on their screen, in ~40 seconds. | 1 week to schedule |
| Technical review | Their architect reads `docs/openapi.yaml`, runs `scripts/quickstart.sh`, and asks the questions in `docs/SALES_OBJECTION_HANDLER.md`. | 2–3 weeks |
| Pilot agreement | `docs/PILOT_AGREEMENT_TEMPLATE.md` through their legal and procurement. | 4–8 weeks — assume the longer end |
| Pilot | 12 weeks, one product family, one desk. | 12 weeks |
| Production | Tier 2S or Tier 2, informed by the actual volume the pilot revealed. | 4–6 weeks |

Roughly six to nine months from first call to production revenue. Anyone
modelling faster than that has not sold to a bank.

---

## Two things to fix before the first pricing conversation

Both are commercial blockers found while writing these documents, and neither
is a matter of opinion.

1. **There is no `LICENSE` file in this repository, though `README.md` states
   "MIT License – See LICENSE file for details."** A bank's counsel will check
   this in the first week of diligence, and finding an unfulfilled licence
   reference is exactly the sort of thing that turns a technical review into a
   legal one. It is also a decision, not a formality: MIT is a generous grant to
   attach to something being licensed at $25,000 a month, and a source-available
   or dual licence may serve better. Whichever it is, it needs to be chosen
   deliberately and the file added.
2. **Availability commitments in this table are promises, not measurements.**
   There is no uptime history, no status page, and no incident record, because
   there has been no production deployment. Offer the SLA contractually with
   service credits — that is normal and defensible — but never imply it is
   evidenced.

---

## Using the calculator in a meeting

```bash
python3 scripts/roi_calculator.py           # asks the questions one at a time
python3 scripts/roi_calculator.py --json    # for a spreadsheet
python3 scripts/roi_calculator.py --tier desk --products-per-year 2500
```

It tags every input with where the number comes from — `[YOURS]`, `[ASSUMPTION]`,
`[OURS]` — and prints those tags in the output. Hand the printout over. A model
that shows which parts of the case are the vendor's is a model a risk function
can take to a committee; one that does not gets sent back.
