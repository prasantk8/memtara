# Target list criteria — sourcing 60 names to get 20 interviews

No named individuals or fabricated contact details appear in this document.
It is a procedure, not a list. Run the procedure yourself and put the
results in `marketing/LEAD_LIST.md`'s tracking table, following that file's
own rule: no name goes in without a source you can point to and a date you
retrieved it.

---

## The funnel, and why 60

`[ASSUMPTION]` A cold, no-pitch, 25-minute research ask from a first-time
founder with no reference customers converts at roughly 25–35% from
"sourced and contacted" to "completed interview," based on typical
founder-led B2B discovery response rates — not on any data this company has
generated yet, because it has none. That puts 20 completed interviews at
roughly 60 sourced, qualified contacts. Track your actual rate from
interview 1 and revise this ratio for the remaining sourcing rather than
trusting the estimate past the first 15–20 contacts.

Budget for attrition at each stage, not just the final one:

| Stage | Rough count | Note |
|---|---:|---|
| Sourced (passes disqualifiers below) | 60 | Firm-level, before you have a person's name |
| Named contact identified | ~50 | Some firms will have no publicly self-disclosed name at the right role — skip, don't guess |
| Contacted | ~50 | |
| Replied (yes or no) | ~25 | `[ASSUMPTION]` |
| Call booked | ~22 | |
| Call held and completed (passes Q0) | ~20 | Some booked calls turn out pre-frequency and get logged short, per `INTERVIEW_GUIDE.md` |

If your real conversion is running well below this after the first 20
contacts, that is itself a data point — log it, and consider whether the
firm-type mix needs to shift before sourcing the next 40.

---

## Firm criteria

### Firm type — in the order `marketing/LEAD_LIST.md` already ranks them

1. DIFC private banks and wealth managers
2. ADGM private banks and wealth managers
3. Local retail banks with private-banking arms
4. Independent wealth managers
5. Multi-family offices (not single-family — see disqualifiers)

Source roughly proportional to fit, weighted toward 1, 2 and 4 — those are
the segments `marketing/LEAD_LIST.md` rates highest for actual pilot odds,
and 4 is also the segment `BUYER_MAP.md`'s "flat firm" column describes,
which is where role-count collapse makes a single 25-minute call cover
champion, economic buyer and validator at once.

### Size band

`[ASSUMPTION]` Target AUM roughly $200M–$5B for wealth managers and private
banks. Below that, a firm is unlikely to have deployed any advisory AI in
production yet (Q0 will fail more often, wasting sourcing effort). Above
roughly $5–10B, the firm likely resembles `BUYER_MAP.md`'s large-enterprise
column, with a 6–9 month cycle per `docs/PRICING_MODEL.md:178-179` and
vendor-risk machinery `marketing/LEAD_LIST.md:59-61` already flags as a
blocker — still worth some calls for the AML/STR frequency data point, but
do not weight the list toward them for discovery-stage speed.

### Jurisdiction

DIFC and ADGM first (regulator-mapped in `docs/REGULATORY_MATRIX.md`).
Onshore UAE (CBUAE-regulated) second, with the caveat already stated in
`marketing/LEAD_LIST.md:84-91` about slower cycles. Do not source outside
the UAE for this round — every other jurisdiction starts from zero
regulatory mapping per `beachhead_pressure_test.md`, and discovery calls
outside the mapped jurisdictions answer a different question than the one
this round is trying to answer.

---

## Observable signals that a firm has AI in an advisory workflow *today*

The point of every signal below is to raise the odds a firm passes Q0
before you spend a contact attempt on it. None of these confirms production
use on its own — they raise probability, they do not prove it. Confirm on
the call itself; do not skip Q0 because a signal looked strong.

- **Job postings.** Search the firm's careers page and LinkedIn Jobs for
  roles combining wealth/advisory terms with AI/ML/copilot/automation terms
  — "Digital Wealth," "AI Governance," "Model Risk," "Conversational
  Banking," "Advisor Copilot." A live requisition is a stronger signal than
  a filled role from a year ago; check the posting date.
- **Conference talks and speaker programmes.** UAE fintech events with
  public programmes — Dubai FinTech Summit, GITEX, Abu Dhabi Finance Week,
  ADGM's own fintech programming — publish speaker lists and session
  abstracts. A firm's compliance, digital, or risk lead speaking on an
  AI-in-advisory panel is a strong, dated, self-disclosed signal.
- **Vendor announcements.** Press releases or case studies from known
  advisory-AI, robo-advisory, or conversational-banking vendors naming a
  DIFC/ADGM client. Vendors publicize wins; this is often the single
  cleanest signal because the firm did not have to say anything itself.
- **Regulatory filings and public statements.** DFSA and FSRA publish
  public registers of regulated firms and, periodically, thematic review
  findings and speeches referencing AI adoption in the sector. A firm named
  in a DFSA or FSRA public statement about AI in advisory services is a
  strong signal and also a natural opening line for outreach.
- **The firm's own public materials.** Client-facing brochures, website
  copy, or annual reports describing an "AI-powered" or "digital advisor"
  offering. Treat marketing language skeptically — per `incident_source.md`'s
  Delphia/Global Predictions cases, firms sometimes describe AI capability
  they have not actually implemented. A marketing claim raises a firm to
  "worth contacting," not to "confirmed" — that is exactly the gap Q0
  exists to close.

---

## Disqualifiers

Drop a firm from the list — do not spend a contact attempt — if any apply:

- **Single-family office.** Per `marketing/LEAD_LIST.md:110-113`, no
  external suitability obligation exists when the client and the firm are
  the same economic party. There is no regulatory audience for the pain
  this round of discovery is testing.
- **No structured-product or advisory-recommendation business at all.**
  Pure execution-only brokers or custody-only operations have no
  suitability-shaped decision to evidence.
- **Already a competitor's disclosed customer**, if this becomes knowable
  during sourcing. Not a priority to screen for at this stage, but do not
  spend a contact attempt confirming it once found.
- **No publicly self-disclosed contact at any of the five `BUYER_MAP.md`
  roles.** Per the sourcing rule, do not guess an email format or scrape a
  personal address to manufacture a contact. Skip the firm rather than
  invent a path in.
- **Outside DIFC/ADGM/onshore UAE**, per the jurisdiction criterion above.

---

## Worked example of the sourcing procedure

This is a walkthrough of the *method*, run generically — it does not name a
real firm or person, and none of the phrasing below should be copied into a
tracking sheet as if it were a real result.

1. **Pick a firm-type bucket** — start with DIFC independent wealth
   managers, per the priority order above.
2. **Pull the DFSA public register** of firms authorised for wealth
   management / advisory activity in DIFC. This gives you a firm-level
   list with no guessing involved — it is the regulator's own published
   data.
3. **For each firm, check for an AI-in-production signal** using the five
   categories above, in this order (cheapest checks first): firm's own
   website / brochure → LinkedIn Jobs search scoped to the firm →
   conference speaker programmes for the last 12–18 months → a general
   search for the firm's name plus "AI" or "copilot" → DFSA/FSRA public
   statements naming the firm. Stop as soon as one clear signal is found;
   log which category it came from — this becomes the checkable claim, if
   any, in the outreach message's subject line.
4. **If no signal is found after all five checks**, do not add the firm to
   the outreach list yet. Put it in a second-tier "pre-frequency risk"
   bucket — worth contacting later in the round if the first-tier list
   runs short, but expect a higher Q0 failure rate.
5. **Identify a named contact at one of the five `BUYER_MAP.md` roles**,
   sourced only from a place they chose to publish it — their own LinkedIn
   profile, the firm's own leadership page, a conference programme, or the
   regulator's public register (some DFSA/FSRA filings name a compliance
   officer of record). If the firm passed step 3 via a job posting, the
   posting itself sometimes names the hiring manager — check before
   assuming you need a second search.
6. **Record firm, segment, target role, name, and source-with-date directly
   into `marketing/LEAD_LIST.md`'s tracking table** — this document only
   describes how to source; the actual pipeline lives there, per its own
   sourcing-hygiene rule.
7. **Repeat across firm-type buckets** in priority order until 60 qualified,
   named contacts are logged, weighting toward DIFC/ADGM independents and
   private banks as described above.

Expect step 3 to be the slowest step and the one most tempting to shortcut.
Do not shortcut it — a contact list sourced without any AI-in-production
signal is a list that will fail Q0 at a much higher rate, burning contact
attempts on firms that were never going to clear the gate.
