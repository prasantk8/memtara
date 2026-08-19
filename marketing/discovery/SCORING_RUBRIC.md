# Scoring rubric — turning 20 conversations into a decision

Score every call within 24 hours, using `INTERVIEW_GUIDE.md`'s question
numbers as the source for each field. Twenty unscored anecdotes is a
collection of good stories. Twenty scored calls is a decision.

Keep one row per interview in a spreadsheet with these exact columns. Do not
paraphrase scores into prose until all 20 are in — narrative writes itself
around whichever three calls you remember best.

---

## Per-interview fields

| Field | Source question | How to score |
|---|---|---|
| Firm / segment | — | From `TARGET_LIST_CRITERIA.md` sourcing sheet |
| Pre-frequency? (Y/N) | Q0 | If Y, stop scoring the rest — log as pre-frequency and move on |
| Pain acuteness | Q1, Q11 | 0–4, see anchors below |
| Evidence-assembly cost (hours) | Q4 | Raw number of hours, as stated. If a range, record the low end |
| Systems touched | Q3 | Raw number |
| Frequency (qualifying decisions/month) | Q10 | Raw number. This is the direct test of the frequency risk in `beachhead_pressure_test.md` |
| AML/STR volume (decisions/month) | Q10a | Raw number, asked on every call regardless of what Q1 surfaced |
| Budget owner named? (Y/N) | Q13 | Y only if a name **and** title were given, not a department |
| Budget owner title | Q13 | Verbatim |
| Regulatory urgency | Q9 | 0–4, see anchors below |
| Unprompted different pain | Q1, Q10a, and anywhere else it surfaces | Verbatim quote + which category (see below) |
| Reaction to the one-sentence close | Last question | Verbatim, plus interviewer's one-line read |

### Pain acuteness anchors (0–4)

- **0** — No consequence described. "We'd probably just note it and move on."
- **1** — Process friction only. Extra work, no named risk to the firm or a person.
- **2** — Named organisational risk (audit finding, remediation plan) but no
  individual exposure and no deadline attached.
- **3** — Named individual exposure (a signature, a personally accountable
  officer) or a live remediation with a deadline.
- **4** — A described instance of actual harm already occurred: a fine, a
  lost client, a regulator visit, disciplinary action, a licence question.

### Regulatory urgency anchors (0–4)

- **0** — No regulator contact on this topic, ever, per Q9.
- **1** — Industry-wide letter or thematic review touched the *area* but not
  this firm specifically.
- **2** — This firm was named in a thematic review or received a general
  information request.
- **3** — This firm received a direct, firm-specific regulatory question or
  finding on this exact workflow.
- **4** — Live remediation plan with the regulator, on this exact workflow,
  with a stated deadline.

---

## The pre-committed re-open trigger

`beachhead_pressure_test.md` names this explicitly: **if AML/STR (or any
single alternative pain point) is named as a funded priority in 2 of the
first 5 calls, re-open the beachhead decision** — do not push on suitability
by default. This is written down now, before any call happens, so it cannot
be rationalised away at 11pm after a long week of calls that "felt" fine.

### What counts as "named as a funded priority" — the exact test

All four of the following must be true. If any one is missing, it does not
count, no matter how enthusiastic the prospect sounded.

1. **It was unprompted.** It came from Q1 or Q10a's open framing, or the
   prospect raised it on their own — not from you asking "would AML/STR
   matter more to you?" (which the guide already forbids as a hypothetical).
2. **It names an active budget allocation, not a wish.** "We have budget
   approved for this this year" or "we're already evaluating vendors for
   this" counts. "We should probably look at this" or "that would be nice
   to fix" does not.
3. **It has a named or clearly implied owner.** Either the same person named
   in Q13, or a different named role the prospect identifies as the one
   pushing it.
4. **It is current or next-quarter, not "eventually."** A timeframe was
   given, or the prospect described active work happening now.

Write the interview's verdict on this test as one line: **"funded priority:
yes"** or **"funded priority: no — [which of the four tests failed]."** Do
not write "sort of" or "kind of." If you cannot cleanly answer yes, it is no.

### The trigger, stated as arithmetic

- Take the first 5 *completed* interviews (not scheduled, not attempted —
  completed, meaning Q0 passed and the call ran).
- Count how many independently score "funded priority: yes" for the **same**
  alternative (AML/STR is the named candidate; if a different alternative —
  KYC, MRM, something else entirely — hits the same bar twice, treat it the
  same way).
- **2 or more → stop. Re-open the beachhead decision before booking call 6.**
  This means re-running the weighting exercise in
  `beachhead_pressure_test.md` with the new evidence, not quietly drifting
  the pitch. Tell the person you'd otherwise report to before continuing.
- **0 or 1 → continue as planned.** Keep asking Q10a on every remaining
  call regardless — the trigger is checked again at calls 6–10, 11–15, and
  16–20 using the same 2-of-5 bar applied to each fresh window, not a
  cumulative count that never resets.

This is a stop-and-check gate, not a vote you can lose 2–18 and still call a
win. Two independent "yes" verdicts in five calls is a strong, low-probability
signal if the null hypothesis is "no strong preference exists" — do not wait
for a bigger sample size to confirm what the pre-commitment already decided.

---

## Turning 20 rows into a call

After 20 completed interviews (or after any re-open trigger fires and is
resolved), compute:

- **% pre-frequency** (Q0 = N). `[ASSUMPTION]` If this is above roughly a
  third of everyone contacted who agreed to a call, the wedge is
  substantially pre-frequency in this market segment today, independent of
  everything else in this rubric — that is change-my-mind fact #2 from
  `beachhead_pressure_test.md` materialising in the data, not a scoring
  artefact.
- **Median frequency (Q10)** across non-pre-frequency calls. Compare
  directly against the ~208/month figure in `docs/PRICING_MODEL.md` — remember
  that figure is tagged `[ASSUMPTION]` there and was never discovery-derived.
  If the median sits at or below the "twelve a month, spreadsheet is fine"
  level `marketing/LEAD_LIST.md:104–106` predicts, that prediction has been
  confirmed, not merely anticipated.
- **% with a named budget owner (Q13 = Y)**. This is the single number
  `beachhead_pressure_test.md` weights ×3 above every other criterion.
  A low percentage here is a harder problem than a low pain score — pain
  without an identifiable signer does not close.
- **Mean pain acuteness and regulatory urgency**, split by segment (DIFC
  private bank / ADGM / retail private-banking arm / independent wealth
  manager / family office — per `marketing/LEAD_LIST.md`'s segmentation).
  Look for the split, not just the average — a 2.5 average hiding a 4 and
  a 1 is two different markets, not one mediocre one.
- **Evidence-assembly cost distribution (Q4, Q3)**. This is your raw
  material for a discovery-derived ROI case to replace the `[ASSUMPTION]`
  inputs in `docs/PRICING_MODEL.md`'s calculator once you have enough
  real numbers to be worth substituting.

### Decision bands `[ASSUMPTION]` — set before calls start, not after

- **Proceed, unchanged.** ≥12 of 20 completed calls score pain ≥3 AND have a
  named budget owner AND report frequency at or above roughly 150/month, AND
  the re-open trigger never fired.
- **Proceed, re-scoped.** The re-open trigger fired, and after re-running the
  weighting the alternative wins — move the primary pitch to that
  alternative and treat suitability as the named second shot instead.
- **No-go on current wedge, without a clear alternative.** Pain and budget
  scores are weak across the board, no alternative pain surfaces strongly
  enough to trigger a re-open. This is the least comfortable outcome and
  the one most likely to be argued away — do not argue it away.

These bands are drafted now, before evidence exists, precisely so they
cannot flex around whatever the data turns out to say.
