# Discovery interview guide

For the founder, live, on the call. 25 minutes. Read this once at 7am, then
run it from memory — do not read questions off a screen at a compliance
officer.

Companion docs: `SCORING_RUBRIC.md` (how to score what you hear),
`BUYER_MAP.md` (who you should be talking to), `OUTREACH_SEQUENCE.md` (how
you got the call).

---

## The three rules that govern every call

1. **Past behaviour only. Never ask a hypothetical-purchase question.**
   Not "would you use AI governance tooling?" Not "would this be useful to
   you?" Not "if a vendor offered X, would you buy it?" People are bad
   at predicting their own future behaviour and generous when a founder is
   listening. Ask what happened last time. If nothing has happened yet, that
   is itself the finding — see the gate below.
2. **Never describe our product before the last question of the call.**
   Not the name, not "zero-knowledge," not "cryptographic proof," not
   "case file." The moment you describe what we build, every answer after
   that point is contaminated — the prospect starts answering the question
   "would I want *that*" instead of the question "what actually happened to
   me." If they ask "what do you do?" early, say: "I will tell you in ten
   minutes — I want your unfiltered experience first, it's more useful to
   both of us." That line is allowed. A product description is not.
3. **You are not pitching. You are asking for 25 minutes of their expertise.**
   If the call starts to feel like a sales call, stop, and say so out loud:
   "I want to flag — I'm not selling anything on this call, I'm trying to
   understand a problem." This is not modesty. A prospect who thinks they
   are being sold to gives guarded, polite answers. A prospect who believes
   they are the expert being consulted gives you the real ones.

Do not violate rule 2 to be polite. Silence after a hard question is fine.
Let it sit.

---

## Q0 — The gate (ask this first, literally, before anything else)

> "Before we get into it — is there any AI involved in your advisory or
> recommendation workflow today, in production? Not a pilot, not something
> IT is evaluating — something advisors or the business are actually using
> to produce a recommendation, disposition, or decision right now."

Why this is Q0, not Q1: if the answer is no, this firm is **pre-frequency**.
There is no decision stream yet for evidence to attach to. They cannot buy
what we are building because there is nothing yet to evidence. This is a
different and worse problem than "low volume" — see
`beachhead_pressure_test.md`'s change-my-mind fact #2. Find this out in
minute two, not week six.

- **If no** — do not abandon the call. Ask two things and then wrap early:
  "Is there a plan to bring AI into this workflow, and on what timeline?"
  and "Who inside the firm is pushing for that, and who is resisting it?"
  Log as **pre-frequency** in the scoring rubric. This is still a useful
  data point — it tells you how far out your market actually is — but do
  not run the rest of the script as if they were a live prospect. Thank
  them, ask if you can reconnect in 6 months, end at minute 10.
- **If yes** — proceed to Q1.

Do not let "we're looking at a copilot" count as yes. "Looking at" is not
production. Push once: "so an advisor used it to produce an actual
recommendation this month?" If the honest answer is still no, treat as no.

---

## Q1 — The opening (the board's question, not ours)

> "Walk me through the last AI-assisted decision you had to defend — to
> Internal Audit, to Compliance, to a regulator, or to a client dispute.
> What happened?"

This is deliberately open. Do not narrow it to "suitability" or "structured
products" — if they bring up AML/STR, KYC, or something else entirely, that
is signal, not noise. Let them choose the example. Write down which category
they picked before you ask anything else; it is your first data point for
the rubric's "different pain, unprompted" score.

If they say "we haven't had to defend one yet" — that's still Q0's answer in
disguise (low frequency of *disputed* decisions, not necessarily
pre-frequency). Ask: "okay — walk me through the last one you produced, even
if nobody challenged it."

---

## Q2–Q11 — Follow-ups

Ask these roughly in order, but follow the thread if they hand you something
sharper. Do not read them as a checklist in front of the prospect.

**Q2 — Where did the evidence come from?**
> "When you had to put that file together, where did the evidence actually
> come from? What did you point to as proof the check was done?"

**Q3 — How many systems?**
> "How many different systems did you have to pull from to assemble that?"
Get a number. "A few" is not a number — ask "two? five? ten?" until they
commit to one.

**Q4 — How long did it take?**
> "Start to finish, how many hours did that take? Whose hours?"
Get a number in hours, not "a while." If they hedge, ask about the specific
last instance, not the general case: "the actual one you just described —
how long did that one take?"

**Q5 — Who assembled it?**
> "Whose job was it to put that file together? Was it their whole job that
> week, or one task among many?"
This is a proxy for cost and for whether the pain is acute enough to have a
name attached to it.

**Q6 — What could not be proven?**
> "Was there anything in that file you couldn't actually prove — where you
> ended up asserting it rather than evidencing it?"
This is the sharpest question in the guide. Let the silence sit if it comes.
A confident, immediate "no, we could prove everything" from a firm that just
described a six-system, twelve-hour reconstruction is worth noting as
possible social-desirability answering — flag it, don't argue with it.

**Q7 — What did Internal Audit ask for?**
> "What did Internal Audit specifically ask to see? What did they push back
> on or reject?"

**Q8 — What did Compliance ask for?**
> "Separately from Audit — what did Compliance want, and was it the same
> thing or something different?"
The gap between Q7 and Q8's answers tells you whether Audit and Compliance
are one buyer or two — directly feeds `BUYER_MAP.md`.

**Q9 — What did the regulator ask for?**
> "Has a regulator — DFSA, FSRA, CBUAE, anyone — ever asked about this
> directly? What did they want, and how did you answer it?"
If the firm has never had a direct regulatory ask, do not treat that as a
weak answer — ask instead whether a *thematic review* or *industry-wide*
letter touched this area. Distinguish "never asked" from "never asked us
specifically yet."

**Q10 — How often does this happen?**
> "How many of these — AI-assisted decisions that could end up defended —
> does the firm make in a typical month?"
Get a number. This is the single most important number on the call — it is
the direct test of the frequency risk flagged in `beachhead_pressure_test.md`
(the ~208/month assumption in `docs/PRICING_MODEL.md` is untested). Push
past "it varies" the same way as Q4: "last month, specifically, roughly how
many?"

If the number sounds low, do not defend the wedge. Ask the follow-up
honestly: "if that's roughly twelve a month, is a spreadsheet actually
fine for you?" Let them answer. `marketing/LEAD_LIST.md:104–106` predicts
they may say yes — and concedes they may be right.

**Q10a — the named second shot (ask every call, not just when Q1 raised it)**
> "Separately — how many AML or STR dispositions does compliance handle in
> a typical month, and how does the evidence burden on those compare to what
> you just described?"
This is the AML/STR volume check `beachhead_pressure_test.md` requires on
every discovery call. Get a number for this too, even if Q1's example was
about suitability.

**Q11 — What happens if evidence is missing?**
> "What actually happens — to the decision, to the advisor, to the firm —
> if that evidence turns out to be missing or incomplete when it's asked
> for?"
This is your pain-acuteness question. Listen for consequence, not process:
a fine, a lost licence, a personally-liable signature, a client walking, a
regulator visit — versus "we'd probably just write it up after the fact."

**Q12 — Who owns this problem?**
> "Whose problem is this, really? If it got worse, whose job gets harder?"
Get a name and title if you can, not just a department. "Compliance" is not
an answer for `BUYER_MAP.md`; "Head of Compliance, reports to the CRO" is.

**Q13 — Which budget pays for it?**
> "If someone wanted to fix this properly, which budget would that come out
> of? Whose sign-off would it need?"
This is the single most decision-relevant question on the call — see
`SCORING_RUBRIC.md`'s weighting of budget owner. Get a name and title, not
a department, if the conversation allows it. If they cannot name a person,
write that down explicitly — "no named owner" is a finding, not a gap in
your notes.

---

## The last question — and only now, the product

Only after Q13, and only if the conversation has earned it:

> "I'll tell you what we're building, in one sentence, and I'd like your
> honest reaction: independently verifiable evidence that a defined
> governance check was applied to a specific AI-assisted decision — produced
> at the moment of the decision, not reconstructed afterward. Does that
> match a real gap in what you just described, or am I solving a problem you
> don't actually have?"

Notice what this sentence does not say. It does not say "compliant." It does
not say the product proves a control "operated" or that governance was
"effective." It says evidence that a check was applied to a decision. That
is the whole claim — do not embellish it live, even if the prospect offers
you a bigger one ("so this proves we're compliant?" — the correct answer is
"no — it proves the check happened on this specific decision. Whether that
satisfies your regulatory obligation is your call, not something I can tell
you.").

Then stop talking. Their reaction to this sentence — not their answer to a
hypothetical "would you buy it" — is the closest thing to a purchase signal
this call is allowed to produce.

---

## After the call

Score it immediately using `SCORING_RUBRIC.md` while the notes are fresh.
Do not batch scoring to the end of the week — memory of tone and hesitation
decays faster than the numbers do.
