# Outreach sequence — first touch to booked call

This is a research ask, not a sales sequence. `marketing/LEAD_LIST.md`'s
scripts sell a product; every message below asks for 25 minutes of the
recipient's expertise and explicitly promises not to pitch. That promise
must be kept on the call itself — see `INTERVIEW_GUIDE.md` rule 2. Breaking
it in the outreach undermines the interview before it starts.

Do not name the product, describe what we build, or use any capability
language in these messages — not "evidence infrastructure," not
"cryptographic," not "zero-knowledge," nothing. The one-line description of
what we're building belongs only at the end of the call itself, per
`INTERVIEW_GUIDE.md`. An outreach message that pitches gets a guarded,
sales-filtered reply instead of a real one, if it gets a reply at all.

Sourcing rule carried over from `marketing/LEAD_LIST.md`: do not paste a
name into any tracking sheet that you have not sourced yourself from a place
the person chose to publish it. See `TARGET_LIST_CRITERIA.md`.

---

## Variant A — opens on a real enforcement action (their risk, not our product)

Use when you have a specific, checkable enforcement action that is
plausibly relevant to the recipient's world. Two are strong fits for a
wealth-advisory compliance audience and are both sourced and verifiable
(see `incident_source.md`, itself flagged as a secondary source — re-check
the primary filing before you send if you have any doubt about a figure):

- **Delphia / Global Predictions (SEC, March 2024)** — two US investment
  advisers fined a combined $400,000 for describing AI capability in
  marketing and Form ADV filings that did not match what the systems
  actually did. Directly relevant to any firm running or piloting an
  advisory copilot: the exposure is not just "the model was wrong," it is
  "what we said about the model didn't match reality."
- **Air Canada (BC Civil Resolution Tribunal, 2024)** — a chatbot gave
  advice that contradicted the airline's own written policy. The airline's
  defence — that the chatbot was a separate, self-operating entity — was
  rejected outright. Directly relevant to "who is accountable when an
  AI-assisted output turns out to be wrong."

> **Subject:** A question about [Delphia / the Air Canada chatbot ruling] —
> not a pitch
>
> [Name] — I'm researching how firms with AI in the advisory workflow
> actually defend a decision after the fact, not whether they should use AI.
>
> The SEC fined two US advisers $400k in March 2024 for describing AI
> capability that didn't match what their systems actually did
> [Delphia / Global Predictions, cited]. I'd like to understand how a firm
> like yours would answer the equivalent question today — not hypothetically,
> but based on what actually happens when Audit or Compliance asks you to
> show your work on an AI-assisted decision.
>
> I'm not selling anything on this call. I'm a founder doing discovery
> before I build anything further, and 25 minutes of your actual experience
> is worth more to me than a demo would be to you. Would you have 25 minutes
> in the next two weeks?
>
> [Your name], founder
> [reply address] · reply "no thanks" and I won't follow up again

**Compliance note carried from `marketing/LEAD_LIST.md` §6**: this is
business-card-level contact information used for a purpose relevant to the
recipient's actual role — a compliance officer, asked about AI decision
defensibility, is squarely inside that purpose. The same identity and
opt-out requirements apply here as to any commercial outreach; do not treat
"it's just research" as an exemption.

---

## Variant B — opens on a peer question

Use when you do not have a clean enforcement-action hook, or when the
recipient's firm is small enough that a peer-comparison framing lands
better than a regulatory-action framing (see `BUYER_MAP.md`'s flat-firm
column — a principal at a boutique manager responds to "how are peers
handling this" more than to a headline about a bank).

> **Subject:** How is [firm type] actually handling this — 25 minutes?
>
> [Name] — I'm talking to compliance and risk leads at DIFC/ADGM wealth
> managers about one specific question: when an AI-assisted recommendation
> gets challenged — by Audit, by a client dispute, by a regulator — what does
> the firm actually have to show for it, and how long does it take to put
> together?
>
> I'm not selling anything on this call — I'm a founder doing discovery, and
> I'd rather have 25 minutes of your real experience than pitch you
> something you haven't asked for. If it's useful, I'll also tell you what
> I'm hearing from other firms doing the same thing, once we're a few calls
> in either direction.
>
> Would you have 25 minutes in the next two weeks?
>
> [Your name], founder
> [reply address] · reply "no thanks" and I won't follow up again

---

## LinkedIn connection note (under 300 characters, either variant)

> Researching how DIFC/ADGM wealth managers defend AI-assisted
> recommendations after the fact — not selling anything. Would value 25
> minutes of your actual experience, no pitch attached.

Count the characters before sending. No link in the note.

---

## Follow-up cadence

Same two-step structure as `marketing/LEAD_LIST.md` §5, same rule: every
follow-up adds new information, never "just bumping this."

**Day 4 — add specificity, not urgency.**

> Following up with something more specific rather than a reminder.
>
> I'm not asking in the abstract — I'd like to walk through one real example:
> the last time your firm had to defend, reconstruct, or justify an
> AI-assisted recommendation to anyone internal or external. Fifteen minutes
> would genuinely be enough if that's easier to find in your calendar than
> 25.
>
> Still not a sales call. If the answer is no, telling me is a real help.

**Day 11 — last one, and make the exit easy.**

> Last message from me on this.
>
> If AI isn't yet part of your actual advisory workflow in production, that
> itself is useful for me to know — it tells me the market is earlier than I
> think, and I'd rather hear that in one line from you than assume otherwise.
>
> If it is, and 25 minutes is workable, the offer stands. If not, no further
> follow-up — good luck with the rest of the year.

Stop after day 11, same rule as `marketing/LEAD_LIST.md`: a third message
means the honest read is a no.

---

## The "we handle twelve a month, a spreadsheet is fine" answer

`marketing/LEAD_LIST.md:104-106` predicts this answer from independent
wealth managers and concedes outright: *"If the volume is genuinely that
low, they are right and you should move on."* This will happen. Plan for it
now, not in the moment.

**If it comes in outreach, before a call is booked:**
Do not argue with it by email. Reply once:

> That's a completely fair answer, and it may well be the right one for a
> firm your size. Two quick things, if you're open to it: would you still be
> willing to give me 10 minutes just to confirm the shape of that — roughly
> how the twelve get handled today, and whether AML or STR volume looks
> similar or different? That comparison is genuinely useful to me even when
> the answer is "we're fine."

This is not a disguised pitch — it is the Q10a comparison from
`INTERVIEW_GUIDE.md`, asked in miniature. If they decline even the 10
minutes, log the reason and stop. Do not send a third message trying to
recover a clean, well-reasoned no.

**If it comes on the call itself (Q10):**
Follow `INTERVIEW_GUIDE.md`'s instruction directly: do not defend the
wedge. Ask the honest follow-up ("if that's roughly twelve a month, is a
spreadsheet actually fine for you?"), let them answer, and move to Q10a to
check whether AML/STR volume tells a different story at the same firm. Log
the call as low-frequency in `SCORING_RUBRIC.md` regardless of how the rest
of the conversation goes — a firm's warmth toward you is not evidence of
volume.

**What this answer is not:** a reason to narrow the target list further
toward larger institutions without also checking `BUYER_MAP.md`'s sequence
and cycle-length tradeoffs. A "twelve a month" independent manager is a fast
no; a large private bank is a slow maybe. Both are useful data — record
both, and do not let one bad-fit call at a small firm push all future
sourcing toward slower, harder-to-close large institutions without a
deliberate decision to do so.
