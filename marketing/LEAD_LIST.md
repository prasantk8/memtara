# Outreach playbook

This file contains **no real individuals**. It is a template you fill in
yourself, plus the segmentation, the buyer roles and the scripts.

Two rules that hold for everything below:

1. Do not paste a name into this file that you have not sourced yourself from a
   place the person chose to publish it — their own LinkedIn profile, a firm's
   own leadership page, a conference programme, a regulator's public register.
2. Every claim in every message must be checkable in the repository. If you
   cannot point at the file, delete the sentence.

---

## 1. Tracking table

Copy this into a spreadsheet if you prefer; keep the columns identical either
way so the notes stay comparable.

| Institution | Segment | Target role | Name (fill in) | Source | First touch date | Status | Next action | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| *EXAMPLE — not a real firm* `[Bank A — DIFC private bank]` | DIFC private bank | Chief Risk Officer | `[FILL IN]` | `[FILL IN — e.g. firm leadership page, retrieved DD/MM]` | `[DD/MM/YYYY]` | Sent, no reply | Day-4 follow-up with the case-file link | Structured notes on the shelf; likely already has a suitability remediation programme |
| *EXAMPLE — not a real firm* `[Wealth Manager B — ADGM, independent]` | Independent wealth manager | Head of Digital Wealth | `[FILL IN]` | `[FILL IN]` | `[DD/MM/YYYY]` | Replied, call booked | Send the 15-minute agenda 24h before | Asked who else is running it — answer is nobody, say so first, before they ask twice |
|  |  |  |  |  |  |  |  |  |
|  |  |  |  |  |  |  |  |  |
|  |  |  |  |  |  |  |  |  |
|  |  |  |  |  |  |  |  |  |
|  |  |  |  |  |  |  |  |  |
|  |  |  |  |  |  |  |  |  |
|  |  |  |  |  |  |  |  |  |
|  |  |  |  |  |  |  |  |  |

**Status values to use, so the pipeline means something:** `Not contacted` →
`Sent` → `Opened / viewed profile` → `Replied` → `Call booked` → `Call held` →
`Pilot discussion` → `No — reason recorded` → `Dormant`.

Record the reason on every `No`. With a list this small, the pattern in the
refusals is more valuable than the pipeline.

---

## 2. Segmentation — UAE institution types

Target the type first, then find the person. Roughly in order of fit.

### DIFC private banks and wealth managers

**Fit:** highest. DFSA-regulated, Conduct of Business applies, structured
products are actively distributed, and suitability under COB 3.4 is a live
supervisory topic. The evidence problem this solves is one they already know
they have.

**Buying trigger:** a suitability finding in an internal audit or a DFSA
thematic review; onboarding a new structured-product shelf; a complaint or
dispute where the file had to be reconstructed; an AI advisor-copilot pilot
that legal has stalled over auditability.

**Why they say no:** procurement will ask for SOC 2, a penetration test report
and references. We have none of the three, and no container image. Expect the
technical buyer to be interested and the vendor-risk process to be the blocker.

### ADGM private banks and wealth managers

**Fit:** high, with a caveat. FSRA rather than DFSA, so the rulebook citation
changes and our matrix is written against CBUAE guidance plus a DFSA COB
appendix. The mechanism transfers cleanly; the paperwork mapping does not, and
you should say so rather than let them discover it.

**Buying trigger:** the same as DIFC, plus ADGM's comparatively active posture
on digital assets and technology adoption making an internal champion easier to
find.

**Why they say no:** "your regulatory mapping is not against our rulebook." A
fair objection. Do not bluff it — offer to do the FSRA mapping as pilot scope.

### Local retail banks with private-banking arms

**Fit:** medium. The private-banking arm has the right problem; the
institution's procurement, security review and vendor-onboarding cycle is
measured in quarters, and a founder-led company with zero customers will
struggle to clear it.

**Buying trigger:** a CBUAE-driven AI governance programme, where our mapping
against the CBUAE Guidance Note on the responsible adoption of AI and ML is
directly useful; or a group-level mandate to reduce client data held in
systems.

**Why they say no:** vendor-risk thresholds and the "who else uses it" question
with more force than anywhere else. Realistically these are relationship-led
and slow. Worth two or three approaches, not twenty.

### Independent wealth managers

**Fit:** medium-high, and the best odds of an actual pilot. Small enough that
one person can decide, regulated enough to care, and without the vendor-risk
machinery that will stop the big names.

**Buying trigger:** they are being asked by a distributor or a custodian to
evidence suitability more rigorously than their current process supports; or
they are already using an LLM in the advisory workflow and have no audit story
for it.

**Why they say no:** budget, and a fair "we handle twelve of these a month, a
spreadsheet is fine". If the volume is genuinely that low, they are right and
you should move on.

### Family offices

**Fit:** low to medium, and different in kind. A single-family office often has
no external suitability obligation at all — the client and the firm are the same
economic party. A multi-family office does have one, and is closer to the
independent wealth manager profile.

**Buying trigger:** governance rather than regulation. A principal who wants
provable process around what the office recommends, or a next-generation
transition where "show me what was checked" becomes a live question.

**Why they say no:** no regulatory forcing function, so it competes with every
other discretionary spend. Qualify hard on single vs multi-family before
investing time.

### Regulator-adjacent programmes

These are public programmes and may be named as programmes. We have **not**
applied to either, we hold no place in either, and nothing in our material may
suggest otherwise.

**DFSA Innovation Testing Licence (ITL).** A restricted licence for testing an
innovative product within the DIFC under supervision.

**ADGM RegLab.** The FSRA's equivalent regulatory sandbox.

**Fit:** these are not customers. They matter for two reasons: participation
would be a credibility asset we currently lack, and firms already inside them
are unusually willing to take a call from an unproven vendor.

**Buying trigger:** not applicable — the relevant action is a future application
on our side, or an introduction to a cohort firm.

**Why it might not work:** both programmes are aimed at firms carrying out
regulated activity. Memtara is infrastructure sold to regulated firms, not a
regulated activity in itself, so the natural route is *with* a licensed partner
rather than alone. Check the current eligibility criteria before spending time
on an application, and never describe an intention to apply as a status.

---

## 3. The three buyer roles

You are usually selling to all three, in this order, and the message has to
change for each.

### Chief Risk Officer / Head of Compliance — evidence and defensibility

Cares about what the file looks like two years from now when someone disputes
the recommendation. Wants to know: who can re-verify this, with what key, and
what happens if we no longer exist. Will test you by asking what the system
*cannot* do.

**Lead with:** evidence produced at the moment of advice rather than
reconstructed; a decline carries the same signed, chained evidence as an
approval, because a firm that can only evidence approvals fails the rule it is
claiming to satisfy; re-verification from a published key.

**Do not:** claim admissibility, claim regulatory endorsement, or gloss the four
gaps named on page one of the regulatory matrix. Volunteer them.

### Head of Digital Wealth — advisor productivity and time-to-recommendation

Cares about whether the advisor's day gets faster or slower, and about whether
their AI copilot project can now pass legal. Suitability evidence is a cost
centre to them, not a product.

**Lead with:** the forty-second end-to-end run; the fact that the verified claim
is injected before the model replies, so the copilot stops being a compliance
argument; no document collection from the client for the four assessed figures.

**Do not:** open with cryptography. They will forward it to the person who
cares, but only if the first two lines were about the workflow.

### CTO / Head of Architecture — integration cost and who holds the keys

Cares about what runs where, what the failure modes are, and who is on the hook
when it breaks. Will read the OpenAPI spec before they reply to you.

**Lead with:** 28 documented paths in `docs/openapi.yaml`; AIHOOTS validates
the attestation locally against a published JWKS with no synchronous call back;
`/health` compares the running verification key against the one committed to the
repo and returns 503 on divergence; the server generates verification keys at
boot and refuses to start rather than coming up as a verifier that cannot
verify; every table scoped by `org_id`, with a test that fails if one tenant can
see another's registry.

**Do not:** hide that there is no container image yet, that org self-registration
is currently unauthenticated, or that rate limiting is per process and therefore
not a security boundary. They will find all three, and finding them unprompted
is what ends the conversation.

---

## 4. The outreach script

### As provided

> **Subject:** DFSA COB 3.4 Suitability—Provable in 40 seconds.
>
> We've built a cryptographic engine that proves suitability for structured
> products without exposing client data. It attaches the proof to your AI's
> recommendation audit trail. We have a pilot running for Q4 2026. If you're
> the Head of Digital Wealth or CRO, I'd love a 15-minute demo.

### Corrected version — use this one

> **Subject:** DFSA COB 3.4 suitability — provable in 40 seconds
>
> We've built a cryptographic engine that proves suitability for structured
> products without the bank ever receiving the client's income, liquid assets,
> risk tolerance or holdings. It attaches the proof to your AI's recommendation
> audit trail.
>
> We are opening two pilot slots for Q4 2026 and have no pilots running today.
>
> If you're the Head of Digital Wealth or CRO, I'd like 15 minutes to show you
> the demo — one command, about forty seconds, ending in a sealed case file you
> can re-verify yourself.
>
> [Your name], founder, Memtara
> [repository link] · [your email] · unsubscribe: reply "no thanks" and I will
> not contact you again

### What changed, and why it matters

**"We have a pilot running for Q4 2026" → "We are opening two pilot slots for
Q4 2026 and have no pilots running today."** This is the change that matters.
There are zero pilots. The first thing a serious buyer asks after a sentence
like the original is "which bank" — and the answer is either a name you cannot
give, a hedge, or a retraction. Any of the three, in the first five minutes,
tells a risk officer that your claims need verifying before they can be used.
That is a fatal impression for a product whose entire pitch is that everything
it says is checkable. Volunteering the zero is not a weakness here; it is the
single most on-brand thing in the email, and it makes every other claim in it
more credible rather than less.

**"without exposing client data" → "without the bank ever receiving the
client's income, liquid assets, risk tolerance or holdings."** The original is
broader than what is true and will not survive a data-protection review.
Memtara does hold personal data: a phone number, optionally an email, device
names, session records, a persistent user ID, and an encrypted vault blob it
cannot decrypt. What it never receives is the four financial figures. The
narrower claim is both accurate and stronger, because it is specific enough to
be tested.

**Subject line kept, with the em dash normalised.** "DFSA COB 3.4" is the
correct citation — COB 3.1 is "Application", and the tokens in the repo emit
`COB 3.1` for legacy string-matching reasons that you should be ready to
explain if a compliance reader spots it. Be ready to say what the forty seconds
refers to: the full demo run on a developer laptop, not a production SLA.

**Identity and opt-out added.** See the compliance note in section 6.

---

## 5. Variants

### LinkedIn connection note (under 300 characters)

> I've built a suitability engine for structured products — the client's device
> proves income, assets, risk tolerance and concentration against your
> registered terms, and the bank never receives the figures. Runs end to end in
> about 40 seconds. Would value 15 minutes of your read on it.

Count it before sending; LinkedIn silently truncates. Do not attach a link in
the note itself — it lowers acceptance rates and the profile carries it anyway.

### Warm-intro request — send to the mutual contact, not the target

> [Name] — a favour, and an easy no.
>
> I've built Memtara: structured-product suitability proved on the client's own
> device, so the bank gets signed, re-verifiable evidence and never receives the
> income or asset figures. It's real — there's a public demo that runs in about
> forty seconds and produces a sealed case file. There are no pilots yet; I'm
> looking for the first two.
>
> You know [target's role] at [firm]. If you think it's worth their fifteen
> minutes, would you forward the paragraph above? If you don't, tell me and I'll
> drop it — I'd rather have your honest read than the introduction.
>
> Happy to send anything you'd want to look at first.

The forwardable paragraph is deliberately self-contained so your contact does
not have to write anything. Giving them an explicit exit is what makes the ask
cheap.

### Two-step follow-up

Each follow-up must carry information the previous message did not. A message
whose content is "just bumping this" teaches the recipient that ignoring you
works.

**Day 4 — add the artefact.**

> Following up with the thing rather than a reminder.
>
> This is what the demo produces: a case file of about 51 KB with a detached
> SHA-256 seal. The verifier exits 0 on the genuine file and 1 on a copy with a
> single byte flipped. It is not a PAdES signature and no PDF reader will show a
> green tick — the authenticity claim is a JWT you can check against our
> published JWKS.
>
> [link to the repo, or the case file itself]
>
> Still a 15-minute ask. If the answer is no, saying so is a real help.

**Day 11 — add the limits.**

> Last one from me.
>
> Since the pitch is that everything we say is checkable, here is the part most
> vendors leave out. Rate limiting is per process, so two replicas permit twice
> the limit — it bounds cost, it is not a security boundary. A proof token is
> not revocable inside its 300-second life. We do not measure disparate impact,
> which is a separate obligation under the CBUAE guidance. There is no container
> image yet. And there are still zero pilots.
>
> If none of that is disqualifying, the offer stands: 15 minutes.
>
> If it is, that is genuinely useful for me to know, and I'll close the file.

Stop after day 11. If a third message is tempting, the honest read is that this
prospect is a no and the list is too short.

---

## 6. Compliance note on outreach

**This is practical guidance, not legal advice.** Get a UAE-qualified adviser to
review your process before you run it at any volume.

**The frameworks that apply.** Onshore UAE has a federal personal data
protection law; the DIFC and ADGM each have their own data protection regimes,
both closer in shape to GDPR. Business contact details are personal data under
all of them. There is also a separate onshore regime around unsolicited
electronic marketing that you should be aware of before doing anything at scale
or by SMS.

**The normal basis for what you are doing.** Business-card-level contact
information — name, job title, employer, work email, work phone — processed for
a genuine business-to-business purpose that is relevant to the recipient's
actual professional role is the ordinary basis for B2B outreach, generally
resting on a legitimate-interests style analysis. The words doing the work are
*business-card-level* and *relevant to their role*. Emailing a Head of Digital
Wealth about a suitability product is within it. Emailing the same person about
something unrelated to their job is not.

**Every message needs two things.** A real identity — your actual name, the
company name, and a real reply address that a human answers — and a genuine way
to opt out. A single line ("reply 'no thanks' and I will not contact you
again") is sufficient, provided you honour it immediately and permanently.
Record every opt-out in the tracking table and never re-approach through
another channel.

**What is not worth the risk.** Scraped personal email addresses. Personal
mobile numbers. Bought lists, enriched lists, and anything from a vendor who
will not tell you the source of each record. Guessing address formats to reach
someone who has not published one. All of it raises your legal exposure, all of
it lowers your reply rate, and for a founder pitching provable integrity to
compliance officers, being caught doing any of it is unrecoverable in a market
this small.

**Sourcing hygiene.** Fill in the `Source` column for every row, with where you
got the name and the date you got it. If you cannot write a source, do not
write the name. Delete a record on request, and delete records you never
contacted rather than keeping them indefinitely.
