# Pilot email — Head of Wealth

Cold outreach asking for fifteen minutes. Paste-ready.

## Where this fits

[`../LEAD_LIST.md` § 4](../LEAD_LIST.md) holds the canonical outreach script and,
more importantly, the reasoning behind every line of it — what was changed from
the first draft and why. **Read that section before you edit this one.** Several
phrasings below look like they could be tightened and cannot: they are narrow on
purpose, and the narrowness is what survives a compliance reader.

This file is the same email aimed specifically at a **Head of Wealth / Head of
Digital Wealth** — a P&L owner, not a risk officer. `LEAD_LIST.md § 3` describes
all three buyer roles; the CRO variant leads with defensibility, this one leads
with the advisor's time. Send one, not both, to the same firm.

## Before you send

- **The repository link resolves.** `github.com/prasantk8/memtara` returns 200
  and is public. It used to be written `memtara-zkp`, which never existed and
  404'd in every send — corrected across the repository on 18 Aug 2026. If you
  are copying this text from an older draft, check the link before you send: an
  email whose one verifiable link is broken fails at exactly the moment it was
  working.
- **`www.aihoots.com` returns 522.** Link the apex, `https://aihoots.com`, never
  `www.` — and fix [§ C](../../docs/INFRASTRUCTURE.md#section-c--wwwaihootscom-is-returning-522-fix-this-first),
  because some clients rewrite bare domains to `www.`.
- **Fill every `[BRACKET]`.** There are five.
- **Read [`marketing/README.md` § What not to do](../README.md#what-not-to-do).**
  Zero pilots, zero customers, no DFSA or CBUAE approval, no sandbox place, no
  SOC 2. None of that may be softened, including by omission.

---

## The email

> **Subject:** DFSA COB 3.4 suitability — provable in 40 seconds
>
> [FIRST NAME] —
>
> Your advisors assemble a suitability file after the recommendation. That
> ordering is the problem I've been working on: "reasonable basis" describes
> something that exists before the advice, not a folder produced after it.
>
> Memtara moves the check to the moment of recommendation. The client's own
> device proves — against the product terms your firm registered in advance —
> that income, liquid assets, risk tolerance and portfolio concentration each
> clear that instrument's thresholds. The device sends a proof and one bit:
> suitable, or not. **The bank never receives the four figures.**
>
> What your advisor gets is a sealed case file, issued at the point of advice,
> that a third party can re-verify years later from a published key.
>
> I'd rather you checked this than took my word for it. There's a public demo
> that runs end to end in about forty seconds on a laptop — one command, real
> proofs, ending in that case file. Link below.
>
> We are opening two pilot slots for Q4 2026 and have no pilots running today.
> A pilot is one instrument from your registry, its real terms, and synthetic
> clients — no client data crosses into it.
>
> Would fifteen minutes in the week of [DATE] be worth it? I'll show the demo
> and the four gaps we haven't closed.
>
> [YOUR NAME], founder, Memtara
> https://aihoots.com · [YOUR EMAIL]
> Unsubscribe: reply "no thanks" and I will not contact you again.
>
> *P.S. — for whoever you forward this to: it's open source. 87 Rust tests,
> 61 circuit tests, 196 Python tests, all running in CI. Baby Jubjub EdDSA,
> Poseidon commitments, Noir circuits, Barretenberg proving, an Ed25519
> attestation validated against a published JWKS. The suitability circuit's
> verification key is committed rather than generated at boot, so a proof issued
> today re-verifies without trusting our build.
> github.com/prasantk8/memtara*

---

## Why it is built this way

**The subject line keeps "COB 3.4".** A plainer "DFSA Suitability Proof in 40
Seconds" tests about the same on open rate and gives up the one thing that makes
this email different from every other RegTech cold email in the inbox: a correct
rule citation. COB 3.1 is *Application*; 3.4 is the suitability obligation. Be
ready to explain that the tokens in the repository emit `COB 3.1` for legacy
string-matching reasons — a compliance reader will find it, and having the answer
ready is worth more than the subject line ever was.

**The test counts are in the P.S., not the body.** "87/87 tests pass" means very
little to a Head of Wealth and a great deal to the architect they forward this
to. Putting it in the lead spends your best sentence on your second reader. The
P.S. is written to be forwarded intact, which is why it repeats the primitives
by name rather than saying "advanced cryptography".

**"The bank never receives the four figures" is the strongest claim you may
make, and it is narrower than "we don't expose client data."** Memtara does hold
personal data — a phone number, optionally an email, device names, session
records, a persistent user ID, and an encrypted vault blob it cannot decrypt.
The broad version will not survive a data-protection review; the narrow version
is specific enough to be tested, which is why it lands harder.

**Volunteering the zero pilots is the most on-brand line in the email.** The
alternative is a buyer asking "which bank" in the first five minutes and getting
a hedge — fatal for a product whose whole pitch is that its claims are checkable.
Full reasoning in [`LEAD_LIST.md` § 4](../LEAD_LIST.md).

**Offering the gaps in the meeting ask** ("the four gaps we haven't closed") does
more work than another benefit would. It is the sentence that makes a risk-minded
reader believe the rest, and it pre-empts the discovery that would otherwise
cost you the second meeting.

**Identity and a working opt-out are not optional.** See
[`LEAD_LIST.md` § 6](../LEAD_LIST.md) for the UAE compliance note. Honour the
opt-out on the first reply, without a "just checking" follow-up.

---

## Variants

**Subject-line alternates**, if the primary underperforms after ~30 sends —
change one variable at a time and log results in the tracking table:

- `Proving suitability without receiving the client's figures`
- `A suitability file that exists before the recommendation`
- `Two pilot slots, Q4 — DFSA COB 3.4 suitability`

**If they replied to a LinkedIn post**, do not send this. Send a four-line reply
that quotes what they said and asks for the fifteen minutes directly. A cold
template sent to a warm contact reads as automation and discards the warmth.
See [`LINKEDIN_POST.md` § After publishing](./LINKEDIN_POST.md#after-publishing).

**For a CRO or Head of Compliance**, swap the opening two paragraphs for the
defensibility framing in `LEAD_LIST.md § 3` and lead with re-verifiability rather
than advisor time. Keep the P.S. unchanged.

**Warm-intro request and LinkedIn connection note**: already written, in
[`LEAD_LIST.md` § 5](../LEAD_LIST.md). Do not rewrite them here.

---

## Follow-up

Two follow-ups, maximum, then stop. Each must carry information the previous
message did not — a "just bumping this" teaches the recipient that ignoring you
works.

| When | Carry this |
|---|---|
| +5 working days | One concrete artefact: the regulatory matrix, and the four gaps it names on page one. Two sentences, no re-pitch. |
| +12 working days | The close-out. "I'll stop here — if the timing changes, the repository is public and the demo runs without me." Then actually stop. |

Log every send, reply and non-reply in the tracking table in
[`LEAD_LIST.md` § 1](../LEAD_LIST.md). Objections that come back belong in
[`OBJECTION_HANDLER.md`](./OBJECTION_HANDLER.md) — and if one arrives that isn't
covered there, add it.
