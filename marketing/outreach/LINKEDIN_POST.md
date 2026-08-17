# LinkedIn — the launch sequence

Five posts, in publishing order, covering: **we launched → the CRO demo → the
architecture → the open-source ethos → the call to action.**

## Read this before you schedule anything

**Three of these five are already written.** A full five-post series exists at
[`../LINKEDIN_SERIES.md`](../LINKEDIN_SERIES.md) with copy, hooks, hashtags,
graphic specs and two Mermaid diagrams. Posts 3, 4 and 5 of that series *are*
the launch, demo and call-to-action posts asked for here.

So this file does not re-type them. Two versions of the same post in two files
is how a post gets published from the stale copy. Instead: the three existing
posts are referenced by their hook and publish date, and the **two genuinely
missing ones — Architecture and Open Source — are drafted in full below.**

Conventions are inherited from the series and are not optional: hook in the
first two lines and nothing above them, 150–250 words, no engagement bait, no
exclamation marks, at most one emoji (none of these use one). Read the
["What not to do"](../README.md#what-not-to-do) section of
[`marketing/README.md`](../README.md) before you edit a word of this. Zero
pilots, zero customers, no regulatory approval — and no phrasing that implies
otherwise, including by omission.

## Blocker — do not publish until this is fixed

Every repository link below now points at `github.com/prasantk8/memtara`, which
returns **200** and is public. These links previously read `memtara-zkp`, a name
that has never existed; they were corrected across the repository on
18 Aug 2026. The **live** landing pages still serve whatever was last deployed,
so `wrangler pages deploy` has to run before any of this is published — see
[`docs/INFRASTRUCTURE.md` § D](../../docs/INFRASTRUCTURE.md#section-d--every-read-the-code-button-on-the-live-site-is-a-404).

`www.aihoots.com` is also returning **522** right now, and browsers autocomplete
`www.`. Fix [§ C](../../docs/INFRASTRUCTURE.md#section-c--wwwaihootscom-is-returning-522-fix-this-first)
too. A launch post whose links are dead is worse than no launch post: the
audience for this campaign checks, which is the entire premise of the campaign.

---

## The sequence

| # | Post | Where the copy lives | Publish |
|---|---|---|---|
| 1 | **We launched** — introducing Memtara and AIHOOTS | [`LINKEDIN_SERIES.md` § Post 3](../LINKEDIN_SERIES.md) | Wed 26 Aug 2026 |
| 2 | **The CRO demo** — forty seconds to a cryptographic case file | [`LINKEDIN_SERIES.md` § Post 4](../LINKEDIN_SERIES.md) | Tue 1 Sep 2026 |
| 3 | **The architecture** — ZK proof meets SHA-256 chain | **Below** | Thu 3 Sep 2026 |
| 4 | **The open-source ethos** | **Below** | Tue 8 Sep 2026 |
| 5 | **The call to action** — two pilot banks | [`LINKEDIN_SERIES.md` § Post 5](../LINKEDIN_SERIES.md) | Thu 10 Sep 2026 |

The series file dates posts 3–5 as 26 Aug / 1 Sep / 3 Sep. Inserting two posts
pushes the call to action to 10 Sep; the dates above are the merged schedule.
Keep the roughly-two-day gaps and the ordering. The two new posts sit
deliberately *between* the demo and the ask: someone who watched the demo and
then read how it works is the person worth asking.

Posts 1 and 2 of the existing series — the mis-selling problem, and why AI
hallucinations break suitability — are the problem-framing posts that should run
*before* this sequence, on 18 and 20 Aug. They are not part of the launch
sequence but they are what makes it land.

---

## Post 3 — The architecture: a ZK proof and a hash chain, and the one value that joins them

**Publish:** Thursday 3 September 2026

**Hook (first two lines):**
> Two different cryptographic systems, doing two different jobs.
> One 32-byte value is the only thing connecting them, and that is the design.

**Copy:**

Two different cryptographic systems, doing two different jobs.

One 32-byte value is the only thing connecting them, and that is the design.

A zero-knowledge proof answers one question: did this client clear the
thresholds this product requires. The client's device runs it. Baby Jubjub EdDSA
signatures over their attributes, Poseidon hashes and Merkle commitments,
circuits in Noir, proving with Barretenberg. Income, liquid assets, risk
tolerance and concentration go in. One bit comes out.

A hash chain answers a different question: what did this system do, in what
order, and has anyone edited the record since. AIHOOTS keeps that one —
SHA-256, append-only, each entry committing to the last.

Neither substitutes for the other. A proof with no log tells you a check passed
but not when, or against which version of the product's terms. A log with no
proof tells you a check was recorded, which is what a spreadsheet also tells you.

The join key is the proof hash. It appears in Memtara's attestation and in
AIHOOTS's chain entry. Given one, you can find the other, and neither system had
to call the other synchronously to make that true — the attestation is an Ed25519
JWT validated locally against a key published at /.well-known/jwks.json.

Which means a regulator can re-verify a decision years later without asking us
for anything.

**Hashtags:** #ZeroKnowledgeProofs #Cryptography #RegTech #AuditTrail #Noir

**Graphic:** Diagram 1 from
[`LINKEDIN_SERIES.md` § Graphics](../LINKEDIN_SERIES.md) if it is not already
spent on Post 1 — otherwise a two-box drawing, *proof* on the left and *chain*
on the right, with a single labelled arrow `proof_hash` between them and nothing
else on the canvas. The emptiness is the point.

**What a good response looks like:** An argument about whether the chain should
be anchored somewhere external. That is a real limitation, it is a fair
challenge, and the honest answer — it is not anchored to a public ledger today —
is a better reply than a deflection. Someone asking why not a JWT for the
disclosure itself is also self-identifying as worth a call.

**Do not say:** "immutable". The chain is tamper-*evident*: it detects edits, it
does not prevent them. Anyone who has implemented one will notice the difference
and stop reading.

---

## Post 4 — The open-source ethos

**Publish:** Tuesday 8 September 2026

**Hook (first two lines):**
> We are asking banks to trust a cryptographic claim from a company with no customers.
> The only honest way to do that is to publish the thing and let them check it.

**Copy:**

We are asking banks to trust a cryptographic claim from a company with no
customers.

The only honest way to do that is to publish the thing and let them check it.

So the repository is public. Not a marketing repo with a README and a demo
video — the circuits, the verifier, the backend, the test suite, and the
regulatory mapping.

Three things in it are worth your architect's time specifically.

The regulatory matrix maps every clause of the CBUAE Guidance Note on AI and ML
to what the system actually does, and names four genuine gaps on its first page.
We put them on the first page because a risk officer who finds a gap themselves
stops believing everything else.

The end-to-end suitability test is the one place where no part of the
cryptography is stood in for. Real Baby Jubjub signatures, real Poseidon
commitments, real proving, real verification. It runs in CI on every commit.

And the verification key for the suitability circuit is committed, not generated
at boot, so a proof issued today can be re-verified by someone who does not
trust our build pipeline.

Current state, precisely: 87 Rust tests, 61 circuit tests, 196 Python tests. No
SOC 2. No penetration test. No container image. Zero pilots.

Read it before you talk to us. That ordering is the point.

github.com/prasantk8/memtara

**Hashtags:** #OpenSource #RegTech #ZeroKnowledgeProofs #Compliance #UAE

**Graphic:** A screenshot of the first page of `docs/REGULATORY_MATRIX.md`, with
the four named gaps visible. Nothing sells "we are not hiding anything" like
showing the part that is unflattering. Do not annotate or highlight it — a clean
screenshot reads as a document, a marked-up one reads as an advert.

**What a good response looks like:** A GitHub star from someone with a bank in
their headline, or an issue filed. Treat an issue as the strongest possible
signal and reply the same day, in the repository rather than in DMs, because the
reply is then also evidence for the next reader.

**Before publishing:** confirm the link resolves. See the blocker at the top of
this file — it does not, today.

---

## After publishing

Log every reply in the tracking table in
[`../LEAD_LIST.md` § 1](../LEAD_LIST.md), not in your inbox. A named engagement
on the architecture or open-source post is a warmer lead than a cold email will
ever produce, and the next step for one is
[`PILOT_EMAIL.md`](./PILOT_EMAIL.md) — sent as a follow-up that references what
they actually said, not as the cold template.
