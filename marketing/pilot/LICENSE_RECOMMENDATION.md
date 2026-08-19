# Licence recommendation — for the founder to decide, not for this document to decide

This document does not create a `LICENSE` file. That choice has real,
hard-to-reverse consequences for the business and belongs to the founder.
What follows lays out the realistic options, what each means for a bank's
procurement and for the "verify it yourself" claim the whole product rests
on, and closes with a recommendation and the exact next action.

**Why this can't wait.** **No `LICENSE` file exists in this repository.**
Absent one, the default is exclusive copyright: a bank's counsel reading
the repository has no grant to rely on, and the "clone it and check for
yourself" invitation on the public site has nothing behind it.
`docs/PRICING_MODEL.md` already names this as a week-one procurement
blocker — counsel checks it early, and an absent licence converts a
technical review into a legal one.

*Correction to an earlier draft of this section, checked against the tree
on 19 Aug 2026:* `README.md` does **not** state "MIT License – See LICENSE
file for details". That claim was removed at some point, which is the
right outcome — an MIT reference pointing at a file that does not exist
would have been worse than silence. But three documents still assert that
the README says it: `docs/PRICING_MODEL.md:189`,
`docs/SALES_OBJECTION_HANDLER.md:440` and
`docs/PILOT_AGREEMENT_TEMPLATE.md:242`. Those three lines are now
themselves stale and should be corrected in the same pass that adds the
licence, so nobody re-derives a problem that has already been half-fixed.

---

## What "verify it yourself" actually requires — and what it doesn't

Get this distinction right first, because it changes which parts of the
repository need to be permissively licensed at all.

The claim the product is built on is: an examiner, holding an exported case
file, can independently verify a proof without trusting Memtara's build
pipeline. That claim rests on exactly three things being freely usable:

1. **`bb`** — the Barretenberg verifier. Already open source, already not
   ours to license. Nothing to decide here.
2. **The Noir circuit source** (`circuits/wealth_suitability/`) and its
   **committed verification key** — so an examiner (or their own counsel's
   technical expert) can recompile the circuit and confirm the committed
   vkey matches, rather than trusting Memtara's word that it does.
3. **The verification instructions and schema** — plain documentation, not
   commercially sensitive.

It does **not** require the rest of the platform — the backend
(`backend/api/`), the auth/session orchestration, the product-registry
governance logic, the export/sealing tooling's internals, the prover SDK's
production hardening — to be open at all. Those are the commercial product.
Conflating "verify it yourself" with "the whole codebase must be MIT" gives
away the business for a promise that only needs a narrow slice of it.

---

## The options

### Apache-2.0 (whole repository)

**What it means for a bank.** Maximally permissive, and carries an express
**patent grant with a litigation-termination clause** (§3): every
contributor grants a royalty-free patent licence covering their
contributions, and that licence terminates automatically for anyone who
initiates patent litigation against Apache-2.0-licensed work. For a bank's
patent counsel evaluating a small, unproven vendor's cryptographic claims,
this is a genuinely reassuring, standard, well-understood term — it removes
the "does using this expose us to a later patent claim from the vendor
itself" worry cleanly.

**What it means for us.** Gives away the entire commercial product,
including the backend, the export tooling, and every piece of engineering
this company is trying to sell at $5,000–$50,000+/month. A well-resourced
competitor, or a customer's own engineering team, can fork the whole thing
and stop paying. At this price point and this stage, this is not a
defensible default for the *whole* repository — see the split
recommendation below for where Apache-2.0 is actually the right choice.

### MIT (whole repository)

**What it means for a bank.** Simple, extremely well understood, and what
`README.md` currently (falsely) claims. **Says nothing about patents at
all.** MIT relies on an implied-licence theory for patent coverage that is
considerably weaker and less litigated than Apache-2.0's explicit grant —
a real gap for exactly the buyer this product targets, a regulated
institution whose counsel will ask the patent question directly.

**What it means for us.** Same commercial exposure as Apache-2.0, without
even the reassurance value the patent grant provides. There is no scenario
where MIT beats Apache-2.0 for this business, for either audience. If any
part of the repository is going fully permissive, it should be Apache-2.0,
not MIT — the current README claim is the weaker of the two options
available and should not be the one left standing by default.

### BSL / source-available (whole repository, or the commercial layer)

**What it means for a bank.** Source is visible and auditable — a bank's
security and technical reviewers can read every line, which serves the
diligence process — but the licence restricts production/competitive use
until a stated conversion date (typically converting to an open licence,
often Apache-2.0, some years out). This is a real, common pattern for
infrastructure companies at exactly this stage (CockroachDB, Sentry,
HashiCorp pre-license-change, and others used variants of this). A bank's
procurement team can generally work with this — it is not open source in
the OSI sense, but "we can read and audit it, and can't resell it as a
competing product" is a distinction most bank counsel have seen before and
know how to evaluate.

**What it means for us.** Preserves the commercial moat while still
supporting the audit/diligence half of the "verify it yourself" pitch — a
bank's technical reviewer can confirm the circuit does what is claimed
without needing unrestricted rights to redeploy it commercially. The
patent question is murkier than Apache-2.0's explicit grant (most BSL
variants don't include one), which matters for the circuits specifically
(see the split recommendation) but matters less for the backend and
tooling, where a bank isn't relying on a patent grant to trust the crypto —
they're relying on it to avoid infringement risk from running vendor code,
which a standard contractual IP warranty (already drafted in
`docs/PILOT_AGREEMENT_TEMPLATE.md` §7.1) covers regardless of the OSS
licence chosen.

### Proprietary, source-visible-for-diligence-only

**What it means for a bank.** They can read the code under an NDA or a
restricted-viewing licence for audit purposes, but have no rights to run,
modify, or redeploy it outside the commercial agreement. This satisfies
"we let you look" without satisfying "we let you independently verify
without a relationship with us," which is a meaningfully weaker version of
the verify-it-yourself pitch than what this company has been building
toward and marketing.

**What it means for us.** Maximum commercial protection, minimum support
for the core sales argument. Not recommended as the primary structure for
the parts of the repository the verification claim depends on — it
undercuts the company's own strongest differentiator.

---

## What a patent grant does and does not do — said plainly, because this gets confused

**What it does.** Removes the specific fear that the party granting the
licence (us, or any future contributor) will later sue a user of the
licensed code for patent infringement over that same code. Apache-2.0's
mutual termination-on-litigation clause additionally discourages a licensee
from suing *us* over the licensed work, since doing so forfeits their own
licence. For a bank relying on cryptographic infrastructure from an early,
unproven vendor, this closes a real, specific, and reasonable diligence
question: "if we build on this and it turns out to read on someone's
patent, are we more exposed than if the code were proprietary?" — no, not
because of anything the vendor promises, but because of what the licence
itself grants.

**What it does not do.**

- It does not grant any right in **third-party** patents — Barretenberg,
  the broader Noir/Aztec toolchain, or anything else this company doesn't
  own. Those parties' own licences govern their own IP, unaffected by what
  Memtara licenses.
- It does not **indemnify** the bank against a third-party patent claim.
  Indemnification is a contractual promise (see
  `docs/PILOT_AGREEMENT_TEMPLATE.md` §7.1) backed by a company's ability to
  pay, not a property of the open-source licence. A patent grant and an
  indemnity answer different questions and a bank's counsel will ask for
  both.
- It does not cover code that isn't licensed under it. If the backend
  stays proprietary while the circuits go Apache-2.0, the patent grant
  applies only to the circuits — say this explicitly rather than letting a
  bank assume the whole platform is covered.
- It does not substitute for a non-infringement warranty in the commercial
  contract, and it does not reduce this company's own exposure if it
  turns out to be infringing someone else's patent — a patent grant
  protects licensees from the licensor, not the licensor from the world.

---

## Recommendation

**Split the licence.**

1. **`circuits/` (the Noir source), the committed verification keys, and
   the verification instructions/schema: Apache-2.0.** This is exactly the
   slice the "verify it yourself" claim depends on, it's the slice where a
   bank's patent counsel will actually ask the question, and Apache-2.0's
   patent grant is the direct, standard answer to that question. Giving
   this slice away costs the business little — the circuits are not what
   customers are paying $5,000–$50,000+/month for; the platform,
   integration, evidence pipeline, and support are.
2. **Everything else — `backend/`, `clients/prover/`'s production
   hardening, the export/sealing tooling, `vault/` — proprietary,
   source-visible-for-diligence-under-agreement, with no LICENSE-file grant
   of MIT or Apache rights.** State this explicitly in the pilot/production
   agreement's IP clause (`docs/PILOT_AGREEMENT_TEMPLATE.md` §5 already has
   the placeholder; it needs the actual decision filled in, not a default).

This keeps the marketing claim honest — a bank genuinely can audit and
independently rebuild the cryptographic verification path without our
cooperation — without giving away the commercial product the pricing model
depends on. It also directly fixes the specific gap `docs/PRICING_MODEL.md`
and `docs/SALES_OBJECTION_HANDLER.md` both flag: replace the false MIT
claim with something true, deliberately chosen, and defensible under
questioning, rather than leaving the current unfulfilled reference in
place a day longer than necessary.

**Do not choose plain MIT for anything.** If the founder prefers
simplicity over the split, Apache-2.0 for the whole repository is the
better single-licence fallback — never MIT, given the patent-grant gap and
that MIT offers no advantage over Apache-2.0 for either audience.

---

## Exact next action

1. Founder confirms, in writing, one of: (a) the split above, (b)
   Apache-2.0 for everything, or (c) proprietary/source-available for
   everything, keeping the current audit-only posture and accepting the
   weaker verify-it-yourself claim that implies.
2. Whichever is chosen, the actual `LICENSE` file(s) get added — this is a
   ten-minute task once the decision is made, not an engineering project —
   and `README.md`'s current MIT claim gets corrected to match, along with
   `docs/PILOT_AGREEMENT_TEMPLATE.md` §5.6's placeholder.
3. If (a) or (c): one short conversation with counsel to confirm the
   proprietary-licence text protects against the specific risk of a
   pilot bank's engineers redistributing what they were given diligence
   access to.

That is the whole decision. It does not require new code, new pricing, or
a new pilot term — it requires one sentence from the founder.
