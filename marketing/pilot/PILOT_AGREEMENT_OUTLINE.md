# Pilot Agreement — heads of terms

**This is not a contract, is not legal advice, and creates no binding
obligation on either party.** It is a structured outline of the terms a
lawyer should turn into a drafted agreement. A fuller clause-by-clause
drafting aid already exists at `docs/PILOT_AGREEMENT_TEMPLATE.md` — use this
document to check nothing has been forgotten before that draft goes to
counsel, not as a substitute for it.

Every technical fact below is traceable to a file in this repository and
should be verified before it is relied on in a drafted clause. Every
commercial position is a starting point, not a demand — see "negotiable"
markers.

---

## 1. Parties and structure

- Memtara entity (name, jurisdiction, registration) and the Bank (legal name,
  regulator, licence number).
- Pilot Agreement only. Not a production agreement, not a reseller
  agreement, not an outsourcing arrangement unless the Bank's own regulator
  determines it is one (see §8 below).

## 2. Scope

- One decision type, one workflow, a fixed number of decisions, a named
  product family, a named user group and count. Pin this to
  `marketing/pilot/PILOT_OFFER.md`'s scope table, or state the deviation
  explicitly. Anything not listed is out of scope by default.
- Deployment: Memtara-hosted evaluation environment, or the Bank's own
  infrastructure. State which — it changes the data-handling section below
  substantially.

## 3. Term, fees, conversion

- **Term.** 3 months, negotiable extension by written agreement only — no
  silent rollover.
- **Fee.** USD 5,000/month, invoiced monthly in advance, exclusive of UAE
  VAT. *Negotiable: term length and reference commitments, not price — see
  `docs/PRICING_MODEL.md`'s discounting order.*
- **Pilot credit.** *(Negotiable, recommend keeping.)* Fees paid during the
  pilot credited in full against the first production invoice if a
  production agreement is signed within a stated window (e.g. 90 days) of
  pilot end.
- **Conversion terms.** State which production tier the pilot is expected to
  convert into (Tier 2S or Tier 2, per `docs/PRICING_MODEL.md`), informed by
  the volume the pilot actually reveals rather than fixed in advance. Do not
  let the pilot agreement silently commit the Bank to a tier priced for a
  volume the pilot has not yet confirmed.

## 4. Data handling and residency

- **Roles.** Bank is Controller of client personal data; Memtara is
  Processor, acting only on the Bank's documented instructions.
- **The inventory.** State plainly what Memtara receives and what it never
  receives. Never received, structurally (not by policy): client income,
  liquid assets, risk-tolerance score, existing holdings value — these are
  proof witnesses that exist only on the client's device. Received: a
  pseudonymous client identifier, contact identifier(s), encrypted vault
  ciphertext (Memtara holds no key capable of decrypting it), the vault
  commitment, proof bytes and public inputs, the suitability verdict, and
  audit-log entries keyed to the pseudonymous identifier. Verify this table
  against `backend/api/migrations/` before it goes in a signed clause — do
  not rely on this outline's summary as the source of truth.
- **Hosting location.** Must be stated explicitly and completed before
  signature — for a CBUAE-licensed institution this is frequently the
  determinative term, and leaving it blank is read as "then no."
- **Cross-border transfer.** No transfer outside the agreed jurisdiction
  without prior written consent, save where required by law.
- **Sub-processors.** Named at signature (hosting provider; any monitoring
  service actually in use). Notice period before adding a new one, with a
  right to object.
- **Retention and deletion tension, named rather than hidden.** The audit
  log is an append-only hash chain; deleting a row breaks tamper-evidence.
  Erasure is effected by deleting the identifying `users` row, which severs
  the link between the pseudonymous identifier and the natural person while
  leaving the chain intact — this needs the Bank's own counsel to confirm it
  satisfies their erasure obligations; Memtara believes it does and is not
  the party positioned to decide.
- **Incident notification.** A defined window (e.g. without undue delay,
  within 24 hours of becoming aware) to notify the Bank of a personal data
  breach, with information sufficient for the Bank's own notification
  duties.

## 5. Intellectual property

- **Memtara's IP.** Memtara retains ownership of the platform: circuits,
  verification keys, backend, prover SDK, export/sealing tooling,
  documentation. See `marketing/pilot/LICENSE_RECOMMENDATION.md` for the
  licensing decision underlying this — that decision must be settled before
  this clause is drafted, not after.
- **The Bank's IP.** The Bank retains ownership of its data, product
  definitions and suitability terms, its AI prompts, and every Canonical
  Case File exported during the pilot.
- **Licence to the Bank.** Non-exclusive, non-transferable, revocable
  licence to use the platform for the pilot term and purpose only.
- **No reference without consent.** Neither party names the other in
  marketing without prior written consent — the Bank's consent, freely
  withheld, unless and until a separate reference agreement is reached.
- **Disclose the licensing position, do not wait to be asked.** State
  plainly whatever the actual licence position is at signature — do not
  let a bank's counsel discover a gap between what `README.md` claims and
  what is actually in force.

## 6. Sealed evidence after the pilot ends — a promise with a technical requirement behind it

This is not boilerplate; it is the clause that makes or breaks the "verify
without us" claim the whole pilot is meant to demonstrate.

- **The promise.** Case files exported during the pilot remain the Bank's
  property and remain verifiable after termination, independent of whether
  Memtara continues to operate.
- **The technical requirement this rests on.** The proof is checked by
  `bb`, an open-source tool Memtara does not control. The verification key
  is a file, not a service. The attestation is validated against a JWKS
  document. None of these three requires Memtara to exist at verification
  time — *provided* the JWKS is archived alongside the case file rather than
  fetched live at verification time. Build that requirement into the
  clause explicitly:
  - Memtara keeps its published JWKS reachable at its published URL for a
    stated minimum period after termination (e.g. 24 months); **and**
  - on request, at or before termination, Memtara provides an offline
    archive: JWKS, verification key, and verification instructions,
    sufficient to re-verify with zero dependency on any Memtara service.
- **Ask for the offline archive regardless of whether it seems needed at
  signature.** A vendor unwilling to commit to this is telling the Bank
  what the evidence is actually worth.

## 7. Liability

- **Cap.** A cap tied to fees paid is standard for a pilot at this price
  point but will read as low to bank procurement; expect negotiation and do
  not agree to an uninsurable number to close faster.
- **Exclusions.** No liability for indirect or consequential loss, loss of
  profit, or loss of anticipated savings, in either direction.
- **Carve-outs.** No limit on liability for death or personal injury caused
  by negligence, fraud, or fraudulent misrepresentation, or anything that
  cannot lawfully be limited.
- **IP indemnity from Memtara** for third-party IP infringement claims
  arising from permitted use of the platform, subject to the cap.
- **Indemnity from the Bank** for claims arising from the Bank's use of the
  platform, including claims relating to the Bank's own investment advice,
  suitability determinations, or regulatory obligations — the platform
  supplies a cryptographic tool; the Bank makes and is answerable for the
  recommendation.

## 8. What Memtara explicitly does NOT warrant

State these in the agreement, not just in a sales conversation — a claim
made only in a meeting and not in the contract is not a claim the Bank can
rely on, and a claim made in the contract that is false is the kind of
finding that ends a relationship.

- Does not warrant that the platform satisfies any specific provision of
  any regulator's rulebook. `docs/REGULATORY_MATRIX.md` states, clause by
  clause, what is and is not covered, gaps first — it is an engineering
  analysis, not a legal opinion, and must not be relied on as one.
- Does not warrant or measure algorithmic bias or disparate impact.
- Does not warrant any specific availability or uptime during the pilot —
  this is an evaluation service; SLA commitments belong in a production
  agreement and would otherwise be a promise with no operating history
  behind it.
- Does not warrant that a verification succeeding means the client was
  found suitable — it means the proof was correctly constructed, including
  a proof that the client is not suitable, which verifies exactly as
  cleanly. Reading the verdict, not just the exit code, is the Bank's
  integration responsibility.
- Does not warrant that any artifact produced constitutes a legally
  admissible signature in any specific forum — that is a question for the
  Bank's own counsel.
- No SOC 2, ISO 27001 certification, or independent penetration test exists
  as of signature. State this in the contract itself, not only in
  `docs/SECURITY_FAQ.md`.

## 9. Term and termination

- Either party may terminate on notice (e.g. 30 days) for any reason, or
  immediately for uncured material breach or insolvency.
- On termination: access ends; data handling per §4; the Bank keeps every
  exported Canonical Case File indefinitely, per §6.
- Survival: confidentiality, the §6 evidence-verifiability commitments, the
  §8 non-warranties, and the liability terms all survive termination — list
  them by clause number in the final draft so nothing lapses by omission.

## 10. Regulatory cooperation

- The Bank determines, for itself, whether the arrangement is outsourcing
  or a material third-party arrangement under its own regulator's rules,
  and handles any resulting notification.
- Memtara cooperates with, and permits reasonable access by, the Bank's
  regulators, internal audit, and external auditors on reasonable notice.

## 11. General

- Governing law and forum (DIFC, ADGM, or onshore UAE — pick one before the
  first legal call, not during it).
- Assignment restricted, save to a group company or on sale of substantially
  all assets.
- Entire agreement; variations in writing, signed by both parties.

---

## What to expect from the Bank's counsel, and where to hold

The liability cap, data residency, and the SOC 2 gap are the three points
most likely to stall. `docs/PILOT_AGREEMENT_TEMPLATE.md`'s closing section,
"For the Memtara team: what counsel will change, and where to hold," covers
this in more depth and should be read before the first legal call.
