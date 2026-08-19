# The Memtara Pilot — one page, forwardable to your CRO

Memtara is verifiable AI decision evidence infrastructure. It does not make an
institution compliant, and compliance stays the institution's responsibility.
What it does: for a defined decision, it produces independently verifiable
evidence that defined governance checks were applied — evidence a third party
can check without taking AIHOOTS's word for it.

---

## Scope

| | |
|---|---|
| **Decision type** | DIFC/CBUAE structured-product suitability recommendations (`wealth_suitability`) — the only decision type with a complete evidence pipeline today: product registry, per-decision evidence export, and a Canonical Case File. |
| **Workflow** | Advisor-initiated suitability check, advisor terminal or desktop. Not a consumer mobile app — the in-browser/mobile prover is specified but not yet built (`clients/prover/README.md`). |
| **Volume** | Up to 250 assessments over the pilot period `[ASSUMPTION — default cap; set to the Bank's actual 12-week volume at kickoff if lower]`. |
| **Duration** | 3 months (12 weeks). |
| **Price** | USD 5,000/month, USD 15,000 total. No setup fee. Exclusive of UAE VAT. |

## What we deliver

- Platform access (Memtara-hosted evaluation environment, or your infrastructure — see below), scoped to one product family, up to 10 named users.
- Product registry configuration for the instruments you specify, with risk-committee-approval gating enforced (an assessment cannot open against unregistered or unapproved terms).
- A Canonical Case File, sealed and exportable, for every assessment — approved or declined (see below).
- Regulatory clause mapping for the decisions in scope (`docs/REGULATORY_MATRIX.md`), stated with its gaps on page one, not buried.
- A named engineering contact and, by pilot end, the offline verification bundle described under Success Criteria — this is a pilot deliverable, not something we already ship today; see the honesty note there.
- Weekly working session with your compliance/risk lead.

## What you must provide

- Approved suitability thresholds for the product family in scope — your risk committee's decision, not ours. This is the single most common thing that slips a pilot's start date; decide it before kickoff, not during.
- Synthetic or anonymized test client data for the pilot. We do not require, and this pilot is not scoped for, live client financial data.
- Named users and a compliance reviewer who will sign off on whether the exported case file satisfies your standard.
- Your own integration effort. `clients/prover/README.md` states plainly what this involves, including the parts that are genuinely awkward — read it before signing, not after.

## Success criteria — agreed before the pilot starts, checked without argument at the end

**Primary criterion, and the board's own north star:** *an independent auditor,
holding only the exported evidence pack, can verify the complete evidence of a
material AI-assisted decision without contacting AIHOOTS.*

Stated honestly, in two parts:

1. **True today, for this decision type.** The cryptographic core — the proof
   that a suitability threshold check was correctly performed against the
   registered terms — is independently verifiable now, with `bb verify` (an
   open-source tool, not ours) against the committed verification key and the
   proof's public inputs. No AIHOOTS API key or account is needed for this
   step.
2. **A pilot deliverable, not a standing claim.** The *full* evidence
   pack — including the issuer JWKS used to validate the signed attestation,
   and the audit-chain excerpt — currently depends on a live fetch to
   AIHOOTS/Memtara for some components. Before this pilot ends, we will ship
   the offline bundle that removes that dependency for the decisions in
   scope: a pinned JWKS snapshot, the proof, the vkey, the audit-chain
   segment, and the canonical evidence JSON, packaged so a third party with
   only that bundle, `bb`, and a standard JOSE library can complete every
   check with zero network calls. **This is a commitment, not a fact about
   the platform today — we are telling you now so it is not discovered at
   the finish line.**

| # | Criterion | Measure | Owner |
|---|---|---|---|
| 1 | A real proof is generated and verified for a live-equivalent client | `bb verify` succeeds; the verdict (public input index 11) is read and matches the case | Bank |
| 2 | **The primary criterion above** — full offline verification | A third party (Internal Audit or an external reviewer) verifies a randomly selected case file using only the offline bundle, no AIHOOTS involvement | Joint |
| 3 | A Canonical Case File satisfies your compliance reviewer | Written sign-off | Bank |
| 4 | The seal detects tampering | A single modified byte fails verification | Joint |
| 5 | Product-registry governance holds | An assessment cannot be opened against unregistered or unapproved terms | Joint |
| 6 | Integration effort for production is understood | Written estimate, informed by actual pilot experience | Bank |

## The line we already committed to

**A decline must produce the same signed evidence as an approval.**

This is deliberate, and it is the harder half. `wealth/evidence.rs` treats a
proof of "not suitable" as a full, present result — not an absent one — and
it is the one place in the current codebase that already gets this
discipline right. It matters more than the approval case because a decline
is the decision most likely to be disputed. A client who was told no is far
more likely to allege the check was unfair, applied inconsistently, or
skipped than a client who got what they wanted. If evidence infrastructure
only worked for the outcomes nobody complains about, it would not be
evidence infrastructure — it would be a marketing artifact for the easy
half of the job. Evidence that a defined check was applied, symmetrically,
to a decision someone is unhappy about is the only version of this claim
worth having.

**What we do not claim.** We do not claim the recommendation was correct,
that your governance controls were effective, or that this pilot makes you
compliant with any specific regulatory provision. We claim exactly this:
independently verifiable evidence that defined governance checks were
applied to a specific AI-assisted decision. Compliance judgment, and
compliance, remain yours.

---

*Companion documents: `marketing/pilot/PILOT_AGREEMENT_OUTLINE.md` (terms for
your counsel to draft from — not a contract), `docs/SECURITY_FAQ.md` (for
your security review), `marketing/pilot/PRICING_POSITION.md` (the economics
beyond the pilot, stated honestly), `docs/REGULATORY_MATRIX.md`,
`docs/PILOT_AGREEMENT_TEMPLATE.md`.*
