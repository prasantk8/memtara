# Evidence-to-Obligation Map — `DecisionEvidence` v1

**Scope.** This document maps the six blocks of the `DecisionEvidence` record —
`decision`, `policy`, `data`, `model`, `human_review`, `evidence` — to the
specific regulatory obligations each block produces evidence *for*, and states
plainly which obligations it does not. The record's shape is defined in Task 1
of `decision_evidence_spec.md`; field names below refer to that schema
(`evidence_schema_version` not yet released — this maps the v1 design, not a
shipped, versioned artifact).

**Frameworks covered.** DFSA Conduct of Business Module (COB); EU AI Act
(Regulation (EU) 2024/1689); GDPR Arts. 13, 14, 22, 83; SR 11-7 (Federal
Reserve/OCC model risk management guidance); ISO/IEC 42001:2023; NIST AI RMF
1.0. NYC Local Law 144 is noted once, as an adjacent example of a mandated
independent-audit regime — it is not a framework this product targets, and no
row below maps a `DecisionEvidence` field to it.

Not covered here: CBUAE's *Guidance Note on Consumer Protection and the
Responsible Adoption and Use of AI/ML*. That mapping already exists, clause by
clause, in `docs/REGULATORY_MATRIX.md`, including its own "four gaps a CRO
should see on page one." This document does not duplicate it — read both
together.

**Sourcing and standards.**
- Every citation below was checked against a current source in this pass
  (dates noted per framework, below) and is marked **[confirmed]**,
  **[confirmed-structure]** (the section/rule exists and is titled as stated,
  but the full verbatim rule text was not independently re-quoted), or
  **[unconfirmed]**. Nothing is paraphrased from training-data memory and
  presented as current text — where current wording could not be retrieved,
  it is flagged rather than guessed.
- **DFSA COB**, checked 2026-08-19 against the live DFSA Rulebook
  (`dfsaen.thomsonreuters.com/rulebook/...`). This is the same rulebook
  `docs/REGULATORY_MATRIX.md`'s appendix flagged as unreachable at the time it
  was written (that appendix worked from an archived `COB/VER7/08-06` PDF).
  This pass reached the live portal and reconfirms the matrix's central
  correction — see §0 below.
- **EU AI Act**, checked against `artificialintelligenceact.eu`, a
  secondary reference maintained by the Future of Life Institute, not the
  Official Journal. Article numbers, titles and paraphrased obligations below
  are **[confirmed-structure]** against that source; before this citation is
  used in a filing or a customer-facing claim, cross-check against the
  consolidated OJEU text (Regulation (EU) 2024/1689), the same discipline
  `AI_INCIDENT_EVIDENCE_LIBRARY.md` applies to its own secondary source.
- **GDPR**, checked against `gdpr-info.eu`, a standard full-text mirror of the
  consolidated regulation. Marked **[confirmed]**.
- **SR 11-7 / ISO 42001 / NIST AI RMF** — structural claims only (which
  functions/clauses/expectations exist, and their names), sourced from
  secondary summaries, not the primary PDF/standard text, consistent with how
  `incident_source.md`'s control recommendations are already treated in this
  repo as secondary. Marked **[confirmed-structure, secondary source]**.
- "AI compliance infrastructure" is never used. "AI evidence infrastructure"
  or "verifiable AI decision evidence" only. Nothing below claims a control
  "operated," and nothing below claims a firm "is compliant" with anything.
  Reasoning that is not a citation is marked `[ASSUMPTION]`.

---

## 0. A citation correction reconfirmed, and one nobody had flagged yet

`docs/REGULATORY_MATRIX.md`'s appendix already corrected the commissioning
brief's citation of "COB 3.1 — Suitability": COB 3.1 is **[confirmed]** titled
"Application," and suitability is **[confirmed]** at **COB 3.4**, "Suitability,"
with the assessment itself at **3.4.2**, "Suitability Assessment." That
correction is now independently reconfirmed against the live rulebook rather
than an archived PDF — the marketing and code that already say "COB 3.4"
(`docs/SALES_LANDING_PAGE.md`) are citing the right rule; the token claim and
several source comments that still emit the literal string `"COB 3.1"`
(`backend/api/src/wealth/evidence.rs:193`, `crypto/signer.rs:360`,
`wealth/mod.rs:380`, `issuance/mod.rs:139,187`, `docs/openapi.yaml:133`,
`docs/REGULATORY_DEMO_REPORT.md:901,940,958`) do not, and REGULATORY_MATRIX.md
already explains why that was left alone rather than fixed silently (a
relying party was told to match the literal string). Nothing new here beyond
reconfirming it against a live source.

**What is new in this pass**: COB 3.4.2 is **[confirmed-structure]** to have
two distinct sub-rules, not one uniform assessment — **3.4.2(1)** requires the
full suitability assessment for a **Retail Client**, and **3.4.2(2)** permits
a firm to give a **Professional Client** a *limited* assessment accompanied by
a mandatory written warning that the firm is not doing so, in a stand-alone
document. Client classification itself sits at **COB 2.3** — 2.3.2
**[confirmed-structure]** is the default-to-Retail rule, 2.3.3–2.3.6A cover
Professional Client categories (deemed and service-based).

This matters directly for the `data` block, §3.3 below: `DecisionEvidence`'s
`customer` object, as specced, carries no client-classification field. A
record produced today cannot show whether a given assessment was performed
under 3.4.2(1) or 3.4.2(2) — meaning it cannot show which suitability
standard applied to the client in front of it. That gap was not visible in
`docs/REGULATORY_MATRIX.md`'s appendix because that appendix was written
against an archived rule text that did not surface the (1)/(2) split. It is
carried into the gap table in §4.

---

## 1. What this document is not

A `DecisionEvidence` record is not a compliance assessment and does not
demonstrate compliance with any provision cited below. It produces
independently verifiable evidence that defined governance checks were applied
to a specific AI-assisted decision. Whether those checks were the right ones,
and whether the firm complied with the obligation in question, remains the
firm's own determination and its regulator's. Every "evidences" cell below
should be read with that ceiling attached, whether or not it is restated in
the cell.

## 2. The four obligations no per-decision record can evidence

A `DecisionEvidence` record is scoped to one `decision_id`. Four categories of
obligation are structurally outside what any single record — or any number of
them, read one at a time — can speak to.

1. **Aggregate or systemic model performance, drift, and disparate impact.**
   EU AI Act Art. 9(2) requires risk management as a continuous process
   informed by post-market monitoring data (Art. 72); SR 11-7's validation
   element includes ongoing monitoring and outcomes analysis (back-testing)
   across the model's use, not one use; NIST AI RMF's Measure and Manage
   functions operate on the system, not the instance. A single record shows
   one input, one output, one review. It cannot show that the model's error
   rate is drifting, that outcomes are disparate across a protected class, or
   that population-level performance still matches what was validated at
   deployment. `docs/REGULATORY_MATRIX.md` already names this exact gap for
   CBUAE §3(a)/§3(c) ("Memtara narrows the feature surface; it does not
   measure disparate impact") — it is the same structural limit, not specific
   to CBUAE. `[ASSUMPTION]`: a corpus of many `DecisionEvidence` records is
   plausible *input* to a separate aggregate-analysis function; producing
   that analysis is not something this record, or this product as specced,
   does.

2. **The adequacy of a policy, as distinct from whether a decision followed
   it.** The `policy` block shows which named policy version and which
   threshold values were pinned for this decision — a sequencing and
   application fact. It does not show that the policy itself is a sufficient
   suitability policy under COB 3.4.2(1) (does it actually capture
   "investment objectives," not only risk tolerance and the four financial
   limbs the circuit encodes — see `docs/REGULATORY_MATRIX.md`'s appendix on
   exactly this point), that an AI Act Art. 9 risk-acceptability judgment was
   itself sound, or that a GDPR Art. 6 lawful-basis analysis behind an
   automated-decision policy was correctly reasoned. Policy design review is
   a product-governance-committee function; this record evidences that a
   committee-approved policy existed and was applied, not that the committee
   got the policy right.

3. **Organisational governance structures and accountability assignment.**
   `human_review.reviewer_id`/`reviewer_role` show a named person acted on
   this decision. They do not show that the governance framework which put
   that person in that seat is adequate: EU AI Act Art. 26(2)
   **[confirmed-structure]** requires deployers to assign oversight to
   persons with "the necessary competence, training and authority" — a role
   label is not a competence attestation. SR 11-7's third expectation is
   "strong governance, policies and controls," including board and senior
   management oversight; ISO/IEC 42001 clause 5 (leadership) and clause 9
   (performance evaluation, management review) sit at the same organisational
   level. None of that is a per-decision fact.

4. **Whether the firm chose the correct threshold or criteria, as opposed to
   applying a threshold consistently.** This is the sharpest of the four, and
   this codebase has already demonstrated it concretely, not hypothetically:
   `docs/REGULATORY_MATRIX.md`'s DFSA appendix documents that whoever holds
   the org API key can register `min_income: 0`, `max_concentration_percent:
   100`, `product_risk_level: 5` — a threshold anyone would clear — and
   `submit_wealth_proof` produces a genuine, cryptographically valid,
   hash-chained "suitable" attestation against it. `thresholds.values`, once
   captured, is an evidentiary fact about which numbers were used. It is not,
   and structurally cannot be, an evidentiary fact about whether those
   numbers were the right numbers for that client's objectives and risk
   tolerance under COB 3.4.2, or that they clear the AI Act Art. 9
   risk-acceptability bar. A record that a threshold was applied is
   indistinguishable, byte-for-byte, from a record that a rigged threshold
   was applied — the cryptography is equally clean either way.

Items 2 and 4 are related but not the same claim: 2 is about whether a
policy's *design* is complete against what the rule enumerates; 4 is about
whether a specific *parameter value* inside an otherwise-adequate policy was
set by a party with no interest in setting it fairly. A firm can fail either
independently of the other.

## 3. Block-by-block mapping

Confidence legend: **High** — the block is close to a direct evidentiary fit
for the stated half of the obligation. **Medium** — the block contributes
necessary but not sufficient evidence. **Low** — the connection exists but is
weak enough that citing it unqualified would overclaim.

### 3.1 `decision` — `decision_id`, `institution`, `business_process`, `final_decision{outcome, decided_at, decision_basis}`, `status`

Implementation status per `decision_evidence_spec.md` §1.2: `decision_id`
PARTIAL (aliasable from an existing key), `institution` EXISTS,
`business_process` MISSING, `final_decision.outcome`/`decided_at` EXIST,
`decision_basis` MISSING, `status` PARTIAL (today a pipeline status, not an
approved/rejected/modified decision status).

| Obligation | What this block evidences | What it does not evidence | Confidence |
|---|---|---|---|
| DFSA COB 3.4.2 — a declined recommendation must be evidenced as fully as an approved one **[confirmed-structure]** | A discrete, timestamped decision record exists whether `outcome` is approved or declined, per Task 1 §1.3's non-`Option` design — the same discipline `wealth/evidence.rs:180-187` already applies to the proof's own output. | That the recommendation was actually suitable, or that "any other requirements or relevant facts about the Client" — COB 3.4.2's open-ended limb — were considered. This block is a container for the fact that a decision was made, not evidence the substance was right. | High for record existence; Low for substantive suitability |
| EU AI Act Art. 12 record-keeping / Art. 26(6) deployer log retention **[confirmed-structure]** | `decision_id` + `business_process` + `decided_at` let one specific event be located and dated within a log stream — the locatability half of record-keeping. | That the underlying system logs *every* such event automatically over its lifetime (Art. 12(1) is a system-design property, not a per-record one), or that whatever store holds this record after export actually honors the Art. 26(6) six-month retention floor. | Medium |
| GDPR Art. 22(3) — right to obtain human intervention and to contest the decision **[confirmed]** | `decision_id` and `final_decision.outcome` give a client a concrete, referenceable decision to contest. | That a contest channel exists at all, or that the client was told about it — `docs/REGULATORY_MATRIX.md` already flags the CBUAE-equivalent obligation (§7(c)) as "not covered": "no complaints-handling workflow exists in either system." Nothing in this block changes that. | Medium for referenceability; none for the channel itself |
| EU AI Act Annex III / "high-impact decision" classification generally | `business_process`, once populated, names which process produced the decision, giving a regulator or auditor a field to classify against. | That the classification was performed, or performed correctly — classifying a process as high-risk under Annex III (or "high-impact" under CBUAE §1) is the deployer's determination, not a fact this field asserts. | Low |

### 3.2 `policy` — `policy{id, version, source}`, `thresholds{set_id, version, values, source}`

Implementation status: `policy.id/version` MISSING today (an ad hoc JSON
snapshot exists, `wealth/mod.rs:294-322`, but no `policy_versions` table or
version field); `thresholds.set_id/version` PARTIAL (`products` table carries
the values and an audit trail, but no version number field exists yet).

| Obligation | What this block evidences | What it does not evidence | Confidence |
|---|---|---|---|
| DFSA COB 3.4.2 — assessment against defined criteria, pinned before the recommendation **[confirmed-structure]** | Which named policy version and which threshold values were in force and snapshotted at the moment this specific assessment opened — the sequencing fact the rule cares about (`wealth/mod.rs:294-299,338-354` already implements the snapshot-on-write pattern this block would surface). | Whether those criteria constitute a sufficient suitability policy (cannot-evidence item 2), and — new finding in this pass — whether the client in front of this policy was Retail (3.4.2(1), full assessment) or Professional (3.4.2(2), limited assessment plus mandatory written warning). `customer` carries no classification field, so this block cannot show which sub-rule this assessment was performed under. | High for "which version was pinned"; none for classification-linkage |
| EU AI Act Art. 9 risk management system **[confirmed-structure]** | That a specific, versioned configuration of risk-relevant parameters was in force for this decision — a traceability anchor a risk-management process needs to point to. | The risk management system itself, which Art. 9(2) requires to be a continuous, lifecycle-spanning process (cannot-evidence item 1), and whether the risk-acceptability judgment behind these particular values was sound (cannot-evidence item 2). | Medium |
| GDPR Art. 22(2) — lawful basis for automated decision-making **[confirmed]** | `policy.source`, once populated, can show which basis (contract, consent, authorising law) a policy is grounded in. | That the lawful-basis analysis behind that grounding was correctly reasoned — this is a legal determination, not a field value. | Low |
| SR 11-7 — model inventory / development-and-use expectation **[confirmed-structure, secondary source]** | `policy_id`/`policy_version` give an inventory pointer: which configuration was used, when. | That the inventory is complete, or that development of this policy/model configuration underwent SR 11-7's conceptual-soundness review before deployment — a pre-deployment fact, not a per-decision one. | Medium |

### 3.3 `data` — `customer{subject_id, data_provenance, data_provenance_version}`, `input_context_fingerprint`

Implementation status: `subject_id` EXISTS; `data_provenance` PARTIAL (an
absence statement today — Memtara discloses it holds none of the client's
financial data — not a structured provenance object); `data_provenance_version`
and `input_context_fingerprint` MISSING.

| Obligation | What this block evidences | What it does not evidence | Confidence |
|---|---|---|---|
| GDPR Art. 13(2)(f)/14(2)(g) — meaningful information about the logic involved **[confirmed]** | `data_provenance`/`input_context_fingerprint`, once populated, can show which data categories and which version of the input context fed a specific decision — raw material a disclosure could be built from. | The disclosure itself. Art. 13/14 requires the controller give the data subject plain-language, meaningful information; a fingerprint is not a notice, and this schema has no field for one. | Low |
| EU AI Act Art. 10 — data governance for high-risk systems **[confirmed-structure]** | `input_context_fingerprint` evidences integrity: this specific input was not altered after the fact. | Art. 10(2)(f)-(g)'s substantive requirement — examination for possible biases, representativeness of the data — which is a property of the dataset and the pipeline, not of one fingerprinted instance (cannot-evidence item 1). | Low |
| DFSA COB 2.3 client classification, feeding COB 3.4.2(1)/(2) **[confirmed-structure]** | Nothing today. `customer` has no classification field. | Which suitability standard (full vs. limited-with-warning) applied to this client. Flagged as a gap in §4. | None |
| CBUAE §5(a)/(c) — data provenance, minimisation | Cross-reference only — this obligation is mapped in depth in `docs/REGULATORY_MATRIX.md` §5, which finds it Memtara's strongest clause fit. Not re-derived here. | — | See REGULATORY_MATRIX.md |

### 3.4 `model` — `model{provider, model_name, model_version, environment, config_fingerprint, system_prompt_or_policy_id, timestamp}`, `output_fingerprint`

**Implementation status, stated plainly: every field in this block is MISSING
from the codebase today** (`decision_evidence_spec.md` §1.2 — "no LLM/model-
provider concept exists"; `output_fingerprint` is PARTIAL only in the narrow
sense that `proof_digest_hex` hashes the cryptographic proof, not any upstream
model output). Everything below describes what this block would evidence
*once built*, not what exists in production today.

| Obligation | What this block would evidence | What it would not evidence | Confidence |
|---|---|---|---|
| EU AI Act Art. 12/19 — record-keeping, per-event logging **[confirmed-structure]** | Which model instance, version and configuration produced a specific output, at a specific time — exactly the shape of "event" Art. 12 asks a log to capture, at the per-decision level. | That the AI system's overall logging capability meets Art. 12(1)'s "automatic... over the lifetime of the system" bar (a system design property), or that Art. 19's retention duration is honored operationally after export. | Medium (once built) |
| GDPR Art. 13(2)(f)/14(2)(g) — meaningful information about the logic **[confirmed]** | `system_prompt_or_policy_id` + `config_fingerprint` as a technical anchor for which logic configuration was used. | The plain-language explanation itself — same limitation as §3.3; a config fingerprint is not a "meaningful information" disclosure, it is what a disclosure would be built *from*. | Low |
| SR 11-7 — model identification for the inventory **[confirmed-structure, secondary source]** | `provider`/`model_name`/`model_version` is exactly the identifying data an inventory needs per decision — "this model version was in production use on this date." | That the model underwent SR 11-7's validation (conceptual soundness, outcomes analysis) before deployment — a pre-deployment fact. | Medium (once built) |
| ISO/IEC 42001 / NIST AI RMF "Map" function **[confirmed-structure, secondary source]** | `environment`/`config_fingerprint` support system characterization at the per-instance level. | The organisation-level AI system inventory and risk categorization that ISO 42001 clause 4.3/8 and NIST's Govern function require — an org register, not a decision field. | Low |
| `output_fingerprint` — general integrity | That a specific output was captured and can be checked for tampering after the fact. | That the output was correct, unbiased, or fit for purpose — an integrity property, not a quality one. | Medium |

### 3.5 `human_review` — `reviewer_id`, `reviewer_role`, `action{approved\|rejected\|modified}`, `override`, `override_reason`, `reviewed_at`

**Implementation status: also entirely MISSING today.** Zero matches for
"reviewer" in `backend/api/src/`; the only existing governance concept,
`products.approved_by_risk_committee`, approves a catalogue entry, not a
per-decision review (`decision_evidence_spec.md` §1.2).

| Obligation | What this block would evidence | What it would not evidence | Confidence |
|---|---|---|---|
| EU AI Act Art. 14 — human oversight **[confirmed-structure]** | That a natural person engaged with this specific decision and recorded an action; `override`/`override_reason` directly address Art. 14(4)(c)-(d)'s "decide... to disregard, override or reverse" the output. | That the reviewer had "the necessary competence, training and authority" (Art. 26(2)) — a role label is not a competence attestation — or that the interface let them "correctly interpret the output" (Art. 14(4)(b)) free of automation bias (Art. 14(4)(a)). Maps to cannot-evidence item 3. | Medium |
| GDPR Art. 22(3) — right to obtain human intervention **[confirmed]** | `reviewer_id` + `action` evidence a human engaged with the decision — the substantive core of the Art. 22(3) safeguard. | That the intervention was *meaningful* rather than a rubber stamp — the same field pattern is consistent with both, per `AI_INCIDENT_EVIDENCE_LIBRARY.md`'s Cigna and UnitedHealth entries. Distinguishing the two needs a pattern across many records (cannot-evidence item 1), not one. | Medium |
| Cigna-pattern review duration (no named rule; an evidentiary capability worth noting) | Cross-block: `reviewed_at` compared against `evidence.timestamps.opened_at` derives a review duration per decision — the one field the Cigna case (`AI_INCIDENT_EVIDENCE_LIBRARY.md` #10) turned on. This is the strongest fit in this block. | That a short duration means a bad review or a long one means a good one — duration is a signal, not a verdict, and still requires someone to look at the aggregate. | Medium-High |
| DFSA COB 3.4 | No explicit per-decision human-review mandate in the rule text itself — suitability is a firm obligation, not phrased as requiring a second human signature on every recommendation. Where a firm builds one in as an internal control, this block evidences that internal control ran. | An affirmative COB requirement — do not cite this block as evidencing a COB-mandated review step, because the rule does not clearly mandate one. | Low (no direct rule anchor) |

### 3.6 `evidence` — `regulatory_control_mapping`, `evidence_artifacts`, `cryptographic_proofs`, `timestamps{opened_at, assessed_at, exported_at}`, `evidence_schema_version`

Implementation status: `regulatory_control_mapping` and `cryptographic_proofs`
EXIST and are the strongest-implemented parts of the whole schema today;
`evidence_artifacts` PARTIAL (data exists, scattered across separate fields
rather than one array); `timestamps` PARTIAL (`exported_at` lives only in a
PDF filename today, not a hashed field).

| Obligation | What this block evidences | What it does not evidence | Confidence |
|---|---|---|---|
| DFSA COB 3.4.2 — the firm must be able to demonstrate it assessed **[confirmed-structure]** | `cryptographic_proofs` re-verifies years later against a published `vkey` and JWKS, independent of the firm's word or Memtara's continued existence — already the strongest part of the pipeline per `docs/REGULATORY_MATRIX.md`'s appendix. | The rule's 6-year (archived-version) retention requirement — `docs/REGULATORY_MATRIX.md` already flags this as "Not covered... the hash chain proves internal consistency, not availability." An operator can still delete the whole record. | High for demonstrability; none for retention |
| EU AI Act Art. 12 — record-keeping **[confirmed-structure]** | A well-formed, tamper-evident record of one event, with `evidence_schema_version` letting an examiner locate the exact schema a record validates against. | That the underlying system produces this record for *every* decision — if the pipeline silently drops some, no evidence block can detect the absence of a record that was never generated. This is a distinct gap from Task 1's "REJECTED = same evidence as APPROVED" discipline, which only covers decisions that *do* produce a record. | Medium |
| GDPR Art. 5(2) — accountability, demonstrating compliance **[confirmed]** | `evidence_artifacts`/`cryptographic_proofs` give the firm something concrete and reconstructible to produce on demand. | Compliance itself — only that a check was performed and is independently reconstructible. | Medium |
| `regulatory_control_mapping` field, specifically | That a claim was made, at record-creation time, about which framework/clause a decision speaks to, and that claim is now cryptographically bound to the record. | That the claim is *correct*. This field is populated statically per circuit (`wealth/evidence.rs:192-195`) by whoever configures the mapping — it is exactly the kind of field a wrong citation (this document's own §0 finding: `"COB 3.1"` still emitted live in several source files) would sit inside, sealed with the same integrity as a correct one. A wrong clause number in this field is not detectable by the cryptography; it can only be caught by the same kind of review that produced this document. | Explicitly flagged, not scored |

## 4. Gap table — obligations we currently produce no evidence for

These are obligations a DFSA-regulated, GDPR-adjacent buyer will ask about,
that today have **no** field, block, or artifact behind them — not partial,
not planned-and-partly-built. Listed honestly rather than mapped to the
nearest adjacent field.

| Obligation area | Framework hook | Why there is no evidence today |
|---|---|---|
| **Consent** | GDPR Art. 22(2)(c) (consent as a lawful basis for automated decision-making, with a right to withdraw); DFSA COB client-agreement disclosures | There is no consent object anywhere in the backend. The nearest concept, `SessionPolicy.purpose_hash` (`vault/src/session.rs:53,102`), is a hash of a **fixed, non-revocable** string bound at session creation — it is a purpose *binding*, not a consent record with an id, a version, a scope, a grant timestamp, or a revocation endpoint. Any mapping in §3 that implied a `data` or `human_review` field evidences consent would be false, and none does. This is the single largest gap in this document. |
| **Client classification (Retail vs. Professional), and which suitability standard applied** | DFSA COB 2.3 → 3.4.2(1)/(2) | `customer` carries no classification field (§3.3, new finding this pass). A record today cannot show whether COB 3.4.2(1)'s full assessment or 3.4.2(2)'s limited assessment-plus-warning was the applicable standard for a given client. |
| **Bias / disparate-impact testing** | EU AI Act Art. 10(2)(f)-(g); adjacent to NYC LL144's mandated independent bias audit (not our market, noted for shape only) | No field in any block carries a fairness metric, disparate-outcome test result, or audit reference. Cannot-evidence item 1 covers why a per-decision record structurally can't carry this; the point here is that nothing upstream of it does either, today. |
| **The reviewer's independence from the party who set the threshold** | The "adviser trap" — cannot-evidence item 4, `docs/REGULATORY_MATRIX.md`'s DFSA appendix | Nothing in `human_review` or `policy` enforces or evidences that the person reviewing a decision is a different party from whoever registered the thresholds it was assessed against. Two roles can be the same person and the record would look identical to a case where they were properly separated. |
| **Meaningful, plain-language explanation delivered to the data subject** | GDPR Art. 13(2)(f)/14(2)(g) | `model.system_prompt_or_policy_id` and `config_fingerprint` are technical anchors, not a disclosure artifact. No field holds the actual explanation text given to a client, or confirmation it was given at all. |
| **Retention schedule for the exported record itself** | DFSA COB (6-year retention in the archived rule text); GDPR Art. 5(1)(e) storage limitation | Already flagged in `docs/REGULATORY_MATRIX.md`'s DFSA appendix and reconfirmed here: the hash chain proves internal consistency, not availability. Nothing prevents an operator from deleting a whole exported record; no field asserts a retention commitment. |
| **A complaints or contest channel tied to a specific decision** | GDPR Art. 22(3); DFSA general conduct obligations; CBUAE §7(c) (already flagged there as "not covered") | `decision_id` gives a client something to reference in a complaint; no field or endpoint records that a complaint was made, received, or resolved against that reference. |
| **Whether the underlying business process is "high-risk" under the AI Act, or "high-impact" under CBUAE** | EU AI Act Annex III; CBUAE §1 | `business_process` (itself MISSING today) would let a process be *named*; classification is the deployer's determination, and no field asserts a classification was made, let alone made correctly. |

## 5. Sources

- DFSA Rulebook, Conduct of Business Module — live portal,
  `dfsaen.thomsonreuters.com/rulebook/cob-34-suitability`,
  `.../suitability-assessment`, `.../cob-234`, `.../cob-232`,
  `.../professional-client`, checked 2026-08-19.
- EU AI Act, Regulation (EU) 2024/1689 — Articles 9, 12, 14, 19, 26, 99,
  `artificialintelligenceact.eu/article/{9,12,14,19,26,99}`, checked
  2026-08-19. Cross-check against the OJEU consolidated text before filing
  or customer-facing use.
- GDPR — Articles 13, 14, 22, 83, `gdpr-info.eu/art-{13,14,22,83}-gdpr`,
  checked 2026-08-19.
- SR 11-7 (Federal Reserve SR 11-7 / OCC Bulletin 2011-12), "Guidance on
  Model Risk Management" — structural summary only, secondary-sourced.
- ISO/IEC 42001:2023, "Information technology — Artificial intelligence —
  Management system" — clause structure only, secondary-sourced.
- NIST AI RMF 1.0 (NIST AI 100-1), Govern/Map/Measure/Manage functions —
  `nist.gov`/`airc.nist.gov`, structural confirmation.
- `decision_evidence_spec.md` (this repo's scratchpad) — Task 1, schema
  authority and field-by-field implementation status.
- `docs/REGULATORY_MATRIX.md` — CBUAE mapping and the original DFSA
  citation correction, not duplicated here.
- `docs/AI_INCIDENT_EVIDENCE_LIBRARY.md` — case-level grounding for the
  Cigna/UnitedHealth `human_review` reasoning in §3.5.
