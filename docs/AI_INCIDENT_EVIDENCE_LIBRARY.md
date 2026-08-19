# AI Incident Evidence Library

Internal reference. Eleven real enforcement actions, court rulings, and losses involving
AI-assisted or AI-driven decisions, each mapped against the six blocks of our
`DecisionEvidence` record (`decision`, `policy`, `data`, `model`, `human_review`, `evidence`)
and stress-tested against what verifiable per-decision evidence would and would not have
changed.

**Purpose.** Two things: (1) an honest test of whether "AI evidence infrastructure" would
have mattered in each case, and (2) discovery-call material — one concrete, checkable
question per case about the *prospect's* risk, not our cryptography.

**Sourcing and standards.**
- Primary source for every case entry is the founder-supplied research document, extracted
  verbatim-in-substance at
  `/private/tmp/claude-501/-Users-prashantsingh-Desktop-memtara-zkp/b94871b6-f917-4718-a550-c5ab94e43a16/scratchpad/incident_source.md`.
  Every figure in that document is treated here as **secondary** unless independently
  re-verified against a primary filing, press release, or docket below — re-verified figures
  are marked **[verified]**; figures that could not be independently confirmed in this pass
  are marked **[unverified — recheck before quoting to a customer]**.
- We do not claim AIHOOTS "would have prevented" any of these outcomes. We produce evidence;
  we do not produce good decisions, good policies, or good executives.
- We do not claim to prove a control "operated." The defensible claim, used throughout, is:
  *independently verifiable evidence that defined governance checks were applied to a
  specific AI-assisted decision.*
- "AI compliance infrastructure" is never used. "AI evidence infrastructure" or "verifiable
  AI decision evidence" only.

---

## 1. Zillow Group — Zillow Offers

**What happened.** Zillow's iBuying arm priced home purchase offers using a pricing model
whose forecasts drifted from actual market conditions through 2021. Company leadership
directed the business to keep scaling purchase volume, overriding the model's own
uncertainty-suppression mechanism rather than slowing acquisitions when the model's
confidence should have triggered a pullback. Zillow wound the business down in November
2021, laying off roughly a quarter of its staff.

**The governance failure.** Not "the model was wrong" — models drift. The failure was that
**authority over the model's own risk boundary sat with the business-line managers being
measured on volume**, not with an independent risk function, so when the model's internal
signal said slow down, the people incentivized to keep buying could and did override it.
There was no control preventing the executives who benefited from volume from being the same
people empowered to waive the volume brake.

**The outcome.** [verified] Q3 2021 inventory write-down of approximately $304M and direct
Zillow Offers program operating losses of $528M for the quarter (Zillow Group Q3 2021
shareholder letter and 10-Q, Nov. 2, 2021, sec.gov/Archives/edgar/data/1617640). [verified]
Stock fell approximately 24–25% on the announcement (CNBC, Nov. 3, 2021); headcount cut by
roughly 25% (~2,000 roles) as part of the wind-down (Zillow investor release, Nov. 2, 2021).
[unverified — recheck before quoting to a customer] The source document's cumulative
"$881M–$900M+ total write-downs," "~$7.8B market-cap loss," and "~18,000 homes liquidated at
5–7% losses to Pretium Partners" are directionally corroborated by secondary reporting (one
industry source cites $881M in full-year 2021 flipping losses; contemporaneous coverage cites
an 18,000-home backlog sold at an estimated 5–7% loss) but the exact cumulative figures were
not independently reconciled to a single primary filing in this pass and should be re-pulled
from the FY2021 10-K before use with a customer. A stock-drop shareholder class action was
also filed (classaction.org, Nov. 2021) — not independently confirmed to a resolution here.

**Which evidence block would have been at issue.** `policy`/`threshold` override, with a
`human_review` dimension: this is the case named explicitly in the source document as the
reason the recommended control set puts override *authority* with an independent committee,
not a documentation fix. In `DecisionEvidence` terms, the relevant fact is not "what did the
model output" (that's recoverable from logs) but "who overrode the model's uncertainty
threshold, under what authority, and was that override itself logged as a reviewed action" —
i.e., a `human_review` record with `override: true` sitting on top of a `threshold` change.

**What a per-decision evidence record would and would not have done.** It would not have
stopped the override. The executives who chose to keep buying above the model's confidence
band had the organizational authority to make that call — a signed record of the override
does not revoke that authority, and nothing about evidence infrastructure changes who sits
on the risk committee. What it would have done: converted "leadership decided to keep buying
despite the model's own signal" from a fact reconstructed after the fact through shareholder
litigation discovery into a contemporaneous, attributable, non-repudiable record — visible to
a board risk committee in near-real-time rather than in a 10-Q three months later. That is a
speed-and-attribution change, not a prevention. The prevention the source document actually
recommends — moving override authority to an independent committee — is an org-design fix
evidence infrastructure can support (by making overrides visible to that committee) but
cannot substitute for.

**The discovery question it generates.** "When your model's own confidence or risk threshold
would trigger a slowdown, who has the authority to override it — and is that override
captured anywhere your board can see before the losses show up in a quarterly filing?"

---

## 2. Rite Aid Corporation

**What happened.** From 2012–2020, Rite Aid deployed facial recognition technology in
hundreds of stores to flag customers as likely shoplifters. The system was not validated for
accuracy, produced disproportionately high false-positive rates against Black, Asian,
Hispanic, and female consumers, and staff acted on its alerts to detain, publicly accuse, or
eject flagged customers. The FTC brought an enforcement action in December 2023.

**The governance failure.** No pre-deployment validation of the model's disparate false-positive
rate before it was put into a workflow with real physical and reputational consequences, and
no meaningful human check between an unvalidated match score and a detention.

**The outcome.** [verified] FTC v. Rite Aid Corp., FTC File No. 2023190 (announced Dec. 19,
2023; ftc.gov/legal-library/browse/cases-proceedings/2023190-rite-aid-corporation-ftc-v): a
five-year ban on Rite Aid's use of facial recognition for surveillance, plus a modified
decision and order requiring Rite Aid to delete or destroy all photos, videos, and any
"data, models, or algorithms derived in whole or in part therefrom," and to notify any third
parties who received that data or those models and instruct them to do the same
(ftc.gov/system/files/ftc_gov/pdf/c4308riteaidmodifiedorder.pdf). Note the precise mechanism:
the order compels *Rite Aid* to notify and instruct third-party vendors/developers to delete
derivative models — it is not the FTC directly ordering third parties, which is a meaningful
distinction if this case is cited to a customer with vendor-model exposure.

**Which evidence block would have been at issue.** `model` and `data` — specifically, whether
the facial-match model's confidence threshold and known false-positive-rate disparity were
ever validated and recorded before the model was wired into a store workflow, and whether the
input image/data pipeline had any documented provenance or retention limits.

**What a per-decision evidence record would and would not have done.** It would not have
stopped Rite Aid from deploying an unvalidated model — that is a pre-deployment decision made
before any single "decision" record exists to capture. It would not have closed the racial
disparity in the underlying facial recognition technology itself. What a per-decision record
*would* have done: for each flagged customer, a `model` block carrying the match confidence
and threshold used, plus a `human_review` block recording whether a human reviewed the match
before acting on it (in most alleged incidents, none did) — turning "disproportionate false
positives" from a statistical finding an FTC investigation had to reconstruct from years of
store records into something provable, per incident, by the flagged customer or a regulator
in days rather than an eight-year investigation window. This is a speed-of-proof case, not a
prevention case — and it would also have made Rite Aid's own exposure visible to Rite Aid's
own compliance function years earlier than the FTC found it.

**The discovery question it generates.** "If a regulator asked you today to produce, for a
specific adverse action against a specific customer, the model version, the confidence score,
and whether a human reviewed it before acting — how long would that take, and whose record
would it be?"

---

## 3. Delphia (USA) Inc.

**What happened.** Between 2019 and 2023, Delphia told investors in its Form ADV, a press
release, and its website that its algorithms ingested client data to forecast financial
markets and inform portfolio decisions. The described data-ingestion and forecasting
workflow was never actually implemented. The SEC charged Delphia with violating the
Investment Advisers Act's antifraud and marketing-rule provisions in March 2024.

**The governance failure.** There was no gap between a control and its evidence — there was
no underlying capability at all. The marketing and regulatory-filing claims were never
checked against what the engineering team had actually built.

**The outcome.** [verified] SEC, In the Matter of Delphia (USA) Inc., Advisers Act
§§206(2), 206(4) and Rule 206(4)-1 (Marketing Rule), Release No. IA-6535 (Mar. 18, 2024):
$225,000 civil penalty, censure, and cease-and-desist order (SEC press release and orders;
corroborated by WilmerHale, Debevoise & Plimpton, and ABA Banking Journal client alerts,
Mar.–Apr. 2024).

**Which evidence block would have been at issue.** `model` — specifically, the entire premise
of a `model` block (provider, model_name, model_version, a live inference call producing an
output) presupposes a model that actually runs. Here, the capability asserted in disclosures
did not exist to be evidenced.

**What a per-decision evidence record would and would not have done.** Nothing, as a
retrospective matter — and this is the most important negative finding in this library. A
`DecisionEvidence` record is generated *by* an AI-assisted decision pipeline; if the pipeline
never existed, there is no decision to generate a record for, and no amount of evidence
tooling applied after the fact changes that the underlying claim was fabricated at the
marketing and filing layer, not the decision layer. The only way evidence infrastructure
becomes relevant here is prospectively and contractually: if a customer or counterparty had
required, as a condition of the relationship, that Delphia produce a signed `DecisionEvidence`
record for a sample of client-facing "AI-informed" recommendations, the absence of any such
record — or the inability to produce one — would have been a fast, structural tell that no
qualifying pipeline existed. That is a due-diligence use case for a counterparty, not a
capability we can claim protects the company making the claim.

**The discovery question it generates.** "For the specific AI capability described in your
marketing or regulatory filings, can you produce even one real, timestamped decision record
that pipeline actually generated — not a description of what it's designed to do?"

---

## 4. Global Predictions Inc.

**What happened.** Global Predictions marketed itself, without substantiation, as the "first
regulated AI financial adviser" and made other unsubstantiated claims about its AI
capabilities and services. The SEC charged the firm under the Marketing Rule in March 2024,
alongside the Delphia action, as part of the SEC's first "AI-washing" enforcement sweep.

**The governance failure.** Same pattern as Delphia: a marketing and positioning claim never
checked against a substantiation file, filed with a regulator.

**The outcome.** [verified] SEC, In the Matter of Global Predictions Inc., Marketing Rule
206(4)-1 (Mar. 18, 2024): $175,000 civil penalty, censure, cease-and-desist order, and
required retraction of the marketing claims (SEC release; corroborated by the same set of
Mar.–Apr. 2024 law-firm client alerts as Delphia, above). Combined Delphia + Global
Predictions penalty: $400,000 (ABA Banking Journal, Apr. 2024).

**Which evidence block would have been at issue.** `model` — an unsubstantiated capability
claim, not a decision-level control gap.

**What a per-decision evidence record would and would not have done.** Same conclusion as
Delphia, and for the same reason: there is no decision-level fix for a claim made at the
marketing layer about a capability's existence. This is the case the founder should not lose
sight of for a different reason — see `docs/EVIDENCE_THESIS_TEST.md`, "the observation that
points back at us."

**The discovery question it generates.** "Has legal or compliance signed off that every AI
capability claim on your public site and in your regulatory filings matches what the
production system actually does today — and when was that check last run?"

---

## 5. DoNotPay Inc.

**What happened.** DoNotPay marketed its product as a "robot lawyer" capable of substituting
for a human attorney — generating legal documents, suing for assault without a lawyer, and
running automated "compliance audits" claiming to detect legal violations from an email
address alone. It never tested whether the AI's output met the standard of a licensed
attorney's work and never retained attorneys to validate the legal-substance features. The FTC
brought this as part of "Operation AI Comply" in September 2024.

**The governance failure.** A real system producing real outputs, but with no validation
pipeline behind the claim that those outputs were reliable, and no licensed-professional
review layer despite marketing the product as a professional substitute.

**The outcome.** [verified] FTC v. DoNotPay Inc. (complaint announced Sept. 25, 2024, as part
of Operation AI Comply; final order Feb. 2025 — ftc.gov/news-events/news/press-releases/2025/02/ftc-finalizes-order-donotpay-prohibits-deceptive-ai-lawyer-claims-imposes-monetary-relief-requires):
$193,000 monetary relief, mandatory notice to subscribers from 2021–2023, and a prohibition
on unsubstantiated claims that the product's output is equivalent to a licensed professional's
work.

**Which evidence block would have been at issue.** `model` (capability claim vs. actual
tested performance) and `evidence` — specifically the *absence* of `evidence_artifacts`: no
testing record, no attorney sign-off artifact, ever existed to substantiate the marketing
claim, because the validation step itself was never performed.

**What a per-decision evidence record would and would not have done.** It would not have made
the underlying legal-document generation more accurate — that is a model-quality and
validation-process question, not an evidence question. What it would have done: a
`human_review` block that is structurally required to be non-empty for any output marketed as
professional-equivalent would have made "no attorney ever reviewed this" a visible, provable
gap on every single output, rather than a pattern the FTC had to establish in aggregate
through investigation. This is a speed-and-visibility case, close to Rite Aid in shape: proof
of an absence, made cheap and immediate instead of expensive and retrospective.

**The discovery question it generates.** "For outputs you market as equivalent to
professional judgment, do you have a per-output record of who — or what credentialed process —
reviewed it, or only a description of the review process you intend to run?"

---

## 6. Air Canada — *Moffatt v. Air Canada*

**What happened.** In November 2022, a customer used Air Canada's website chatbot to ask
about bereavement fares; the chatbot told him he could apply for a bereavement discount
retroactively, contradicting Air Canada's actual written policy, which required the request
before travel. Air Canada refused the retroactive discount and argued in the tribunal that the
chatbot was a separate legal actor and that the customer should have verified the chatbot's
answer against the static policy page.

**The governance failure.** No deterministic check of the chatbot's output against the actual
policy document it was supposed to represent, and no version binding between what the chatbot
said and the policy text in force at that moment — the chatbot was answering from a stale or
unverified representation of the policy, with nothing catching the contradiction before it
reached the customer.

**The outcome.** [verified] *Moffatt v. Air Canada*, 2024 BCCRT 149 (B.C. Civil Resolution
Tribunal, Feb. 14, 2024; canlii.org/en/bc/bccrt/doc/2024/2024bccrt149): negligent
misrepresentation found against Air Canada. Both defenses were rejected — the "algorithmic
separability" argument (that the chatbot was a distinct entity, not simply part of the
airline's website) and the "hyperlink cure" argument (that the customer should have
cross-checked the chatbot against the static policy page). Damages of $650.88 CAD plus
tribunal fees, ~$812.02 CAD total.

**Which evidence block would have been at issue.** `model` plus `policy` version: which
policy version the chatbot's response was actually grounded in (or whether it was grounded in
any specific version at all), and whether the output was checked against that version before
being shown to the customer.

**What a per-decision evidence record would and would not have done.** It would not have
prevented the chatbot from generating an incorrect answer in the first place — that is a
model-grounding and verification-pipeline problem (the source document's recommended control:
"closed-domain RAG on validated policy, deterministic verification of outputs against business
rules"), not an evidence problem. What it would have done, had the underlying system
generated one: a record binding the specific chatbot response to a `policy_id`/`policy_version`
and a fingerprint of the input context would have let Air Canada determine, immediately and
without a tribunal proceeding, exactly which policy text the bot was working from when it gave
the wrong answer — useful for a fast internal fix, and for demonstrating (or disproving)
whether this was a one-off or a systemic grounding failure. It would not have changed the
liability finding: Air Canada was found liable because the chatbot's output was wrong and the
company is responsible for its own website, a conclusion evidence about *how* it was wrong
does not disturb.

**The discovery question it generates.** "If your customer-facing AI gives an answer that
contradicts your written policy, can you show which version of that policy the AI was actually
grounded in at that moment — or only that a general RAG pipeline exists?"

---

## 7. iTutorGroup, Inc.

**What happened.** iTutorGroup's applicant-screening software was configured to automatically
reject female applicants aged 55+ and male applicants aged 60+, filtering out more than 200
qualified tutoring candidates in 2020. The discrimination was discovered when a rejected
applicant reapplied with a falsified, more recent birth date and was immediately offered an
interview. The EEOC brought its first AI-hiring-discrimination suit over this conduct.

**The governance failure.** The discriminatory criterion was not a bias that emerged from
training data or model drift — it was an explicit, intentional configuration choice (a hard
age cutoff) coded directly into the screening logic, with no pre-deployment disparate-impact
review and no human step between the automated rejection and the applicant.

**The outcome.** [verified] EEOC v. iTutorGroup, Inc. et al. (E.D.N.Y.), joint notice of
settlement Aug. 9, 2023 (eeoc.gov/newsroom/itutorgroup-pay-365000-settle-eeoc-discriminatory-hiring-suit):
$365,000 settlement for the class of 200+ rejected applicants, plus injunctive relief —
mandatory anti-discrimination training for hiring staff, a new anti-discrimination policy, and
an injunction against using automated tools to screen by age or request birth dates.

**Which evidence block would have been at issue.** `model`/`policy` — the screening criteria
were the policy, coded into the model configuration, applied identically and automatically to
every applicant. There is no `human_review` block to speak of: the record would show a
fully-automated rejection with no human step at all.

**What a per-decision evidence record would and would not have done.** This is the case
worth being most honest about, because a per-decision evidence record here does something
uncomfortable: it does not help the company. A `DecisionEvidence` record for each of the 200+
rejections would have faithfully shown "policy version X, threshold age < 55/60, model
applied policy exactly as configured, human_review: none" — cryptographically signed,
consistent across every single applicant. That is not a defense; it is a signed admission of
systematic, uniform application of an illegal criterion, which if anything strengthens a
disparate-treatment claim (deliberate, consistent policy) over a disparate-impact one (emergent,
statistical bias) — generally a *worse* position for the defendant, not a better one. Evidence
infrastructure does not distinguish between "the policy was applied faithfully" and "the
policy was applied faithfully and the policy was illegal." It proves the former and is
indifferent to the latter. The only place evidence genuinely helps here is pre-deployment: if
producing a `DecisionEvidence`-shaped record were part of a mandatory pre-launch bias-audit
gate, the audit reviewing threshold values before go-live (not the per-decision record after
launch) is what would have caught this — and that is a validation-process control, not an
evidence-product feature.

**The discovery question it generates.** "If every rejection your screening tool has made
this year were laid out in a single, undeniable, signed table — threshold applied, criterion
used, no human step — are you confident about what that table would show?"

---

## 8. Workday, Inc. — *Mobley v. Workday*

**What happened.** Workday's AI-powered applicant screening and ranking features (including
HiredScore) were alleged to produce systemic disparate impact by race, age, and disability
across the many employers using them. A federal court held in 2024 that while Workday was not
itself an "employment agency," it could be a Title VII/ADEA/ADA "agent" of the employers using
its tools — exposing the vendor, not just its customers, to direct discrimination liability.

**The governance failure.** No customer-specific, per-decision accountability trail across a
one-to-many vendor relationship: one scoring model operating inside potentially thousands of
employers' hiring pipelines, with no mechanism to attribute a specific adverse outcome to a
specific model version, a specific customer's configuration, or a specific decision, only an
aggregate statistical pattern visible after years of use.

**The outcome.** [verified] *Mobley v. Workday, Inc.*, No. 4:23-cv-00770 (N.D. Cal.): July 12,
2024, the court dismissed the "employment agency" theory but allowed the "agent" theory to
proceed to discovery (Seyfarth Shaw, Mondaq client alerts, July 2024). May 16, 2025, the court
granted conditional nationwide ADEA collective certification (Judge Rita Lin; Fennemore,
Labor and Employment Law Insights, May–July 2025). July 7, 2025, the court ordered Workday to
identify and produce a list of customers using the relevant AI screening features so affected
applicants could be notified — pulling employer customers into the case's discovery scope
(Labor and Employment Law Insights, July 2025); a notice plan was approved and the customer
list produced in Dec. 2025. **[verified, and a correction to the source document]**: the
source document characterizes a "May 2026" ruling as holding that "internal bias audits are
discoverable... unless counsel designed, curated and supervised the testing." The actual
May 28, 2026 order (Magistrate Judge Laurel Beeler) reached the opposite result on Workday's
specific facts: the court **denied** plaintiffs' motion to compel Workday's bias-testing data,
finding it protected by attorney-client privilege because Workday's attorneys had curated it
and used it to give legal advice, and separately denied a motion to compel Workday's
customers' applicant data (Duane Morris, Norton Rose Fulbright, "Behind the Privilege Shield,"
June 2026). The *general principle* in the source document is directionally correct and is
exactly what this ruling illustrates — bias testing conducted at counsel's direction can stay
privileged; testing run as an ordinary business function generally will not — but the ruling
itself is a case where privilege *held*, not a holding that audits are broadly discoverable.
Cite the June 2026 commentary, not the source document's phrasing, if this comes up with a
customer.

**Which evidence block would have been at issue.** `model` — but the sharper issue is
`institution`/attribution across a vendor-to-many-customers topology: a single scoring model's
`DecisionEvidence` records are meaningless without being attributable to the specific
customer's configuration and the specific applicant decision, at a scale (potentially millions
of applicants across dozens of Fortune 500 employers) our schema has not been tested against.

**What a per-decision evidence record would and would not have done.** It would not have
prevented disparate impact from an already-biased scoring model — that is a pre-deployment
validation question. What it plausibly would have changed: individual per-decision records,
each attributing a specific score to a specific model version and a specific customer's
threshold configuration, would have let a plaintiff or regulator establish which employer's
configuration produced the disparity — and how many applicants were affected — in months
rather than through two years of certification litigation and a compelled customer-list
production. It is a speed-and-attribution case, not a prevention case. The May 2026 privilege
ruling is directly relevant to how we would need to structure any bias-audit feature we build:
if we want a customer's own bias testing to survive discovery, that testing needs to be
structured under counsel from the start, mirroring exactly what protected Workday's data here
— worth internalizing for our own audit-feature design, not just as a case study.

**The discovery question it generates.** "If one of your vendor's AI hiring tools showed a
disparate outcome across your applicant pool, could you produce, per rejected applicant,
which model version and which of your configured thresholds produced that outcome — or would
you have to ask the vendor and wait?"

---

## 9. UnitedHealth Group / naviHealth — *Estate of Lokken*

**What happened.** naviHealth's nH Predict model forecast a post-acute-care patient's length
of stay; UnitedHealth allegedly used those forecasts to batch-deny continued coverage,
overriding treating physicians' recommendations. Reviewers were allegedly held to a
sub-1%-variance target against the model's projection and faced discipline for approving stays
that deviated from it. Multiple estates sued in 2023 alleging breach of contract and bad
faith.

**The governance failure.** The nominal human review step existed on paper, but the reviewers
performing it were incentivized — under threat of discipline — to rubber-stamp the model's
output rather than exercise the independent clinical judgment the health plan's own terms
required. A `human_review` step that cannot deviate from the model without punishment is not
a review; it is a second signature on the model's decision.

**The outcome.** [verified] *Estate of Gene B. Lokken et al. v. UnitedHealth Group, Inc. et
al.*, No. 0:23-cv-03514 (D. Minn.): on Feb. 13, 2025, Judge John R. Tunheim granted in part
and denied in part the motion to dismiss, allowing the breach of contract and breach of the
implied covenant of good faith and fair dealing claims to proceed while dismissing unjust
enrichment, negligence per se, and several state unfair-practices claims with prejudice
(courthousenews.com order PDF; minnlawyer.com, Feb. 18, 2025). Discovery into the algorithm's
design has proceeded (ArentFox Schiff, "Federal Court Orders Broad Discovery Against UHC in AI
Coverage Denial Lawsuit"); class-certification declarations were due Sept. 14, 2026.
[unverified — pled allegation, not a judicial finding] The complaint's specific claims that
"over 90% of denials and 80% of preauthorization denials were reversed on appeal" and that
reviewers were held to a **1% variance band** are allegations reported in secondary coverage
of the complaint, not yet adjudicated facts — flag this distinction explicitly if this case is
cited to a customer; the case has survived a motion to dismiss, which tests plausibility, not
proof.

**Which evidence block would have been at issue.** `human_review`, under duress — the
mapping the founder specifically wants preserved: this is not a missing review step, it is a
review step whose independence was structurally compromised by a management incentive
running in parallel with it.

**What a per-decision evidence record would and would not have done.** It would not have
stopped management from setting a variance target and disciplining reviewers who missed it —
that is a personnel-policy and incentive-design failure, external to any single decision
record. What it plausibly would have done: a `human_review` block with a mandatory
`override: bool` and `override_reason` field, populated identically for every decision and
independently exportable (not editable after the fact by the company that generated it),
aggregated across thousands of decisions, would have made a near-zero override rate visible as
a statistical anomaly — internally, to a compliance function, or externally, to a regulator or
plaintiff's expert — far faster than years of individual case litigation and formal discovery
were required to establish the same pattern. This is closer to the Cigna case than to Zillow:
the evidence would not have stopped the incentive from being set, but a record designed so the
company itself cannot quietly suppress the "override" signal would have made the coercion
pattern visible on its own before litigation, not just discoverable during it. The caveat: it
would not, on its own, capture the disciplinary threat itself (that lives in HR records and
management communications, not in a decision record) — it would only make the *symptom*
(suspiciously low deviation rate) visible early.

**The discovery question it generates.** "Across your last quarter of AI-assisted coverage or
underwriting decisions, what percentage of cases had a human reviewer approve something
different from what the model recommended — and do you know that number today, or would you
have to go find it?"

---

## 10. Cigna — *Kisting-Leung v. Cigna*

**What happened.** Cigna's PxDx system batch-reviewed medical necessity claims; ProPublica
reporting, cited in the litigation, found that Cigna's medical directors denied more than
300,000 claims over two months in 2022 while spending an average of 1.2 seconds per claim,
often in batches of hundreds without opening individual patient files. Plaintiffs sued
alleging this could not constitute the individualized medical review the health plans'
governing terms required.

**The governance failure.** A `human_review` step existed in name — a licensed medical
director's signature was attached to every denial — but the duration of that "review" makes
clear no individualized review occurred. This is the sharpest case in the library because the
governance failure and the evidence that exposed it are the same fact: a timestamp.

**The outcome.** [verified] *Kisting-Leung v. Cigna Corp.*, No. 2:23-cv-01477 (E.D. Cal.): in
March 2025, Judge Dale Drozd allowed ERISA fiduciary-breach claims (29 U.S.C. §1104) and
claims under California Health & Safety Code §1367.01(e) — via ERISA's insurance
savings-clause — to proceed, while finding three of six named plaintiffs lacked standing on
some counts because they could not disprove Cigna's assertion that PxDx was not used on their
specific claims (digitalhealthcare.law, May 14, 2025; app.midpage.ai case summary). The
underlying "1.2 seconds per claim, 300,000+ claims in two months" figure originates in
ProPublica investigative reporting and is cited in the litigation, not itself a separate
regulatory or judicial finding of fact — worth being precise about that distinction with a
customer.

**Which evidence block would have been at issue.** `human_review` — and specifically the one
field the founder is right to flag as the whole case: **duration**. Not whether a review
happened (Cigna's records presumably show a reviewer's name and a decision on every claim) but
how long it took, which is not a field anyone was required to capture, examine, or notice
internally until an outside investigation did.

**What a per-decision evidence record would and would not have done.** This is the one case
in this library where the honest answer leans toward "materially changed," not merely "changed
the speed of proving it." A `human_review` block with mandatory `reviewed_at` and a derivable
duration (time between the record being opened and the reviewer's action) — signed at the time
of each decision, not reconstructible or editable after the fact — would have made "our medical
directors are averaging 1.2 seconds per claim" a fact visible to Cigna's own compliance
function continuously, from the first month of the practice, not a fact ProPublica had to
discover externally through reporting years later. It would not have stopped a medical
director from moving fast if nothing was watching the duration field — the practice requires
someone, internal or external, to actually look at the aggregate. But unlike Zillow (where the
overriding executives had unambiguous authority to override and evidence only documents that),
here the practice was almost certainly *not* something Cigna's own leadership would have
knowingly defended as policy if it had been visible to them in real time — mass sub-2-second
"reviews" is not a position anyone drafts as an explicit policy, unlike Zillow's override or
iTutorGroup's age cutoff. That makes this the strongest case for evidence infrastructure
functioning as an internal early-warning system rather than only a post-hoc discovery
accelerant.

**The discovery question it generates.** "Do you know the average time your reviewers spend
on an AI-assisted decision before approving or denying it — and if that number turned out to
be under two seconds, would you find out from your own systems, or from a reporter?"

---

## 11. Foodinho S.r.l. (Glovo)

**What happened.** Foodinho, a Glovo subsidiary, used an opaque algorithm to dispatch and
score delivery couriers, determining shift access and standing largely through automated
profiling. Couriers were subject to adverse actions, including suspension, with no meaningful
human review and no disclosure of the logic behind the scoring. Italy's data protection
authority (Garante) investigated and fined the company in 2021.

**The governance failure.** No GDPR Article 22-compliant human-in-the-loop review of adverse
automated decisions, no Article 13/14 disclosure of the logic involved, and consent/notice to
couriers that did not meet the transparency bar for automated profiling with material
consequences for their livelihood.

**The outcome.** [verified] Garante per la protezione dei dati personali, decision against
Foodinho S.r.l. (2021): €2.6 million fine (EDPB national-news summary,
edpb.europa.eu/news/national-news/2021/riders-italian-sa-says-no-algorithms-causing-discrimination-platform-glovo_en;
corroborated by AlgorithmWatch and Silicon Republic reporting). Note: some secondary sources
report different figures (e.g., "$3M," "€5M") for related or subsequent Glovo/Foodinho
enforcement — the EDPB's own summary for this specific 2021 decision states €2.6M, matching
the source document; if a different figure surfaces in later research it likely refers to a
separate or amended action and should be checked against the specific Garante docket before
being conflated with this one.

**Which evidence block would have been at issue.** `data`/consent, plus `human_review` — both
the transparency obligation (what data fed the score, disclosed to the subject) and the
absence of a genuine human review step before an adverse action.

**What a per-decision evidence record would and would not have done.** It would not have made
the dispatch algorithm less opaque by design — that is a model-transparency and disclosure
choice, not an evidence-capture choice. What it would have done: a `consent` block with a
scope and grant record, and a `human_review` block that is required to be populated (not
optional) before any adverse action like a suspension takes effect, would have made "there was
no human review of this suspension" a visible, per-incident, provable fact for any individual
courier immediately — rather than something that took a regulator's investigation to establish
in aggregate across thousands of riders. Speed-and-individual-provability, not prevention: a
courier with a signed record showing no review occurred could contest a specific suspension in
days; without it, only a systemic regulatory investigation could establish the pattern, which
is what happened here.

**The discovery question it generates.** "If one of your gig workers or customers disputed an
automated suspension or rejection today, could they get a specific record showing a human
reviewed their specific case — or only your general policy describing that reviews are
supposed to happen?"

---

## Summary table

| # | Entity | Forum | Primary evidence blocks | Verified independently? |
|---|---|---|---|---|
| 1 | Zillow Group | Capital markets / board | policy/threshold override, human_review | Core figures verified; cumulative totals unverified |
| 2 | Rite Aid | FTC File No. 2023190 | model, data | Verified |
| 3 | Delphia | SEC IA-6535 | model | Verified |
| 4 | Global Predictions | SEC (Mar. 2024) | model | Verified |
| 5 | DoNotPay | FTC (Operation AI Comply) | model, evidence | Verified |
| 6 | Air Canada | BC CRT 2024 BCCRT 149 | model, policy version | Verified |
| 7 | iTutorGroup | EEOC (E.D.N.Y.) | model/policy, (no human_review) | Verified |
| 8 | Workday | N.D. Cal. 4:23-cv-00770 | model, institution/attribution | Verified; source doc's May 2026 characterization corrected above |
| 9 | UnitedHealth/naviHealth | D. Minn. 0:23-cv-03514 | human_review (under duress) | MTD ruling verified; 1% figure is a pled allegation |
| 10 | Cigna | E.D. Cal. 2:23-cv-01477 | human_review (duration) | Verified; 1.2s figure is ProPublica reporting cited in suit |
| 11 | Foodinho/Glovo | Garante (Italy) | data/consent, human_review | Verified |
