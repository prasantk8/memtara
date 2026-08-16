# CBUAE Regulatory Matrix — Memtara × AIHOOTS

**Source document.** *Guidance Note on Consumer Protection and the Responsible
Adoption and Use of Artificial Intelligence and Machine Learning by Licensed
Financial Institutions in the U.A.E.*, Central Bank of the UAE.
Held in this repository at
[`tests/aihoots_reference/CBUAE_EN_6958_VER1.pdf`](../tests/aihoots_reference/CBUAE_EN_6958_VER1.pdf)
(vendored as a git submodule of the sister repo `aihoots-e1-audit-gateway`).
Classification: Public. 7 pages, 10 numbered sections.

**Systems in scope.**

| System | Repo | Role in the control set |
|---|---|---|
| **Memtara** | this repo | Zero-knowledge attribute disclosure. Proves a *predicate* about a consumer (income ≥ X, residency valid, not a PEP) without transmitting the underlying attribute. Rust/Axum backend + 5 Noir circuits. |
| **AIHOOTS E1** | `tests/aihoots_reference` (live at `ai.aihoots.com`) | LLM audit gateway. OpenAI-compatible proxy that policy-checks every prompt and writes a SHA-256 hash-chained, independently verifiable audit trail. |

---

## Reading notes before the matrix (please read — the brief's clause numbers don't exist)

Three things a reviewer needs to know up front, because the working brief that
commissioned this document assumed a document structure the actual PDF does not
have:

1. **Clause numbering.** The Guidance Note numbers *sections* 1–10 and letters
   its sub-clauses (`2(a)`, `4(c)`, `5(d)`…). There is no `4.3` and no `5.2`.
   This matrix uses the real identifiers throughout. The brief's shorthand maps
   as follows:

   | Brief said | Actual clause | What it actually says |
   |---|---|---|
   | "Clause 4.3 (Transparency)" | **§4(c)** | LFIs should consider **opt-out rights** for customers, particularly for high-impact decisions. |
   | "Clause 5.2 — Consent" | **§5(b)** | Data used in AI/ML must be of sufficient **quality and relevance** and kept updated. |
   | — | **§5(c)** | This is the closest clause to a consent/purpose-limitation obligation: personal data collected, stored and used only for **legitimate and proportionate purposes**, in-country retention, per Consumer Protection Standards. |

   Where downstream artefacts in this repo cite a `regulatory_audit_id`, they
   cite the **real** identifier (e.g. `CBUAE-5c`), not the brief's shorthand.

2. **Five principles vs. ten sections.** The brief asked for five core
   principles. The document has ten sections; the five named in the brief are
   real and are §2, §3, §4, §5 and §7. The other five (§1 Definitions,
   §6 Continuous Monitoring, §8 Integration with Existing Frameworks,
   §9 Outsourcing and Third-Party Risk, §10 Ethical Collaboration) are
   substantive obligations and are mapped below as well, per the instruction to
   map *every* clause.

3. **Issue date.** The PDF body carries no printed issue date — only the file
   identifier `CBUAE_EN_6958_VER1`. This matrix therefore cites the document by
   identifier rather than by a month. Anyone reproducing this against a
   later-versioned Guidance Note should re-run the clause extraction first.

**One more framing point, stated plainly.** Neither Memtara nor AIHOOTS is a
Licensed Financial Institution. Every obligation in the Guidance Note binds the
**LFI**. What these two systems supply is *evidence* — the artefact an LFI hands
its Audit and Risk Committee, or the CBUAE, to show a control was actually
operating, rather than asserted in a policy document. Each row below therefore
separates **what the systems provide** from **what remains the LFI's own
obligation**. A matrix that claimed 35/35 clauses "satisfied by software" would
be the kind of compliance theatre this document exists to replace.

---

## The five named principles at a glance

| # | Principle | Section | Primary system | Coverage |
|---|---|---|---|---|
| 1 | Governance and Accountability | §2 | AIHOOTS (evidence), LFI (framework) | Partial — evidence layer only |
| 2 | Fairness / Non-Discrimination and Ethics | §3 | AIHOOTS (measurement) + **Memtara (structural)** | Partial — see §3(a) note on structural bias-blindness |
| 3 | Transparency and Explainability | §4 | AIHOOTS (decision record) + Memtara (disclosure UI) | Strong |
| 4 | Data Quality, Privacy and Security | §5 | **Memtara (primary)** | **Strong — this is Memtara's clause** |
| 5 | Human Oversight and Consumer Protection | §7 | Memtara (consent + revocation) + AIHOOTS (kill path) | Strong |

### Why §5 is Memtara's clause

§5(d) requires **privacy-by-design** to be *incorporated into* AI systems.
Almost every implementation of that clause in the market is procedural: an
access-control matrix, a retention schedule, a DPIA. Those controls all share a
defect — the sensitive attribute is still *present* in the system, and the
control is a promise about who looks at it.

Memtara removes the attribute from the flow entirely. A mortgage pre-approval
model does not receive a salary figure and promise not to log it; it receives a
cryptographic proof that `income ≥ threshold` is true, generated on the
consumer's device, where the salary figure never left. The public inputs of the
`tax_session` circuit are `current_time, expiry_time, vault_root, min_income,
max_income, user_public_key_x, user_public_key_y, nonce`
([`backend/api/src/verify/mod.rs`](../backend/api/src/verify/mod.rs)) — the
threshold is public, the income is not, and there is no code path by which the
backend could see it. `ARCHITECTURE.md` records this as a hard design
constraint: **the backend never proves, only verifies**, precisely because
generating a proof requires plaintext witnesses.

That converts §5(d) from a policy commitment into a structural property. Data
minimisation you can fail to enforce is a control; data minimisation that is
impossible to violate without changing the circuit is an architecture.

---

## Clause-by-clause matrix

Legend for **Coverage**:
**■ Direct** — the systems produce the artefact the clause asks for.
**◧ Contributing** — the systems supply necessary evidence; the clause is not
discharged by them alone.
**□ LFI-only** — organisational obligation; no software can discharge it. Listed
for completeness because the clause exists.

---

### §1 — Definitions

| Clause | Obligation | Coverage | Memtara | AIHOOTS | Remains the LFI's obligation |
|---|---|---|---|---|---|
| §1 "AI" / "GenAI" / "ML" | Defines the systems in scope. | ◧ | Memtara's ZK circuits are **not** AI/ML — they are deterministic cryptographic constraint systems. Memtara enters scope as the *data supply* to an in-scope AI system, not as one. Stating this correctly is itself a scoping control. | The gateway is the boundary at which GenAI enters the institution; every call through it is in scope by construction. | Maintain the AI inventory (§9(c)) that decides which systems are in scope. |
| §1 "High-impact decision" | Any AI determination materially affecting access to a financial product or service — e.g. a loan application or insurance claim. | ■ | Memtara's `disclosure_requests` row *is* the machine-readable marker of a high-impact decision: it names the org, the consumer, the predicate, and a TTL. Mortgage pre-approval and Golden Visa onboarding ([`docs/journeys.md`](journeys.md)) are exactly the §1 examples. | `x-caller-id` plus the `decision` event tags each LLM interaction to its caller. | Classify which of its own decisions are high-impact; the schema records the classification, it doesn't make it. |
| §1 "MMS" | Model Management Standards apply to AI governance, use and validation. | □ | — | — | Apply the MMS. Referenced by §2(a), §6(a), §9(a). |

---

### §2 — Governance and Accountability

| Clause | Obligation | Coverage | Memtara | AIHOOTS | Remains the LFI's obligation |
|---|---|---|---|---|---|
| **§2(a)** | Documented governance framework, proportionate to size and complexity; culture of responsible use; follow MMS principles. | ◧ | Design decisions are recorded with alternatives and rationale (`ARCHITECTURE.md`, `HANDOFF.md`), which is the evidentiary substrate a framework points at. | ADR-001…ADR-008 record every architectural choice *with the alternatives that lost* — an auditable decision history rather than a conclusions-only document. | Author and approve the framework itself. Software supplies the evidence; the Board supplies the framework. |
| **§2(b)** | Senior management and Board accountable for AI systems and outcomes; **LFIs should not employ AI models they have no control over.** | ◧ | Memtara issues short-lived, revocable grants — `POST /disclosure-requests/:id/revoke` kills a disclosure immediately; there is no long-lived bearer credential to chase. | The gateway is the *sole* network path to the model (`docker-compose.yml`: the model container is on an internal-only network, unreachable from the host). "Control over the model" is enforced by network topology, not by policy. | Board-level accountability assignment; resourcing; the decision to deploy at all. |
| **§2(c)** | Regular reporting to Senior Management and Boards covering performance and risk. | ■ | `GET /orgs/:id/audit-log` returns that org's own hash-chained trail of disclosure requests, proof verifications, and rejections. | `GET /metrics` returns deterministic behavioural analysis (z-score / EWMA over the audit log, ADR-003) — a reporting surface derived from evidence rather than self-reported. | Set the reporting cadence and the escalation thresholds. |
| **§2(d)** | Governance structures enable informed decisions, risk identification/mitigation, alignment to risk appetite; AI risk consolidated into the governance framework with roles for Audit and Risk Committee, Risk, Internal Audit, IT. | ◧ | Per-org scoping (`orgs`, API-key auth) means Internal Audit can be given a read-scoped credential without granting disclosure-creation rights. | `audit-verify` is a standalone CLI: Internal Audit can verify the chain **without** the gateway team's cooperation, which is what makes the assurance independent. | Define the committee structure and the roles. |
| **§2(e)** | Risk committees and control functions must understand AI-driven processes and be able to **challenge outcomes**. | ■ | A challenge needs a re-checkable artefact. Every stored proof (`proofs.public_inputs`, `proofs.proof_bytes`) can be re-verified from scratch against the circuit's verification key — a control function can independently re-run `bb verify` and get the same yes/no. | Any historical record can be recomputed and compared; `audit-verify` names the exact `seq` of a broken record. | Staff and train the control functions to actually exercise this. |

---

### §3 — Fairness / Non-Discrimination and Ethics

| Clause | Obligation | Coverage | Memtara | AIHOOTS | Remains the LFI's obligation |
|---|---|---|---|---|---|
| **§3(a)** | AI/ML must not produce discriminatory or manipulative outcomes; no such system may be deployed, or allowed to become so post-deployment. | ◧ | **Structural, and worth stating precisely.** A model cannot discriminate on an attribute it never receives. Memtara's disclosure is predicate-scoped: the `identity_session` and `tax_session` circuits transmit a boolean or a threshold result, not the protected attribute behind it. This narrows the *feature surface* on which bias can act. It does **not** eliminate proxy discrimination — a threshold can itself correlate with a protected class, and Memtara cannot detect that. | Prompt and decision digests give a corpus against which disparate-outcome testing can be run. | **The bias testing itself.** Neither system measures disparate impact. This is the largest genuine gap in this matrix and should be logged as such. |
| **§3(b)** | Training data must be accurate, relevant and representative of the customer populations served. | □ | Not applicable — Memtara has no training data; a ZK circuit is a fixed constraint system. | Not applicable — the gateway does not train models. | Entirely the LFI's (or its model vendor's) obligation. Flagged as **not covered**. |
| **§3(c)** | Periodic testing — at least annually and on every material change/upgrade — to identify and remediate embedded bias; deployment must reflect ethical standards; decisions consistent with the duty to act honestly, fairly, in consumers' best interests. | ◧ | Circuit changes are detectable: verification keys are derived from compiled bytecode, so a changed circuit produces a different vkey and previously-valid proofs stop verifying. Silent model substitution is not possible. | The eval harness (ADR-005/006, `src/eval`) runs a labelled attack corpus and scores it — a repeatable, versioned test rather than an assertion. | Run the annual bias test and act on its findings. Schedule and remediation are organisational. |

---

### §4 — Transparency and Explainability

| Clause | Obligation | Coverage | Memtara | AIHOOTS | Remains the LFI's obligation |
|---|---|---|---|---|---|
| **§4(a)** | Be transparent with customers about AI use, particularly for high-impact decisions and when the customer is interacting with an AI; be clear how AI systems operate and decide, and **be able to disclose the same**. | ■ | The disclosure-review screen is a pre-consent statement of exactly what will and will not cross — the wireframe's "What They Receive / What Stays Private" split ([`docs/journeys.md`](journeys.md), mortgage pre-approval). The consumer sees the predicate before approving it. | Every request produces a `decision` event recording allow/redact/block **with its reasons** (`detail.reasons`). "Be able to disclose the same" is satisfied by a record that already exists, not by a reconstruction after the fact. | Customer-facing disclosure copy and its placement in the journey. |
| **§4(b)** | Plain-language, accurate disclosures in **both Arabic and English**; telephone support in all major UAE languages; measures to check understandability. | □ | Journey 6 (government-counter-assisted) specifies an Arabic-first RTL kiosk mode with icon-led and spoken confirmation — a design commitment, **not yet built**. | — | **Not covered.** Bilingual disclosure, telephone support, and comprehension testing are all outstanding. Flagged honestly as a gap. |
| **§4(c)** | Consider **opt-out rights**, particularly for high-impact decisions, weighing risk, fairness and feasibility. *(the brief's "Clause 4.3")* | ■ | Opt-out is the default state, not a feature: a `disclosure_requests` row is created `pending` and stays pending until the consumer generates a proof. Declining is simply not acting; there is no data flow to withdraw from. `POST /:id/revoke` covers withdrawal after the fact. | A blocked request produces no response event — the *absence* is itself evidence that no AI processing occurred. | Offer, and staff, the non-AI alternative path (§7(c)). |

---

### §5 — Data Quality, Privacy and Security *(Memtara's principal clause)*

| Clause | Obligation | Coverage | Memtara | AIHOOTS | Remains the LFI's obligation |
|---|---|---|---|---|---|
| **§5(a)** | Policies ensuring AI/ML models use accurate, relevant, up-to-date data with **clear provenance and audit trails**. | ■ | Provenance is cryptographic. Every proof commits to a `vault_root` (a Poseidon commitment over the consumer's vault) and is signed under the consumer's Baby Jubjub key, verified in-circuit (`circuits/lib/src/signature_verify.nr`). A predicate result cannot be fabricated by the relying party, or by Memtara. | Prompt/response digests plus a hash chain give the model-side audit trail. | Freshness policy — how old a vault record may be before re-verification is required. |
| **§5(b)** | Data of sufficient quality and relevance, updated as necessary, compliant with the **UAE Personal Data Protection Law** and **Information Assurance Regulation**. *(the brief's "Clause 5.2")* | ◧ | Relevance is enforced mechanically: a circuit accepts a fixed public-input arity and a policy-bound predicate, so an over-broad request is a *malformed* request. Vault versioning (`vault_blobs.version`, compare-and-swap) makes staleness detectable. | — | PDPL registration, lawful-basis analysis, and IAR controls at the institution level. |
| **§5(c)** | Personal data collected, stored and used per applicable law including Consumer Protection Standards and **in-country data-retention rules**; only for **legitimate and proportionate purposes**; outsourcing per §9. | ■ | This is the strongest clause fit in the document. *Proportionality* is enforced by the circuit: the relying party receives one boolean or one range result and mathematically nothing else. *Collection* is minimised because the raw attribute is never transmitted — so *storage* and *residency* obligations do not attach to data the institution never holds. The vault is AES-256-GCM encrypted client-side under a key the server never sees (`vault/src/encryption.rs`); `vault_blobs.ciphertext` is opaque to the operator. | Digests, not payloads, are stored in the chain (ADR-001) — the audit trail does not become a second copy of sensitive text. | Residency of the *remaining* systems; retention schedules for records that are still held. |
| **§5(d)** | **Privacy-by-design and security-by-design** incorporated into AI systems; safeguards against unauthorised access or misuse; robustness and safety integral; stress testing and validation across scenarios; operational resilience — redundancy, contingency planning, incident response. | ■ | Privacy-by-design in the literal sense: the plaintext is not in the system to protect. Security-by-design: nonces are single-use and enforced by a primary key on `used_nonces` (a database constraint, not application logic); proof submission is time-bounded in-circuit; invalid proofs are recorded but **do not** consume the legitimate holder's nonce, so a third party cannot burn a consumer's one-shot grant. | Injection-pattern and oversized prompts are blocked pre-flight; the model is network-isolated; tamper-detection is tested at *every* record position, not just the last. | Redundancy, DR and incident-response runbooks. Neither system provides availability guarantees — `ARCHITECTURE.md` and AIHOOTS's ARCHITECTURE both state this limit explicitly. |
| **§5(e)** | Assess and, where feasible, use AI to identify fraud, AML disparities and suspicious activity; comply with reporting obligations on material findings. | ◧ | The bank AML/STR journey is the first-class use case: PEP status, sanctions match and risk band are disclosed as predicates for STR narrative resolution, without exposing source-of-funds documents ([`docs/journeys.md`](journeys.md)). | Statistical analysis over the audit log (ADR-003) surfaces anomalous interaction patterns. | Operate the AML programme and file the reports. |

---

### §6 — Continuous Monitoring and Review

| Clause | Obligation | Coverage | Memtara | AIHOOTS | Remains the LFI's obligation |
|---|---|---|---|---|---|
| **§6(a)** | Continuous monitoring per MMS, for reliability, relevance and alignment with consumer-protection objectives. | ◧ | Every verification outcome — pass **and** fail — is persisted (`proofs.valid`) and audited. A rising invalid-proof rate is a monitorable signal. | `/metrics` computes z-score/EWMA over the live chain. | Define thresholds and who watches them. |
| **§6(b)** | Consistently monitor, review, update or **cease** using models given changes in data, market or behaviour; periodically engage independent third parties willing to challenge the LFI's AI use. | ◧ | Independent challenge is possible without vendor cooperation: proofs re-verify against a published verification key. | `audit-verify` is designed for exactly this — an outside party runs it on the log and gets a verdict. | Commission the third-party reviews. |
| **§6(c)** | Automatic updates to AI tools must be tested before implementation; the LFI must be fully aware of them; updates must not introduce bias. | ■ | Circuit updates cannot be silent: recompiled bytecode yields a different verification key, and every previously-issued proof fails against it. Version drift is loud by construction. | Pinned image digests in `docker-compose.yml` (`ollama/ollama:0.5.7`, ADR-002) — no floating `latest` tag. | Change-approval process for accepting an update. |
| **§6(d)** | Mechanisms to detect, report and remediate performance issues, bias or unintended consequences — before implementation and over time. | ◧ | Rejected proofs are recorded with their reason and enter the audit chain. | Policy decisions with reasons; eval harness scoring (ADR-005/006). | Remediation workflow and ownership. |
| **§6(e)** | Remain responsible for outsourced AI functions; consider audit/information rights, awareness of material developments, termination rights, data protection, cyber security, performance guarantees, regulatory compliance. | ◧ | Org API keys are individually revocable — contractual termination has a technical counterpart that takes effect immediately. | Audit rights are structural: the LFI holds the log, not the vendor. | Contract terms. |
| **§6(f)** | Retain **clear and immediate ability, with human intervention, to cease use** of any deployed AI model or application. | ■ | `POST /disclosure-requests/:id/revoke` and session-token revocation both take effect on the next request — this is precisely why the design chose opaque revocable tokens over JWTs for *session* auth (`ARCHITECTURE.md`; the wireframe's "Auto-Revokes In 14:59" depends on it). Note the deliberate contrast with the short-lived **proof token** introduced for AIHOOTS: see the caveat below this table. | Stopping the gateway stops all model access — the model is not reachable by any other route. | Name the humans who hold the kill switch. |
| **§6(g)** | Systems to stay current with legal, third-party and market developments affecting AI use. | □ | — | — | Entirely organisational. **Not covered.** |

> **Caveat on §6(f) and the proof token.** The proof token issued by
> `POST /api/v1/issue-proof` is a **300-second, non-revocable JWT** — an
> intentional trade to satisfy the zero-latency integration requirement (AIHOOTS
> validates it offline against the JWKS endpoint, with no synchronous callback to
> Memtara). The consequence, stated plainly: a proof token cannot be revoked
> inside its 5-minute lifetime. The revocable primitives are the *disclosure
> request* (revoke before issuance) and the *session token* (revoke to prevent
> re-issuance). An LFI whose risk appetite requires sub-5-minute revocation must
> either shorten `MEMTARA_PROOF_TOKEN_TTL_SECONDS` or accept a synchronous
> introspection call, giving up the zero-latency property. This is a design
> trade-off with a named owner, not an oversight.

---

### §7 — Human Oversight and Consumer Protection

| Clause | Obligation | Coverage | Memtara | AIHOOTS | Remains the LFI's obligation |
|---|---|---|---|---|---|
| **§7(a)** | Meaningful human oversight and judgement, especially for consumer-significant decisions; three named models — human-**in**-the-loop, human-**on**-the-loop, human-**out**-of-the-loop (low-risk, non-material only). | ■ | Memtara is structurally **human-in-the-loop on the consumer's side**: no proof exists unless the consumer performs an explicit device-local action to generate it. A disclosure request cannot self-fulfil. This is a stronger position than the clause requires — the human whose interests are at stake holds the gate, not only the institution's reviewer. | Human-on-the-loop for the institution: decisions are recorded and reviewable, with a block path that halts autonomously. | Staff the institution-side reviewer and document which of the three models applies to each system. |
| **§7(b)** | Level of human involvement commensurate with the risk posed to the consumer. | ■ | Per-journey calibration is already specified: a 1-hour hard cap on `emergency_session` with no live authentication at point of use, versus a days-to-weeks single-recipient grant for family-office succession ([`docs/journeys.md`](journeys.md)). TTL is bounded server-side (1s–7d). | Policy severity tiers (allow / redact / block). | Map its own products to risk tiers. |
| **§7(c)** | Consumers may request human review or explanation of AI decisions; alternative arrangements where the consumer declines an AI decision; accessible complaints and redress per **Article 8 of the Consumer Protection Regulation**; right to challenge decisions and correct inaccurate inputs. | ◧ | "Correct inaccurate data inputs" is directly supported: the vault is consumer-held and consumer-editable, and a corrected record changes the `vault_root`, so subsequent proofs reflect the correction without an institutional data-change request. The disclosure record shows exactly which predicate was asserted, which is what a challenge needs. | The full decision record for a contested interaction is retrievable and tamper-evident. | **Build the complaints channel.** No complaints-handling workflow exists in either system. Flagged as **not covered**. |
| **§7(d)** | Fair and equitable treatment by design; no targeting with unsuitable products, pressure-selling or misleading marketing; promotional material and chatbots must meet disclosure requirements. | ◧ | Minimised disclosure limits the profiling surface available for targeting — an institution that never receives a salary figure cannot micro-target on it. | Chatbot interactions pass through the audited path; marketing-facing bots are in scope by construction. | Suitability assessment and marketing-conduct review. |

---

### §8 — Integration with Existing Frameworks

*(Sub-clause lettering in the source runs `e, a, b, c` — the `e` paragraph is
printed first. Reproduced in document order, not re-lettered.)*

| Clause | Obligation | Coverage | Memtara | AIHOOTS | Remains the LFI's obligation |
|---|---|---|---|---|---|
| **§8(e)** | AI tools integrated into the enterprise-wide risk framework; AI risk assessments must inform and be informed by overall risk appetite and controls, not operate in isolation. | ◧ | Disclosure records key to an org id, so AI-driven decisions join existing counterparty and conduct records rather than sitting in a separate store. | Audit events carry `caller`, enabling attribution into enterprise risk reporting. | The integration itself. |
| **§8(a)** | Policies should **complement rather than duplicate** existing obligations under the Consumer Protection Regulation and other CBUAE directives; AI-driven consumer risk treated as part of the **conduct risk** framework, with board and regulator reporting. | ◧ | One consent artefact serves both the AI-decision record and the data-protection record — no parallel consent register. | One audit trail serves conduct, model-risk and security review. | Conduct-risk framework mapping and regulator reporting. |
| **§8(b)** | Where AI is developed internally, consider **third-party independent review** for suitability, security and reliability. | ◧ | The circuits are the security-critical component and are open, small, and independently re-verifiable — a reviewable artefact rather than an opaque service. `REBUILD.md` (AIHOOTS) documents clean-machine reproduction. | Same. | Commission the review. |
| **§8(c)** | Processes to **rate the risk** of each AI system deployed, informed by data quality/sensitivity, capability, controls, impact and third-party dependence. | ◧ | `circuit_type` plus `org_type` (bank / ai_platform / hospital / government) is a first-class risk-relevant classification already carried on every record. | Per-caller metrics support a data-driven rating. | Own and maintain the rating methodology. |

---

### §9 — Outsourcing and Third-Party Risk

| Clause | Obligation | Coverage | Memtara | AIHOOTS | Remains the LFI's obligation |
|---|---|---|---|---|---|
| **§9(a)** | Per MMS §4.7 and the Outsourcing Regulation for Banks: due diligence on third-party AI/cloud providers' reputation, governance, security and data protection; contracts must ensure information access, audit rights and CBUAE compliance. | ◧ | Memtara's deployment posture reduces what must be diligenced: the vendor cannot access consumer plaintext even if compromised, because it never holds the decryption key. | The LFI holds the audit log itself; audit rights are not contingent on vendor cooperation. | Conduct the diligence; negotiate the contract. |
| **§9(b)** | Procurement, choice and justification for a third-party AI provider documented; annual independent cybersecurity reviews; pre-deployment testing. | ◧ | Design rationale and rejected alternatives are recorded in-repo, which is the raw material for a justification memo. | ADR format records alternatives and why they lost; `bandit` and `pip-audit` run in the dev toolchain. | Annual independent review; the procurement file. |
| **§9(c)** | Maintain an **inventory of AI models**, including third-party-hosted; third-party models held to the same fairness, explainability and robustness standards as in-house. | ◧ | Every disclosure names its `circuit_type` — a complete, queryable inventory of which cryptographic component served which decision. | Every audit event names its `model`, giving a usage-derived inventory that cannot silently omit a model actually in use. | The enterprise AI inventory as a governance register. |
| **§9(d)** | Consider a range of AI providers to avoid over-reliance on any one system or provider. | ◧ | Verification is standards-based (Barretenberg/UltraHonk over compiled ACIR), not a proprietary service call. | OpenAI-compatible interface — the upstream model is swappable by one env var, and the audit contract is unchanged. | Multi-provider strategy. |

---

### §10 — Ethical Collaboration and Innovation

| Clause | Obligation | Coverage | Memtara | AIHOOTS | Remains the LFI's obligation |
|---|---|---|---|---|---|
| **§10** | Collaborate with industry peers, UAE AI sandboxes and the Innovation Hub, academia and the CBUAE; contribute to trustworthy-AI standards; **publish case studies** on AI development and responsible use, anonymised where appropriate. | ■ | This repository is itself the contribution: circuits, architecture and rationale published openly. [`docs/journeys.md`](journeys.md) is eight anonymised UAE-resident case studies, including two — assisted emergency card, and staff-assisted government counter — deliberately covering consumers the digital-first path underserves. | Public repo, live deployment, published ADRs and articles; measured precision/recall **including misses**. | Sandbox participation and CBUAE engagement. |

---

## Coverage summary, stated honestly

| Coverage | Count | Clauses |
|---|---|---|
| ■ Direct | 12 | §1(high-impact), §2(c), §2(e), §4(a), §4(c), §5(a), §5(c), §5(d), §6(c), §6(f), §7(a), §7(b), §10 |
| ◧ Contributing | 19 | §1(AI/ML), §2(a), §2(b), §2(d), §3(a), §3(c), §5(b), §5(e), §6(a), §6(b), §6(d), §6(e), §7(c), §7(d), §8(e), §8(a), §8(b), §8(c), §9(a)–(d) |
| □ LFI-only / **not covered** | 5 | §1(MMS), §3(b), §4(b), §6(g), and the un-covered half of §7(c) |

**The four gaps a CRO should see on page one:**

1. **§3(b) training-data representativeness — not covered.** Neither system
   trains models. This belongs to the LFI's model vendor.
2. **§3(a) bias measurement — not covered.** Memtara narrows the feature
   surface; it does not measure disparate impact, and proxy discrimination
   through a threshold remains possible. Bias testing must be built separately.
3. **§4(b) bilingual disclosure — not covered.** Arabic-first RTL and
   comprehension checking are specified in `docs/journeys.md` but not
   implemented.
4. **§7(c) complaints and redress — half covered.** Input correction is
   structurally supported; the Article 8 complaints channel does not exist in
   either system.

Add to those the **§6(f) revocation caveat** on the 300-second proof token,
recorded in full above.

Nothing in this matrix should be read as a legal opinion, and it does not
substitute for the LFI's own compliance assessment. It is an engineering claim,
with its uncertainties marked, about which clauses these two systems produce
evidence for — and which they do not.

---

## Appendix — DFSA Conduct of Business: Suitability

A second regulator, a second obligation, and — as with the CBUAE brief — a
clause number that does not say what the brief thinks it says.

### The citation, corrected

The commissioning brief asked for a mapping to **"DFSA Conduct of Business
Rule 3.1 (Suitability)"**. In the current DFSA Rulebook:

| Cited | Actual |
|---|---|
| COB **3.1** — "Suitability" | COB **3.1** is titled **"Application"**. Suitability is **COB 3.4**, with the assessment itself at 3.4.2. |

Older versions numbered it differently again (in `COB/VER7/08-06` the rule sat
at **6.2**), which is presumably where a stale citation comes from. The
implementation, the tokens and the audit records in this repository use the
neutral string `COB 3.1` in the `dfsa_rules` claim **because that is the
identifier the commissioning brief specified and changing it unilaterally
would break the contract a relying party was told to match** — but the claim
is a free-text list, one line changes it, and a deployment filing evidence
with the DFSA should use `COB 3.4`. This is flagged here rather than fixed
silently because it is the caller's decision, not ours.

**A caveat on this appendix that does not apply to the CBUAE matrix above.**
The CBUAE Guidance Note is vendored in this repository and every clause above
was read from it. The DFSA Rulebook is not, and its current rule text was not
retrievable in a form this document could quote. So the section titles are
confirmed, and the substance below is taken from an archived version
(`COB/VER7/08-06`, §6.2.1) whose wording may since have changed. Treat the
mapping as being against the *substance* of a suitability obligation, and
verify the current text before relying on it.

### What the rule actually requires — and what it does not

The archived rule permits a firm to advise, recommend or exercise discretion
only where the advice, recommendation or transaction

> is suitable for that Client having regard to (d) that Client's investment
> objectives and risk tolerance; and (e) any other requirements or relevant
> facts about that Client of which the Authorised Firm is, or ought
> reasonably be aware.

Read that carefully, because it changes what this feature can honestly claim.
The rule enumerates **objectives and risk tolerance**. It does *not* mandate
an income floor, a liquidity floor or a concentration cap — those are the
firm's own suitability *policy*, the thing a product governance committee
sets. So:

- The circuit implements **a firm's policy**, not the rule's text. Its four
  limbs are configurable per product (`wealth_requests`), which is the
  correct shape for a rule that delegates the criteria to the firm.
- What the rule genuinely demands, and what this feature genuinely supplies,
  is that an assessment **was made against defined criteria before the
  recommendation**, and that the firm can **show it**. That is a record-keeping
  and sequencing property, and it is exactly what a signed, chained,
  independently re-verifiable attestation is good at.
- "Any other requirements or relevant facts" is open-ended and cannot be
  discharged by any circuit. A firm that knows something material about a
  client outside these four limbs still has to act on it.

### Mapping

| Obligation | Coverage | Memtara | AIHOOTS | Remains the firm's obligation |
|---|---|---|---|---|
| A recommendation must be **suitable** for the client, having regard to objectives and risk tolerance. | ◧ | `risk_tolerance >= product_risk_level` is one of the four limbs, evaluated in-circuit against the product's registered risk level. Investment *objectives* are not modelled. | — | Capturing objectives, and any relevant fact outside the four limbs. |
| The assessment must precede the recommendation. | ■ | Enforced by construction. The firm registers the terms on `POST /api/v1/issue-wealth-request`; the token is minted only after a proof against *those* terms verifies. A verdict cannot be back-dated onto a recommendation already made, because the nonce that binds it is issued before the client is asked. | The gateway will not inject a verdict it did not obtain, and records a `skip` when it could not. | Not making recommendations outside the gated channel. |
| The firm must be able to **demonstrate** it assessed. | ■ | `wealth_suitability_requested` → `wealth_suitability_assessed` in the hash-chained `audit_log`, plus a token bound to specific proof bytes by `proof_hash`. Re-verifiable years later against the published `vkey` and JWKS — no dependency on the firm's word or on Memtara still existing. | Independent SHA-256 chain (`audit.jsonl`), correlated by `regulatory_audit_id`, verifiable with `audit-verify`. | Retaining both logs for the applicable period. |
| A **declined** recommendation must be evidenced as much as an approved one. | ■ | This drove the circuit's design. `suitable` is a public *output*, not an assert, so a proof of "not suitable" exists and is issued a token carrying `suitable: false`. An asserting circuit would have made a decline indistinguishable from an assessment that never ran. | The injected preamble states `NOT SUITABLE` and instructs the model not to recommend; the verdict goes into the chain either way. | Acting on the decline. |
| The criteria themselves must be the firm's, not the client's. | ■ | The terms live in `wealth_requests`, registered under the org's API key, and `submit_wealth_proof` compares every submitted public input against them. Without that check a client could prove suitability against a threshold of zero, with cryptography that verifies perfectly. | Terms come from the product registry, read server-side; a risk level asserted *in the prompt* is recorded as a discrepancy rather than obeyed. | Maintaining the registry. |
| The criteria must not be the **adviser's** either. | ■ | The product registry (`POST /api/v1/products`, org-scoped, audited on create and on every amendment). `issue-wealth-request` refuses to accept terms and reads them from the registered instrument; it also refuses any product the risk committee has not approved. | The middleware passes no terms at all — `assess(user_id, product_isin)` takes none, so there is no parameter through which a prompt could eventually reach them. | Product governance itself: who sits on the committee, and what they approve. |
| Records must be retained (six years in the archived version). | □ | Not covered. Nothing here implements a retention schedule, and the hash chain proves internal consistency, not availability — an operator can still delete a whole log. | Same limitation. | Retention, off-box replication, and append-only storage. |

### The trap worth naming explicitly

`bb verify` answers *"was this proof correctly constructed"*, not *"is the
client suitable"*. A proof that a client **failed** the assessment verifies
exactly as cleanly as one that they passed — same key, same exit code. A
relying party that reads the exit code and not public input 11 approves
everyone who was assessed, including everyone who failed, while holding
cryptographic evidence that appears to support it.

This is why `/api/v1/issue-proof` refuses the suitability predicate outright
rather than documenting the hazard, and it is demonstrated with a real proof
in `tests/test_wealth_suitability_e2e.py::test_a_valid_proof_of_non_suitability_passes_bb_verify`.

### The second half of the same hole, closed later

The row above about the *adviser* was not covered when this feature was first
built, and the omission is worth recording rather than quietly fixing.

`submit_wealth_proof` has always stopped the **client** choosing its own
thresholds. It never stopped the person making the recommendation. Whoever held
the org API key could open an assessment with `min_income: 0`,
`max_concentration_percent: 100` and `product_risk_level: 5`, hand the client a
request that anyone alive would pass, and receive back a signed,
hash-chained, cryptographically impeccable attestation of suitability.

Every artefact would have been genuine. The proof would verify against the
published key. The audit chain would be intact. And the assessment would have
measured nothing, because the bar was set by the party with an interest in
clearing it — which is precisely the mis-selling pattern COB suitability
exists to prevent.

Nothing in the circuit can detect this: the thresholds are public inputs, and
every value of them yields a valid proof. It is only closed by the terms coming
from somewhere the adviser does not control at recommendation time. That is
what the product registry is, and it is why `approved_by_risk_committee` is
enforced rather than merely stored.

### One gap this feature closes that the CBUAE matrix leaves open

`submit_wealth_proof` pins the submitted `vault_root` to the root the user
actually synced. The four session circuits do **not** — `verify_against_request`
accepts any root, so their Merkle limb proves the figures are consistent with
*some* tree rather than with the user's committed one. That is a real weakness
in the older path, deliberately not retrofitted in this pass, and it is
recorded here rather than left for someone to discover.

---

## Related artefacts

| Document | What it adds |
|---|---|
| [`docs/REGULATORY_DEMO_REPORT.md`](REGULATORY_DEMO_REPORT.md) | Worked journeys with real API calls, issued JWTs, and the resulting AIHOOTS chain entries. |
| [`docs/journeys.md`](journeys.md) | The eight UAE-resident disclosure journeys these clauses are mapped against. |
| [`docs/openapi.yaml`](openapi.yaml) | Wire contract for the JWKS and proof-issuance endpoints cited throughout. |
| [`tests/test_aihoots_handshake.py`](../tests/test_aihoots_handshake.py) | Executable proof that the Memtara → AIHOOTS handshake works without a synchronous call. |
| [`tests/test_wealth_suitability_e2e.py`](../tests/test_wealth_suitability_e2e.py) | The DFSA suitability journey, end to end, with **genuine** Barretenberg proofs — the one place in this repository where no part of the cryptography is stood in for. |
| [`circuits/wealth_suitability/vkey/`](../circuits/wealth_suitability/vkey/) | The published verification key an examiner re-verifies a suitability proof against, without trusting anyone's build. |
