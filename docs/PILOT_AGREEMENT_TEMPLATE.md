# Memtara — Pilot Agreement (template)

> ## This is a drafting aid, not a contract, and not legal advice
>
> It was written by the vendor's product team to make the first legal
> conversation shorter, not to replace it. Neither party should sign anything
> derived from it without review by qualified counsel admitted in the relevant
> jurisdiction — for a UAE bank that ordinarily means DIFC or ADGM counsel, and
> for an onshore institution, UAE counsel familiar with the CBUAE outsourcing
> and consumer-protection regime.
>
> Where a clause records a technical fact about how the software behaves, that
> fact is traceable to a named file in this repository and can be verified
> before signature. Where a clause is a commercial position, it is marked as
> negotiable. Nothing here should be read as a representation that the
> arrangement satisfies any particular regulatory obligation of the Bank.

**Fill in every `[SQUARE BRACKET]` before sending. A template sent with
brackets still in it tells the recipient exactly how much attention they are
getting.**

---

## Parties and commencement

This Pilot Agreement (the **"Agreement"**) is made on `[DATE]` between:

**(1)** `[MEMTARA ENTITY NAME]`, a company incorporated in `[JURISDICTION]` with
registered number `[NUMBER]` and registered office at `[ADDRESS]`
(**"Memtara"**, **"we"**, **"us"**); and

**(2)** `[BANK LEGAL NAME]`, a `[bank / financial institution]` licensed by
`[DFSA / FSRA / CBUAE]` under licence number `[NUMBER]`, of `[ADDRESS]`
(**"the Bank"**, **"you"**),

each a **"Party"** and together the **"Parties"**.

---

## 1. What this pilot is

**1.1** Memtara provides a zero-knowledge suitability platform. It allows a
client's own device to prove, against suitability terms the Bank has registered
in advance, that the client satisfies those terms — and to disclose only the
result, not the underlying figures.

**1.2** The pilot is an evaluation. Its purpose is to establish whether the
platform works in the Bank's environment and produces evidence the Bank's risk
and compliance functions find useful. It is **not** a production deployment,
and Clause 9.2 says what that means in practice.

**1.3** The scope of the pilot is set out in **Schedule 1**. Anything not in
Schedule 1 is out of scope.

---

## 2. Term and fees

**2.1 Term.** Three (3) months from `[START DATE]` (the **"Pilot Period"**),
unless extended by written agreement or terminated under Clause 9.

**2.2 Fees.** USD 5,000 per month, invoiced monthly in advance, payable within
`[30]` days. No setup fee. Exclusive of UAE VAT, which the Bank pays in addition
where applicable.

**2.3 Pilot credit.** *(Negotiable, and we suggest keeping it.)* If the Bank
enters a production agreement within `[90]` days of the end of the Pilot Period,
100% of fees paid under this Agreement are credited against the first
production invoice.

**2.4 The Bank's own costs.** The Bank bears its own integration, testing and
staffing costs. `clients/prover/README.md` describes what integration involves,
including the parts that are genuinely awkward, and the Bank should read it
before signing rather than after.

---

## 3. Data protection

This clause is a **Data Processing Addendum** and takes effect as part of this
Agreement.

### 3.1 Roles

**3.1.1** The Bank is the **Controller** in respect of Client Personal Data.
Memtara is the **Processor**, and processes Client Personal Data only on the
Bank's documented instructions, of which this Agreement is one.

**3.1.2** Memtara is an independent **Controller** in respect of its own
security, availability and billing records — the ordinary logs any operator of a
service keeps about the service. These do not contain Client Personal Data
beyond the identifiers listed at 3.2.

### 3.2 What Memtara actually receives — the inventory

This is the clause the Bank's privacy office will read first, so it is stated
precisely rather than favourably. Each row is verifiable against
`backend/api/migrations/` before signature.

| Category | Held by Memtara? | Where | Notes |
|---|---|---|---|
| Client name | **No** | — | The platform has a `display_name` column; the pilot configuration leaves it null. |
| Client mobile number | **Yes** | `users.phone_e164` | Directly identifying. The schema requires at least one contact identifier per client record. |
| Client email address | Optional | `users.email` | Only if the Bank supplies it. |
| UAE Pass subject identifier | Optional | `users.uae_pass_sub` | Only if UAE Pass login is enabled; not enabled by default in a pilot. |
| Pseudonymous client identifier | **Yes** | `user_id` (UUID) | Used throughout. Persistent, and therefore personal data. |
| Device name and passkey public key | **Yes** | `webauthn_credentials` | Only where device authentication is used. |
| Session records | **Yes** | `sessions` | Token hashes and timestamps. |
| **Client income** | **No** | — | Never transmitted. It is a proof witness and exists only on the client's device. |
| **Client liquid assets** | **No** | — | As above. |
| **Client risk-tolerance score** | **No** | — | As above. |
| **Client existing holdings value** | **No** | — | As above. |
| Encrypted vault contents | **Yes, as ciphertext** | `vault_blobs.ciphertext` | Encrypted on the client device. Memtara does not hold, and cannot obtain, the decryption key. |
| Vault commitment | **Yes** | `vault_blobs.vault_root` | A Poseidon hash. Not reversible to the figures. |
| Product identifier and terms | **Yes** | `products`, `wealth_requests` | The Bank's data, not the client's. |
| The suitability result | **Yes** | proof public inputs | One bit: suitable, or not. |
| Proof bytes and public inputs | **Yes** | `proofs` | Public inputs comprise the thresholds, the commitment, the window and the verdict. No client figure appears among them. |
| Audit chain entries | **Yes** | `audit_log` | Event type, `user_id`, product identifier, timestamps, and a SHA-256 chain. No contact details. |

**3.2.1 The claim the Bank should hold us to.** Memtara **never receives the
client's financial figures.** That is the guarantee, it is structural rather
than policy-based — proving `income >= X` requires the income as a witness, so a
server able to generate these proofs would by definition be a server holding
plaintext, which is why Memtara cannot generate them — and it can be verified
by inspection of `clients/prover/` and `backend/api/src/verify/`.

**3.2.2 The claim the Bank should not accept from anyone.** That Memtara "holds
no personal data". It holds the identifiers in the table above, and any vendor
telling you otherwise about a system with a `users` table has either not read
their own schema or is hoping you will not read it.

### 3.3 Purpose limitation

Memtara processes Client Personal Data solely to provide the platform described
in Schedule 1. Memtara will not use it to train machine-learning models, to
develop or market other products, or for any analytics beyond operating and
securing the service.

### 3.4 Location and transfers

**3.4.1** Hosting location for the Pilot Period: `[SPECIFY — e.g. AWS me-central-1
(UAE)]`. **Complete this before sending.** For a CBUAE-licensed institution it
is frequently the determinative term, and leaving it blank invites the answer
"then no".

**3.4.2** Memtara will not transfer Client Personal Data outside
`[JURISDICTION]` without the Bank's prior written consent, save where required
by law, in which case Memtara will notify the Bank unless legally prohibited.

**3.4.3** Sub-processors as at the date of this Agreement: `[LIST — hosting
provider, and any managed database or monitoring service]`. Memtara will give
the Bank `[30]` days' written notice before appointing a new sub-processor, and
the Bank may object on reasonable data-protection grounds.

### 3.5 Security

**3.5.1** Memtara will maintain the measures in **Schedule 3**.

**3.5.2 Stated plainly:** Memtara holds no SOC 2 report, no ISO 27001
certification, and has not commissioned an independent penetration test. The
Bank should assume it is contracting with an early-stage vendor and set the
pilot's scope accordingly — which is one reason the pilot is limited to a single
product family and a bounded user group.

### 3.6 Retention, deletion, and the honest tension with the audit chain

**3.6.1** On expiry or termination, Memtara will, at the Bank's election within
`[30]` days, return or delete Client Personal Data.

**3.6.2** **The exception, and why it exists.** The `audit_log` is an
append-only SHA-256 hash chain. Deleting a row breaks the chain, and a broken
chain is indistinguishable from a tampered one — so honouring an erasure request
by deleting audit rows would destroy the tamper-evidence property that is the
reason for having the log.

The chain is designed so this is not a conflict in practice. Audit entries
identify a client only by the pseudonymous `user_id`, never by name, number or
email. Erasure is therefore effected by **deleting the `users` row**, which
severs the link between the pseudonymous identifier and the natural person, and
leaves the chain arithmetically intact. The Bank should confirm with its own
counsel that this satisfies its erasure obligations before relying on it; we
believe it does, and we are not the right party to decide.

**3.6.3** Exported Canonical Case Files are the Bank's records, held by the
Bank, and are outside this clause. See Clause 9.3.

### 3.7 Incidents

Memtara will notify the Bank without undue delay and in any event within
`[24]` hours of becoming aware of a Personal Data Breach affecting Client
Personal Data, with the information the Bank reasonably needs to meet its own
notification obligations.

### 3.8 Assistance

Memtara will provide reasonable assistance with data-subject requests, data
protection impact assessments, and regulator enquiries, at no additional charge
during the Pilot Period.

---

## 4. Confidentiality

**4.1** Each Party will keep the other's Confidential Information confidential,
use it only for this Agreement, and disclose it only to personnel and advisers
who need it and are bound by equivalent obligations.

**4.2** The obligation does not apply to information that is public other than
through breach, was already lawfully held, is independently developed, or must
be disclosed by law or to a regulator — and disclosure to the DFSA, FSRA or
CBUAE is expressly permitted without notice to the other Party.

**4.3** Survives termination by `[3]` years, save for trade secrets, which
survive indefinitely.

---

## 5. Intellectual property

**5.1 Memtara's IP.** Memtara owns and retains all rights in the platform: the
Noir circuits, the verification keys, the backend, the prover SDK, the export
and sealing tooling, and all documentation.

**5.2 The Bank's IP.** The Bank owns and retains all rights in its data,
including client records, vault contents, product definitions and suitability
terms, its AI prompts and prompt templates, and all Canonical Case Files
exported during the pilot.

**5.3 Licence to the Bank.** Memtara grants the Bank a non-exclusive,
non-transferable, revocable licence to use the platform for the Pilot Period,
for the purposes in Schedule 1.

**5.4 Feedback.** Memtara may use feedback and suggestions freely, provided it
does so without identifying the Bank and without disclosing the Bank's
Confidential Information.

**5.5 No reference without consent.** Memtara will not name the Bank, use its
marks, or refer to it in any marketing, funding or press material without the
Bank's prior written consent, which the Bank may withhold for any reason.

**5.6 Licensing status — disclose this, do not wait to be asked.** The public
repository's `README.md` refers to an MIT licence. `[Memtara: confirm the actual
position and state it here before sending. If the repository licence has not
been settled, say so — a bank's counsel will check, and finding an unfulfilled
licence reference is worse than finding an unfinished one.]`

---

## 6. What Memtara promises, and what it does not

**6.1** Memtara warrants that it will perform with reasonable skill and care,
and that the platform will materially perform as described in the documentation
referenced in Schedule 1.

**6.2 No availability commitment during the pilot.** This is an evaluation
service. Uptime commitments and service credits belong in a production
agreement, and offering them here would be offering something we have no
operating history to support.

**6.3 The platform is a tool, not a judgement.** Memtara verifies that a
cryptographic proof was correctly constructed against terms the Bank registered.
It does not determine whether a product is suitable for a client, does not set
suitability terms, does not supervise advisers, and does not discharge any
obligation the Bank owes to its clients or its regulator. The Bank remains
solely responsible for its advice, its adviser conduct, its product governance,
and its regulatory compliance.

**6.4 Three limits stated in the contract because they are true.**

- **(a)** A verification succeeding means the proof was correctly constructed —
  including a proof that the client is **not** suitable, which verifies exactly
  as cleanly. Reading the outcome and not merely the verification is the Bank's
  responsibility, and the Bank's integration must do so.
- **(b)** An issued attestation token cannot be revoked within its 300-second
  lifetime. Revoking the underlying request or session is the available remedy.
- **(c)** Neither Memtara nor AIHOOTS measures algorithmic bias or disparate
  impact. Where the Bank has such an obligation, it is not met by this platform.

**6.5** Save as expressly stated, all warranties implied by law are excluded to
the fullest extent permitted.

---

## 7. Indemnities and liability

**7.1 Memtara indemnifies the Bank** against third-party claims that the
platform, used as permitted, infringes that third party's intellectual property
rights, subject to the cap at 7.4.

**7.2 The Bank indemnifies Memtara** against claims arising from the Bank's use
of the platform, including claims by the Bank's clients relating to investment
advice, product suitability determinations, adviser conduct, or the Bank's
regulatory obligations. This reflects Clause 6.3: we supply a cryptographic
tool, the Bank makes and is answerable for the recommendation.

**7.3 Neither Party is liable** for indirect or consequential loss, loss of
profit, loss of business, or loss of anticipated savings.

**7.4 Cap.** Each Party's aggregate liability is limited to the greater of
`[USD 15,000]` (total fees payable over the Pilot Period) and `[USD 50,000]`.
*Negotiable, and a fee-based cap on a $5,000/month pilot will strike most bank
procurement teams as low; expect to move, and expect the number the Bank
proposes to be uninsurable at this stage — say so rather than agreeing to it.*

**7.5** Nothing limits liability for death or personal injury caused by
negligence, fraud or fraudulent misrepresentation, or any liability that cannot
lawfully be limited.

---

## 8. Regulatory

**8.1** The Bank is responsible for determining whether this arrangement
constitutes outsourcing or a material third-party arrangement under its
regulator's rules, and for any notification or approval that follows. Memtara
will provide information reasonably required for that assessment.

**8.2** Memtara will co-operate with, and permit access by, the Bank's
regulators, internal audit and external auditors, on reasonable notice, in
respect of services provided under this Agreement.

**8.3** No representation is made that the platform satisfies any specific
provision of the DFSA Rulebook, the CBUAE Guidance Note, or any other
instrument. `docs/REGULATORY_MATRIX.md` sets out, clause by clause, what the
platform does and does not produce evidence for, and names its gaps first. It
is an engineering analysis. It is not a legal opinion and must not be relied on
as one.

---

## 9. Termination and exit

**9.1** Either Party may terminate on `[30]` days' written notice, for any
reason or none. Either Party may terminate immediately on the other's material
breach not remedied within `[14]` days, or on insolvency.

**9.2** On termination, the Bank's access ends and Clause 3.6 applies.

**9.3 What the Bank keeps.** All Canonical Case Files exported before
termination remain the Bank's property, and the Bank may retain and use them
indefinitely.

**9.4 They stay verifiable without us.** Every exported case file contains the
verification key digest and the public inputs, and each carries a Memtara-issued
attestation validated against a published JWKS. Memtara will:

- **(a)** keep the JWKS reachable at its published URL for at least `[24]`
  months after termination; and
- **(b)** on request, at or before termination, provide the Bank with an offline
  archive of the JWKS, the verification key, and the verification instructions,
  so the files can be re-verified with no dependence on any Memtara service.

*Ask for (b) whether or not you expect to need it. A vendor unwilling to make
its evidence independently checkable after the relationship ends is telling you
what the evidence is worth.*

**9.5** Clauses 3.6, 4, 5, 6.3, 7 and 9.3–9.4 survive termination.

---

## 10. General

**10.1 Governing law and jurisdiction.** `[SELECT ONE]`

- **DIFC law, DIFC Courts.** Usual where either Party is DIFC-based; an English-
  language common-law forum, familiar to most counterparties here.
- **ADGM law, ADGM Courts.** The equivalent for Abu Dhabi.
- **UAE federal law, Dubai Courts.** Often required by onshore institutions.
  Expect a longer negotiation and take local advice.

**10.2** Neither Party may assign without the other's consent, save to a group
company or on a sale of substantially all assets.

**10.3** This Agreement, with its Schedules, is the entire agreement between the
Parties on its subject matter, and supersedes prior discussions.

**10.4** Variations must be in writing and signed by both Parties.

**10.5** No partnership, joint venture or employment relationship is created.

**10.6** Notices: `[EMAIL AND POSTAL ADDRESS FOR EACH PARTY]`.

---

## Schedule 1 — Scope of the pilot

| | |
|---|---|
| **Product family** | `[ONE — e.g. principal-protected structured notes]` |
| **Instruments registered** | `[NUMBER]` |
| **Named users** | Up to 10 |
| **Client records** | Up to `[NUMBER]` |
| **Environment** | Memtara-hosted evaluation environment at `[URL]` |
| **Deployment** | Non-production. Not to be used for live client advice unless the Bank's own governance expressly permits it. |
| **Export** | Manual, via the `memtara-export` CLI |
| **Support** | Email, next business day, `[ADDRESS]` |
| **Documentation** | `docs/openapi.yaml`, `clients/prover/README.md`, `docs/REGULATORY_MATRIX.md`, `README.md` (including its "Honest limits" section) |

### Success criteria

Agree these before the pilot starts, not at the end of it. A pilot without
written criteria is decided by whoever is most senior in the closing meeting.

| # | Criterion | Measure | Owner |
|---|---|---|---|
| 1 | A real proof is generated and verified for a live-equivalent client | `bb verify` succeeds; attestation validates against the published JWKS | `[BANK]` |
| 2 | A Canonical Case File satisfies the Bank's compliance reviewer | Written sign-off from `[ROLE]` | `[BANK]` |
| 3 | The seal detects tampering | A modified file fails `memtara-export verify` | Joint |
| 4 | Product registry governance holds | An assessment cannot be opened against unregistered or unapproved terms | Joint |
| 5 | Integration effort is understood | Written estimate for production integration | `[BANK]` |
| 6 | `[BANK-SPECIFIC CRITERION]` | `[MEASURE]` | `[OWNER]` |

---

## Schedule 2 — Fees

| Item | Amount | Frequency |
|---|---|---|
| Pilot licence | USD 5,000 | Monthly in advance |
| Setup | USD 0 | — |
| Support | Included | — |
| Additional user groups beyond Schedule 1 | `[BY AGREEMENT]` | — |
| On-premise deployment | Not offered during the pilot | — |

---

## Schedule 3 — Security measures

Stated as what is in place, with the gaps named. A schedule that reads as
complete when it is not gets discovered during the pilot, and being discovered
is much worse than disclosing.

**In place**

- TLS in transit; encryption at rest through the hosting provider.
- Client vault contents encrypted on the device; Memtara holds no key capable of
  decrypting them.
- Tenant isolation by `org_id` on every table, with an automated test that fails
  if one tenant can read another's registry or evidence.
- Append-only SHA-256 hash-chained audit log.
- Attestation signing keys held server-side; public keys published at
  `/.well-known/jwks.json`.
- Rate limiting on proof submission, default 10 per minute per client.
- `GET /health` returns 503 if the running verification key diverges from the
  published one.
- Access to production systems restricted to `[NUMBER]` named individuals.
- OTP codes stored only as Argon2 hashes.

**Not in place, disclosed**

- No SOC 2, no ISO 27001, no independent penetration test.
- Rate limiting is per process; horizontally scaled instances multiply the
  effective limit. It bounds cost, and is not a security boundary.
- The hash chain proves internal consistency, not availability. An operator with
  database access can still destroy a log; append-only storage and off-box
  replication are the mitigations and neither is deployed.
- Organisation self-registration is unauthenticated in the current build and
  must be network-restricted in any deployment the Bank uses.
- The default OTP provider logs codes rather than sending them, and is labelled
  dev-only in the source. It must be replaced before any deployment carrying
  real client authentication, and the Bank should confirm at kick-off that it
  has been.
- No formal business-continuity or disaster-recovery plan.

---

## Signatures

| | Memtara | The Bank |
|---|---|---|
| Signature | | |
| Name | `[NAME]` | `[NAME]` |
| Title | `[TITLE]` | `[TITLE]` |
| Date | | |

---

## For the Memtara team: what counsel will change, and where to hold

Expect these, and decide your position before the call rather than during it.

1. **The liability cap (7.4).** They will ask for uncapped, or a multiple of
   fees far beyond what an early-stage company can insure. Say plainly what you
   can carry, offer to revisit at production scale, and do not sign something
   you could not survive.
2. **Data residency (3.4.1).** Frequently non-negotiable for CBUAE-licensed
   institutions. Know your hosting answer before the first legal call; "we can
   look into it" costs weeks.
3. **Audit and inspection rights (8.2).** Reasonable. Agree, with notice periods.
4. **The erasure carve-out (3.6.2).** Their privacy office will push. The
   pseudonymity argument is genuinely strong — but let their counsel reach that
   conclusion by walking the schema, rather than asserting it at them.
5. **The reference clause (5.5).** They will want it exactly as drafted. Ask
   separately, later, once the pilot has actually worked — and be willing to
   trade real commercial value for it, because a first named reference is worth
   more than a discount.
6. **SOC 2 (3.5.2).** They will ask. There is no version of "we're working
   towards it" that helps if it is not true. What does help is a bounded pilot
   scope, which is why Schedule 1 is bounded.
