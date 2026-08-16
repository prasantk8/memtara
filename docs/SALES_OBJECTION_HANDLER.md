# Sales Objection Handler — Memtara

For anyone taking a Memtara conversation into a UAE bank. Eight objections, each
in four parts: what they said, what they meant, what to answer, and what they can
check before the meeting ends. Every entry closes with the case where the
objection is correct and the right move is to scope down or walk away.

Two rules before you use this document.

**Never bluff.** Everything below is traceable to a file in this repository. A
bank's technology team can falsify a bad claim in an afternoon, and doing so
converts a warm lead into a vendor they have decided is unreliable. If you are
asked something not covered here, say you will find out.

**Say the honest numbers out loud.** Zero pilots. Zero paying customers. No
regulatory approval, no CBUAE or DFSA endorsement, no sandbox admission. No SOC 2,
no ISO 27001, no penetration test. Naming these first is what buys you the right
to be believed about the parts that are strong.

---

## 1. "We don't have vault infrastructure."

### What they are actually worried about

They have heard "local-first vault" and pictured a programme: a new datastore, a
key-management estate, an HSM procurement, a two-year platform project with a
steering committee. What they are really asking is *how big is this on my side of
the line, and does it need a budget cycle I do not have.*

There is usually a second, quieter worry underneath: that "the client's device
does the proving" means their retail app team has to become cryptographers.

### The answer

There is no vault infrastructure to build. The "vault" is a file and a signing
key on whichever machine already talks to the client — one JSON file holding four
figures and a Baby Jubjub key. The prover is a Python CLI, `clients/prover/`, with
no Python dependencies at all: the elliptic-curve arithmetic is integer maths in
the standard library and every Poseidon hash is delegated to the circuits' own
implementation, so there is no second cryptographic library on your side that
could silently disagree with the verifier.

What it does cost you is the Noir toolchain wherever the proof is generated. Two
routes, and you should choose before you scope. **The subprocess route** — ship
`nargo` and `bb` binaries for the target architecture, call the CLI with `--json`,
parse one object off stdout. That is real work: two native binaries per
architecture, and on iOS the sandbox makes spawning subprocesses impractical, so
this route suits an advisor's iPad or desktop terminal, not a consumer app. **The
WASM route** — replace two subprocess calls with `noir_wasm` and `bb.js` in the
app's JavaScript runtime, or `noir_rs` compiled for the target. That is the route a
consumer app should take, and it is not written yet: `clients/prover/README.md`
specifies exactly what to replace, in a three-row table, and `wealth_client.py` is
under 700 lines and written to be read as the specification for that port. It is a
bounded engineering task on your side, not a research project, but it is a task.

Two things break that port silently, and they are the reason to talk to us before
you start. The verifier target must stay `noir-recursive`; any other target
produces proofs that fail verification with no useful diagnostic. And the Baby
Jubjub cofactor of 8 has to land on the right multiplication — get it wrong and
every signature fails inside the circuit, with an unsatisfied constraint as the
only symptom.

### The proof

`clients/prover/README.md`, sections "The two deployments" and "Integrating into a
mobile app". Then run the whole thing end to end on a laptop:

```
python3 scripts/demo_cro_workflow.py
```

Roughly forty seconds, exits 0, and generates a real proof with real `nargo
execute` and `bb prove` — nothing seeded.

### When this objection is fatal

When the channel is a consumer mobile app, the deadline is this quarter, and they
have no mobile engineering capacity to spend on a WASM prover. Do not sell them a
timeline we cannot hold. Scope down to the advisor terminal — where the CLI runs
today with no port at all — and treat the mobile channel as a phase two with its
own budget. If they have no advisor channel either, walk.

---

## 2. "Our legal team will never accept a JWT as legal proof."

### What they are actually worried about

Not the JWT. Their legal team has been handed vendor "attestations" before and
found that when a dispute arrived, the artefact meant nothing without the vendor's
cooperation. The real question is: *in a hearing, three years from now, with a
customer alleging mis-selling, what can we put in front of a tribunal and who has
to still exist for it to mean anything.*

There is also a fear of being sold a replacement for something legal already
knows how to defend — the signed suitability file.

### The answer

Start by removing the replacement fear. The artefact does not replace your
existing suitability file. It makes your existing file checkable. You keep the
signed record, the advisor's notes, the wet-ink or DocuSign signature, everything
your counsel already knows how to produce. What you add is a small cryptographic
object that lets a third party confirm the assessment was performed, against
whose thresholds, and when — without taking anyone's word for it.

Three specific properties, stated exactly. The attestation is an Ed25519 JWT that
anyone can verify against the key published at `/.well-known/jwks.json` — no call
to us, no API key, no cooperation required. The zero-knowledge proof underneath it
is independently re-verifiable years later with `bb verify` against the
verification key committed at `circuits/wealth_suitability/vkey/vk`; the examiner
does not have to trust our build pipeline, because the key is published separately
from the server that used it. And both audit logs — Memtara's `audit_log` and
AIHOOTS's — are SHA-256 hash-chained, so an altered record disagrees with a digest
anyone holding the payload can recompute.

Now the honest boundary, and say it before their counsel does. What is
cryptographically stronger than a scanned signature is narrow and real: the
integrity and non-repudiation *of the content* are machine-checkable. Nobody can
alter what was assessed, or against which thresholds, without the check failing —
and a scanned signature offers no equivalent. What is **not** settled is legal
admissibility in any particular forum. Whether a UAE court or the DFSA accepts a
given artefact is a question for their counsel and not for us, and we will not
pretend otherwise. Nor is the sealed PDF a PAdES signature: no PDF viewer will
show a green tick for it. The seal is a detached SHA-256 digest with an optional
Ed25519 signature in a sidecar file. The strongest authenticity claim in the pack
is the JWT, not the PDF — and the exporter says so on the page.

One operational point that matters to legal more than it sounds: a hash chain
proves internal consistency, not availability. It proves nobody edited a record.
It does not stop an operator deleting the whole log. Append-only storage and
off-box replication are the mitigations, and neither is in this repository — they
are yours to run.

### The proof

Hand them the sealed case file and the two commands that check it.

```
scripts/memtara-export --request-id "$REQUEST_ID" --base-url $MEMTARA \
  --org-api-key "$KEY" --output ./case_file.pdf
./scripts/memtara-export verify ./case_file.pdf     # exits 0
```

Flip one byte in the PDF and run it again: it exits 1. Section 5c of the generated
document is titled "What the seal is not" and states in the pack itself that this
is not a PAdES or AdES signature and no viewer will validate it. A vendor whose own
evidence pack names its own limits is the point of the demo.

### When this objection is fatal

When their regulatory filing requires a qualified or advanced electronic signature
under a named framework, and the artefact must validate inside a PDF reader. We do
not produce that today, and telling them we do is a lie they will discover during
implementation. Scope to the JWT-and-proof layer as supplementary evidence
alongside whatever qualified signature they already use, or walk.

---

## 3. "Can we run this on-premise, away from your cloud?"

### What they are actually worried about

Rarely the servers. This is usually a proxy for three things at once: data
residency (see objection 8), whether we can see their customer book, and whether a
vendor outage becomes their outage. Sometimes it is also a test — they want to
know whether you will claim on-prem is trivial.

### The answer

Yes, and it is more accurate to say the platform *only* runs from source today.
There is no container image, no Helm chart, and no packaged installer. The stack is
Rust and Axum, Postgres 15, and the Noir toolchain — `nargo` and `bb` on `PATH`,
with the circuits compiled. The server generates its verification keys at boot and
refuses to start if it cannot, rather than coming up as a verifier that cannot
verify. So an on-premise deployment is a genuine engineering engagement, measured
in weeks with your platform team, not an afternoon.

On telemetry, the answer is unusually clean: nothing is phoned home because there
is no telemetry code. Not disabled by a flag — absent. Read `backend/api/Cargo.toml`
and there is no analytics, crash-reporting or telemetry crate in the dependency
list. The only external host in the default configuration is the UAE Pass identity
provider, and that is a URL you set.

What an on-prem deployment actually requires of you: a Rust build toolchain and a
place to run the build; Postgres 15 with your own backup and restore; `bb` and
`nargo` on the host, pinned to versions we agree; a persistent directory for the
generated verification keys; custody of the `MEMTARA_PRIVATE_KEY` issuer signing
key, which is the key everything downstream trusts; TLS termination and ingress;
and your own patching. One thing you must do at the edge that we do not do for you:
**org self-registration is currently unauthenticated.** Anyone who can reach
`POST /orgs` can mint a tenant. On-prem, that endpoint has to sit behind your
network controls or an allowlist. Gating it in the product is a real open item, and
it is named in the README rather than hidden.

### The proof

`README.md`, the "Quick Start" and "Honest limits" sections — the missing container
image and the unauthenticated `POST /orgs` are both listed there by us, not
discovered by them. Then:

```
grep -ri "telemetry\|analytics\|sentry\|posthog" backend/api/Cargo.toml   # no hits
curl -s $MEMTARA/health | jq .
```

### When this objection is fatal

When they need a supported, versioned, air-gapped appliance with a documented
upgrade path and a support SLA on day one. We can offer an SLA contractually; we
cannot evidence a track record for one, and we do not have the packaging. If their
platform team has no capacity to co-build the deployment, this is a phase-two
conversation and pushing it now produces a failed implementation.

---

## 4. "What happens if the vault_root becomes corrupted?"

### What they are actually worried about

The word behind this question is almost always "outage". They are imagining an
advisor sitting with a client, a screen that will not proceed, and no way to
override it. What they want to know is whether a cryptographic failure becomes a
branch-level service incident, and who picks up the phone.

### The answer

If the `vault_root` in a submitted proof does not match the root the client
actually synced, the submission is rejected. No token is minted, no attestation is
issued, and the advisor cannot proceed with that assessment. The system fails
closed, deliberately.

That is the right behaviour, and it is worth spending thirty seconds on why. The
`vault_root` is what binds the proof to *this client's* committed figures rather
than to some arbitrary tree the prover happened to construct. `submit_wealth_proof`
pins it; if it did not, a mathematically perfect proof could attest that *somebody*
clears your thresholds. Failing open here would mean issuing signed, hash-chained,
regulator-facing evidence of a suitability assessment that measured the wrong
person. A blocked advisor is a support ticket. A false attestation is a mis-selling
finding with your signature on it.

The recovery path is re-synchronisation, and you should staff for it rather than
be surprised by it. The client re-derives their root with `memtara-prove
vault-root`, the encrypted blob is re-synced — `vault_blobs` carries a `version`
column and uses compare-and-swap, so a stale write is detected rather than
silently applied — and a **new** assessment is opened. Not a retry: the nonce is
single-use by design, so a failed submission needs a fresh request. The hard case
is a client who has lost the vault file itself. We cannot recover it for them,
because the server holds only ciphertext and has never had the key. That is the
same property that makes the privacy claim true, and the cost of it is that
recovery means the client re-entering their four figures. Budget a helpdesk script
and an advisor-side escalation path for exactly this.

One related limit worth volunteering: the four older session circuits do **not**
pin `vault_root` to the user's synced vault. Only `wealth_suitability` does. Their
Merkle limb proves the figures are consistent with *some* tree rather than the
client's committed one. That is recorded in the README and the regulatory matrix as
a known weakness in the older path.

### The proof

`backend/api/migrations/0001_init.sql` — the `vault_blobs` table is
`ciphertext`, `vault_root`, `version`, and nothing else; the server has no column
in which a decryption key could live. The pinning behaviour and the older
circuits' gap are both stated in `docs/REGULATORY_MATRIX.md`, in the section
titled "One gap this feature closes that the CBUAE matrix leaves open".

### When this objection is fatal

When they require an advisor-side override — a way for a supervisor to proceed
without a valid proof. We will not build that, because an override path is a way to
manufacture unearned evidence, and the artefact's whole value is that it cannot be
manufactured. If a manual override is a hard requirement, we are the wrong product.

---

## 5. "How do we know you won't change the vkey and invalidate our old audits?"

### What they are actually worried about

Vendor lock-in with a cryptographic twist. They are asking whether a routine
release on our side can quietly turn three years of their compliance evidence into
unverifiable bytes — and whether they would even find out before an examiner did.

### The answer

Three answers, and you should be clear which of them is a mechanism and which is a
promise.

The mechanism is in three parts. The verification key is committed to the
repository at `circuits/wealth_suitability/vkey/vk`, alongside its hash, precisely
so an examiner can re-verify a proof without trusting anyone's build pipeline. CI
regenerates that key from the circuit on every run and fails the build if the bytes
differ, so the committed key cannot drift from the circuit unnoticed. And `GET
/health` compares the key the running server actually verifies against with the
published one, and returns 503 with `"status": "DIVERGED"` if they differ.

That third check deserves its own sentence, because it is the part engineers
respect. Both keys work perfectly well in isolation. A server running a drifted key
verifies proofs happily, issues valid-looking attestations, and shows no error
anywhere — while every proof it accepts today becomes unverifiable tomorrow by the
examiner holding the published key. A divergence has no other symptom. That is
exactly why there is a check for it, and it is why the instance takes itself out of
rotation rather than logging a warning nobody reads.

The promise, stated as a promise: a six-month notice period before retiring a
verification key is something we can commit to contractually. It is not a
mechanism. Nothing in the code enforces it. What *does* protect you mechanically is
that retiring a key does not break your old evidence — the old key still verifies
the old proofs. Retain the verification key with the case files, which is why its
SHA-256 is printed inside the generated pack, and your archive stays checkable
regardless of what we ship next.

One honest nuance, because their engineer will find it: if no published key is
present to compare against, the check reports `unknown` rather than degrading the
instance. That is legitimate for a deployment shipped without the repository — but
it means the check is only protecting you if the published key is deployed
alongside the server. Make that part of the on-prem runbook.

### The proof

`backend/api/src/ops/health.rs` — the reasoning is in the file header comment, not
just the code. `.github/workflows/ci.yml`, the step named "Check the committed
wealth vkey still matches the circuit". And live:

```
curl -s $MEMTARA/health | jq '.checks.published_wealth_vkey'
```

which returns `matches` or `DIVERGED` with both SHA-256 digests side by side.

### When this objection is fatal

When they require a contractual, audited key-lifecycle process with an independent
notary or escrowed key ceremony. We have a committed file, a CI check and a health
endpoint — good engineering, not a governed key ceremony. If their model-risk
policy demands the latter before go-live, scope the pilot to non-production
evidence and be explicit that key governance is an open item.

---

## 6. "You have no customers and no SOC 2."

### What they are actually worried about

This is almost never a question about our security posture. It is a question about
*their* career risk. Somebody has to sign a vendor-onboarding form asserting that
due diligence was done, and there is no box on that form for "pre-revenue startup
with good tests". They are asking you to give them a defensible way to say yes.

Treating this as an objection to argue with is the most common way this deal dies.
It is a structuring problem.

### The answer

Both facts are true and you say them first. Zero banks in production, zero paying
customers, no SOC 2, no ISO 27001, no independent penetration test, no SLA track
record. We can offer an SLA contractually; we cannot evidence one. Anyone who tells
you otherwise about a company at this stage is telling you something else that is
untrue as well.

What we offer instead is a pilot shaped so that saying yes costs them very little.
Synthetic clients only, no production customer data, no integration into a live
advice journey, running on their infrastructure from source so no data reaches us
at any point. Fixed scope, fixed duration, and exit criteria written down in
advance — what has to be true at the end for this to proceed, and what ends it.
The pilot's purpose is not to prove we are a mature vendor. It is to convert an
unanswerable procurement question into a scoped technical evaluation their
engineers can actually complete.

And make the certification gap part of the pilot rather than a promise about the
future. An independent security review, commissioned during the pilot against an
agreed scope, with the findings shared with them, is a deliverable we can put in
the contract. That converts "no pentest" from a permanent state into a dated
milestone with their name on the scope.

What they can evaluate today, without trusting us at all, is unusually large for a
pre-revenue vendor: the full source, the circuits, the regulatory mapping with its
gaps named on page one, and a test suite that is green — `cargo test` 87/87, `nargo
test --workspace` 61/61, Python 134/134. The suitability end-to-end test is the one
place in the repository where no part of the cryptography is stood in for.

Piloted by zero banks? Yes. Ready for yours? That is what the pilot is for.

### The proof

One command on their own laptop, in front of them:

```
python3 scripts/demo_cro_workflow.py
```

Then `docs/REGULATORY_MATRIX.md`, and specifically the four gaps stated on page one
— training-data representativeness, bias measurement, bilingual Arabic disclosure,
and the complaints channel. A vendor who publishes their own gaps is the argument.

### When this objection is fatal

When there is a hard policy gate: no contract of any kind, including a paid proof
of concept, without SOC 2 Type II. Find out early whether an exception exists and
who signs it — that is one of the three qualifying questions in Appendix B. If no
exception path exists, offer a non-contractual technical evaluation from source on
their own hardware and accept that revenue is a year away, or walk. Do not spend
three months courting a committee that has no mechanism to say yes.

---

## 7. "What happens to us if your company disappears?"

### What they are actually worried about

Under the CBUAE Outsourcing Regulation and their own third-party risk framework,
somebody has to document an exit plan. But there is a sharper version of the worry
underneath: if this vendor folds, does every suitability assessment we made using
them become unevidenced? That is not a continuity question, it is a retrospective
compliance question, and it is the one that actually frightens a CRO.

### The answer

Take the sharper question first, because the answer is genuinely strong. Your
exported case files remain verifiable without us. The proof is verified by
`bb verify`, which is Barretenberg — an open-source tool from the Noir ecosystem,
not something we control or license. The verification key it checks against is a
file committed in the source, so it travels with the code and does not depend on
our servers existing. The attestation is verified against a JWKS document, which is
plain JSON. So an examiner in 2031 needs: the proof bytes, the public inputs, the
verification key, the JWKS, and an open-source binary. None of those is us.

There is one operational condition on that, and it matters. If you run the platform
on-premise, your own instance serves the JWKS and the question does not arise. If we
host it, **archive the JWKS document alongside each case file** — otherwise the key
that validates your attestations disappears with our DNS. That is one line in a
retention runbook, and it is the difference between the paragraph above being true
for you and being true in theory.

On the corporate continuity side: the platform is source-available to you, and the
right structure is for the source and the deployment runbook to sit with a named
escrow agent under terms your counsel drafts. Be careful here and do not
freelance — the README states an MIT licence but there is **no LICENSE file in the
repository**, so the licence grant is currently an assertion in a document rather
than an executed instrument. Do not tell a bank's legal team they already have
perpetual rights. Tell them the licence terms are settled in the contract, and get
it done there.

### The proof

`circuits/wealth_suitability/vkey/README.md` — the section titled "Why this one is
committed when the others are not" explains that the second audience for that key
is an examiner who should not have to trust our build. Then, from an exported pack,
re-verify with nothing of ours in the loop:

```
bb verify -i <public_inputs> -p <proof> \
          -k circuits/wealth_suitability/vkey/vk -t noir-recursive
```

Public input 11 is the verdict — and read it, because a proof of *not suitable*
verifies exactly as cleanly as a proof of suitable.

### When this objection is fatal

When their outsourcing policy requires a named escrow agent with verified build
reproduction, or a supplier with a balance sheet capable of indemnifying them. We
cannot supply the second. If both are hard requirements, the realistic path is a
systems integrator or a bank-side sponsor who holds the contract and carries the
counterparty risk, with us as a subcontractor. If neither is available, walk.

---

## 8. "Our data cannot leave the UAE."

### What they are actually worried about

Two separate things wearing one sentence. The compliance officer means in-country
retention under the Consumer Protection Standards and the PDPL. The security lead
means "does a foreign company end up holding a copy of our customer book". Answer
both, and answer them with a table of what is actually stored, because a vague
residency assurance is what makes them stop listening.

### The answer

Start with the claim we do **not** make. Memtara is not a system that holds no
personal data. It holds a `users` row with a phone number, optionally an email, a
UAE Pass subject identifier and a display name — the schema requires at least one
of those. It holds passkey records with device names, session records, an encrypted
vault blob, and a persistent user identifier. Anyone who tells you a bank vendor
holds "no personal data" is either wrong or being careful with words.

The true claim is narrower and considerably more useful: **Memtara never receives
the client's financial figures.** Income, liquid assets, risk tolerance and
holdings value are witnesses to a proof generated on the client's device. There is
no endpoint that accepts them, no column that stores them, and no code path by
which the backend could see them — because generating the proof requires the
plaintext, and the backend never proves, it only verifies. That is structural, not
a policy. The thresholds you *will* find in the database — `min_income`,
`min_liquidity`, `max_concentration_percent` — are the bank's own product terms,
which are public inputs to the proof, not the client's figures.

On residency, the answer is architectural rather than contractual: there is one
Postgres database and nothing else. No analytics pipeline, no data warehouse, no
telemetry, no second store. Put that database in the UAE and the residency question
is answered by where you run it, which is the on-premise deployment in objection 3.
The `/metrics` endpoint carries no tenant-identifying label at all — no `org_id`,
no `user_id`, no `product_isin` — and there is a test that fails if anyone adds
one, so even your monitoring scrape does not export a tenant directory.

What remains yours: PDPL registration, lawful-basis analysis, retention schedules
for the records you still hold, and the residency of your other systems. The
regulatory matrix says so in the §5(c) row rather than claiming we discharge it.

### The proof

`backend/api/migrations/0001_init.sql` is short enough to read in the meeting —
every table, every column. Point at `vault_blobs`: `ciphertext`, `vault_root`,
`version`, and no key column anywhere in the schema. Then
`backend/api/migrations/0003_wealth_suitability.sql` and `0004_products.sql` for
where the thresholds live and why they are the bank's rather than the client's.
And:

```
curl -s $MEMTARA/metrics | grep -E 'org_id|user_id|isin'    # no hits
```

### When this objection is fatal

When they require a certified sovereign-cloud region with attested residency
controls and a vendor able to produce a completed DPIA and a data-processing
addendum reviewed against the PDPL. We can run entirely on their infrastructure,
which answers the substance — but we cannot supply the certification or the legal
paperwork at this stage. If the gate is documentary rather than technical, name the
gap and let their counsel decide whether an on-prem deployment satisfies it.

---

## Appendix A — Technical due-diligence answer sheet

Twelve answers for the engineer who fires questions at you in a corridor. Short
enough to say from memory; each one has a file behind it.

**Which curve?** Baby Jubjub for the in-circuit EdDSA signature — chosen because it
is native to the BN254 proving field, so verifying a signature inside the circuit
does not require expensive non-native field emulation. Hashes and Merkle
commitments are Poseidon over BN254.

**Which proving system?** Noir circuits compiled to ACIR, proved and verified with
Barretenberg (`bb`), version 5.1.0 at the time of writing. Verifier target
`noir-recursive` — poseidon2 transcript, ZK-preserving. Deliberately not a `-no-zk`
target, because the entire premise is that a proof leaks nothing beyond the public
inputs. Fixed in `backend/api/src/verify/mod.rs`, not configurable per deployment.

**Key management?** The issuer key is Ed25519, loaded from `MEMTARA_PRIVATE_KEY`,
with the public half at `/.well-known/jwks.json`. `GET /health` returns 503 if the
`kid` the server signs with is not present in the JWKS it publishes, because
otherwise it would happily issue tokens nobody can verify. Circuit verification keys
are generated at boot into `backend/api/vkeys/`; the wealth key is additionally
committed. The client's Baby Jubjub signing key lives in `vault.json`, and the
module refuses to load one whose file mode is readable beyond its owner. On a phone
that key belongs in the Secure Enclave or Android Keystore — correct, and not built.

**Multi-tenancy isolation?** Every table is scoped by `org_id`. The product registry
is keyed on `(org_id, product_isin)` rather than the ISIN alone, so two banks can
list the same instrument with different terms and neither can read the other's
product governance. There is a test that fails if one tenant can see another's
registry or evidence pack: `test_one_banks_registry_is_invisible_to_another` in
`tests/test_wealth_suitability_e2e.py`.

**Rate limits?** Ten proof submissions per user per sixty seconds by default,
configurable via `MEMTARA_PROOF_RATE_LIMIT` and its window. Honest limit: it is
per-process, so two replicas behind a load balancer permit twice the configured
rate. It bounds the only genuinely expensive operation the server performs; it is
not a security boundary. A true global limit belongs at the edge or behind Redis,
and the `RateLimiter` seam is shaped for it.

**What is stored?** Read `backend/api/migrations/0001_init.sql` — it is short.
Users with a phone number and optional email, UAE Pass subject and display name;
passkey records; hashed OTP codes; hashed session tokens; an opaque encrypted vault
blob with its root and version; organisations with hashed API keys; disclosure
requests; proof bytes and public inputs; used nonces; and the audit log. Not
stored, anywhere: the client's income, liquid assets, risk tolerance or holdings
value.

**What is logged?** A SHA-256 hash-chained `audit_log` — event type, reference id,
event hash, previous hash. `org_id` is on the row but deliberately outside the
hash, because folding it in would have invalidated every row written before that
migration, which for a compliance log is a self-inflicted tamper alarm; the payload
already carries it and the payload is hashed. Prometheus exposition at `/metrics`,
with no tenant-identifying label, enforced by a test. Application tracing goes to
stdout.

**How long does a proof take?** A few seconds on a developer laptop for `nargo
execute` plus `bb prove`. The whole one-command demo — build, boot, register a
product, onboard a client, prove, verify, attest, drive the AIHOOTS chain, export a
sealed PDF — runs in roughly forty seconds. We have no published benchmark for a
phone, and will not invent one.

**What happens on verification failure?** The proof is recorded with `valid =
false` and audited, no token is minted, and the submission is refused. An invalid
proof does **not** consume the legitimate holder's nonce, so a third party cannot
burn someone's one-shot grant. Nonce replay is prevented by a primary key on
`used_nonces` — a database constraint, not application logic.

**The trap in `bb verify`.** Exit code 0 means the proof was correctly constructed,
not that the client is suitable. Public input 11 is the verdict, and a proof of
*not suitable* verifies exactly as cleanly. A relying party that reads the exit code
and not index 11 approves everyone who was assessed. `/api/v1/issue-proof` refuses
the suitability predicate outright rather than trusting anyone to remember this.

**Dependencies?** Backend: Axum, Tokio, sqlx against Postgres 15, `webauthn-rs`,
`ed25519-dalek`, `sha2`, `argon2`. No telemetry, analytics or crash-reporting crate.
External binaries: `nargo` and `bb`. The prover CLI has no Python dependencies at
all. The Python test and reporting tooling uses pytest, httpx, `cryptography`,
pg8000 and faker, and none of it is required to run the platform.

**What is the weakest link?** The holder's device, and we will not pretend
otherwise. `vault.json` is a plaintext file protected by its file mode — right for
an advisor terminal, wrong for a consumer phone, where the key belongs in hardware
and the figures in the encrypted vault the `vault/` crate already implements. The
file format mirrors that structure so the port is a substitution rather than a
redesign, but the port is not written. Separately: a proof token is not revocable
inside its 300-second lifetime — revoke the disclosure request or the session
instead.

---

## Appendix B — Three questions we should ask them

Ask these early. Each one either qualifies the deal or ends it before anyone has
spent a quarter on it.

**1. "Who owns your product registry today, and has your risk committee already
approved the instruments you would assess against?"**

What it tests: whether the control we sell has anything to attach to. Memtara's
central guarantee is that suitability thresholds come from a registry the adviser
does not control at recommendation time, and that assessments are refused against
products the risk committee has not approved. If product governance is a spreadsheet
nobody owns, we are not selling them evidence of a control — we are asking them to
build the control first. That is a different, longer engagement, and it should be
priced and scheduled as one.

**2. "Does your vendor policy permit a paid pilot with a pre-SOC-2 supplier, and who
signs that exception?"**

What it tests: whether a path to yes exists at all. Ask for the name, not the
policy. If nobody can be named, the enthusiasm in the room is not connected to a
mechanism, and the deal will die quietly at onboarding after months of meetings.
This is the single most useful question in this document.

**3. "Where does the client-side app live — do you own a mobile codebase you can
ship a prover into, or is your advice channel an advisor terminal?"**

What it tests: whether the integration is two weeks or two quarters. An advisor
terminal runs the CLI today with no port at all. A consumer mobile app needs the
WASM prover, which means their mobile team, their release cycle, and their
appetite for shipping cryptographic code. If the answer is "consumer app" and they
have no mobile capacity, sell the advisor channel now and put the app in phase two —
or accept that the timeline is theirs, not ours.
