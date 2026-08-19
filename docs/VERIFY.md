# How to verify this evidence bundle

For an internal auditor, an external examiner, or anyone else who has to
decide whether a document is worth relying on. You do not need to understand
cryptography to run this procedure, and you should not have to. Every step is
a command you type and a value you compare.

You do not need an internet connection, an account with anyone, a password,
or a person from the firm sitting next to you. If any step below appears to
need one of those, that is a defect in the bundle and not something to work
around.

**Time required:** about ten minutes for steps 1-3 and 6-9. Step 5 needs one
tool installed (see below) and takes a few seconds once it is.

---

## Before you start

You need:

- A computer with **Python 3.9 or later**. Type `python3 --version` to check.
- For step 8 only: the `cryptography` package (`python3 -m pip install cryptography`).
- For step 5 only: `bb`, an open-source tool published by Aztec, not by
  Memtara. The exact version to install is written in `MANIFEST.json` under
  `pinned_dependencies.bb`. Steps 1-4 and 6-9 do not need it.

Everything else is inside the bundle.

**The fast route.** The whole procedure below is also a script, shipped in the
bundle:

```
python3 tools/verify_bundle.py .
```

It prints every step, both verdicts, and refuses to open a network connection
while it runs. Read the rest of this document anyway — it tells you what each
result means, which the script cannot decide for you.

---

## What is in the bundle

| File | What it is |
|---|---|
| `MANIFEST.json` | A list of every other file with its SHA-256 fingerprint, plus the exact versions of the two outside tools this procedure uses. |
| `decision_evidence.json` | The decision record itself, in the exact byte form that was fingerprinted. |
| `evidence_schema/` | A description of what shape that record is supposed to be. |
| `proof/` | The mathematical proof, and the public values it was checked against. |
| `vkey/` | The key the proof is checked with, as published by Memtara. |
| `audit_chain_segment.jsonl` | This decision's entries from Memtara's tamper-evident log. |
| `institution_and_thresholds.json` | Who the firm is, and the thresholds this assessment was measured against. |
| `aihoots_audit_chain.jsonl` | The relying party's own independent log, if one was supplied. |
| `jwks_snapshot.json` | The issuer's public keys, captured at the time the evidence was issued. |
| `case_file.pdf` + `.seal.json` | The readable version, and a fingerprint over it. |
| `tools/` | This procedure as a script, and the relying party's own log checker. |

If `MANIFEST.json` has an `absent` section, read it first. It lists what the
bundle does **not** contain and why. Anything named there means a step below
will report **NOT RUN**.

---

## Step 1 — Every file is the file the manifest says it is

```
python3 tools/verify_bundle.py . 2>&1 | head -20
```

Or by hand, for any file:

```
shasum -a 256 decision_evidence.json
```

and compare with that file's `sha256` entry in `MANIFEST.json`.

**A PASS means:** none of these files has been altered since the bundle was
assembled, and there is nothing in the bundle the manifest does not account
for.

**A PASS does NOT mean:** that the manifest itself is genuine. A manifest is
just a file. Anyone who can change the evidence can change the manifest to
match. What stops that is a signature over the manifest — see step 9. Until
you have checked step 9, treat step 1 as proving *internal consistency*, which
is a much weaker thing than authenticity.

**If it fails:** stop. Do not continue and do not weigh the later results.
A hash mismatch means the bytes in front of you are not the bytes that were
sealed, and no later step can repair that.

---

## Step 2 — The record matches the seal

```
shasum -a 256 decision_evidence.json
```

Compare with `canonical_evidence_sha256` inside `case_file.pdf.seal.json`.
They must be identical.

**A PASS means:** the decision record and the printed case file describe the
same export. The PDF is a rendering of this record and not of some other one.

**A PASS does NOT mean:** the record is true. This compares a file with a
fingerprint of that file. Whether the firm's database held the right facts on
the day is a separate question that no digest can answer.

---

## Step 3 — The record is the right shape

The script validates `decision_evidence.json` against
`evidence_schema/case_file_pack.v1.schema.json`.

**A PASS means:** every field the format requires is present, with the right
kind of value. In particular, a *declined* assessment carries exactly the same
fields as an approved one — no field disappears because the answer was no.

**A PASS does NOT mean:** the values are correct, or that the schema covers
everything a regulator might want. It does not. This record has no field for
which AI model was involved, no field for which human reviewed the decision,
and no consent record, because the system that produced it does not capture
them. The schema file says so in its own `description`. A PASS here is a
statement about structure and nothing else.

---

## Step 4 — The key is the one Memtara published

```
shasum -a 256 vkey/wealth_suitability.vk
```

Compare with `verification_key.sha256` inside `decision_evidence.json`.

**A PASS means:** the key in this bundle is the key the assessment was
actually checked against. This matters because step 5 is meaningless without
it: a proof will happily verify against a key chosen to make it verify.

**A PASS does NOT mean:** that the key is honest. What backs that claim is
separate and worth knowing: this key is committed into Memtara's public source
repository, and their build pipeline regenerates it from the circuit on every
change and **fails the build if the bytes differ**. So the key can be compared
against the published repository by anyone, without Memtara's cooperation.

**A note on `vkey/vk_hash`.** That file is a 32-byte value produced by `bb`
itself. It is *not* a SHA-256 of the key file, and `shasum` will not reproduce
it. Do not treat a mismatch there as a finding — comparing it requires
regenerating the key with the toolchain, which is what Memtara's build pipeline
does, not something this procedure asks of you.

---

## Step 5 — The proof verifies

```
bb verify -i proof/public_inputs \
          -p proof/wealth_suitability.proof \
          -k vkey/wealth_suitability.vk \
          -t noir-recursive
```

Exit code 0, and a line reading that the proof verified.

**A PASS means:** the assessment was genuinely carried out. Someone with the
client's actual figures ran them through the published rules and produced a
result. The firm cannot manufacture this: producing a proof that verifies
against that key requires having done the computation.

**A PASS does NOT mean — and this is the single most important line in this
document — that the client was found suitable.** A proof that the client
**failed** the assessment verifies exactly as cleanly as one that they passed:
same key, same exit code, same success message. Exit code 0 tells you the
assessment was performed correctly. It does not tell you what it concluded.
**The answer is in step 6, and only in step 6.**

**If it reports NOT RUN:** either `bb` is not installed, or the bundle does
not contain the proof bytes. The second case is common: Memtara's evidence
endpoint returns the proof's *length* and its fingerprint, not the proof
itself, so the proof can only be in the bundle if the firm supplied it from
its own records. NOT RUN means nobody has checked the proof here. It does not
mean the proof failed, and it must not be recorded as if it passed.

---

## Step 6 — What was actually decided

The decision is the twelfth public value, at index 11, named `suitable`:

```
python3 -c "
import sys
data = open('proof/public_inputs','rb').read()
print('SUITABLE' if int.from_bytes(data[11*32:12*32],'big') else 'NOT SUITABLE')
"
```

The script prints all twelve values with the answer marked.

**A PASS means:** nothing — this step has no pass or fail. It is a reading.
The value is either 1 (suitable) or 0 (not suitable), and the script also
checks that this reading agrees with what the written record claims. If those
two disagree, that is a failure of *integrity*, reported separately.

**What this reading does NOT mean:** it does not mean the recommendation was
appropriate. The circuit evaluates four things: minimum income, minimum liquid
assets, maximum concentration after the trade, and whether the client's risk
tolerance is at least the product's risk level. Anything outside those four —
the client's objectives, their circumstances, anything an adviser was told in
a meeting — is not in this proof and never was.

Note also that the four thresholds are the **firm's**, taken from its product
registry and fixed before the client was asked anything. That is what makes
the answer meaningful. A client who could pick their own minimum income could
prove themselves suitable for anything, with mathematics that checks out
perfectly. The thresholds used are in `institution_and_thresholds.json`.

---

## Step 7 — The audit logs

The script reads `audit_chain_segment.jsonl` and, if present, runs the relying
party's **own** log checker over `aihoots_audit_chain.jsonl`.

**A PASS on the relying party's chain means:** every entry's fingerprint
matches its own contents and links correctly to the entry before it. Nothing
in that log was altered after it was written.

**A PASS does NOT mean the log is complete.** A chain of this kind proves
nothing was *changed*. It cannot prove nothing was *deleted from the end*, or
never written in the first place. Retention and off-site copies remain the
firm's obligation and are not evidenced here.

**On Memtara's own segment, be careful what you conclude.** Two limitations,
both structural:

1. Memtara's log is a single chain across all of its customers. This
   assessment's entries are therefore normally *not* next to each other — the
   entries between them belong to other firms and are correctly not in this
   bundle. So you will usually see "0 of 1 adjacent pairs could be linked
   here", and that is expected, not a finding.
2. The log stores a fingerprint of each event's details but not the details
   themselves. That means the entries here **cannot be recomputed and checked
   at all** from this bundle. Their integrity rests entirely on steps 1 and 2.

Anyone who tells you this segment independently proves what happened is
overstating it. What it does prove, if you later obtain the full log from the
firm, is *where* these events sat in history — which is enough to catch an
event that was inserted or reordered afterwards.

---

## Step 8 — The issuance token against the pinned keys

**A PASS means:** the bundle carries a token issued by Memtara at the time of
the assessment, and its signature verifies against the public key captured in
`jwks_snapshot.json`. This is the strongest origin evidence in the bundle.

The keys are **pinned inside the bundle** and were captured when the evidence
was exported. This procedure does not, and cannot, fetch them: the verifying
script refuses to open a network connection at all. That is deliberate. A pack
whose authenticity depended on what a domain name resolved to on the day you
happened to check it would be asserting something it cannot evidence — and
would stop verifying entirely on the day Memtara, or that key, goes away.

**A PASS does NOT mean:** that these keys are Memtara's. The firm captured
them. A firm that captured a key set of its own making would produce a bundle
that is perfectly self-consistent and proves nothing. To turn this into real
origin evidence, compare the `thumbprint_rfc7638` value printed by the script
against the same value obtained **from somewhere other than this bundle** —
the firm's key register, a fingerprint published by Memtara, or an earlier
bundle from the same issuer. That comparison is the check; everything before
it is bookkeeping.

**If it reports NOT RUN:** the firm did not keep the token. Memtara's server
does not retain it (it is a bearer credential and their log is deliberately
not a place to steal one), so it can only appear here if the firm kept it. In
that case the bundle has no origin evidence at all, and the strongest thing in
it is the proof from steps 4 and 5.

---

## Step 9 — Who produced this

**Read `case_file.pdf.seal.json`. If `"signature": null`, then:**

> **The seal is not a signature.** It is a fingerprint. It will detect any
> change to the document, and it establishes nothing whatsoever about who
> produced it. It is not a PAdES or AdES signature, it is not embedded in the
> PDF, and no PDF viewer will show a signature panel or a green tick for it.
> If you open the file expecting your viewer to vouch for it, your viewer will
> tell you nothing, and that is the correct behaviour rather than a fault.

The field is null because no signing key was supplied when the pack was
exported, and the exporting tool refuses to generate one of its own. That
refusal is right: a signature that verifies against a key nobody holds looks
exactly like a signature that means something.

The same applies to `MANIFEST.json.sig`. If it is absent, the manifest is
unauthenticated and step 1 proves internal consistency only.

**A PASS with a signature present means:** the bytes were signed by the holder
of the key named in the file.

**A PASS does NOT mean** the signer is who you think, unless you supplied the
expected key yourself:

```
python3 tools/verify_bundle.py . --expected-public-key <hex you obtained elsewhere>
```

Verifying a signature against a key carried in the same file it signs proves
only that the two files agree. Anyone who can replace both can produce a
consistent pair.

---

## The two verdicts

Record both. They answer different questions, and no single word covers both.

### 1. Evidence integrity — `VALID` / `INVALID` / `INCOMPLETE`

Are these the bytes that were sealed, and do they agree with each other?

- `VALID` — every applicable check ran and passed.
- `INVALID` — at least one check failed. Something has been altered, or two
  parts of the bundle contradict each other.
- `INCOMPLETE` — nothing failed, but some check could not be run: a tool was
  missing, or the bundle did not carry the file that check needs. **This is
  not a pass.** The reasons are printed above the verdict; read them and
  decide whether you can accept the gap.

### 2. Decision outcome — `SUITABLE` / `NOT SUITABLE` / `NOT ASSESSED`

What did the assessment conclude? Read from public input 11, and from nowhere
else.

- `SUITABLE` — the client met all four thresholds.
- `NOT SUITABLE` — the client did not. **This is a correctly evidenced
  decline.** With `VALID` integrity it means the firm assessed this client and
  turned them away, and did so provably. It is a *good* result for a pack to
  contain, not a defect in it.
- `NOT ASSESSED` — no proof exists. The assessment was opened but never
  completed. This is a third state and it is materially different from a
  decline: nobody said no, nobody said anything. Any recommendation made to
  this client on this instrument was made outside the assessed channel.

**The two verdicts do not combine.** `VALID` + `NOT SUITABLE` is a complete,
sound, correctly formed rejection. Any report, dashboard or script that
collapses these into one word — "PASS", "verified", a green tick — will show a
correct decline as an approval. If you are handed such a summary, ask for
these two lines instead.

---

## What this bundle is independent of, and what it is not

**Scope of the cryptographic independence claim:**

> The cryptographic independence this bundle offers covers the
> `wealth_suitability` circuit and no other. That circuit's verification key is
> committed to the repository and CI fails if it drifts from a fresh build, so
> an examiner can check the proof without trusting Memtara's build pipeline.
> The other four circuits' verification keys are gitignored build artefacts
> regenerated at boot, and no equivalent guarantee exists for them. This is a
> property of one circuit, not of the system.

**Independent of Memtara:** steps 1-6 and 9. They use files in this bundle,
one open-source tool that is not Memtara's, and nothing else. They will work
in ten years with Memtara gone.

**Independent of the firm:** the same steps. The firm cannot produce a proof
that verifies against the published key without having actually run the
assessment.

**Not independent of anyone — the honest list:**

- **Whether the client's figures were true.** The proof shows the arithmetic
  was done on figures committed to a data vault. It cannot show those figures
  described a real person's real finances.
- **Whether a human reviewed this decision.** No such record exists in this
  system. There is no field for it, so there is nothing here to check.
- **Whether consent was obtained.** Same: no consent record exists.
- **Which AI model, if any, was involved.** Same again.
- **Whether the log is complete** (step 7).
- **Whether the pinned keys are really Memtara's** (step 8), unless you
  compare the thumbprint against a source outside this bundle.

A bundle that claimed otherwise would be more comfortable to read and worth
less.
