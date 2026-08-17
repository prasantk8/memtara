# README.md changes for `aihoots-e1-audit-gateway`

Two edits. Both are additive; nothing existing is removed.

---

## Edit 1 — the companion badge, under the title

**Find:**

```markdown
# AIHOOTS E1 — LLM Audit Gateway

An OpenAI-compatible proxy that produces a **tamper-evident, independently
verifiable audit trail** of every LLM request, response, and policy decision —
the control every AI regulation implies and almost nobody ships as working code.
```

**Replace with:**

```markdown
# AIHOOTS E1 — LLM Audit Gateway

[![Memtara Companion](https://img.shields.io/badge/Memtara-Companion-a86a12)](https://aihoots.com/memtara)
[![Real ZK Proofs (Baby Jubjub)](https://img.shields.io/badge/Real%20ZK%20Proofs-Baby%20Jubjub-2f6f4e)](https://github.com/prasantk8/memtara)

An OpenAI-compatible proxy that produces a **tamper-evident, independently
verifiable audit trail** of every LLM request, response, and policy decision —
the control every AI regulation implies and almost nobody ships as working code.
```

---

## Edit 2 — a section, immediately after "What's inside"

**Find:**

```markdown
## Design decisions
See `docs/ADR-001`..`ADR-003`. Every choice records the alternatives considered and why they lost.
```

**Insert directly above it:**

```markdown
## Memtara — the companion that proves the facts

This gateway makes what a model was told **auditable**. It does not make it
**true**. A prompt asserting "this client qualifies for the note" is chained
faithfully and is still just prompt text, which is attacker-controlled.

[Memtara](https://github.com/prasantk8/memtara) closes that half. A client's
own device generates a zero-knowledge proof that it meets a structured product's
registered suitability terms; Memtara verifies it and signs a short-lived Ed25519
attestation; this gateway validates that attestation locally against a published
JWKS, injects the verified fact into the model's context, and appends the proof
hash to the chain — with no synchronous call back to Memtara.

The client's income, liquid assets, risk tolerance and holdings never leave
their device. The bank receives one bit and a proof.

```bash
git clone --recurse-submodules https://github.com/prasantk8/memtara.git
cd memtara && ./scripts/quickstart.sh
```

Real Baby Jubjub signatures, real Poseidon commitments, real `bb prove` and
`bb verify` — about forty seconds, ending in a sealed PDF whose seal fails on a
single flipped byte. Piloted by zero banks so far, and the landing page says so.

**More:** [aihoots.com/memtara](https://aihoots.com/memtara) ·
[the regulatory matrix](https://github.com/prasantk8/memtara/blob/main/docs/REGULATORY_MATRIX.md),
which names its four gaps before any of its coverage.
```

---

## A note on the badge colours

`a86a12` is the amber the Memtara page spends its single accent on; `2f6f4e` is
the green already used by the ZK badge in the Memtara README. Reusing both keeps
the two repositories visually related without introducing a third colour that
belongs to neither.
