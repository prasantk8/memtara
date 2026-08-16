# `memtara-prove` — the device prover

Generates a real zero-knowledge proof that a client meets a structured
product's suitability terms, and submits it. The client's income, liquid
assets, risk tolerance and holdings never leave the machine this runs on. The
bank receives one bit and a proof.

This is the party Memtara's backend deliberately cannot be. Proving
`income >= 500,000` requires the income as a witness, so a server that could
generate this proof would be a server holding plaintext — and the entire
privacy claim would be false. There is no server-side fallback, and adding
one would not be an optimisation.

## Quick start

```bash
# 1. Create a vault (once per client, on their device)
clients/prover/memtara-prove init-vault \
    --vault-path ~/.memtara/vault.json \
    --income 750000 --liquid-assets 2000000 \
    --risk-tolerance 4 --existing-holdings-value 300000

# 2. Tell the bank the Merkle root, so it can be pinned
clients/prover/memtara-prove vault-root --vault-path ~/.memtara/vault.json

# 3. Prove
clients/prover/memtara-prove \
    --user-id 9f1c…  --product-isin XS1234567890 \
    --vault-path ~/.memtara/vault.json \
    --base-url https://api.memtara.example \
    --org-api-key "$MEMTARA_ORG_API_KEY"
```

Exit codes: `0` suitable, `3` assessed and **not** suitable, `1` error.
(Three rather than two: argparse already uses 2 for a usage error, and an
embedder must never confuse "you invoked me wrongly" with "your client is
unsuitable".) A decline is a successful run — it produces evidence, which is
the point.

## Requirements

`nargo` and `bb` on `PATH`, and `circuits/target/wealth_suitability.json`
compiled. No Python dependencies at all: the Baby Jubjub arithmetic is
integer maths in the standard library, and every Poseidon hash is delegated
to the circuits' own implementation through `circuits/witness_oracle`. That
delegation is the reason there is no `requirements.txt` here, and it is
deliberate — a second Poseidon written in Python could disagree with the
verifier's, and it would do so silently.

## The two deployments

|                        | Advisor terminal | Holder's device |
|------------------------|------------------|-----------------|
| Holds an org API key   | yes              | **never**       |
| Opens the assessment   | yes              | no              |
| Answers it             | yes              | yes             |
| Credential used        | org API key      | session token   |
| Invocation             | `--org-api-key`  | `--request-id --request-file --session-token` |

An org API key can open an assessment against *any* of the bank's users. Put
one on a phone and a compromised handset becomes a way to interrogate the
bank's whole book. So the mobile shape is:

```
bank    POST /api/v1/issue-wealth-request      -> {request_id, nonce, terms, …}
bank    push that JSON to the holder's device
device  memtara-prove --request-id <id> --request-file req.json \
                      --session-token <holder's token> --vault-path …
```

The request body is not secret — every value in it is a public input the
proof will publish anyway.

## Integrating into a mobile app

Two routes, and the choice is about where the Noir toolchain runs, not about
the protocol. Both produce byte-identical proofs.

### Subprocess (React Native, Flutter with a native module, Electron)

Ship `nargo` and `bb` binaries for the target architecture, call this CLI
with `--json`, and parse one object off stdout. Progress goes to stderr, so
stdout stays clean.

```jsonc
{
  "request_id": "…", "product_isin": "XS1234567890",
  "product_name": "5-Year S&P Principal Protected Note",
  "suitable": true, "proof_token": "eyJhbGciOiJFZERTQSIs…",
  "expires_in": 300, "regulatory_audit_id": "…",
  "vault_root": "0x1f13…"
}
```

The honest caveat: shipping two native binaries per architecture is real
work, and on iOS the sandbox makes spawning subprocesses impractical. This
route suits an advisor's iPad or desktop terminal better than a consumer app.

### WASM (the route a consumer app should take)

Replace the two subprocess calls with `noir_wasm` + `bb.js` in the app's
JavaScript runtime, or `noir_rs` compiled for the target. What you are
replacing is small and clearly bounded:

| This CLI does | The app does instead |
|---|---|
| `nargo execute` over `witness_oracle` for Poseidon | call the same Noir library through `noir_wasm` |
| `nargo execute` over `wealth_suitability` | `noir_wasm` `execute` with the same witness map |
| `bb prove -t noir-recursive` | `bb.js` `generateProof`, **same verifier target** |

Everything else — `clients/wealth_client.py`'s Baby Jubjub signing, the
witness layout, the Merkle slots, the public-input ordering — ports as
straight arithmetic. `wealth_client.py` is under 700 lines and is written to
be read as a specification for exactly this port.

Two things that will break the port silently if you get them wrong:

- **The verifier target must stay `noir-recursive`.** A proof produced under
  any other target fails verification with no useful diagnostic. The server's
  choice is fixed in `backend/api/src/verify/mod.rs` and is not configurable.
- **The cofactor of 8.** `eddsa_verify` multiplies the public key by 8 before
  checking `S·B8 = R8 + h·A8`, so the signing scalar is `8k mod SUBORDER`
  while the published public key is `B8·k`. `Keypair.from_seed` keeps that
  factor explicit for this reason. Fold it into the wrong multiplication and
  every signature fails inside the circuit, with the only symptom being an
  unsatisfied constraint.

### Where the key lives

`vault.json` is a plaintext file, and this module refuses to load one whose
mode is readable beyond its owner. That is right for an advisor terminal and
CI, and wrong for a phone: there the signing key belongs in the Secure
Enclave or Android Keystore, where it can sign but not be exported, and the
figures belong in the encrypted vault the `vault/` Rust crate already
implements. The file format mirrors that structure — a key, and a category of
figures — so the port is a substitution rather than a redesign.

## What this tool checks before it submits

After generating the proof and before sending it, the CLI re-evaluates the
same four limbs in plain Python (`WealthVault.expected_verdict`) and refuses
to submit if that disagrees with the circuit's answer. Two independent
implementations agreeing is weak evidence; two disagreeing is conclusive, and
the device is the right place to find out — before a signed attestation
exists.

## What it does not do

- **It does not choose the thresholds.** They come back from
  `issue-wealth-request`, fixed by the server from the bank's product
  registry, and the server re-checks every one of them at submission.
  `--show-product` fetches the registry entry for display only; if the CLI
  proved against *that* copy and the two ever disagreed, the proof would fail
  verification for a reason the holder could not see.
- **It does not retry.** The nonce is single-use by design. A failed
  submission needs a new assessment, not a retry loop.
- **It does not cache proofs.** A proof is bound to one nonce and one
  window; a cached one is a proof of nothing current.
