# `wealth_suitability` verification key

`vk` and `vk_hash` are produced by:

```bash
cd circuits
nargo compile --package wealth_suitability --skip-brillig-constraints-check
bb write_vk -b target/wealth_suitability.json -o wealth_suitability/vkey -t noir-recursive
```

`-t noir-recursive` is not optional — it selects the poseidon2 transcript and
the ZK-preserving proving target, and it must match
`BB_VERIFIER_TARGET` in `backend/api/src/verify/mod.rs`. A key written with a
different target verifies nothing this system produces.

## Why this one is committed when the others are not

Every other circuit's verification key is a build artifact: the backend
regenerates it at boot into `backend/api/vkeys/` (gitignored), because the
only party that needs it is the backend, and the backend can always rebuild
it from the circuit it ships with.

This key has a second audience. A DFSA examiner reviewing a suitability
recommendation should be able to take the proof and public inputs out of the
bank's audit log and check them *without* trusting Memtara's build pipeline
to have produced an honest key. That requires a key published independently
of the server that used it — which is what this directory is.

Committing a build artifact costs something: it can drift from the circuit
and nobody notices. So CI regenerates it and fails if the bytes differ (see
`.github/workflows/ci.yml`, "Check the committed wealth vkey"). If that step
ever fails, the circuit changed and this key is stale — regenerate it with
the commands above and commit the result.

## Public input layout

12 field elements, 32 bytes each, big-endian, in this order — `main`'s public
parameters in declaration order, then the public return value last
(confirmed empirically against `bb prove`'s own `public_inputs` output, not
read off the source):

| # | name |
|---|---|
| 0 | `current_time` |
| 1 | `expiry_time` |
| 2 | `vault_root` |
| 3 | `product_ref` |
| 4 | `min_income` |
| 5 | `min_liquidity` |
| 6 | `max_concentration_percent` |
| 7 | `product_risk_level` |
| 8 | `user_public_key_x` |
| 9 | `user_public_key_y` |
| 10 | `nonce` |
| 11 | `suitable` (return value: 1 or 0) |

Index 11 is the answer. `bb verify` exiting 0 means the assessment was
performed correctly — **not** that the client is suitable. A verifier that
skips index 11 accepts a valid proof of unsuitability as an approval.
