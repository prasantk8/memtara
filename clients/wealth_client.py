"""The device side of a structured-product suitability assessment.

This is the party Memtara's backend deliberately cannot be. Generating a
proof about someone's income requires the income as a witness, so whatever
runs this code holds the plaintext vault — which is why it is a client, and
why the server never grows an endpoint that does this for you.

A shipping product runs this inside the mobile app via ``noir_wasm``. Here it
runs the same circuits through the ``nargo``/``bb`` CLIs. The cryptography is
identical; only the host differs.

What it does, end to end::

    request  = bank calls POST /api/v1/issue-wealth-request   (org API key)
    ---------------------------------------------------------- device starts
    vault    = the four figures, committed to a Poseidon Merkle tree
    sign     = the user's Baby Jubjub key signs the policy commitment
    prove    = nargo execute + bb prove over wealth_suitability
    submit   = POST /api/v1/submit-wealth-proof                (user session)
    ---------------------------------------------------------- device ends
    token    = a signed attestation the bank can hand to an LLM gateway

Nothing here is mocked. The proof this module produces is a real
Barretenberg UltraHonk proof over the real compiled circuit, and the backend
verifies it with `bb verify` against the committed verification key.

Hashing is delegated to ``circuits/witness_oracle`` rather than
reimplemented — see that circuit's header for why a second Poseidon
implementation would be a liability rather than an optimisation.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
CIRCUITS_DIR = REPO_ROOT / "circuits"
CIRCUIT_NAME = "wealth_suitability"

# ---------------------------------------------------------------------------
# Baby Jubjub
#
# The curve the circuits sign on. Not Ed25519: verifying an Ed25519 signature
# inside a BN254 circuit means emulating a foreign field, which costs orders
# of magnitude more constraints than using a curve whose base field IS the
# proving field. See ARCHITECTURE.md for the accepted deviation.
#
# Constants are the standard Baby Jubjub parameters, and BASE8/SUBORDER are
# copied from circuits/lib/src/signature_verify.nr — the values the verifier
# will actually use. `test_constants_match_the_circuit` in the e2e test reads
# them back out of that file so the two cannot drift.
# ---------------------------------------------------------------------------

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
A = 168700
D = 168696

BASE8 = (
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
)
SUBORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041

Point = tuple[int, int]


def point_add(p: Point, q: Point) -> Point:
    """Twisted Edwards addition. Complete — no special case for doubling or
    for the identity, which is why this curve is used for in-circuit work."""
    x1, y1 = p
    x2, y2 = q
    x1x2 = x1 * x2 % P
    y1y2 = y1 * y2 % P
    dxy = D * x1x2 % P * y1y2 % P
    x3 = (x1 * y2 + y1 * x2) % P * pow(1 + dxy, -1, P) % P
    y3 = (y1y2 - A * x1x2) % P * pow(1 - dxy, -1, P) % P
    return (x3, y3)


def point_mul(p: Point, k: int) -> Point:
    """Double-and-add. Not constant time, and it does not need to be: this
    runs on the holder's own device over the holder's own key, with no
    attacker-observable timing channel between them."""
    result: Point = (0, 1)  # the identity on a twisted Edwards curve
    addend = p
    k = k % SUBORDER
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def on_curve(p: Point) -> bool:
    x, y = p
    return (A * x * x + y * y - 1 - D * x * x % P * y % P * y) % P == 0


@dataclass(frozen=True)
class Keypair:
    """A Baby Jubjub signing key.

    ``scalar`` is the value the verifier's equation uses (``s`` in
    ``S*B8 = R8 + h*A8``); ``public`` is ``B8 * (scalar / 8)``, because
    `eddsa_verify` multiplies the public key by the cofactor 8 before using
    it. Keeping that factor of 8 explicit here rather than folding it into
    the multiplication is deliberate: it is the single easiest thing to get
    wrong, and getting it wrong produces a signature that fails inside the
    circuit with no diagnostic.
    """

    scalar: int
    public: Point

    @classmethod
    def generate(cls, rng: secrets.SystemRandom | None = None) -> "Keypair":
        r = rng or secrets.SystemRandom()
        return cls.from_seed(r.randrange(1, SUBORDER))

    @classmethod
    def from_seed(cls, k: int) -> "Keypair":
        """Derive a keypair from an integer seed. Deterministic, so a test or
        a demo can reproduce a client exactly."""
        k = k % SUBORDER
        if k == 0:
            raise ValueError("seed must not be a multiple of the subgroup order")
        public = point_mul(BASE8, k)
        return cls(scalar=(8 * k) % SUBORDER, public=public)


def sign(keypair: Keypair, message: int, oracle: "NargoOracle", *, nonce: int | None = None) -> tuple[Point, int]:
    """EdDSA over Baby Jubjub, in the form `eddsa_verify` checks.

    Returns ``(R8, S)`` such that ``S*B8 == R8 + h*A8`` where
    ``h = Poseidon(R8.x, R8.y, A.x, A.y, message)``.

    ``nonce`` exists for reproducible demos. Reusing one across two different
    messages leaks the private scalar — the classic EdDSA/ECDSA nonce-reuse
    break — so it defaults to fresh randomness and callers who pass it should
    be sure they are signing exactly one thing.
    """
    r = nonce if nonce is not None else secrets.randbelow(SUBORDER - 1) + 1
    r8 = point_mul(BASE8, r)
    h = oracle.eddsa_challenge(r8[0], r8[1], keypair.public[0], keypair.public[1], message)
    s = (r + h * keypair.scalar) % SUBORDER
    return r8, s


# ---------------------------------------------------------------------------
# The oracle
# ---------------------------------------------------------------------------


class OracleError(RuntimeError):
    pass


_OUTPUT_RE = re.compile(r"Circuit output:\s*(\[[^\]]*\]|0x[0-9a-fA-F]+)")


class NargoOracle:
    """Runs ``circuits/witness_oracle`` to obtain Poseidon values.

    Each call is a subprocess, which is slow by the standards of a hash
    function and irrelevant by the standards of proof generation: a
    suitability proof takes seconds, and this adds two invocations to it.
    """

    def __init__(self, circuits_dir: Path = CIRCUITS_DIR, nargo: str = "nargo") -> None:
        self.circuits_dir = circuits_dir
        self.nargo = nargo

    def _run(self, op: int, inputs: Sequence[int]) -> list[int]:
        if len(inputs) > 16:
            raise OracleError(f"oracle takes at most 16 inputs, got {len(inputs)}")
        padded = list(inputs) + [0] * (16 - len(inputs))
        # A unique prover name per call so concurrent clients (pytest -n, two
        # journeys in the demo generator) cannot overwrite each other's
        # inputs mid-execution.
        name = f"oracle_{uuid.uuid4().hex}"
        package_dir = self.circuits_dir / "witness_oracle"
        toml_path = package_dir / f"{name}.toml"
        toml_path.write_text(_to_toml({"op": op, "inputs": padded}), encoding="utf-8")
        try:
            proc = subprocess.run(
                [self.nargo, "execute", name, "--package", "witness_oracle", "--prover-name", name],
                cwd=self.circuits_dir,
                capture_output=True,
                text=True,
            )
        finally:
            toml_path.unlink(missing_ok=True)
            (self.circuits_dir / "target" / f"{name}.gz").unlink(missing_ok=True)

        if proc.returncode != 0:
            raise OracleError(f"nargo execute failed for op={op}:\n{proc.stdout}\n{proc.stderr}")

        match = _OUTPUT_RE.search(proc.stdout)
        if not match:
            raise OracleError(f"could not find a circuit output in nargo's stdout:\n{proc.stdout}")
        raw = match.group(1)
        if raw.startswith("["):
            values = [v.strip() for v in raw[1:-1].split(",") if v.strip()]
        else:
            values = [raw]
        return [int(v, 16) for v in values]

    def merkle(self, leaves: Sequence[int]) -> tuple[int, list[list[int]]]:
        """Root and the authentication paths for the first four leaves."""
        if len(leaves) != 16:
            raise OracleError(f"the vault tree has 16 leaves, got {len(leaves)}")
        out = self._run(0, leaves)
        root = out[0]
        paths = [out[1 + i * 4 : 5 + i * 4] for i in range(4)]
        return root, paths

    def policy_commitment(
        self,
        *,
        current_time: int,
        start_time: int,
        expiry_time: int,
        vault_root: int,
        product_ref: int,
        min_income: int,
        min_liquidity: int,
        max_concentration_percent: int,
        product_risk_level: int,
        nonce: int,
    ) -> int:
        return self._run(
            1,
            [
                current_time,
                start_time,
                expiry_time,
                vault_root,
                product_ref,
                min_income,
                min_liquidity,
                max_concentration_percent,
                product_risk_level,
                nonce,
            ],
        )[0]

    def eddsa_challenge(self, r8_x: int, r8_y: int, pk_x: int, pk_y: int, message: int) -> int:
        return self._run(2, [r8_x, r8_y, pk_x, pk_y, message])[0]


# ---------------------------------------------------------------------------
# The vault
# ---------------------------------------------------------------------------

# Leaf slots in the wealth category of the vault tree. Fixed positions,
# matching circuits/wealth_suitability/src/main.nr's own test module.
INCOME_SLOT = 0
LIQUID_SLOT = 1
RISK_SLOT = 2
HOLDINGS_SLOT = 3
TREE_LEAVES = 16


@dataclass
class WealthVault:
    """The four figures a suitability assessment reads, plus the key that
    authorises disclosing anything about them.

    In the product these come out of the encrypted local vault. Here they are
    a dataclass, which is the only difference.
    """

    income: int
    liquid_assets: int
    risk_tolerance: int
    existing_holdings_value: int
    keypair: Keypair
    other_leaves: dict[int, int] = field(default_factory=dict)

    def leaves(self) -> list[int]:
        leaves = [0] * TREE_LEAVES
        leaves[INCOME_SLOT] = self.income
        leaves[LIQUID_SLOT] = self.liquid_assets
        leaves[RISK_SLOT] = self.risk_tolerance
        leaves[HOLDINGS_SLOT] = self.existing_holdings_value
        for slot, value in self.other_leaves.items():
            if slot < 4:
                raise ValueError(f"slot {slot} is reserved for a wealth figure")
            leaves[slot] = value
        return leaves

    def expected_verdict(
        self, *, min_income: int, min_liquidity: int, max_concentration_percent: int, product_risk_level: int
    ) -> bool:
        """What the circuit should conclude, computed independently in Python.

        Used by callers to assert that the proof agrees with a completely
        separate evaluation of the same rule — if the circuit and this
        function ever disagree, one of them is wrong and the test says so
        instead of both being wrong in the same direction.
        """
        total = self.liquid_assets + self.existing_holdings_value
        return (
            self.income >= min_income
            and self.liquid_assets >= min_liquidity
            and self.risk_tolerance >= product_risk_level
            and self.existing_holdings_value * 100 <= max_concentration_percent * total
        )


# ---------------------------------------------------------------------------
# Proof generation
# ---------------------------------------------------------------------------


class ProvingError(RuntimeError):
    pass


def _to_field(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return int(value, 16) if value.startswith("0x") else int(value)


def _hex32(value: int) -> str:
    return "0x" + format(value, "064x")


@dataclass(frozen=True)
class GeneratedProof:
    public_inputs: list[str]
    proof_b64: str
    vault_root: int
    suitable: bool


def generate_proof(
    request: dict[str, Any],
    vault: WealthVault,
    *,
    oracle: NargoOracle | None = None,
    current_time: int | None = None,
    nargo: str = "nargo",
    bb: str = "bb",
    signing_nonce: int | None = None,
) -> GeneratedProof:
    """Produce a real proof for the assessment described by ``request``.

    ``request`` is the JSON body returned by
    ``POST /api/v1/issue-wealth-request`` — the terms, the nonce and the
    product reference all come from the server, so a client cannot choose the
    thresholds it is measured against.
    """
    oracle = oracle or NargoOracle(nargo=nargo)

    window_start = _iso_to_epoch(request["window_start"])
    window_end = _iso_to_epoch(request["window_end"])
    if current_time is None:
        current_time = window_start
    if not window_start <= current_time <= window_end:
        raise ProvingError(
            f"current_time {current_time} is outside the assessment window "
            f"[{window_start}, {window_end}] — the server will reject the submission"
        )

    min_income = int(request["min_income"])
    min_liquidity = int(request["min_liquidity"])
    max_concentration = int(request["max_concentration_percent"])
    risk_level = int(request["product_risk_level"])
    product_ref = _to_field(request["product_ref"])
    nonce = int.from_bytes(base64.urlsafe_b64decode(request["nonce"] + "=="), "big")

    vault_root, paths = oracle.merkle(vault.leaves())

    commitment = oracle.policy_commitment(
        current_time=current_time,
        start_time=window_start,
        expiry_time=window_end,
        vault_root=vault_root,
        product_ref=product_ref,
        min_income=min_income,
        min_liquidity=min_liquidity,
        max_concentration_percent=max_concentration,
        product_risk_level=risk_level,
        nonce=nonce,
    )
    r8, s = sign(vault.keypair, commitment, oracle, nonce=signing_nonce)

    prover_inputs = {
        "current_time": str(current_time),
        "start_time": str(window_start),
        "expiry_time": str(window_end),
        "vault_root": str(vault_root),
        "product_ref": str(product_ref),
        "income": str(vault.income),
        "liquid_assets": str(vault.liquid_assets),
        "risk_tolerance": str(vault.risk_tolerance),
        "existing_holdings_value": str(vault.existing_holdings_value),
        "income_index": str(INCOME_SLOT),
        "income_path": [str(v) for v in paths[INCOME_SLOT]],
        "liquid_assets_index": str(LIQUID_SLOT),
        "liquid_assets_path": [str(v) for v in paths[LIQUID_SLOT]],
        "risk_tolerance_index": str(RISK_SLOT),
        "risk_tolerance_path": [str(v) for v in paths[RISK_SLOT]],
        "existing_holdings_index": str(HOLDINGS_SLOT),
        "existing_holdings_path": [str(v) for v in paths[HOLDINGS_SLOT]],
        "min_income": str(min_income),
        "min_liquidity": str(min_liquidity),
        "max_concentration_percent": str(max_concentration),
        "product_risk_level": str(risk_level),
        "user_public_key_x": str(vault.keypair.public[0]),
        "user_public_key_y": str(vault.keypair.public[1]),
        "signature_r8_x": str(r8[0]),
        "signature_r8_y": str(r8[1]),
        "signature_s": str(s),
        "nonce": str(nonce),
    }

    public_inputs, proof_bytes = _execute_and_prove(prover_inputs, nargo=nargo, bb=bb)

    suitable_field = _to_field(public_inputs[11])
    if suitable_field not in (0, 1):
        raise ProvingError(f"circuit output was {suitable_field}, expected a boolean")

    return GeneratedProof(
        public_inputs=public_inputs,
        proof_b64=base64.urlsafe_b64encode(proof_bytes).decode().rstrip("="),
        vault_root=vault_root,
        suitable=bool(suitable_field),
    )


def _execute_and_prove(prover_inputs: dict[str, Any], *, nargo: str, bb: str) -> tuple[list[str], bytes]:
    name = f"prover_{uuid.uuid4().hex}"
    package_dir = CIRCUITS_DIR / CIRCUIT_NAME
    toml_path = package_dir / f"{name}.toml"
    toml_path.write_text(_to_toml(prover_inputs), encoding="utf-8")
    witness_path = CIRCUITS_DIR / "target" / f"{name}.gz"
    out_dir = Path(tempfile.mkdtemp(prefix="memtara-prove-"))

    try:
        execute = subprocess.run(
            [nargo, "execute", name, "--package", CIRCUIT_NAME, "--prover-name", name],
            cwd=CIRCUITS_DIR,
            capture_output=True,
            text=True,
        )
        if execute.returncode != 0:
            # An unsatisfied constraint here is the interesting failure: it
            # means the witness genuinely does not satisfy the circuit (a
            # figure not in the vault, a bad signature, a closed window) —
            # not a tooling problem. Surface nargo's own message rather than
            # a generic one, because it names the failing assert.
            raise ProvingError(f"nargo execute failed:\n{execute.stdout}\n{execute.stderr}")

        prove = subprocess.run(
            [
                bb, "prove",
                "-b", str(CIRCUITS_DIR / "target" / f"{CIRCUIT_NAME}.json"),
                "-w", str(witness_path),
                "-k", str(package_dir / "vkey" / "vk"),
                "-o", str(out_dir),
                "-t", "noir-recursive",
            ],
            capture_output=True,
            text=True,
        )
        if prove.returncode != 0:
            raise ProvingError(f"bb prove failed:\n{prove.stdout}\n{prove.stderr}")

        raw_public = (out_dir / "public_inputs").read_bytes()
        if len(raw_public) % 32 != 0:
            raise ProvingError(f"public_inputs is {len(raw_public)} bytes, not a multiple of 32")
        public_inputs = ["0x" + raw_public[i : i + 32].hex() for i in range(0, len(raw_public), 32)]
        proof_bytes = (out_dir / "proof").read_bytes()
        return public_inputs, proof_bytes
    finally:
        toml_path.unlink(missing_ok=True)
        witness_path.unlink(missing_ok=True)
        shutil.rmtree(out_dir, ignore_errors=True)


def _to_toml(values: dict[str, Any]) -> str:
    """Minimal TOML writer.

    Everything is emitted as a quoted string, including the integers. That is
    not laziness: Noir field elements routinely exceed 2^63, and TOML's
    integer type does not promise to carry them — a bare `12345...` risks
    being parsed as a bounded integer and silently mangled. Quoted decimal
    strings are what nargo's own documentation uses for `Field` inputs.
    """
    lines = []
    for key, value in values.items():
        if isinstance(value, list):
            rendered = ", ".join('"' + str(v) + '"' for v in value)
            lines.append(key + " = [" + rendered + "]")
        else:
            lines.append(key + ' = "' + str(value) + '"')
    return "\n".join(lines) + "\n"


def _iso_to_epoch(value: str) -> int:
    from datetime import datetime

    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


# ---------------------------------------------------------------------------
# HTTP
#
# urllib rather than requests: this module is imported by the AIHOOTS
# middleware, and a relying-party adapter that drags in a dependency tree is
# a harder sell than one that doesn't.
# ---------------------------------------------------------------------------


class MemtaraApiError(RuntimeError):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


def _post(url: str, payload: dict[str, Any], token: str, *, timeout: float = 120.0) -> dict[str, Any]:
    data = json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"content-type": "application/json", "authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:  # noqa: PERF203 - one call, one handler
        raise MemtaraApiError(exc.code, exc.read().decode(errors="replace")) from None


def get_product(base_url: str, org_api_key: str, product_isin: str, *, timeout: float = 30.0) -> dict[str, Any]:
    """Read one product out of the bank's registry.

    Needs an ORG key, which is the point worth noticing: a customer's phone
    must never hold one, because an org key can open assessments against any
    of the bank's users. So this is for advisor-side callers only, and it is
    for *display* — telling the holder what they are about to be measured
    against. It is never the source of the terms a proof commits to; those
    come back from ``open_assessment`` below, fixed by the server.
    """
    request = urllib.request.Request(
        f"{base_url}/api/v1/products/{product_isin}",
        headers={"authorization": f"Bearer {org_api_key}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise MemtaraApiError(exc.code, exc.read().decode(errors="replace")) from None


def open_assessment(
    base_url: str,
    org_api_key: str,
    *,
    user_id: str,
    product_isin: str,
    ttl_seconds: int = 900,
) -> dict[str, Any]:
    """The bank's half: open an assessment against a registered product.

    The terms are no longer passed in. They come from the product registry —
    see backend/api/src/products/mod.rs for why an advisor being able to
    choose them made the resulting proof worthless as evidence. The response
    still carries all four, because the client needs them to build a witness;
    it just does not get to pick them.
    """
    return _post(
        f"{base_url}/api/v1/issue-wealth-request",
        {"user_id": user_id, "product_isin": product_isin, "ttl_seconds": ttl_seconds},
        org_api_key,
    )


def submit_assessment(base_url: str, credential: str, request_id: str, proof: GeneratedProof) -> dict[str, Any]:
    """The client's half: answer it."""
    return _post(
        f"{base_url}/api/v1/submit-wealth-proof",
        {"request_id": request_id, "public_inputs": proof.public_inputs, "proof": proof.proof_b64},
        credential,
    )


def assess(
    base_url: str,
    *,
    org_api_key: str,
    user_credential: str,
    user_id: str,
    product_isin: str,
    vault: WealthVault,
    ttl_seconds: int = 900,
    oracle: NargoOracle | None = None,
    current_time: int | None = None,
) -> dict[str, Any]:
    """Both halves, for callers orchestrating the whole journey.

    Returns the ``submit-wealth-proof`` response — ``proof_token``,
    ``suitable``, ``product_isin``, ``regulatory_audit_id``.
    """
    request = open_assessment(
        base_url,
        org_api_key,
        user_id=user_id,
        product_isin=product_isin,
        ttl_seconds=ttl_seconds,
    )
    proof = generate_proof(request, vault, oracle=oracle, current_time=current_time)
    result = submit_assessment(base_url, user_credential, request["request_id"], proof)
    result["request"] = request
    return result


def toolchain_available(nargo: str = "nargo", bb: str = "bb") -> bool:
    """Whether proof generation can run here at all."""
    for binary in (nargo, bb):
        if shutil.which(binary) is None and not os.path.isfile(binary):
            return False
    return (CIRCUITS_DIR / "target" / f"{CIRCUIT_NAME}.json").is_file()


def missing_toolchain_reason(nargo: str = "nargo", bb: str = "bb") -> str:
    for binary in (nargo, bb):
        if shutil.which(binary) is None and not os.path.isfile(binary):
            return f"{binary} is not on PATH"
    compiled = CIRCUITS_DIR / "target" / f"{CIRCUIT_NAME}.json"
    if not compiled.is_file():
        return f"{compiled} is missing — run `nargo compile --workspace --skip-brillig-constraints-check`"
    return ""


__all__ = [
    "BASE8",
    "SUBORDER",
    "GeneratedProof",
    "Keypair",
    "MemtaraApiError",
    "NargoOracle",
    "OracleError",
    "ProvingError",
    "WealthVault",
    "assess",
    "generate_proof",
    "get_product",
    "missing_toolchain_reason",
    "on_curve",
    "open_assessment",
    "point_add",
    "point_mul",
    "sign",
    "submit_assessment",
    "toolchain_available",
]
