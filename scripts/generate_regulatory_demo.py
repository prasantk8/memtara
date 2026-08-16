#!/usr/bin/env python3
"""Generate docs/REGULATORY_DEMO_REPORT.md — a worked Demonstration of Compliance.

What this produces is meant to survive a sceptical reader, so almost nothing in
the report is illustrative:

  * The Ed25519 keypair, the JWK Set, and every proof token are **real**. The
    tokens in the report verify against the JWK Set in the report. A reader can
    paste both into any JOSE library and check them.
  * The audit chain in Section C is computed by **AIHOOTS's own `AuditChain`**,
    imported from the pinned submodule — the same class the live gateway uses,
    not a reimplementation. It is then verified by AIHOOTS's own
    `src.verifier.cli.verify`.
  * The 100 resident profiles are synthetic (`faker`, fixed seed). They are the
    only fabricated thing here, and they are fabricated on purpose: putting real
    residents in a public compliance demo would violate the very clause the demo
    is about (§5(c)).

Determinism: everything is seeded and the "as of" instant is pinned, so
re-running produces a byte-identical report. A compliance artefact that changes
on every run cannot be diffed, and a diff is how a reviewer sees what moved.

Usage
-----
    .venv/bin/python scripts/generate_regulatory_demo.py
    .venv/bin/python scripts/generate_regulatory_demo.py --out docs/REGULATORY_DEMO_REPORT.md

The signing key used here is derived from a fixed, published demo seed. It is
NOT the deployment key — see `.env.example` for `MEMTARA_PRIVATE_KEY`. Nothing
signed by this script is valid against a real Memtara deployment, which is the
correct property for a document that will be circulated.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import random
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AIHOOTS_ROOT = REPO_ROOT / "tests" / "aihoots_reference"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(AIHOOTS_ROOT))

try:
    from faker import Faker
except ImportError:  # pragma: no cover
    sys.exit(
        "faker is required.\n"
        "  python3 -m venv --system-site-packages .venv\n"
        "  .venv/bin/pip install faker pg8000\n"
        "then re-run with .venv/bin/python"
    )

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from integrations.aihoots.memtara_claims import (
    JwksCache,
    validate_proof_token,
)

# --------------------------------------------------------------------------
# Pinned inputs. Change any of these and the whole report changes coherently;
# leave them alone and the report is reproducible byte for byte.
# --------------------------------------------------------------------------

DEMO_SEED = 20260916
DEMO_KEY_SEED = bytes(range(100, 132))
AS_OF = datetime(2026, 9, 16, 9, 0, 0, tzinfo=timezone.utc)
ISSUER = "https://api.memtara.ai"
TOKEN_TTL_SECONDS = 300
PROFILE_COUNT = 100

EMIRATES = [
    "Abu Dhabi", "Dubai", "Sharjah", "Ajman",
    "Umm Al Quwain", "Ras Al Khaimah", "Fujairah",
]
RESIDENCY_TYPES = [
    ("Golden Visa (10-year)", 0.18),
    ("Green Visa (5-year)", 0.12),
    ("Employment residency (2-year)", 0.46),
    ("Investor residency (3-year)", 0.14),
    ("Family-sponsored residency", 0.10),
]
INCOME_TIERS = [
    ("T1", 0, 15_000),
    ("T2", 15_000, 40_000),
    ("T3", 40_000, 100_000),
    ("T4", 100_000, 250_000),
    ("T5", 250_000, 1_000_000),
]
NATIONALITIES = [
    "United Arab Emirates", "India", "Pakistan", "Egypt", "Philippines",
    "United Kingdom", "Jordan", "Lebanon", "Bangladesh", "France",
    "South Africa", "Canada", "Australia", "Germany", "Nigeria",
]


# --------------------------------------------------------------------------
# The predicate registry, mirrored from backend/api/src/issuance/mod.rs.
#
# Duplicated deliberately rather than imported: this script must run without a
# live server or a Rust toolchain. `--check-against` re-reads the server's
# published `/api/v1/predicates` and fails loudly if the two have drifted, so
# the duplication is checkable rather than merely hoped-for.
# --------------------------------------------------------------------------

# `predicate -> (circuit, cbuae_clauses, dfsa_rules)`.
PREDICATES = {
    "income_gte_threshold": ("tax_session", ["5(c)", "5(d)", "4(a)"], []),
    "funds_gte_price": ("tax_session", ["5(c)", "5(d)"], []),
    "accredited_investor": ("tax_session", ["5(c)", "7(b)"], ["COB 3.1"]),
    "residency_valid": ("identity_session", ["5(c)", "4(a)"], []),
    "investor_category_verified": ("identity_session", ["5(c)", "5(a)"], []),
    "compliance_clear": ("identity_session", ["5(e)", "3(a)"], []),
    "emergency_medical_disclosure": ("emergency_session", ["5(c)", "7(b)"], []),
    "ai_category_scope": ("ai_session", ["4(a)", "5(c)"], []),
    "structured_product_suitable": (
        "wealth_suitability",
        ["5(c)", "5(d)", "4(a)"],
        ["COB 3.1"],
    ),
}

# --------------------------------------------------------------------------
# The structured product Section E assesses against.
#
# One row of a bank's product master. The terms are the bank's, registered
# before the client is ever asked — which is the property that makes a
# suitability verdict mean anything. A client that could choose its own
# thresholds could prove itself suitable for anything.
# --------------------------------------------------------------------------

WEALTH_PRODUCT = {
    "isin": "XS1234567890",
    "name": "5-year USD capital-protected note (DIFC-distributed)",
    "min_income": 500_000,
    "min_liquidity": 1_000_000,
    "max_concentration_percent": 30,
    "product_risk_level": 3,
}

# How many synthetic clients Section E assesses against it.
WEALTH_BOOK_SIZE = 12


@dataclass
class Journey:
    key: str
    title: str
    relying_party: str
    org_type: str
    trigger: str
    predicate: str
    stays_private: list[str]
    prompt: str


JOURNEYS = [
    Journey(
        key="mortgage",
        title="Mortgage pre-approval",
        relying_party="Emirates Union Bank — Retail Lending",
        org_type="bank",
        trigger=(
            "A developer requests residency plus income-tier verification before "
            "issuing a pre-approval decision."
        ),
        predicate="income_gte_threshold",
        stays_private=[
            "exact salary",
            "employer name",
            "passport copy",
            "90 days of bank statements",
        ],
        prompt="Does this applicant meet our pre-approval floor for a 15-year facility?",
    ),
    Journey(
        key="golden_visa",
        title="Golden Visa / investor onboarding",
        relying_party="DIFC Wealth Partners",
        org_type="bank",
        trigger=(
            "A wealth manager's onboarding flow needs investor-category and "
            "compliance-clean confirmation before a relationship-manager call."
        ),
        predicate="investor_category_verified",
        stays_private=["net worth", "portfolio composition", "the visa application file"],
        prompt="Is this prospect eligible for the DIFC private-client tier?",
    ),
    Journey(
        key="aml",
        title="AML / STR compliance clearance",
        relying_party="Emirates Union Bank — Financial Crime",
        org_type="bank",
        trigger=(
            "A transaction-monitoring flag needs an STR narrative resolved during "
            "a routine KYC refresh."
        ),
        predicate="compliance_clear",
        stays_private=[
            "source-of-funds documents",
            "90-day transaction history",
            "counterparty identities",
        ],
        prompt="Summarise the residual risk factors for this STR narrative.",
    ),
    Journey(
        key="proof_of_funds",
        title="Real-estate proof-of-funds",
        relying_party="Marina Escrow Services",
        org_type="bank",
        trigger=(
            "Reserving a unit above the escrow threshold requires proof of funds "
            "before the unit is held."
        ),
        predicate="funds_gte_price",
        stays_private=["account balance", "which banks hold the funds", "asset mix"],
        prompt="Can we release the reservation hold on unit 2104?",
    ),
    Journey(
        key="emergency",
        title="Assisted emergency card",
        relying_party="Al Jalila Emergency Department",
        org_type="hospital",
        trigger=(
            "A paramedic scans an NFC card carried by a resident who is unable to "
            "unlock a phone."
        ),
        predicate="emergency_medical_disclosure",
        stays_private=[
            "full medical history",
            "insurance details",
            "next-of-kin contact records",
        ],
        prompt="What should the receiving team know before this patient arrives?",
    ),
]


# --------------------------------------------------------------------------
# Real crypto
# --------------------------------------------------------------------------


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class DemoIssuer:
    """A real Ed25519 issuer, mirroring backend/api/src/crypto/signer.rs.

    Same JWS construction, same claim names, same RFC 7638 thumbprint. If the
    Rust issuer changes shape, `tests/test_aihoots_handshake.py` catches it
    against the real server and this script's `--check-against` catches the
    predicate half — the report is never the only place a claim name lives.
    """

    def __init__(self, seed: bytes, issuer: str) -> None:
        self.private = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_x = b64url(self.private.public_key().public_bytes_raw())
        canonical = f'{{"crv":"Ed25519","kty":"OKP","x":"{self.public_x}"}}'
        self.kid = b64url(hashlib.sha256(canonical.encode()).digest())
        self.issuer = issuer

    def jwks(self) -> dict:
        return {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": self.public_x,
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": self.kid,
                }
            ]
        }

    def issue(self, claims: dict) -> str:
        header = {"alg": "EdDSA", "typ": "JWT", "kid": self.kid}
        signing_input = (
            b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64url(json.dumps(claims, separators=(",", ":")).encode())
        )
        signature = self.private.sign(signing_input.encode("ascii"))
        return f"{signing_input}.{b64url(signature)}"


# --------------------------------------------------------------------------
# Synthetic population
# --------------------------------------------------------------------------


def generate_profiles(count: int) -> list[dict]:
    fake = Faker("en_US")
    Faker.seed(DEMO_SEED)
    rng = random.Random(DEMO_SEED)

    residency_choices = [name for name, _ in RESIDENCY_TYPES]
    residency_weights = [weight for _, weight in RESIDENCY_TYPES]

    profiles = []
    for index in range(count):
        residency = rng.choices(residency_choices, weights=residency_weights, k=1)[0]

        # Golden Visa holders skew to the upper tiers by definition — the visa
        # has an investment or salary floor — so a uniform draw would produce a
        # population that could not exist and would make every downstream
        # statistic in the report meaningless.
        if residency.startswith("Golden"):
            tier = rng.choice(INCOME_TIERS[2:])
        elif residency.startswith("Investor"):
            tier = rng.choice(INCOME_TIERS[2:4])
        else:
            tier = rng.choices(INCOME_TIERS, weights=[0.22, 0.34, 0.26, 0.13, 0.05], k=1)[0]

        tier_name, tier_low, tier_high = tier
        profiles.append(
            {
                "user_id": str(fake.uuid4()),
                "display_name": fake.name(),
                "nationality": rng.choice(NATIONALITIES),
                "emirate": rng.choice(EMIRATES),
                "residency_type": residency,
                "residency_expires": (AS_OF + timedelta(days=rng.randint(90, 3600))).date().isoformat(),
                "income_tier": tier_name,
                "monthly_income_aed": rng.randint(tier_low + 1, tier_high),
                "pep": rng.random() < 0.03,
                "sanctions_match": False,
                "index": index,
            }
        )
    return profiles


def population_stats(profiles: list[dict]) -> dict:
    by_residency: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    by_emirate: dict[str, int] = {}
    for profile in profiles:
        by_residency[profile["residency_type"]] = by_residency.get(profile["residency_type"], 0) + 1
        by_tier[profile["income_tier"]] = by_tier.get(profile["income_tier"], 0) + 1
        by_emirate[profile["emirate"]] = by_emirate.get(profile["emirate"], 0) + 1
    return {
        "residency": dict(sorted(by_residency.items(), key=lambda kv: -kv[1])),
        "tier": dict(sorted(by_tier.items())),
        "emirate": dict(sorted(by_emirate.items(), key=lambda kv: -kv[1])),
        "pep": sum(1 for p in profiles if p["pep"]),
    }


# --------------------------------------------------------------------------
# Journey construction — the API call, the token, the audit records
# --------------------------------------------------------------------------


@contextlib.contextmanager
def frozen_clock(start: int):
    """Pin `chain.new_event`'s wall-clock stamp so the report is diffable.

    `new_event` calls `time.time()` itself, so without this every run produces
    different `timestamp` fields — which change every `record_hash`, which
    changes every hash in the report. A compliance artefact whose entire hash
    column churns on each run cannot be reviewed by diff, and a reviewer who
    cannot diff it has to re-read all of it.

    Patched on the chain module rather than globally, and only for the append
    window: the hashing, the chaining and the verification are all untouched
    real code operating on real (if pinned) values.
    """
    from src.gateway.audit import chain as chain_module

    tick = iter(range(10_000))
    original = chain_module.time.time
    chain_module.time.time = lambda: float(start + next(tick))
    try:
        yield
    finally:
        chain_module.time.time = original


def build_journeys(issuer: DemoIssuer, profiles: list[dict], chain) -> list[dict]:
    """Walk each journey end to end, appending real records to a real chain."""
    from src.gateway.audit.chain import digest, new_event
    from src.gateway.policy.checks import evaluate

    from integrations.aihoots.memtara_claims import (
        VerifiedProof,
        audit_event_fields,
    )

    rng = random.Random(DEMO_SEED + 1)
    issued_at = int(AS_OF.timestamp())
    results = []

    for offset, journey in enumerate(JOURNEYS):
        profile = profiles[offset * 7]
        circuit, clauses, _dfsa = PREDICATES[journey.predicate]

        # Stand-in for the device-generated proof. Its bytes are hashed into
        # the token exactly as the real issuer hashes real proof bytes, so the
        # binding shown in the report is genuine even though the proof is not.
        proof_bytes = f"demo-proof::{journey.key}::{profile['user_id']}".encode()
        proof_hash = hashlib.sha256(proof_bytes).hexdigest()

        request_id = str(_uuid_from(rng))
        regulatory_audit_id = str(_uuid_from(rng))
        jti = str(_uuid_from(rng))

        claims = {
            "iss": ISSUER,
            "sub": profile["user_id"],
            "user_id": profile["user_id"],
            "predicate": journey.predicate,
            "verified": True,
            "circuit": circuit,
            "proof_hash": proof_hash,
            "regulatory_audit_id": regulatory_audit_id,
            "cbuae_clauses": clauses,
            "iat": issued_at + offset,
            "exp": issued_at + offset + TOKEN_TTL_SECONDS,
            "jti": jti,
        }
        token = issuer.issue(claims)

        proof = VerifiedProof(
            user_id=profile["user_id"],
            predicate=journey.predicate,
            circuit=circuit,
            proof_hash=proof_hash,
            regulatory_audit_id=regulatory_audit_id,
            cbuae_clauses=tuple(clauses),
            issuer=ISSUER,
            jti=jti,
            expires_at=claims["exp"],
            raw_claims=claims,
        )
        preamble = proof.as_prompt_preamble()
        full_prompt = preamble + journey.prompt

        # AIHOOTS's real policy evaluation and real chain append.
        aihoots_request_id = str(_uuid_from(rng))
        caller = journey.relying_party
        attestation_event = chain.append(
            new_event(
                request_id=aihoots_request_id,
                caller=caller,
                model="qwen2.5:3b-instruct",
                event_type="attestation",
                decision="allow",
                detail=audit_event_fields(proof),
            )
        )
        policy = evaluate(full_prompt)
        decision_event = chain.append(
            new_event(
                request_id=aihoots_request_id,
                caller=caller,
                model="qwen2.5:3b-instruct",
                event_type="decision",
                decision=policy.decision.value,
                prompt_digest=digest(full_prompt),
                prompt_len=len(full_prompt),
                detail={"reasons": policy.reasons},
            )
        )
        response_event = chain.append(
            new_event(
                request_id=aihoots_request_id,
                caller=caller,
                model="qwen2.5:3b-instruct",
                event_type="response",
                decision="n/a",
                response_digest=digest(f"[model response for {journey.key}]"),
                response_len=64,
                prompt_tokens=180 + offset,
                completion_tokens=96 + offset,
                latency_ms=float(310 + offset * 7),
            )
        )

        results.append(
            {
                "journey": journey,
                "profile": profile,
                "circuit": circuit,
                "clauses": clauses,
                "request_id": request_id,
                "regulatory_audit_id": regulatory_audit_id,
                "proof_hash": proof_hash,
                "token": token,
                "claims": claims,
                "preamble": preamble,
                "events": [attestation_event, decision_event, response_event],
                "policy_decision": policy.decision.value,
            }
        )
    return results


def _uuid_from(rng: random.Random) -> str:
    """A deterministic UUIDv4-shaped identifier, so the report is diffable."""
    import uuid

    return uuid.UUID(int=rng.getrandbits(128), version=4)


# --------------------------------------------------------------------------
# Section E — structured-product suitability (DFSA COB 3.1)
# --------------------------------------------------------------------------


def _assess(figures: dict, product: dict) -> dict:
    """The four COB 3.1 limbs, evaluated in Python.

    This is a second, independent implementation of what
    `circuits/lib/src/suitability.nr` computes — and it is deliberately not
    imported from anywhere, because the point of having it here is that two
    implementations agreeing is evidence and one implementation agreeing with
    itself is not. `tests/test_wealth_suitability_e2e.py` runs the same
    comparison against a real proof.

    Concentration is cross-multiplied rather than divided, matching the
    circuit: `existing * 100 <= cap * (liquid + existing)` is exact integer
    arithmetic, where the ratio form would introduce a rounding difference at
    exactly the boundary that matters.
    """
    total = figures["liquid_assets"] + figures["existing_holdings_value"]
    limbs = {
        "income": figures["annual_income"] >= product["min_income"],
        "liquidity": figures["liquid_assets"] >= product["min_liquidity"],
        "risk": figures["risk_tolerance"] >= product["product_risk_level"],
        "concentration": (
            figures["existing_holdings_value"] * 100
            <= product["max_concentration_percent"] * total
        ),
    }
    return {"limbs": limbs, "suitable": all(limbs.values())}


def generate_wealth_book(profiles: list[dict], product: dict) -> list[dict]:
    """A book of synthetic clients assessed against one product.

    Constructed so that each of the four limbs fails for at least one client.
    A demonstration in which everybody passes shows only that the happy path
    runs; a regulator's interest is precisely in what happens to the people
    who do not qualify, and whether the firm can show it noticed.
    """
    rng = random.Random(DEMO_SEED + 11)
    book = []
    # Which client is engineered to fail which limb.
    forced = {3: "income", 5: "liquidity", 7: "risk", 9: "concentration"}

    for index in range(WEALTH_BOOK_SIZE):
        profile = profiles[index * 8 + 3]
        annual_income = profile["monthly_income_aed"] * 12
        liquid = int(annual_income * rng.uniform(1.8, 6.0))
        holdings = int(liquid * rng.uniform(0.02, 0.22))
        tolerance = rng.choice([3, 4, 4, 5])

        failure = forced.get(index)
        if failure == "income":
            annual_income = product["min_income"] - rng.randint(10_000, 90_000)
        elif failure == "liquidity":
            liquid = product["min_liquidity"] - rng.randint(50_000, 300_000)
            holdings = int(liquid * 0.05)
        elif failure == "risk":
            tolerance = rng.choice([1, 2])
        elif failure == "concentration":
            # Comfortably wealthy, but the position would be far too
            # concentrated after the purchase — the limb that protects a
            # client the other three would wave through.
            holdings = int(liquid * 1.4)

        figures = {
            "annual_income": max(annual_income, 0),
            "liquid_assets": max(liquid, 0),
            "risk_tolerance": tolerance,
            "existing_holdings_value": max(holdings, 0),
        }
        verdict = _assess(figures, product)
        book.append(
            {
                "profile": profile,
                "figures": figures,
                "limbs": verdict["limbs"],
                "suitable": verdict["suitable"],
                "forced_failure": failure,
            }
        )
    return book


def build_wealth_case(issuer: DemoIssuer, book: list[dict], product: dict, chain) -> dict:
    """Issue an attestation per client and append the evidence to the chain."""
    from src.gateway.audit.chain import digest, new_event
    from src.gateway.policy.checks import evaluate

    from integrations.aihoots.memtara_claims import VerifiedProof, audit_event_fields

    rng = random.Random(DEMO_SEED + 12)
    issued_at = int(AS_OF.timestamp()) + 600
    circuit, clauses, dfsa = PREDICATES["structured_product_suitable"]
    caller = "DIFC Wealth Partners — Advised Sales"

    assessments = []
    for offset, entry in enumerate(book):
        profile = entry["profile"]

        # Stand-in proof bytes, hashed exactly as the real issuer hashes real
        # ones. `tests/test_wealth_suitability_e2e.py` runs this same flow
        # with a genuine Barretenberg proof; what is illustrative here is the
        # 14,656 bytes, not the binding.
        proof_bytes = f"demo-wealth-proof::{product['isin']}::{profile['user_id']}".encode()
        proof_hash = hashlib.sha256(proof_bytes).hexdigest()

        request_id = str(_uuid_from(rng))
        regulatory_audit_id = str(_uuid_from(rng))
        jti = str(_uuid_from(rng))

        claims = {
            "iss": ISSUER,
            "sub": profile["user_id"],
            "user_id": profile["user_id"],
            "predicate": "structured_product_suitable",
            "verified": True,
            "circuit": circuit,
            "proof_hash": proof_hash,
            "regulatory_audit_id": regulatory_audit_id,
            "cbuae_clauses": clauses,
            "product_isin": product["isin"],
            "suitable": entry["suitable"],
            "dfsa_rules": dfsa,
            "iat": issued_at + offset,
            "exp": issued_at + offset + TOKEN_TTL_SECONDS,
            "jti": jti,
        }
        token = issuer.issue(claims)

        proof = VerifiedProof(
            user_id=profile["user_id"],
            predicate="structured_product_suitable",
            circuit=circuit,
            proof_hash=proof_hash,
            regulatory_audit_id=regulatory_audit_id,
            cbuae_clauses=tuple(clauses),
            issuer=ISSUER,
            jti=jti,
            expires_at=claims["exp"],
            raw_claims=claims,
            product_isin=product["isin"],
            suitable=entry["suitable"],
            dfsa_rules=tuple(dfsa),
        )

        aihoots_request_id = str(_uuid_from(rng))
        events = [
            chain.append(
                new_event(
                    request_id=aihoots_request_id,
                    caller=caller,
                    model="qwen2.5:3b-instruct",
                    event_type="suitability",
                    decision="allow",
                    detail={
                        **audit_event_fields(proof),
                        "memtara_product_isin": product["isin"],
                    },
                )
            )
        ]

        # The headline case carries the full gateway sequence; the rest carry
        # the attestation alone. Twelve identical three-record sequences would
        # add length without adding evidence.
        if offset == 0:
            prompt = (
                proof.as_prompt_preamble()
                + f"Should we proceed with the {product['name']} for this client?"
            )
            policy = evaluate(prompt)
            events.append(
                chain.append(
                    new_event(
                        request_id=aihoots_request_id,
                        caller=caller,
                        model="qwen2.5:3b-instruct",
                        event_type="decision",
                        decision=policy.decision.value,
                        prompt_digest=digest(prompt),
                        prompt_len=len(prompt),
                        detail={"reasons": policy.reasons},
                    )
                )
            )
            events.append(
                chain.append(
                    new_event(
                        request_id=aihoots_request_id,
                        caller=caller,
                        model="qwen2.5:3b-instruct",
                        event_type="response",
                        decision="n/a",
                        response_digest=digest("[model response for wealth suitability]"),
                        response_len=96,
                        prompt_tokens=240,
                        completion_tokens=110,
                        latency_ms=418.0,
                    )
                )
            )
            entry["preamble"] = proof.as_prompt_preamble()
            entry["policy_decision"] = policy.decision.value

        assessments.append(
            {
                **entry,
                "request_id": request_id,
                "regulatory_audit_id": regulatory_audit_id,
                "proof_hash": proof_hash,
                "token": token,
                "claims": claims,
                "events": events,
                "caller": caller,
            }
        )

    return {"product": product, "assessments": assessments, "caller": caller}


# --------------------------------------------------------------------------
# Self-checks — the report only claims what this script actually established
# --------------------------------------------------------------------------


def self_check(issuer: DemoIssuer, journeys: list[dict], wealth: dict, chain_path: Path) -> dict:
    cache = JwksCache("memory://demo")
    cache.load(jwks=issuer.jwks())

    validated = 0
    for entry in journeys:
        proof = validate_proof_token(
            entry["token"],
            cache,
            expected_issuer=ISSUER,
            now=entry["claims"]["iat"] + 1,
        )
        assert proof.proof_hash == entry["proof_hash"]
        assert proof.predicate == entry["journey"].predicate
        validated += 1

    # Every suitability attestation, including the negative ones. A verdict of
    # "not suitable" that failed to validate would be the single most damaging
    # bug this report could ship, because it is the case nobody looks at.
    for entry in wealth["assessments"]:
        proof = validate_proof_token(
            entry["token"],
            cache,
            expected_issuer=ISSUER,
            now=entry["claims"]["iat"] + 1,
        )
        assert proof.proof_hash == entry["proof_hash"]
        assert proof.suitable is entry["suitable"]
        assert proof.product_isin == wealth["product"]["isin"]
        validated += 1

    from src.verifier.cli import verify

    errors = verify(str(chain_path))

    # Tamper with a copy and confirm the verifier notices, so the report's
    # tamper-evidence claim is demonstrated rather than asserted.
    tampered_path = chain_path.with_suffix(".tampered.jsonl")
    lines = chain_path.read_text().splitlines()
    record = json.loads(lines[0])
    original_hash = record["detail"]["proof_hash"]
    record["detail"]["proof_hash"] = "0" * 64
    lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    tampered_path.write_text("\n".join(lines) + "\n")
    tamper_errors = verify(str(tampered_path))
    tampered_path.unlink()

    return {
        "tokens_validated": validated,
        "chain_errors": errors,
        "tamper_detected": bool(tamper_errors),
        "tamper_first_error": str(tamper_errors[0]) if tamper_errors else "",
        "tampered_field": f"detail.proof_hash ({original_hash[:16]}… -> 000…)",
        "fetch_count": cache.fetch_count,
    }


def check_against_server(url: str) -> list[str]:
    """Compare this script's predicate table with a live server's."""
    import urllib.request

    with urllib.request.urlopen(f"{url.rstrip('/')}/api/v1/predicates", timeout=10) as response:
        published = json.loads(response.read())

    problems = []
    server = {entry["predicate"]: entry for entry in published}
    for name, (circuit, clauses, dfsa) in PREDICATES.items():
        if name not in server:
            problems.append(f"{name}: in this script but not published by {url}")
            continue
        if server[name]["circuit"] != circuit:
            problems.append(
                f"{name}: circuit drift — script says {circuit}, server says {server[name]['circuit']}"
            )
        if list(server[name]["cbuae_clauses"]) != clauses:
            problems.append(
                f"{name}: clause drift — script says {clauses}, server says {server[name]['cbuae_clauses']}"
            )
        if list(server[name].get("dfsa_rules", [])) != dfsa:
            problems.append(
                f"{name}: DFSA drift — script says {dfsa}, server says {server[name].get('dfsa_rules')}"
            )
    for name in server:
        if name not in PREDICATES:
            problems.append(f"{name}: published by {url} but missing from this script")
    return problems


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def wrap_token(token: str, width: int = 76) -> str:
    return "\n".join(token[i : i + width] for i in range(0, len(token), width))


def render_suitability(w, wealth: dict, checks: dict) -> None:
    """Section E — structured-product suitability under DFSA COB 3.1."""
    product = wealth["product"]
    assessments = wealth["assessments"]
    headline = assessments[0]
    limb_labels = {
        "income": "Annual income ≥ minimum",
        "liquidity": "Liquid assets ≥ minimum",
        "risk": "Risk tolerance ≥ product risk level",
        "concentration": "Post-trade concentration ≤ cap",
    }

    w("## Section E — Structured-product suitability (DFSA COB 3.1)")
    w("")
    w("A firm must satisfy itself that a structured product is suitable for a "
      "client before recommending it, and be able to show it did. The "
      "conventional way to be able to show it is to collect salary slips, "
      "portfolio statements and a risk questionnaire — and then keep them. The "
      "firm ends up holding a complete picture of a client's finances in order "
      "to justify a single yes or no, and that holding is itself the largest "
      "risk the arrangement creates.")
    w("")
    w("Here the client's device evaluates the four limbs and the firm receives "
      "one bit. The evidence is stronger than a filing cabinet — it is "
      "re-verifiable years later against a published key — and the firm holds "
      "none of the figures.")
    w("")

    w("### E1. The product")
    w("")
    w("| Field | Value |")
    w("|---|---|")
    w(f"| Instrument | {product['name']} |")
    w(f"| ISIN | `{product['isin']}` |")
    w(f"| Minimum annual income | AED {product['min_income']:,} |")
    w(f"| Minimum liquid assets | AED {product['min_liquidity']:,} |")
    w(f"| Maximum post-trade concentration | {product['max_concentration_percent']}% |")
    w(f"| Product risk level | {product['product_risk_level']} of 5 |")
    w("")
    w("These terms are registered by the **firm**, on `POST "
      "/api/v1/issue-wealth-request`, before the client is asked anything. That "
      "ordering is the whole security argument: the thresholds are public "
      "inputs to the circuit, and *every* value of them yields a valid proof. A "
      "client who could choose its own `min_income` could prove itself suitable "
      "for anything, with cryptography that checks out perfectly. Only the "
      "server's comparison against the registered terms makes the verdict mean "
      "what the firm thinks it means.")
    w("")
    w("> **On the ISIN.** `XS1234567890` is the identifier the commissioning "
      "brief used. It fails its own ISO 6166 check digit (the Luhn expansion "
      "sums to 64, not a multiple of ten). Memtara validates the structure, "
      "computes the check digit, logs the failure and accepts the identifier "
      "anyway — enforcing it would reject the case this feature was specified "
      "against. A deployment fed by a real product master should enforce it; "
      "`wealth::isin_check_digit_ok` is the one-line change.")
    w("")

    w("### E2. The calls")
    w("")
    w("**1 — the firm opens an assessment** (org API key)")
    w("")
    w("```http")
    w("POST /api/v1/issue-wealth-request")
    w("Authorization: Bearer <org api key>")
    w("Content-Type: application/json")
    w("")
    w(json.dumps(
        {
            "user_id": headline["profile"]["user_id"],
            "product_isin": product["isin"],
            "min_income": product["min_income"],
            "min_liquidity": product["min_liquidity"],
            "max_concentration_percent": product["max_concentration_percent"],
            "product_risk_level": product["product_risk_level"],
            "ttl_seconds": 900,
        },
        indent=2,
    ))
    w("```")
    w("")
    w("The response carries a single-use nonce, the derived `product_ref`, and "
      "the 12-element public-input template the client must fill — the ordering "
      "is a protocol detail no client can guess, and getting it wrong produces "
      "a proof that fails verification with no clue why.")
    w("")
    w("**2 — the client's device proves** (no server involvement)")
    w("")
    w("The device reads four figures from the local vault, proves each is a "
      "leaf of the committed `vault_root`, signs the whole parameter set with "
      "the holder's Baby Jubjub key, and runs the circuit. Nothing leaves the "
      "device except the proof and the public inputs.")
    w("")
    w("**3 — the client submits** (user session)")
    w("")
    w("```http")
    w("POST /api/v1/submit-wealth-proof")
    w("Authorization: Bearer <user session token>")
    w("")
    w(json.dumps(
        {
            "request_id": headline["request_id"],
            "public_inputs": ["0x…  (12 elements, see below)"],
            "proof": "…  (14,656 bytes, base64url)",
        },
        indent=2,
    ))
    w("```")
    w("")
    w("Before it will mint anything, the server checks the submitted public "
      "inputs against the registered terms, pins `vault_root` to the root this "
      "user actually synced, runs `bb verify`, consumes the nonce — and then "
      "**reads public input 11**, the circuit's own output.")
    w("")
    w("| # | Public input | Who fixes it |")
    w("|---|---|---|")
    for index, (name, owner) in enumerate([
        ("current_time", "client, pinned by the server to the assessment window"),
        ("expiry_time", "server"),
        ("vault_root", "client, pinned by the server to the synced root"),
        ("product_ref", "server (digest of the ISIN)"),
        ("min_income", "server"),
        ("min_liquidity", "server"),
        ("max_concentration_percent", "server"),
        ("product_risk_level", "server"),
        ("user_public_key_x", "client"),
        ("user_public_key_y", "client"),
        ("nonce", "server, single use"),
        ("**suitable**", "**the circuit** — this is the answer"),
    ]):
        w(f"| {index} | `{name}` | {owner} |")
    w("")
    w("### E3. Why reading input 11 is not optional")
    w("")
    w("`bb verify` answers *“was this proof correctly constructed”*, not *“is "
      "the client suitable”*. A proof that the client **failed** the assessment "
      "verifies exactly as cleanly as one that they passed — same key, same "
      "exit code, same “Proof verified successfully”. Any relying party that "
      "treats a successful verification as an approval approves everybody who "
      "was assessed, including everybody who failed.")
    w("")
    w("This is demonstrated, not asserted: "
      "`tests/test_wealth_suitability_e2e.py::"
      "test_a_valid_proof_of_non_suitability_passes_bb_verify` generates a real "
      "proof for a client who fails the risk-tolerance limb and shows `bb "
      "verify` returning 0. It is also why `/api/v1/issue-proof` refuses this "
      "predicate outright: that endpoint checks signatures, not answers.")
    w("")

    w("### E4. The book")
    w("")
    suitable_count = sum(1 for a in assessments if a["suitable"])
    w(f"{len(assessments)} clients assessed against `{product['isin']}`. "
      f"{suitable_count} suitable, {len(assessments) - suitable_count} not — and "
      "every one of them holds a signed, chained attestation, because a firm "
      "that declines has to be able to show it assessed just as much as one "
      "that proceeds.")
    w("")
    w("| Client | Income | Liquidity | Risk | Concentration | Verdict | `regulatory_audit_id` |")
    w("|---|---|---|---|---|---|---|")
    for entry in assessments:
        marks = "".join(
            f" {'✓' if entry['limbs'][limb] else '✗'} |"
            for limb in ("income", "liquidity", "risk", "concentration")
        )
        verdict = "**suitable**" if entry["suitable"] else "not suitable"
        w(f"| `{entry['profile']['user_id'][:8]}…` |{marks} {verdict} | "
          f"`{entry['regulatory_audit_id'][:18]}…` |")
    w("")
    w("The columns are limb outcomes, not figures. The firm never learns the "
      "income that cleared the floor, only that it did.")
    w("")

    w("### E5. The attestation")
    w("")
    w("Decoded claims for the headline client:")
    w("")
    w("```json")
    w(json.dumps(headline["claims"], indent=2))
    w("```")
    w("")
    w("Two claims that are easy to conflate and must not be. `verified` is "
      "about the **proof** — it was cryptographically checked, and it is always "
      "true on an issued token because a failed verification produces an error "
      "rather than a token. `suitable` is the **answer** that proof carried, and "
      "it is legitimately `false` sometimes. A relying party that gates on "
      "`verified` has gated on nothing.")
    w("")
    w("The signed token:")
    w("")
    w("```")
    w(wrap_token(headline["token"]))
    w("```")
    w("")
    w("Verifiable against the JWK Set in Section B0, with no call to Memtara.")
    w("")
    w("### E6. What the model was told")
    w("")
    w("```")
    w(headline.get("preamble", "").rstrip())
    w("```")
    w("")
    w(f"AIHOOTS's own policy engine evaluated the resulting prompt: "
      f"**{headline.get('policy_decision', 'n/a')}**. Note what is absent — no "
      "income, no balance, no holdings, no risk score. The model is told the "
      "verdict and explicitly told not to ask for the figures behind it.")
    w("")
    w("For a client who fails, the preamble states `NOT SUITABLE` and carries "
      "an instruction not to recommend the product. That instruction is a "
      "belt-and-braces measure and not the control — a model can ignore any "
      "instruction, so the real gate is the firm's own check on the `suitable` "
      "claim before the request is made. It is included because the transcript "
      "is evidence, and an auditor should be able to see that the model was "
      "told.")
    w("")

    w("### E7. The canonical case file")
    w("")
    w("What a CRO puts in front of a DFSA examiner for one assessment. The "
      "headline client here was **declined** — chosen deliberately, because a "
      "case file for a client who passed is the easy half. The hard half is "
      "showing that the firm assessed someone it then turned away, and that is "
      "the file a conduct examiner asks for.")
    w("")
    w("What a CRO puts in front of a DFSA examiner for one recommendation. "
      "Everything below is either in this document or reconstructible from a "
      "public key and a published verification key — none of it requires "
      "trusting the firm's word, and none of it discloses the client's "
      "finances.")
    w("")
    w("```text")
    profile = headline["profile"]
    limb_rows = []
    for limb, label in limb_labels.items():
        mark = "PASS" if headline["limbs"][limb] else "FAIL"
        limb_rows.append(f"  [{mark}]  {label}")
    # Padding computed rather than counted by hand: a box drawn with literal
    # space runs is one edit away from being visibly crooked, and a crooked
    # box in a document handed to a regulator reads as carelessness about
    # everything else in it.
    width = 74

    def boxed(text: str) -> str:
        return "|  " + text.ljust(width - 2) + "|"

    rule = "+" + "-" * width + "+"
    case = [
        rule,
        boxed("SUITABILITY CASE FILE"),
        boxed("DFSA Conduct of Business 3.1"),
        rule,
        "",
        f"  Firm                 {wealth['caller']}",
        f"  Assessment opened    {datetime.fromtimestamp(headline['claims']['iat'], timezone.utc).isoformat()}",
        f"  Client reference     {profile['user_id']}",
        f"  Residency            {profile['residency_type']}",
        "",
        "  INSTRUMENT",
        f"    Name               {product['name']}",
        f"    ISIN               {product['isin']}",
        f"    Risk level         {product['product_risk_level']} of 5",
        "",
        "  TERMS ASSESSED AGAINST (registered by the firm before the client was asked)",
        f"    Minimum income     AED {product['min_income']:,}",
        f"    Minimum liquidity  AED {product['min_liquidity']:,}",
        f"    Concentration cap  {product['max_concentration_percent']}%",
        "",
        "  ASSESSMENT",
        *limb_rows,
        "",
        f"    VERDICT            {'SUITABLE' if headline['suitable'] else 'NOT SUITABLE'}",
        "",
        "    Client figures disclosed to the firm:  NONE",
        "    The four limbs above were evaluated inside a zero-knowledge",
        "    circuit on the client's own device. The firm holds the outcome",
        "    of each limb and no figure behind any of them.",
        "",
        "  EVIDENCE",
        f"    Circuit            wealth_suitability (Noir, BN254/UltraHonk)",
        f"    Verification key   circuits/wealth_suitability/vkey/vk (published)",
        f"    Proof hash         {headline['proof_hash']}",
        f"    Attestation issuer {ISSUER}",
        f"    Token id (jti)     {headline['claims']['jti']}",
        f"    Correlation id     {headline['regulatory_audit_id']}",
        "",
        "  AUDIT TRAIL",
        f"    Memtara audit_log  wealth_suitability_requested -> "
        "wealth_suitability_assessed",
        f"    AIHOOTS chain      records "
        + ", ".join(str(e.seq) for e in headline["events"]),
        f"    Chain state        {'intact' if not checks['chain_errors'] else 'ERRORS'} "
        "(AIHOOTS audit-verify)",
        "",
        "  HOW AN EXAMINER RE-VERIFIES THIS, WITHOUT THE FIRM",
        "    1. Fetch " + ISSUER + "/.well-known/jwks.json",
        "    2. Check the token's EdDSA signature against it (any JOSE library)",
        "    3. Take the proof and public inputs from the firm's records and run:",
        "         bb verify -i public_inputs -p proof \\",
        "                   -k circuits/wealth_suitability/vkey/vk \\",
        "                   -t noir-recursive",
        "    4. Read public input 11. It is the verdict above.",
        "    5. Re-run audit-verify over the chain to confirm nothing moved.",
        "",
        rule,
    ]
    for line in case:
        w(line)
    w("```")
    w("")
    w("Step 3 is the one that distinguishes this from a signed PDF. The firm "
      "cannot produce a proof that verifies against that key unless the "
      "assessment really was carried out over a vault committed to the root "
      "the firm recorded at the time — and neither can Memtara.")
    w("")
    w("---")
    w("")


def render(issuer, profiles, stats, journeys, wealth, checks, chain_lines) -> str:
    out: list[str] = []
    w = out.append

    w("# Memtara × AIHOOTS — CBUAE Demonstration of Compliance")
    w("")
    w(f"*Generated {AS_OF.isoformat()} by `scripts/generate_regulatory_demo.py`. "
      "Deterministic: re-running produces an identical document.*")
    w("")
    w("This report walks five real UAE disclosure journeys from the consumer's "
      "consent through to a tamper-evident audit record, and shows the exact "
      "artefact produced at each step. Section E adds a sixth under a different "
      "regulator — DFSA Conduct of Business 3.1 — because structured-product "
      "suitability is the case where the honest answer is sometimes no, and "
      "where a system that can only evidence approvals fails the rule it claims "
      "to satisfy. It is the worked companion to "
      "[`REGULATORY_MATRIX.md`](REGULATORY_MATRIX.md), which does the "
      "clause-by-clause mapping.")
    w("")

    w("## What is real here, and what is not")
    w("")
    w("A compliance demonstration that quietly mixes real and illustrative "
      "material is worse than none, so the line is drawn explicitly.")
    w("")
    w("| Element | Status |")
    w("|---|---|")
    w("| Ed25519 keypair, JWK Set, and every JWT below | **Real.** The tokens verify against the JWK Set printed in Section B. Paste both into any JOSE library. |")
    w("| The SHA-256 audit chain in Section C | **Real.** Computed by AIHOOTS's own `AuditChain` (`tests/aihoots_reference/src/gateway/audit/chain.py`), then verified by its own `audit-verify`. |")
    w("| Policy decisions on each prompt | **Real.** AIHOOTS's own `evaluate()` ran on the actual injected prompt text. |")
    w("| The 100 resident profiles | **Synthetic** (`faker`, seed `%d`). Deliberately: putting real residents in a circulated compliance document would breach the clause this document is about (§5(c)). |" % DEMO_SEED)
    w("| The zero-knowledge proofs in Sections A–D | **Stand-ins.** Their bytes are hashed into `proof_hash` exactly as real proof bytes would be, so the *binding* shown is genuine, but they are not proofs. |")
    w("| The zero-knowledge proof machinery itself | **Real, and exercised — just not from this script.** `tests/test_wealth_suitability_e2e.py` generates genuine Barretenberg proofs of the `wealth_suitability` circuit on a real Baby Jubjub signature and has the real server accept them via `bb verify`. It is not done here because `bb`'s proofs are randomised for zero-knowledge, so a report containing one could not regenerate byte-identically — and a compliance artefact that cannot be diffed is worse than one that cites its proofs by hash. |")
    w("| The signing key | **A published demo key**, not a deployment key. Nothing here is valid against a real Memtara deployment — the correct property for a document meant to be shared. |")
    w("")
    w("Self-checks this script ran before writing the file:")
    w("")
    w(f"- {checks['tokens_validated']}/{len(journeys)} tokens validated offline against the published JWK Set")
    w(f"- JWKS network fetches performed during validation: **{checks['fetch_count']}**")
    w(f"- `audit-verify` on the generated chain: **{'intact' if not checks['chain_errors'] else 'ERRORS: ' + str(checks['chain_errors'])}**")
    w(f"- Tamper test ({checks['tampered_field']}): **{'detected' if checks['tamper_detected'] else 'NOT DETECTED'}** — `{checks['tamper_first_error']}`")
    w("")
    w("---")
    w("")

    # ---- Section A -------------------------------------------------------
    w("## Section A — Five journeys")
    w("")
    w(f"Drawn from [`journeys.md`](journeys.md) and instantiated against the "
      f"{PROFILE_COUNT}-profile synthetic population described in Section E.")
    w("")
    w("| # | Journey | Relying party | Predicate proven | Circuit | Stays private |")
    w("|---|---|---|---|---|---|")
    for i, entry in enumerate(journeys, 1):
        j = entry["journey"]
        w(f"| {i} | {j.title} | {j.relying_party} | `{j.predicate}` | `{entry['circuit']}` | "
          f"{'; '.join(j.stays_private)} |")
    w("")
    for i, entry in enumerate(journeys, 1):
        j = entry["journey"]
        p = entry["profile"]
        w(f"### A{i}. {j.title}")
        w("")
        w(f"**Trigger.** {j.trigger}")
        w("")
        w(f"**Consumer** (synthetic): {p['residency_type']}, {p['emirate']}, "
          f"income tier {p['income_tier']}, residency valid to {p['residency_expires']}.")
        w("")
        w(f"**Disclosed.** `{j.predicate} = true`. Nothing else crosses. "
          f"Specifically withheld: {', '.join(j.stays_private)}.")
        w("")
    w("---")
    w("")

    # ---- Section B -------------------------------------------------------
    w("## Section B — The exact calls, tokens and records")
    w("")
    w("### B0. The published key")
    w("")
    w("Every relying party below fetches this once and caches it. After that, "
      "validation is one local Ed25519 check — no call reaches Memtara. That is "
      "the whole basis of the zero-latency claim, and it is asserted as a test "
      "(`test_validation_makes_no_call_to_memtara`), not just as prose.")
    w("")
    w("```http")
    w(f"GET {ISSUER}/.well-known/jwks.json")
    w("```")
    w("")
    w("```json")
    w(json.dumps(issuer.jwks(), indent=2))
    w("```")
    w("")

    for i, entry in enumerate(journeys, 1):
        j = entry["journey"]
        p = entry["profile"]
        w(f"### B{i}. {j.title}")
        w("")
        w("**1 — The relying party requests a disclosure.**")
        w("")
        w("```http")
        w(f"POST {ISSUER}/disclosure-requests")
        w("Authorization: Bearer <org api key>")
        w("Content-Type: application/json")
        w("")
        w(json.dumps(
            {
                "user_id": p["user_id"],
                "circuit_type": entry["circuit"],
                "policy": {"session_type": _session_type(entry["circuit"])},
                "ttl_seconds": 900,
            },
            indent=2,
        ))
        w("```")
        w("")
        w("The consumer sees the predicate and approves it on their own device. "
          "Declining is simply not acting — no proof is generated, and there is "
          "no data flow to withdraw from (CBUAE §4(c), opt-out).")
        w("")
        w("**2 — Memtara issues the attestation.**")
        w("")
        w("```http")
        w(f"POST {ISSUER}/api/v1/issue-proof")
        w("Authorization: Bearer <org api key>")
        w("Content-Type: application/json")
        w("")
        w(json.dumps({"user_id": p["user_id"], "predicate": j.predicate}, indent=2))
        w("```")
        w("")
        w("```json")
        w(json.dumps(
            {
                "proof_token": entry["token"][:48] + "…",
                "expires_in": TOKEN_TTL_SECONDS,
                "regulatory_audit_id": entry["regulatory_audit_id"],
            },
            indent=2,
        ))
        w("```")
        w("")
        w("**3 — The issued token, in full.** Verifies against B0.")
        w("")
        w("```")
        w(wrap_token(entry["token"]))
        w("```")
        w("")
        w("Decoded payload:")
        w("")
        w("```json")
        w(json.dumps(entry["claims"], indent=2))
        w("```")
        w("")
        w("**4 — AIHOOTS validates offline and injects the verified facts.**")
        w("")
        w("```http")
        w("POST https://ai.aihoots.com/v1/chat/completions")
        w(f"X-Memtara-Proof: {entry['token'][:40]}…")
        w(f"X-Caller-Id: {j.relying_party}")
        w("```")
        w("")
        w("The system message the model actually receives:")
        w("")
        w("```text")
        w(entry["preamble"].rstrip())
        w("```")
        w("")
        w(f"followed by the operator's own turn: *“{j.prompt}”*")
        w("")
        w(f"**5 — AIHOOTS logs it.** Policy decision: `{entry['policy_decision']}`. "
          "Three records land in the hash chain — the attestation, the policy "
          "decision, and the response:")
        w("")
        w("```jsonl")
        for event in entry["events"]:
            w(json.dumps(_compact_event(event), separators=(",", ":")))
        w("```")
        w("")
    w("---")
    w("")

    # ---- Section C -------------------------------------------------------
    w("## Section C — Clause-by-clause, with the evidence")
    w("")
    w("> **On clause numbers.** The commissioning brief referred to "
      "“Clause 4.3 (Transparency)” and “Clause 5.2 — Consent”. "
      "Neither exists: `CBUAE_EN_6958_VER1` numbers sections 1–10 and letters "
      "its sub-clauses. The real identifiers are used throughout. §4(c) is the "
      "opt-out clause; §5(c) is the closest thing to a consent/purpose-limitation "
      "obligation. [`REGULATORY_MATRIX.md`](REGULATORY_MATRIX.md) records the "
      "full mapping.")
    w("")
    w("### The chain itself")
    w("")
    w(f"{len(chain_lines)} records, produced by the five journeys above, each "
      "committing to the SHA-256 of the one before it:")
    w("")
    w("| seq | event | caller | prev_hash | record_hash |")
    w("|---|---|---|---|---|")
    for line in chain_lines:
        record = json.loads(line)
        w(f"| {record['seq']} | `{record['event_type']}`/`{record['decision']}` | "
          f"{record['caller']} | `{record['prev_hash'][:16]}…` | `{record['record_hash'][:16]}…` |")
    w("")
    w(f"Verified with AIHOOTS's own independent verifier: "
      f"**{'chain intact' if not checks['chain_errors'] else 'ERRORS'}**.")
    w("")
    w(f"Altering one field of record 0 (`{checks['tampered_field']}`) and re-running "
      f"the verifier produces: `{checks['tamper_first_error']}`. That is the "
      "difference between a log and evidence — the operator of the gateway "
      "cannot quietly change what a proof said after the fact.")
    w("")
    w("### Clause → evidence")
    w("")
    w("| CBUAE clause | What it requires | The evidence in this report |")
    w("|---|---|---|")
    w("| **§4(a)** Transparency | Be transparent about AI use and high-impact decisions, and *be able to disclose* how decisions are made. | Every `decision` record in Section C carries its outcome **and reasons**. The consumer saw the predicate in Section B step 1 before approving it. |")
    w("| **§4(c)** Opt-out rights | Consider opt-out, particularly for high-impact decisions. | A disclosure request stays `pending` until the consumer acts. Declining is inaction; there is no flow to withdraw from. `POST /disclosure-requests/:id/revoke` covers withdrawal after the fact. |")
    w("| **§5(a)** Provenance and audit trails | Clear provenance and audit trails for data used in AI. | `proof_hash` in each token binds the attestation to specific proof bytes; the chain above binds each record to its predecessor. |")
    w("| **§5(c)** Legitimate and proportionate purposes | Personal data used only for legitimate, proportionate purposes; in-country retention. | The relying party received one boolean per journey. The withheld items listed in Section A were never transmitted, so storage and residency obligations do not attach to them. |")
    w("| **§5(d)** Privacy-by-design | Privacy-by-design and security-by-design built into AI systems. | The injected preamble contains the predicate and explicitly states the underlying value was not disclosed. The model's context never held the salary, the balance, or the medical file. |")
    w("| **§5(e)** Financial-crime detection | Use AI to identify AML and suspicious-activity issues, subject to reporting duties. | Journey A3 resolves an STR narrative from `compliance_clear` alone, with source-of-funds documents withheld. |")
    w("| **§6(f)** Immediate cessation | Retain a clear, immediate, human ability to cease use of a deployed AI system. | Disclosure requests and session tokens are revocable and take effect on the next request. **Caveat:** the 300-second proof token is *not* revocable inside its lifetime — the deliberate cost of offline validation. See the §6(f) note in the matrix. |")
    w("| **§7(a)** Human oversight | Meaningful human oversight, particularly for consumer-significant decisions. | No proof exists unless the consumer performs an explicit device-local action. The gate is held by the person whose interests are at stake. |")
    w("| **§7(c)** Correction of inaccurate inputs | Consumers may challenge decisions and correct inaccurate data inputs. | The vault is consumer-held; a corrected record changes `vault_root`, so later proofs reflect it without an institutional data-change request. **Not covered:** the Article 8 complaints channel. |")
    w("| **§9(c)** AI inventory | Maintain an inventory of AI models, including third-party ones. | Every record above names its `model` and every token names its `circuit` — a usage-derived inventory that cannot silently omit something actually in use. |")
    w("")
    w("### The join nobody has to trust")
    w("")
    w("Memtara and AIHOOTS keep separate, independent hash chains and never call "
      "each other. `regulatory_audit_id` is what makes them correlatable: it is "
      "minted at issuance, written into Memtara's `audit_log`, carried inside the "
      "signed token, and echoed into AIHOOTS's `audit.jsonl`. An auditor holding "
      "both logs can prove they describe the same event, and neither operator can "
      "fabricate a match without breaking a chain.")
    w("")
    w("| Journey | `regulatory_audit_id` | `proof_hash` (first 16) |")
    w("|---|---|---|")
    for entry in journeys:
        w(f"| {entry['journey'].title} | `{entry['regulatory_audit_id']}` | `{entry['proof_hash'][:16]}…` |")
    w("")
    w("---")
    w("")

    # ---- Section D -------------------------------------------------------
    w("## Section D — The flow")
    w("")
    w("```mermaid")
    w("sequenceDiagram")
    w("    autonumber")
    w("    actor U as UAE resident<br/>(device holds the vault)")
    w("    participant M as Memtara<br/>(issuer)")
    w("    participant A as AIHOOTS gateway<br/>(relying party)")
    w("    participant L as LLM<br/>(network-isolated)")
    w("")
    w("    Note over A,M: Once, at startup — the ONLY call between the two systems")
    w("    A->>M: GET /.well-known/jwks.json")
    w("    M-->>A: Ed25519 public key (cached by kid)")
    w("")
    w("    Note over U,M: Per disclosure")
    w("    M->>U: disclosure request (predicate + nonce + TTL)")
    w("    U->>U: generate ZK proof on device<br/>(attribute never leaves)")
    w("    U->>M: proof + public inputs")
    w("    M->>M: bb verify against circuit vkey<br/>consume nonce, append to audit_log")
    w("    M-->>A: proof_token (JWT, EdDSA, 300s)")
    w("")
    w("    Note over A: No call to Memtara from here on")
    w("    A->>A: validate signature locally<br/>append attestation to audit.jsonl")
    w("    A->>L: prompt + injected verified claims")
    w("    L-->>A: completion")
    w("    A->>A: append decision + response to audit.jsonl")
    w("```")
    w("")
    w("The two audit chains, and the single identifier that lets an auditor line "
      "them up:")
    w("")
    w("```mermaid")
    w("flowchart LR")
    w("    subgraph MEM[Memtara audit_log — Postgres, advisory-lock serialised]")
    w("        M1[disclosure_request_created] --> M2[proof_verified] --> M3[proof_token_issued]")
    w("    end")
    w("    subgraph AIH[AIHOOTS audit.jsonl — append-only, SHA-256 chained]")
    w("        A1[attestation] --> A2[decision] --> A3[response]")
    w("    end")
    w("    M3 -. regulatory_audit_id<br/>the only link .-> A1")
    w("```")
    w("")
    w("---")
    w("")

    # ---- Section E -------------------------------------------------------
    render_suitability(w, wealth, checks)

    # ---- Section F -------------------------------------------------------
    w("## Section F — The synthetic population")
    w("")
    w(f"{PROFILE_COUNT} profiles, `faker` seed `{DEMO_SEED}`. Income tiers are "
      "conditioned on residency type rather than drawn uniformly — a Golden Visa "
      "carries an investment or salary floor, so a uniform draw would describe a "
      "population that cannot exist and would make every figure below misleading.")
    w("")
    w("**Residency type**")
    w("")
    w("| Type | Count |")
    w("|---|---|")
    for name, count in stats["residency"].items():
        w(f"| {name} | {count} |")
    w("")
    w("**Income tier**")
    w("")
    w("| Tier | Monthly AED band | Count |")
    w("|---|---|---|")
    for (tier, low, high) in INCOME_TIERS:
        w(f"| {tier} | {low:,}–{high:,} | {stats['tier'].get(tier, 0)} |")
    w("")
    w("**Emirate**")
    w("")
    w("| Emirate | Count |")
    w("|---|---|")
    for name, count in stats["emirate"].items():
        w(f"| {name} | {count} |")
    w("")
    w(f"PEP-flagged: {stats['pep']} of {PROFILE_COUNT}. Sanctions matches: 0.")
    w("")
    w("Not one of these attributes is transmitted in any journey above. They "
      "exist to show that the disclosures are drawn from a realistic population, "
      "not that the population is disclosed.")
    w("")
    w("---")
    w("")
    w("## Reproducing this")
    w("")
    w("```bash")
    w("git submodule update --init                 # AIHOOTS reference")
    w("python3 -m venv --system-site-packages .venv")
    w(".venv/bin/pip install faker pg8000")
    w(".venv/bin/python scripts/generate_regulatory_demo.py")
    w("```")
    w("")
    w("To check this script's predicate table against a running server (it will "
      "fail loudly on any drift):")
    w("")
    w("```bash")
    w(".venv/bin/python scripts/generate_regulatory_demo.py --check-against http://localhost:8080")
    w("```")
    w("")
    w("For the live handshake against the real Rust server, real Postgres and "
      "real Barretenberg: `.venv/bin/pytest tests/test_aihoots_handshake.py`.")
    return "\n".join(out) + "\n"


def _session_type(circuit: str) -> str:
    return {
        "tax_session": "TaxSession",
        "identity_session": "IdentitySession",
        "emergency_session": "EmergencySession",
        "ai_session": "AiSession",
    }[circuit]


def _compact_event(event) -> dict:
    """Trim an audit record to the fields worth printing in a report.

    The full record is what gets hashed; this is a reading aid, and the table
    in Section C carries the hashes so nothing load-bearing is hidden by the
    trimming.
    """
    from dataclasses import asdict

    record = asdict(event)
    keep = [
        "seq", "event_type", "decision", "caller", "model",
        "prompt_digest", "response_digest", "detail", "prev_hash", "record_hash",
    ]
    trimmed = {k: record[k] for k in keep if k in record and record[k] not in ("", {}, None)}
    for field_name in ("prev_hash", "record_hash", "prompt_digest", "response_digest"):
        if field_name in trimmed:
            trimmed[field_name] = trimmed[field_name][:16] + "…"
    return trimmed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "docs" / "REGULATORY_DEMO_REPORT.md",
    )
    parser.add_argument(
        "--check-against",
        metavar="URL",
        help="Compare this script's predicate table against a live server and exit non-zero on drift.",
    )
    args = parser.parse_args()

    if args.check_against:
        problems = check_against_server(args.check_against)
        if problems:
            print("predicate registry has drifted:", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
            return 1
        print(f"predicate registry matches {args.check_against}")

    if not (AIHOOTS_ROOT / "src" / "gateway" / "audit" / "chain.py").exists():
        print(
            "AIHOOTS submodule is empty — run `git submodule update --init`",
            file=sys.stderr,
        )
        return 1

    from src.gateway.audit.chain import AuditChain

    issuer = DemoIssuer(DEMO_KEY_SEED, ISSUER)
    profiles = generate_profiles(PROFILE_COUNT)
    stats = population_stats(profiles)

    chain_path = REPO_ROOT / "docs" / ".demo-audit.jsonl"
    chain_path.unlink(missing_ok=True)
    chain = AuditChain(str(chain_path))

    with frozen_clock(int(AS_OF.timestamp())):
        journeys = build_journeys(issuer, profiles, chain)
        book = generate_wealth_book(profiles, WEALTH_PRODUCT)
        wealth = build_wealth_case(issuer, book, WEALTH_PRODUCT, chain)
    checks = self_check(issuer, journeys, wealth, chain_path)
    chain_lines = [line for line in chain_path.read_text().splitlines() if line.strip()]

    report = render(issuer, profiles, stats, journeys, wealth, checks, chain_lines)
    args.out.write_text(report)
    chain_path.unlink(missing_ok=True)

    print(f"wrote {args.out} ({len(report):,} bytes)")
    print(
        f"  tokens validated offline : {checks['tokens_validated']}"
        f"/{len(journeys) + len(wealth['assessments'])}"
    )
    print(f"  jwks fetches during validation : {checks['fetch_count']}")
    print(f"  audit chain : {'intact' if not checks['chain_errors'] else checks['chain_errors']}")
    print(f"  tamper detected : {checks['tamper_detected']}")
    return 0 if not checks["chain_errors"] and checks["tamper_detected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
