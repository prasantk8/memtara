#!/usr/bin/env python3
"""The Chief Risk Officer demonstration: one command, the whole journey.

    python3 scripts/demo_cro_workflow.py

Registers a structured product under product governance, onboards a synthetic
client, has an advisor ask an LLM to recommend the product, generates a real
zero-knowledge proof on the client's device, verifies it, injects the result
into the model's context, records both sides of the interaction in
tamper-evident chains, and exports a sealed Canonical Case File.

-------------------------------------------------------------------
WHAT IS REAL HERE
-------------------------------------------------------------------
Everything except one thing, and the exception is named on screen rather than
buried:

    REAL   the compiled Rust server, Postgres, the Noir circuit, Barretenberg
           proving and verification, the Baby Jubjub signature, the Ed25519
           issuer key and its published JWKS, AIHOOTS's own gateway and audit
           chain from the pinned submodule, and the PDF's seal.

    NOT    the upstream language model. AIHOOTS stubs it in CI by their own
           policy (their ADR-004), and nothing about suitability depends on
           what the model replies — the claim is injected before the model
           sees the conversation, which is the whole point.

The client is synthetic. Her figures are invented, and after this script has
run, Memtara has never held any of them.

-------------------------------------------------------------------
A NOTE ON THE ISIN
-------------------------------------------------------------------
The brief for this demo specified `TEST1234567890`. That is fourteen
characters; an ISIN is twelve, so it is not an ISIN and the registry refuses
it — correctly, because a registry that accepts non-identifiers cannot be
reconciled against a product master. The demo uses `XS2500000018`, which is
structurally valid and, unlike the illustrative `XS1234567890` used elsewhere
in this repository, passes its own ISO 6166 check digit.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
CLIENTS_DIR = REPO_ROOT / "clients"
AIHOOTS_ROOT = REPO_ROOT / "tests" / "aihoots_reference"

for path in (REPO_ROOT, CLIENTS_DIR, REPO_ROOT / "integrations" / "aihoots", AIHOOTS_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import wealth_client as wc  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://memtara:memtara@localhost:5433/memtara")

# A fixed issuer key so the demo's `kid` is stable across runs and a reviewer
# can compare two case files. Test material — the deployment reads a real
# secret from the environment (see .env.example).
DEMO_PRIVATE_KEY_B64 = base64.b64encode(bytes(range(32))).decode()

PRODUCT = {
    "product_isin": "XS2500000018",
    "product_name": "5-Year S&P 500 Principal Protected Note",
    "risk_level": 3,
    "min_income": 500_000,
    "min_liquidity": 1_000_000,
    "max_concentration_percent": 30,
}

CLIENT = {
    "label": "client_42",
    "income": 750_000,
    "liquid_assets": 2_000_000,
    "risk_tolerance": 4,
    "existing_holdings_value": 250_000,
}

EXIT_NOT_SUITABLE = 3

ADVISOR_PROMPT = (
    "Recommend the 5-Year S&P note to client_42. "
    f"ISIN {PRODUCT['product_isin']}."
)


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"


class Ui:
    def __init__(self, colour: bool) -> None:
        self.colour = colour
        self.step_number = 0

    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.colour else text

    def banner(self, title: str) -> None:
        line = "=" * 74
        print(self._c(line, DIM))
        print(self._c(f" {title}", BOLD))
        print(self._c(line, DIM))

    def step(self, title: str) -> None:
        self.step_number += 1
        print()
        print(self._c(f"[{self.step_number}] {title}", BOLD))

    def detail(self, key: str, value: str) -> None:
        print(f"    {key:<28} {value}")

    def note(self, text: str) -> None:
        print(self._c(f"    · {text}", DIM))

    def warn(self, text: str) -> None:
        print(self._c(f"    ! {text}", YELLOW))

    def ok(self, text: str) -> None:
        print(self._c(f"    ✓ {text}", GREEN))

    def fail(self, text: str) -> None:
        print(self._c(f"    ✗ {text}", RED))


def money(value: int) -> str:
    return f"AED {value:,}"


def discloses(text: str, *values: int) -> list[int]:
    """Which of `values` appears in `text` as a standalone number.

    A plain substring search is wrong here, and wrong in the direction that
    raises a false alarm: the demo's own ISIN, `XS2500000018`, contains the
    digits `250000`, which is also the client's holdings figure. A leak check
    that cries wolf on a coincidence gets disabled, so the digit-boundary
    lookarounds are load-bearing rather than tidiness.
    """
    return [v for v in values if re.search(rf"(?<!\d){v}(?!\d)", text)]


# ---------------------------------------------------------------------------
# Preconditions
#
# Checked up front and reported together. A demo that dies four steps in
# because `bb` is missing wastes the reviewer's time and, worse, leaves them
# unsure how much of what they saw was real.
# ---------------------------------------------------------------------------


@dataclass
class Prereq:
    name: str
    ok: bool
    detail: str


def check_prerequisites(ui: Ui, *, need_server: bool) -> list[Prereq]:
    checks: list[Prereq] = []

    for binary, why in (("nargo", "compiles and executes the circuit"), ("bb", "generates and verifies proofs")):
        found = shutil.which(binary)
        checks.append(Prereq(binary, found is not None, found or f"not on PATH — {why}"))

    if need_server:
        cargo = shutil.which("cargo")
        checks.append(Prereq("cargo", cargo is not None, cargo or "not on PATH — needed to build the server"))

    compiled = REPO_ROOT / "circuits" / "target" / "wealth_suitability.json"
    checks.append(
        Prereq(
            "compiled circuit",
            compiled.is_file(),
            str(compiled) if compiled.is_file() else "run `nargo compile --workspace --skip-brillig-constraints-check`",
        )
    )

    try:
        import pg8000.native  # noqa: F401

        checks.append(Prereq("pg8000", True, "available"))
    except ImportError:
        checks.append(Prereq("pg8000", False, "pip install -r requirements-dev.txt"))

    aihoots = AIHOOTS_ROOT / "src" / "gateway" / "main.py"
    checks.append(
        Prereq(
            "AIHOOTS submodule",
            aihoots.is_file(),
            str(AIHOOTS_ROOT) if aihoots.is_file() else "git submodule update --init --recursive (optional)",
        )
    )

    for check in checks:
        (ui.ok if check.ok else ui.fail)(f"{check.name:<20} {check.detail}")
    return checks


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ManagedServer:
    """Builds and runs a Memtara instance for the life of the demo.

    Booting our own rather than assuming one is running is what makes the
    "run it and watch" promise true. `--base-url` opts out for anyone who
    already has one.
    """

    def __init__(self, ui: Ui) -> None:
        self.ui = ui
        self.process: subprocess.Popen | None = None
        self.base_url = ""

    def start(self) -> str:
        build = subprocess.run(
            ["cargo", "build", "--bin", "memtara-api"],
            cwd=BACKEND_DIR,
            capture_output=True,
            text=True,
            env={**os.environ, "DATABASE_URL": DATABASE_URL},
        )
        if build.returncode != 0:
            raise RuntimeError(f"cargo build failed:\n{build.stderr[-3000:]}")

        port = free_port()
        self.base_url = f"http://127.0.0.1:{port}"
        self.process = subprocess.Popen(
            [str(BACKEND_DIR / "target" / "debug" / "memtara-api")],
            env={
                **os.environ,
                "DATABASE_URL": DATABASE_URL,
                "BIND_ADDR": f"127.0.0.1:{port}",
                "MEMTARA_PRIVATE_KEY": DEMO_PRIVATE_KEY_B64,
                "MEMTARA_ISSUER_BASE_URL": self.base_url,
                "RUST_LOG": "memtara_api=warn",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        deadline = time.time() + 180  # a cold boot writes a verification key per circuit
        while time.time() < deadline:
            if self.process.poll() is not None:
                output = self.process.stdout.read() if self.process.stdout else ""
                raise RuntimeError(f"memtara-api exited during boot:\n{output[-3000:]}")
            try:
                if http_get(f"{self.base_url}/healthz")[0] == 200:
                    return self.base_url
            except OSError:
                time.sleep(0.4)
        raise RuntimeError("memtara-api did not become healthy within 180s")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self.process.kill()


# ---------------------------------------------------------------------------
# HTTP, without a dependency
# ---------------------------------------------------------------------------

import urllib.error  # noqa: E402
import urllib.request  # noqa: E402


def http_get(url: str, token: str | None = None, timeout: float = 30.0) -> tuple[int, str]:
    request = urllib.request.Request(url, method="GET")
    if token:
        request.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def http_json(method: str, url: str, payload: dict | None, token: str | None, timeout: float = 60.0) -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("content-type", "application/json")
    if token:
        request.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode()
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"error": raw}


# ---------------------------------------------------------------------------
# Database access, for the two things the HTTP API deliberately has no route
# for: creating a user without a passkey ceremony, and issuing a session token
# without an OTP round trip. Both are real rows read by the real extractors.
# ---------------------------------------------------------------------------


def db_connect():
    import pg8000.native
    from urllib.parse import urlparse

    parsed = urlparse(DATABASE_URL)
    return pg8000.native.Connection(
        user=parsed.username or "memtara",
        password=parsed.password or "memtara",
        host=parsed.hostname or "localhost",
        port=parsed.port or 5432,
        database=(parsed.path or "/memtara").lstrip("/"),
    )


def hash_session_token(token: str) -> str:
    """Mirror of `auth::session_token::hash_token` — base64url-no-pad SHA-256."""
    return base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).decode().rstrip("=")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


# ---------------------------------------------------------------------------
# The workflow
# ---------------------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    ui = Ui(colour=sys.stdout.isatty() and not args.no_colour)
    started = datetime.now(timezone.utc)

    ui.banner("MEMTARA — STRUCTURED PRODUCT SUITABILITY, END TO END")
    print()
    print("  A DFSA-regulated firm must satisfy itself that a structured product is")
    print("  suitable for a client before recommending it, and be able to show it did.")
    print("  Conventionally that means holding salary slips and portfolio statements.")
    print()
    print("  This demonstration produces the same evidence and holds none of them.")

    ui.step("Checking prerequisites")
    checks = check_prerequisites(ui, need_server=args.base_url is None)
    blocking = [c for c in checks if not c.ok and c.name != "AIHOOTS submodule"]
    if blocking:
        print()
        ui.fail("cannot run: " + ", ".join(c.name for c in blocking))
        return 1
    aihoots_available = next(c.ok for c in checks if c.name == "AIHOOTS submodule")
    if not aihoots_available:
        ui.warn("AIHOOTS submodule absent — steps 6 and 7 will be reported as not performed")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    server = None
    conn = None
    org_id = None
    user_id = str(uuid.uuid4())

    try:
        if args.base_url:
            base_url = args.base_url.rstrip("/")
            ui.step("Using the Memtara instance you supplied")
        else:
            ui.step("Building and starting Memtara")
            ui.note("cargo build, then a cold boot that writes a verification key per circuit")
            server = ManagedServer(ui)
            base_url = server.start()
        ui.detail("base url", base_url)

        status, health = http_json("GET", f"{base_url}/health", None, None)
        ui.detail("health", health.get("status", "?"))
        vkey = health.get("checks", {}).get("published_wealth_vkey", {})
        ui.detail("published vkey", str(vkey.get("status")))
        if vkey.get("status") == "matches":
            ui.note(
                "the key this server verifies against is byte-identical to the one committed "
                "to the repository, so a regulator can re-verify without trusting the deployment"
            )

        # -------------------------------------------------------------
        ui.step("Registering the bank, and the product under governance")
        # -------------------------------------------------------------
        status, org = http_json(
            "POST", f"{base_url}/orgs", {"name": f"DIFC Wealth Desk (demo {started:%Y-%m-%d})", "org_type": "bank"}, None
        )
        if status != 201:
            raise RuntimeError(f"could not create the org: {org}")
        org_id, api_key = org["id"], org["api_key"]
        ui.detail("organisation", org["name"])

        status, product = http_json("POST", f"{base_url}/api/v1/products", PRODUCT, api_key)
        if status != 201:
            raise RuntimeError(f"could not register the product: {product}")
        ui.detail("product", f"{product['product_name']}")
        ui.detail("isin", f"{product['product_isin']} (check digit {'valid' if product['check_digit_valid'] else 'INVALID'})")
        ui.detail("terms", f"income ≥ {money(PRODUCT['min_income'])}, liquid ≥ {money(PRODUCT['min_liquidity'])}")
        ui.detail("", f"concentration ≤ {PRODUCT['max_concentration_percent']}%, risk tolerance ≥ {PRODUCT['risk_level']}")
        ui.detail("risk committee", "NOT YET APPROVED")

        status, refused = http_json(
            "POST",
            f"{base_url}/api/v1/issue-wealth-request",
            {"user_id": user_id, "product_isin": PRODUCT["product_isin"]},
            api_key,
        )
        ui.note(f"an assessment against it is refused ({status}) until the committee signs off")

        http_json(
            "PATCH",
            f"{base_url}/api/v1/products/{PRODUCT['product_isin']}",
            {"approved_by_risk_committee": True},
            api_key,
        )
        ui.detail("risk committee", "APPROVED (audited)")

        # -------------------------------------------------------------
        ui.step("Onboarding the client")
        # -------------------------------------------------------------
        conn = db_connect()
        session_token = f"cro-demo-{uuid.uuid4().hex}"
        conn.run(
            "insert into users (id, phone_e164) values (:id, :phone)",
            id=user_id,
            phone=f"+9715{uuid.uuid4().int % 10**8:08d}",
        )
        conn.run(
            "insert into sessions (user_id, token_hash, expires_at) "
            "values (:uid, :hash, now() + interval '1 hour')",
            uid=user_id,
            hash=hash_session_token(session_token),
        )

        vault_path = output_dir / "client_42_vault.json"
        vault_path.unlink(missing_ok=True)
        prove = str(CLIENTS_DIR / "prover" / "memtara-prove")
        subprocess.run(
            [
                sys.executable, prove, "--quiet", "init-vault",
                "--vault-path", str(vault_path),
                "--user-id", user_id,
                "--income", str(CLIENT["income"]),
                "--liquid-assets", str(CLIENT["liquid_assets"]),
                "--risk-tolerance", str(CLIENT["risk_tolerance"]),
                "--existing-holdings-value", str(CLIENT["existing_holdings_value"]),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        ui.detail("client", CLIENT["label"])
        ui.detail("income", money(CLIENT["income"]))
        ui.detail("liquid assets", money(CLIENT["liquid_assets"]))
        ui.detail("risk tolerance", f"{CLIENT['risk_tolerance']} / 5")
        ui.detail("existing holdings", money(CLIENT["existing_holdings_value"]))
        ui.note(f"these four figures live only in {vault_path} — nothing above is sent anywhere")

        root_out = subprocess.run(
            [sys.executable, prove, "--json", "--quiet", "vault-root", "--vault-path", str(vault_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        vault_root = json.loads(root_out.stdout)["vault_root"]
        http_json(
            "PUT",
            f"{base_url}/vault",
            {
                "ciphertext": b64url(b"the server stores this and cannot read it"),
                "vault_root": b64url(bytes.fromhex(vault_root[2:])),
                "expected_version": 0,
            },
            session_token,
        )
        ui.detail("vault root synced", vault_root[:22] + "…")
        ui.note("a Poseidon commitment; the server pins it so a device cannot invent a tree later")

        status, consent = http_json(
            "POST",
            f"{base_url}/api/v1/consents",
            {
                "user_id": user_id,
                "scope": ["wealth.suitability_recommendation"],
                "consent_version": "cro-demo-v1",
                "granted_via": "mobile_app",
            },
            api_key,
        )
        if status != 201:
            raise RuntimeError(f"could not record the client's consent: {consent}")
        ui.detail("consent on file", "wealth.suitability_recommendation")
        ui.note("issue-wealth-request refuses without this — a purpose binding is not a permission")

        # -------------------------------------------------------------
        ui.step("The advisor asks the AI to recommend the product")
        # -------------------------------------------------------------
        print(f'    {DIM if ui.colour else ""}"{ADVISOR_PROMPT}"{RESET if ui.colour else ""}')
        ui.note("the prompt names the product; it does not — and cannot — set its terms")

        # -------------------------------------------------------------
        ui.step("The client's device generates a zero-knowledge proof")
        # -------------------------------------------------------------
        ui.note("real nargo execute + bb prove over circuits/wealth_suitability; a few seconds")
        proof_started = time.time()
        result_proc = subprocess.run(
            [
                sys.executable, prove, "--json",
                "--base-url", base_url,
                "--user-id", user_id,
                "--product-isin", PRODUCT["product_isin"],
                "--vault-path", str(vault_path),
                "--org-api-key", api_key,
                "--session-token", session_token,
            ],
            capture_output=True,
            text=True,
        )
        if result_proc.returncode not in (0, EXIT_NOT_SUITABLE) or not result_proc.stdout.strip():
            raise RuntimeError(
                f"the device prover exited {result_proc.returncode}:\n"
                f"{result_proc.stdout}\n{result_proc.stderr}"
            )
        assessment = json.loads(result_proc.stdout)
        elapsed = time.time() - proof_started

        ui.detail("elapsed", f"{elapsed:.1f}s")
        ui.detail("request id", assessment["request_id"])
        ui.detail("verdict", "SUITABLE" if assessment["suitable"] else "NOT SUITABLE")
        ui.note("read from public input 11 of the circuit — not inferred from `bb verify` succeeding")

        # -------------------------------------------------------------
        ui.step("Memtara verifies the proof and issues a signed attestation")
        # -------------------------------------------------------------
        status, pack = http_json(
            "GET", f"{base_url}/api/v1/wealth-assessments/{assessment['request_id']}", None, api_key
        )
        if status != 200:
            raise RuntimeError(f"could not read the evidence pack: {pack}")
        accepted = [p for p in pack["proofs"] if p["accepted_by_bb_verify"]]
        proof_hash = accepted[-1]["proof_sha256"]

        ui.detail("bb verify", "accepted")
        ui.detail("verification key", pack["verification_key"]["sha256"][:24] + "…")
        ui.detail("proof sha-256", proof_hash[:24] + "…")
        ui.detail("attestation", assessment["proof_token"][:44] + "…")
        ui.detail("audit id", assessment["regulatory_audit_id"])
        ui.note("anyone can validate that JWT against " + f"{base_url}/.well-known/jwks.json")

        # -------------------------------------------------------------
        ui.step("The claim is injected into the model's context, and logged")
        # -------------------------------------------------------------
        aihoots_audit_path = None
        if aihoots_available:
            try:
                aihoots_audit_path = run_aihoots(ui, output_dir, base_url, assessment, proof_hash)
            except Exception as exc:  # pragma: no cover - environment-dependent
                ui.warn(f"AIHOOTS leg could not run ({exc.__class__.__name__}: {exc})")
                ui.warn("the Memtara-side evidence below is unaffected")
        else:
            ui.warn("not performed — the AIHOOTS submodule is not checked out")

        # -------------------------------------------------------------
        ui.step("Exporting the Canonical Case File")
        # -------------------------------------------------------------
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
        pdf_path = output_dir / f"Case_File_{stamp}.pdf"
        # The module, not the `memtara-export` shim: that shim is /bin/sh and
        # picks its own interpreter, which would silently take the demo out of
        # whatever environment it was started in.
        command = [
            sys.executable, str(REPO_ROOT / "scripts" / "export_audit_evidence.py"),
            "--request-id", assessment["request_id"],
            "--base-url", base_url,
            "--org-api-key", api_key,
            "--proof-token", assessment["proof_token"],
            "--output", str(pdf_path),
        ]
        if aihoots_audit_path:
            command += ["--aihoots-audit", str(aihoots_audit_path)]

        exported = subprocess.run(command, capture_output=True, text=True)
        if exported.returncode != 0:
            raise RuntimeError(f"the exporter failed:\n{exported.stdout}\n{exported.stderr}")

        ui.detail("case file", str(pdf_path))
        ui.detail("size", f"{pdf_path.stat().st_size:,} bytes")
        seal_path = Path(str(pdf_path) + ".seal.json")
        if seal_path.exists():
            seal = json.loads(seal_path.read_text())
            ui.detail("pdf sha-256", str(seal["pdf"]["sha256"])[:24] + "…")
            ui.detail("evidence sha-256", str(seal["canonical_evidence_sha256"])[:24] + "…")
            ui.detail("seal", "signed" if seal.get("signature") else "unsigned (tamper-evident, not authenticated)")
            ui.note(f"re-check it later with: scripts/memtara-export verify {pdf_path}")
            ui.note("not a PAdES signature — no viewer will show a green tick; the JWT is the authenticity claim")

        # -------------------------------------------------------------
        ui.step("What the bank now holds, and what it does not")
        # -------------------------------------------------------------
        holds = [
            "a signed attestation that the product was assessed, and the verdict",
            "the terms it was assessed against, and which registry row supplied them",
            "the proof, its digest, and the verification key that accepted it",
            "a hash-chained audit trail of every step, on both sides",
        ]
        for item in holds:
            ui.ok(item)

        raw_pack = json.dumps(pack)
        leaked = [
            name
            for name, value in (
                ("income", CLIENT["income"]),
                ("liquid assets", CLIENT["liquid_assets"]),
                ("existing holdings", CLIENT["existing_holdings_value"]),
            )
            if discloses(raw_pack, value)
        ]
        print()
        if leaked:
            ui.fail(f"the evidence pack disclosed: {', '.join(leaked)}")
            return 1
        for name, value in (
            ("income", money(CLIENT["income"])),
            ("liquid assets", money(CLIENT["liquid_assets"])),
            ("risk tolerance", f"{CLIENT['risk_tolerance']} / 5"),
            ("existing holdings", money(CLIENT["existing_holdings_value"])),
        ):
            print(f"    not held:  {name:<22} {value}")
        ui.note("verified above against the evidence pack's own bytes, not asserted")

        print()
        print(f"✅ CRO Demo Complete. Report saved to {pdf_path}.")
        print("   Show this to any Head of Digital Wealth.")
        print()
        return 0

    except Exception as exc:
        print()
        ui.fail(f"{exc.__class__.__name__}: {exc}")
        return 1

    finally:
        if conn is not None and org_id is not None and not args.keep_data:
            cleanup(conn, org_id, user_id)
        if conn is not None:
            conn.close()
        if server is not None:
            server.stop()


def run_aihoots(ui: Ui, output_dir: Path, base_url: str, assessment: dict, proof_hash: str) -> Path:
    """Drive AIHOOTS's real gateway through the Memtara middleware.

    The upstream model is stubbed — AIHOOTS's own CI policy, not ours — so what
    this proves is the part that matters: the suitability claim reaches the
    model's context as a system message before the model is called, and both
    the claim and the proof digest land in AIHOOTS's hash-chained log.
    """
    from integrations.aihoots.memtara_claims import JwksCache, validate_proof_token

    audit_path = output_dir / "aihoots_audit.jsonl"
    audit_path.unlink(missing_ok=True)

    jwks = JwksCache(f"{base_url}/.well-known/jwks.json")
    jwks.load()
    verified = validate_proof_token(assessment["proof_token"], jwks=jwks, expected_issuer=base_url)

    # The product name and level come from the registry, not from the token —
    # `ProofTokenClaims` carries neither — so the preamble labels their
    # provenance rather than blending them with the attested facts.
    preamble = verified.as_prompt_preamble(
        product_name=PRODUCT["product_name"], risk_level=PRODUCT["risk_level"]
    )
    ui.detail("injected as", "system message, before the model sees the conversation")
    for line in preamble.strip().splitlines():
        print(f"      {DIM if ui.colour else ''}{line}{RESET if ui.colour else ''}")

    leaked = discloses(preamble, CLIENT["income"], CLIENT["liquid_assets"], CLIENT["existing_holdings_value"])
    if leaked:
        raise RuntimeError(f"the injected claim disclosed {leaked}")
    ui.ok("no client figure appears in the injected claim")

    # AIHOOTS's own chain, its own code.
    from src.gateway.audit.chain import AuditChain, digest, new_event  # type: ignore

    from integrations.aihoots.memtara_claims import audit_event_fields

    chain = AuditChain(str(audit_path))
    entry = chain.append(
        new_event(
            request_id=assessment["regulatory_audit_id"],
            caller="advisor-terminal",
            model="qwen2.5:3b-instruct",
            event_type="decision",
            decision="allow" if assessment["suitable"] else "block",
            prompt_digest=digest(ADVISOR_PROMPT),
            prompt_len=len(ADVISOR_PROMPT),
            # The adapter's own field set, not a hand-written one — so what the
            # demo writes into the chain is exactly what a deployment writes.
            detail=audit_event_fields(verified),
        )
    )
    ui.detail("audit.jsonl", str(audit_path))
    ui.detail("chain entry", f"seq {entry.seq}, record_hash {entry.record_hash[:16]}…")
    ui.detail("linked by", f"proof_hash {proof_hash[:16]}…")
    ui.note("the join key between AIHOOTS's chain and Memtara's evidence pack")

    # AIHOOTS's own verifier, not ours. If their chain format changes, this is
    # where the demo finds out rather than the compliance officer.
    verify = subprocess.run(
        [sys.executable, "-m", "src.verifier.cli", str(audit_path)],
        cwd=AIHOOTS_ROOT,
        capture_output=True,
        text=True,
    )
    if verify.returncode == 0:
        ui.ok("AIHOOTS audit-verify: chain intact")
    else:
        ui.warn(f"AIHOOTS audit-verify reported: {(verify.stdout + verify.stderr).strip()[:200]}")
    return audit_path


def cleanup(conn, org_id: str, user_id: str) -> None:
    """Leave the database as it was found. `--keep-data` opts out for anyone
    who wants to poke at the rows afterwards."""
    for statement in (
        "delete from proofs where request_id in (select id from disclosure_requests where org_id = :oid)",
        "delete from audit_log where org_id = :oid",
        "delete from audit_log where ref_id in (select id from disclosure_requests where org_id = :oid)",
        "delete from wealth_requests where request_id in (select id from disclosure_requests where org_id = :oid)",
        "delete from used_nonces where org_id = :oid",
        "delete from disclosure_requests where org_id = :oid",
        "delete from products where org_id = :oid",
        "delete from organizations where id = :oid",
    ):
        try:
            conn.run(statement, oid=org_id)
        except Exception:  # pragma: no cover - best effort
            pass
    for statement in (
        "delete from vault_blobs where user_id = :uid",
        "delete from sessions where user_id = :uid",
        "delete from users where id = :uid",
    ):
        try:
            conn.run(statement, uid=user_id)
        except Exception:  # pragma: no cover
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "cro_demo"))
    parser.add_argument("--base-url", default=None, help="use an already-running Memtara instead of starting one")
    parser.add_argument("--keep-data", action="store_true", help="leave the demo's database rows in place")
    parser.add_argument("--no-colour", action="store_true")
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
