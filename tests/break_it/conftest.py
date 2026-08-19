"""Shared infrastructure for the "break it" adversarial suite.

This suite exists to answer one question per attack, against the REAL
system, never a mock: when someone tries this, does Memtara stop it?

It deliberately does NOT reuse the root `tests/conftest.py`'s session-scoped
`memtara_server` fixture for any test that mutates on-disk server state
(verification keys, the `bb` binary) or kills the process — that fixture is
shared with every other file pytest happens to collect in the same session,
and a test here that swaps a live vkey out from under a server other test
files are still using would be a self-inflicted, misleading failure, not a
finding about the product. `scripts/break_it.sh` runs this directory as its
own isolated `pytest` invocation for exactly this reason: attacks #5 and #6
get a dedicated, disposable server each; the rest can share the shared
session-scoped server safely because they only ever call the HTTP API and
(for #1/#2/#3/#7) make ordinary rows in Postgres.

Every fixture here fails LOUDLY when a prerequisite is missing (no `bb`, no
`nargo`, no reachable Postgres) via `pytest.skip` with a specific reason —
mirroring the house convention in `tests/conftest.py` and
`tests/test_wealth_suitability_e2e.py`. A missing local toolchain must never
be mistaken for "the attack was stopped."
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

import httpx
import pytest

# The root `tests/conftest.py` is the single definition of "the server under
# test", and this suite re-exports from it rather than re-deriving paths.
# A plain `from conftest import ...` cannot be used: pytest imports both
# conftest files under the bare module name `conftest`, so the import
# resolves to THIS file and pytest aborts collection of the entire test
# suite, not just this directory. Loading the parent by explicit path under
# a distinct module name keeps one source of truth without the collision,
# and the `sys.modules` guard means it is executed once however many attack
# modules import it.
_ROOT_CONFTEST_NAME = "memtara_tests_root_conftest"
if _ROOT_CONFTEST_NAME in sys.modules:
    _root_conftest = sys.modules[_ROOT_CONFTEST_NAME]
else:
    _root_conftest_path = Path(__file__).resolve().parent.parent / "conftest.py"
    _spec = importlib.util.spec_from_file_location(
        _ROOT_CONFTEST_NAME, _root_conftest_path
    )
    if _spec is None or _spec.loader is None:  # pragma: no cover - unreachable
        raise ImportError(f"cannot load the root conftest at {_root_conftest_path}")
    _root_conftest = importlib.util.module_from_spec(_spec)
    sys.modules[_ROOT_CONFTEST_NAME] = _root_conftest
    _spec.loader.exec_module(_root_conftest)

BACKEND_DIR = _root_conftest.BACKEND_DIR
CIRCUITS_DIR = _root_conftest.CIRCUITS_DIR
CLIENTS_DIR = _root_conftest.CLIENTS_DIR
DATABASE_URL = _root_conftest.DATABASE_URL
REPO_ROOT = _root_conftest.REPO_ROOT
TEST_PRIVATE_KEY_B64 = _root_conftest.TEST_PRIVATE_KEY_B64
db_connect = _root_conftest.db_connect
free_port = _root_conftest.free_port

import wealth_client as wc  # noqa: E402 - path set up by tests/conftest.py


def toolchain_or_skip() -> None:
    """Skip (not fail, not silently pass) if this machine cannot run a real
    proof. Mirrors `_toolchain_or_skip` in test_wealth_suitability_e2e.py —
    duplicated rather than imported because that function is module-private
    there and this suite must not depend on another test file's internals.
    """
    reason = wc.missing_toolchain_reason()
    if reason:
        pytest.skip(f"cannot run this adversarial test here: {reason}")


def hash_token(token: str) -> str:
    """Mirror of `auth::session_token::hash_token` (base64url-no-pad SHA-256)."""
    return base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).decode().rstrip("=")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


# ---------------------------------------------------------------------------
# A fresh "bank + client" actor set, built directly against whatever server
# URL a test hands in (the shared session server, or a dedicated one).
# ---------------------------------------------------------------------------

DEFAULT_TERMS = dict(
    min_income=500_000,
    min_liquidity=1_000_000,
    max_concentration_percent=30,
    product_risk_level=3,
)


@dataclasses.dataclass
class Desk:
    org_id: str
    api_key: str
    user_id: str
    session_token: str
    vault: "wc.WealthVault"
    vault_root: int
    oracle: "wc.NargoOracle"
    issuer: str
    product_isin: str
    terms: dict


@pytest.fixture()
def make_desk(request):
    """Factory fixture: `make_desk(base_url, **overrides) -> Desk`.

    Real org (via `POST /orgs`, so the API key is hashed the real way), a
    real registered+approved product, a real user/session row, and a real
    vault commitment via `PUT /vault` — the same shape as `desk` in
    `tests/test_wealth_suitability_e2e.py`, rebuilt here as a factory (not a
    single fixture) because several attacks need a SECOND, differently
    configured actor within the same test (e.g. "the same client, but its
    vault changed"), and because each dedicated server in attacks #5/#6 needs
    its own actor rather than sharing one across processes.

    Cleanup is best-effort DB deletion, registered via `request.addfinalizer`
    so it runs even if the test fails.
    """
    conns = []

    def _make(
        base_url: str,
        *,
        isin: str = "XS1234567890",
        product_name: str = "5-year capital-protected note, USD",
        terms: Optional[dict] = None,
        income: int = 750_000,
        liquid_assets: int = 2_000_000,
        risk_tolerance: int = 4,
        existing_holdings_value: int = 200_000,
        seed: int = 0x5EA_51DE_C0DE,
        approved: bool = True,
    ) -> Desk:
        toolchain_or_skip()
        terms = dict(terms or DEFAULT_TERMS)

        org = httpx.post(
            f"{base_url}/orgs",
            json={"name": f"Break-It Desk {uuid.uuid4().hex[:8]}", "org_type": "bank"},
            timeout=10.0,
        )
        assert org.status_code == 201, org.text
        org_body = org.json()

        registered = httpx.post(
            f"{base_url}/api/v1/products",
            json={
                "product_isin": isin,
                "product_name": product_name,
                "risk_level": terms["product_risk_level"],
                "min_income": terms["min_income"],
                "min_liquidity": terms["min_liquidity"],
                "max_concentration_percent": terms["max_concentration_percent"],
                "approved_by_risk_committee": approved,
            },
            headers={"Authorization": f"Bearer {org_body['api_key']}"},
            timeout=10.0,
        )
        assert registered.status_code == 201, registered.text

        conn = db_connect()
        conns.append(conn)
        user_id = uuid.uuid4()
        session_token = f"break-it-{uuid.uuid4().hex}"
        conn.run(
            "insert into users (id, phone_e164) values (:id, :phone)",
            id=str(user_id),
            phone=f"+9715{uuid.uuid4().int % 10**8:08d}",
        )
        conn.run(
            "insert into sessions (user_id, token_hash, expires_at) "
            "values (:uid, :hash, now() + interval '1 hour')",
            uid=str(user_id),
            hash=hash_token(session_token),
        )

        keypair = wc.Keypair.from_seed(seed)
        vault = wc.WealthVault(
            keypair=keypair,
            income=income,
            liquid_assets=liquid_assets,
            risk_tolerance=risk_tolerance,
            existing_holdings_value=existing_holdings_value,
        )
        oracle = wc.NargoOracle()
        vault_root, _ = oracle.merkle(vault.leaves())

        put = httpx.put(
            f"{base_url}/vault",
            json={
                "ciphertext": b64url(b"ciphertext-the-server-cannot-read"),
                "vault_root": b64url(vault_root.to_bytes(32, "big")),
                "expected_version": 0,
            },
            headers={"Authorization": f"Bearer {session_token}"},
            timeout=10.0,
        )
        assert put.status_code == 200, put.text

        desk = Desk(
            org_id=org_body["id"],
            api_key=org_body["api_key"],
            user_id=str(user_id),
            session_token=session_token,
            vault=vault,
            vault_root=vault_root,
            oracle=oracle,
            issuer=base_url,
            product_isin=isin,
            terms=terms,
        )

        def cleanup():
            for statement, params in [
                ("delete from audit_log where org_id = :oid", {"oid": desk.org_id}),
                (
                    "delete from audit_log where ref_id in "
                    "(select id from disclosure_requests where org_id = :oid)",
                    {"oid": desk.org_id},
                ),
                ("delete from products where org_id = :oid", {"oid": desk.org_id}),
                ("delete from used_nonces where org_id = :oid", {"oid": desk.org_id}),
                ("delete from disclosure_requests where org_id = :oid", {"oid": desk.org_id}),
                ("delete from vault_blobs where user_id = :uid", {"uid": desk.user_id}),
                ("delete from sessions where user_id = :uid", {"uid": desk.user_id}),
                ("delete from organizations where id = :oid", {"oid": desk.org_id}),
                ("delete from users where id = :uid", {"uid": desk.user_id}),
            ]:
                try:
                    conn.run(statement, **params)
                except Exception:  # pragma: no cover - best-effort cleanup
                    pass

        request.addfinalizer(cleanup)
        return desk

    yield _make

    for c in conns:
        try:
            c.close()
        except Exception:  # pragma: no cover
            pass


def resync_vault(base_url: str, desk: Desk, new_vault: "wc.WealthVault", *, expected_version: int) -> int:
    """Re-run `PUT /vault` for `desk`'s user with a genuinely different vault
    (different leaves -> different root), simulating the customer's
    underlying data changing after an earlier commitment/proof. Returns the
    new root as an int.
    """
    oracle = wc.NargoOracle()
    new_root, _ = oracle.merkle(new_vault.leaves())
    put = httpx.put(
        f"{base_url}/vault",
        json={
            "ciphertext": b64url(b"ciphertext-the-server-cannot-read-v2"),
            "vault_root": b64url(new_root.to_bytes(32, "big")),
            "expected_version": expected_version,
        },
        headers={"Authorization": f"Bearer {desk.session_token}"},
        timeout=10.0,
    )
    assert put.status_code == 200, put.text
    return new_root


def open_assessment(base_url: str, desk: Desk, *, isin: Optional[str] = None) -> dict:
    return wc.open_assessment(base_url, desk.api_key, user_id=desk.user_id, product_isin=isin or desk.product_isin)


def audit_log(base_url: str, desk: Desk) -> list[dict]:
    resp = httpx.get(
        f"{base_url}/orgs/{desk.org_id}/audit-log",
        headers={"Authorization": f"Bearer {desk.api_key}"},
        timeout=10.0,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def request_status(request_id: str) -> str:
    conn = db_connect()
    try:
        rows = conn.run("select status from disclosure_requests where id = :id", id=str(request_id))
        assert rows, f"no disclosure_requests row for {request_id}"
        return rows[0][0]
    finally:
        conn.close()


def used_nonce_count(org_id: str, nonce_b64url: str) -> int:
    import base64 as _b64

    nonce_bytes = _b64.urlsafe_b64decode(nonce_b64url + "==")
    conn = db_connect()
    try:
        rows = conn.run(
            "select count(*) from used_nonces where org_id = :oid and nonce = :nonce",
            oid=str(org_id),
            nonce=nonce_bytes,
        )
        return int(rows[0][0])
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Dedicated, disposable servers — for attacks that mutate on-disk server
# state (#5: verification keys, #6: the `bb` binary) or that need to observe
# a boot-time failure (#6a). Never the shared session server.
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ServerHandle:
    base_url: str
    process: subprocess.Popen
    vkeys_dir: Path
    port: int

    def output_tail(self, n: int = 4000) -> str:
        if self.process.stdout is None:
            return ""
        try:
            return self.process.stdout.read()[-n:]
        except Exception:  # pragma: no cover
            return ""

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self.process.kill()


@pytest.fixture()
def dedicated_server_factory(memtara_binary: Path, tmp_path_factory, request):
    """`boot(**kwargs) -> ServerHandle`. Every server this factory starts is
    torn down at the end of the test, whether or not the test itself already
    stopped it.
    """
    handles: list[ServerHandle] = []

    def boot(
        *,
        bb_bin: str = "bb",
        vkeys_dir: Optional[Path] = None,
        wait_healthy: bool = True,
        boot_timeout: float = 150.0,
        extra_env: Optional[dict] = None,
    ) -> ServerHandle:
        toolchain_or_skip()
        port = free_port()
        base_url = f"http://127.0.0.1:{port}"
        vkeys_dir = Path(vkeys_dir) if vkeys_dir is not None else tmp_path_factory.mktemp("break-it-vkeys")

        env = {
            **os.environ,
            "DATABASE_URL": DATABASE_URL,
            "BIND_ADDR": f"127.0.0.1:{port}",
            "MEMTARA_PRIVATE_KEY": TEST_PRIVATE_KEY_B64,
            "MEMTARA_ISSUER_BASE_URL": base_url,
            "RUST_LOG": "memtara_api=warn",
            "MEMTARA_PROOF_RATE_LIMIT": "10000",
            "BB_BIN": str(bb_bin),
            "VKEYS_DIR": str(vkeys_dir),
        }
        if extra_env:
            env.update(extra_env)

        process = subprocess.Popen(
            [str(memtara_binary)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        handle = ServerHandle(base_url=base_url, process=process, vkeys_dir=vkeys_dir, port=port)
        handles.append(handle)

        if not wait_healthy:
            return handle

        deadline = time.time() + boot_timeout
        while time.time() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"memtara-api exited during boot (code {process.returncode}) when it was "
                    f"expected to come up healthy:\n{handle.output_tail()}"
                )
            try:
                if httpx.get(f"{base_url}/healthz", timeout=1.0).status_code == 200:
                    break
            except Exception:
                time.sleep(0.3)
        else:  # pragma: no cover - environment-dependent
            process.terminate()
            raise RuntimeError(f"memtara-api did not become healthy within {boot_timeout}s")

        return handle

    yield boot

    for h in handles:
        h.stop()


def grep_backend(patterns: list[str], *, extra_paths: Optional[list[Path]] = None) -> dict[str, list[str]]:
    """Real, live `grep -rniE` over `backend/api/src` (plus any `extra_paths`,
    e.g. `backend/api/migrations`) for each pattern in `patterns`. Returns
    `{pattern: [matching "file:line:text", ...]}`, omitting patterns with no
    hits.

    Used by the BLOCKED attack tests (#4, #8, #10, #11) to verify — at the
    moment the suite actually runs, not from a stale assumption written into
    a docstring — that the capability they need is still missing before
    skipping. If a future change makes any pattern start matching, the
    calling test is written to FAIL loudly instead of continuing to skip;
    see each test module for why that matters more than it looks like it
    does.
    """
    search_roots = [BACKEND_DIR / "api" / "src"] + (extra_paths or [])
    hits: dict[str, list[str]] = {}
    for pattern in patterns:
        found: list[str] = []
        for root in search_roots:
            if not root.exists():
                continue
            result = subprocess.run(
                ["grep", "-rniE", "--include=*.rs", "--include=*.sql", pattern, str(root)],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                found.extend(result.stdout.strip().splitlines())
        if found:
            hits[pattern] = found
    return hits


def capture_path_hits(patterns: list[str]) -> dict[str, list[str]]:
    """The same live grep, restricted to the places where a capability can
    actually *capture* something: the migrations, and the route tables.

    This exists because of a real ambiguity the first version of these
    tripwires got wrong. On 19 Aug 2026 the `DecisionEvidence` v1 type
    landed with `model.*`, `human_review.*` and consent fields present as
    typed, explicitly-unpopulated placeholders. Grepping `backend/api/src`
    for `model_name` therefore started matching — and all four BLOCKED
    tripwires fired, reporting that the capability had arrived.

    It had not. A struct field with `state: "unpopulated"` cannot be
    attacked: there is no way to submit a model identity, so there is no
    way to swap one. What unblocks these attacks is a *capture path* — a
    migration that gives the value somewhere to live, or a route that lets
    a caller supply it. Nothing else changes what an attacker can reach.

    So the tripwire now has three outcomes rather than two, and the middle
    one is the honest description of where we are: the type exists, the
    capture path does not, the attack still cannot be run.
    """
    return grep_backend(
        patterns,
        extra_paths=[BACKEND_DIR / "api" / "migrations"],
    )


ROUTE_TABLE_PATTERNS = [r"\.route\(", r"\.nest\("]


def blocked_pending_capture(
    *,
    type_patterns: list[str],
    capture_patterns: list[str],
    capability: str,
    unblocked_by: str,
    real_attack: str,
) -> None:
    """Decide, at run time, which of three states a BLOCKED attack is in,
    and skip or fail accordingly. Never returns cleanly — a BLOCKED test
    must not be able to report a silent pass.

    - **capture path present** -> `pytest.fail`. The attack is now runnable
      and this placeholder owes a real implementation. A green skip here
      would be the single worst outcome in this suite: a bank reading the
      table would see a row that looks handled and is not.
    - **type present, capture path absent** -> `pytest.skip`, naming the
      type that landed, so nobody re-derives that half the work is done.
    - **neither** -> `pytest.skip`, the original state.
    """
    capture_hits = capture_path_hits(capture_patterns)
    if capture_hits:
        detail = "\n".join(
            f"  {pattern}: {lines[:3]}" for pattern, lines in capture_hits.items()
        )
        pytest.fail(
            f"TRIPWIRE: {capability} now has a capture path, so this attack is "
            f"runnable and this placeholder is out of date. Found:\n{detail}\n"
            f"Do not re-skip this test — implement the real attack: {real_attack}"
        )

    type_hits = grep_backend(type_patterns)
    if type_hits:
        pytest.skip(
            f"BLOCKED — {capability} exists as a type but has no capture path. "
            f"DecisionEvidence v1 carries the fields as explicitly-unpopulated "
            f"placeholders, which cannot be attacked: there is no way to submit "
            f"a value, so there is no way to tamper with one. Unblocked by: "
            f"{unblocked_by}."
        )

    pytest.skip(
        f"BLOCKED — {capability} does not exist anywhere in the backend. "
        f"Unblocked by: {unblocked_by}."
    )


@pytest.fixture()
def private_bb_copy(tmp_path_factory):
    """A standalone copy of the real `bb` binary this test can delete
    without harming the shared toolchain any other test (or the pre-existing
    suites) relies on. `bb` resolves its own CRS cache independently of
    argv[0]/its own directory (confirmed empirically: `bb --version` from the
    copy works with nothing else copied alongside it), so copying just the
    executable is sufficient.
    """
    real_bb = shutil.which("bb")
    if real_bb is None:
        pytest.skip("bb (Barretenberg) not on PATH")
    d = tmp_path_factory.mktemp("break-it-bb")
    copy_path = d / "bb"
    shutil.copy2(real_bb, copy_path)
    copy_path.chmod(0o755)
    return copy_path
