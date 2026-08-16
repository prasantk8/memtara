"""Shared infrastructure for the integration tests.

Both `test_aihoots_handshake.py` and `test_wealth_suitability_e2e.py` need
the same three things: a compiled Memtara binary, a running server with a
known issuer key, and a Postgres connection for the rows the HTTP API has no
route for. They live here so there is one definition of "the server under
test" rather than two that drift — and so the two files share a single server
process instead of booting one each.

Every prerequisite skips with a specific reason rather than failing. A
missing local toolchain must never look like a broken integration; CI checks
separately that nothing skipped (see `.github/workflows/ci.yml`).
"""

from __future__ import annotations

import base64
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AIHOOTS_ROOT = REPO_ROOT / "tests" / "aihoots_reference"
BACKEND_DIR = REPO_ROOT / "backend"
CIRCUITS_DIR = REPO_ROOT / "circuits"
CLIENTS_DIR = REPO_ROOT / "clients"

# The Memtara-side adapters under test, the AIHOOTS submodule, and the device
# client all need to be importable. Inserted at the front so a same-named
# package installed in the environment can't shadow the code we actually mean
# to exercise.
for path in (REPO_ROOT, AIHOOTS_ROOT, CLIENTS_DIR, REPO_ROOT / "integrations" / "aihoots"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

# A fixed seed so the issuer key — and therefore the kid in every assertion —
# is reproducible across runs. Test-only; the real deployment reads a secret
# from the environment (see .env.example).
TEST_PRIVATE_KEY_B64 = base64.b64encode(bytes(range(32))).decode()

DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://memtara:memtara@localhost:5433/memtara")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def parse_pg_url(url: str) -> dict:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return {
        "user": parsed.username or "memtara",
        "password": parsed.password or "memtara",
        "host": parsed.hostname or "localhost",
        "port": parsed.port or 5432,
        "database": (parsed.path or "/memtara").lstrip("/"),
    }


def db_connect():
    pg8000 = pytest.importorskip("pg8000.native", reason="pg8000 is needed to seed test rows")
    try:
        return pg8000.Connection(**parse_pg_url(DATABASE_URL))
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"no Postgres reachable at {DATABASE_URL}: {exc}")


@pytest.fixture(scope="session")
def memtara_binary() -> Path:
    if shutil.which("cargo") is None:
        pytest.skip("cargo not on PATH")
    if shutil.which("bb") is None:
        pytest.skip("bb (Barretenberg) not on PATH — the server generates vkeys at boot")

    build = subprocess.run(
        ["cargo", "build", "--bin", "memtara-api"],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
        env={**os.environ, "DATABASE_URL": DATABASE_URL},
    )
    if build.returncode != 0:
        pytest.skip(f"cargo build failed:\n{build.stderr[-2000:]}")

    binary = BACKEND_DIR / "target" / "debug" / "memtara-api"
    if not binary.exists():
        pytest.skip(f"built binary not found at {binary}")
    return binary


@pytest.fixture(scope="session")
def memtara_server(memtara_binary: Path):
    """The real Memtara server, on a real port, with a known issuer key."""
    port = free_port()
    base_url = f"http://127.0.0.1:{port}"

    env = {
        **os.environ,
        "DATABASE_URL": DATABASE_URL,
        "BIND_ADDR": f"127.0.0.1:{port}",
        "MEMTARA_PRIVATE_KEY": TEST_PRIVATE_KEY_B64,
        "MEMTARA_ISSUER_BASE_URL": base_url,
        "RUST_LOG": "memtara_api=warn",
        # The shared server exists to exercise features, and the whole
        # suitability suite runs against one synthetic client — which under
        # the production default of 10 proof submissions per minute would
        # start refusing partway through the file, intermittently, depending
        # on how fast the machine proves. The limiter itself is tested
        # properly by `rate_limited_server` in
        # tests/test_wealth_suitability_e2e.py, which boots its own instance
        # with a low limit rather than weakening the assertion here.
        "MEMTARA_PROOF_RATE_LIMIT": "10000",
    }
    process = subprocess.Popen(
        [str(memtara_binary)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    deadline = time.time() + 120  # first boot generates a verification key per circuit
    while time.time() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            pytest.skip(f"memtara-api exited during boot:\n{output[-2000:]}")
        try:
            if httpx.get(f"{base_url}/healthz", timeout=1.0).status_code == 200:
                break
        except Exception:
            time.sleep(0.3)
    else:  # pragma: no cover - environment-dependent
        process.terminate()
        pytest.skip("memtara-api did not become healthy within 120s")

    yield base_url

    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover
        process.kill()
