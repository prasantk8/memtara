#!/usr/bin/env bash
#
# quickstart.sh — from a fresh clone to a sealed Canonical Case File.
#
# Run it, wait, and a PDF opens. Everything in that PDF was produced by the
# real system: a real Baby Jubjub signature, a real Poseidon commitment, a real
# `bb prove`, a real `bb verify` inside the real server, and a real SHA-256
# audit chain. Nothing is stubbed and nothing is pre-recorded.
#
# -------------------------------------------------------------------------
# WHY THIS IS NOT `docker-compose up`
# -------------------------------------------------------------------------
# Because there is no container image yet, and shipping one that did not work
# would cost more trust than the convenience is worth. The honest reason: the
# proving path needs `nargo` and `bb`, and `bb` is a large native binary whose
# published builds are x86_64 Linux — inside a container on an Apple Silicon
# laptop it runs under emulation, and proof generation goes from seconds to
# minutes. A CTO who tries the five-minute quickstart and waits ten minutes
# concludes the product is slow, which is the wrong conclusion drawn from the
# right observation.
#
# So this script runs Memtara natively and puts only Postgres in a container,
# which is the one component where a container is unambiguously better. When a
# tested image exists this script will grow a `--docker` flag; until then the
# README says the same thing this comment does.
#
# -------------------------------------------------------------------------
# WHAT IT WILL TOUCH
# -------------------------------------------------------------------------
#   * a Docker container named `memtara-quickstart-db` (created only if no
#     Postgres is already listening on the port, and never removed by this
#     script)
#   * `.venv/` in this repository
#   * `circuits/target/` (compiled circuits)
#   * `backend/target/` (cargo build output)
#   * `cro_demo/` (the case file, its seal, and a demo vault)
#
# It does not delete anything, does not modify tracked files, and does not
# stop or remove a container it did not create. Toolchain installers are only
# ever run after you say yes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Pinned to the versions CI runs. An unpinned `noirup` will happily install a
# newer nargo whose ACIR the committed verification key does not match, and the
# only symptom is a proof that fails to verify.
NARGO_VERSION="1.0.0-beta.26"
BB_VERSION="5.1.0"

PG_CONTAINER="memtara-quickstart-db"
PG_PORT="${PGPORT_QUICKSTART:-5433}"
DATABASE_URL="${DATABASE_URL:-postgres://memtara:memtara@localhost:${PG_PORT}/memtara}"
export DATABASE_URL

ASSUME_YES=0
OPEN_PDF=1
for arg in "$@"; do
    case "$arg" in
        -y|--yes)    ASSUME_YES=1 ;;
        --no-open)   OPEN_PDF=0 ;;
        -h|--help)
            # Print the header block and stop at the first line that is not a
            # comment, rather than a hardcoded line range that silently starts
            # printing code the moment the header grows.
            awk 'NR>2 && /^#/ { sub(/^# ?/, ""); print; next } NR>2 { exit }' "$0"
            echo "Usage: scripts/quickstart.sh [-y|--yes] [--no-open]"
            echo "  -y, --yes    do not prompt before installing the Noir toolchain"
            echo "      --no-open  do not open the resulting PDF"
            exit 0
            ;;
        *) echo "unknown argument: $arg (try --help)" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

if [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; RED=$'\033[31m'
    YELLOW=$'\033[33m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; GREEN=""; RED=""; YELLOW=""; RESET=""
fi

step()  { printf '\n%s==>%s %s%s%s\n' "$BOLD" "$RESET" "$BOLD" "$1" "$RESET"; }
ok()    { printf '  %s+%s %s\n' "$GREEN" "$RESET" "$1"; }
info()  { printf '  %s%s%s\n' "$DIM" "$1" "$RESET"; }
warn()  { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$1"; }
die()   { printf '\n  %sx%s %s\n\n' "$RED" "$RESET" "$1" >&2; exit 1; }

confirm() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    [ -t 0 ] || die "$1 — rerun with --yes to allow this non-interactively"
    printf '  %s [y/N] ' "$1"
    read -r reply
    case "$reply" in [yY]*) return 0 ;; *) return 1 ;; esac
}

# ---------------------------------------------------------------------------
# 0. Where we are
# ---------------------------------------------------------------------------

printf '\n%sMemtara quickstart%s — a real zero-knowledge suitability proof, end to end.\n' "$BOLD" "$RESET"
info "repository: $REPO_ROOT"
info "database:   $DATABASE_URL"

[ -f circuits/Nargo.toml ] || die "this does not look like the memtara repository (no circuits/Nargo.toml)"

# ---------------------------------------------------------------------------
# 1. The AIHOOTS submodule
# ---------------------------------------------------------------------------
# Optional: without it the demo still produces a proof, a verified attestation
# and a sealed case file, and reports the two AIHOOTS steps as not performed.

step "AIHOOTS submodule"
if [ -f tests/aihoots_reference/src/gateway/main.py ]; then
    ok "present"
elif [ -d .git ] && command -v git >/dev/null 2>&1; then
    info "fetching (this is the audit gateway the proof gets chained into)"
    git submodule update --init --recursive tests/aihoots_reference \
        || warn "could not fetch it; the demo will skip the AIHOOTS steps"
    [ -f tests/aihoots_reference/src/gateway/main.py ] && ok "fetched"
else
    warn "absent, and this is not a git checkout; the demo will skip the AIHOOTS steps"
fi

# ---------------------------------------------------------------------------
# 2. Postgres
# ---------------------------------------------------------------------------
# Reuse anything already listening. Someone running this on a machine that
# already has a Memtara database has almost certainly got it set up correctly,
# and a script that starts a second one on a port it does not own is a script
# that breaks their afternoon.

step "Postgres on port $PG_PORT"
port_open() {
    if command -v nc >/dev/null 2>&1; then
        nc -z localhost "$PG_PORT" >/dev/null 2>&1
    else
        (exec 3<>"/dev/tcp/localhost/$PG_PORT") >/dev/null 2>&1
    fi
}

if port_open; then
    ok "something is already listening — using it"
elif command -v docker >/dev/null 2>&1; then
    if docker ps -a --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
        info "starting the existing $PG_CONTAINER container"
        docker start "$PG_CONTAINER" >/dev/null
    else
        info "starting postgres:15 as $PG_CONTAINER"
        docker run -d --name "$PG_CONTAINER" \
            -e POSTGRES_USER=memtara \
            -e POSTGRES_PASSWORD=memtara \
            -e POSTGRES_DB=memtara \
            -p "${PG_PORT}:5432" \
            postgres:15 >/dev/null
    fi
    printf '  waiting for it'
    for _ in $(seq 1 60); do
        if docker exec "$PG_CONTAINER" pg_isready -U memtara >/dev/null 2>&1; then
            printf '\n'; ok "ready"; break
        fi
        printf '.'; sleep 1
    done
    docker exec "$PG_CONTAINER" pg_isready -U memtara >/dev/null 2>&1 \
        || die "Postgres did not become ready; check: docker logs $PG_CONTAINER"
else
    die "no Postgres on port $PG_PORT and no Docker to start one.
     Start one yourself and set DATABASE_URL, e.g.
       docker run -d --name $PG_CONTAINER -e POSTGRES_USER=memtara \\
         -e POSTGRES_PASSWORD=memtara -e POSTGRES_DB=memtara \\
         -p ${PG_PORT}:5432 postgres:15"
fi

# ---------------------------------------------------------------------------
# 3. Rust
# ---------------------------------------------------------------------------

step "Rust toolchain"
if command -v cargo >/dev/null 2>&1; then
    ok "$(cargo --version)"
else
    die "cargo is not on PATH. Install it from https://rustup.rs and rerun this script.
     Deliberately not automated: rustup wants to modify your shell profile, and a
     quickstart script is not the right thing to be doing that on your behalf."
fi

# ---------------------------------------------------------------------------
# 4. The Noir toolchain
# ---------------------------------------------------------------------------
# The single most common failure on a working machine is that these are
# installed but not on a non-interactive PATH, because their installers write
# to the shell profile. Look in the default locations before concluding
# anything is missing.

step "Noir toolchain (nargo $NARGO_VERSION, bb $BB_VERSION)"
for dir in "$HOME/.nargo/bin" "$HOME/.bb"; do
    if [ -d "$dir" ] && ! printf '%s' ":$PATH:" | grep -q ":$dir:"; then
        PATH="$dir:$PATH"
        info "added $dir to PATH for this run"
    fi
done
export PATH

install_noir() {
    command -v curl >/dev/null 2>&1 || die "curl is needed to install the Noir toolchain"
    info "installing noirup and nargo $NARGO_VERSION"
    curl -fsSL https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
    "$HOME/.nargo/bin/noirup" --version "$NARGO_VERSION"
    info "installing bbup and bb $BB_VERSION"
    curl -fsSL https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
    "$HOME/.bb/bbup" --version "$BB_VERSION"
    PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"
    export PATH
}

if command -v nargo >/dev/null 2>&1 && command -v bb >/dev/null 2>&1; then
    ok "nargo $(nargo --version 2>/dev/null | head -1 | sed 's/.*= //')"
    ok "bb $(bb --version 2>/dev/null | head -1)"
    installed_nargo="$(nargo --version 2>/dev/null | head -1 | sed 's/.*= //')"
    if [ "$installed_nargo" != "$NARGO_VERSION" ]; then
        warn "this repository is verified against nargo $NARGO_VERSION."
        warn "a different version can compile to different ACIR, and the only symptom"
        warn "is a proof that fails to verify against the committed key."
    fi
else
    warn "not found. The installers below are piped from the internet into a shell,"
    warn "which is how upstream distributes them and is worth reading before you agree:"
    info "  https://raw.githubusercontent.com/noir-lang/noirup/main/install"
    info "  https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install"
    if confirm "Install the Noir toolchain now?"; then
        install_noir
    else
        die "install nargo and bb yourself, then rerun. See README.md > Prerequisites."
    fi
fi

# ---------------------------------------------------------------------------
# 5. Compile the circuits
# ---------------------------------------------------------------------------

step "Circuits"
if [ -f circuits/target/wealth_suitability.json ]; then
    ok "already compiled"
else
    info "nargo compile --workspace (about a minute the first time)"
    (cd circuits && nargo compile --workspace --skip-brillig-constraints-check)
    [ -f circuits/target/wealth_suitability.json ] || die "compilation produced no wealth_suitability.json"
    ok "compiled"
fi

# ---------------------------------------------------------------------------
# 6. Python
# ---------------------------------------------------------------------------
# Only the demo harness and the exporter need this. The prover's cryptography
# has no Python dependencies at all — deliberately, so that nothing in a
# requirements file can disagree with the verifier.

step "Python environment"
PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 || die "python3 is not on PATH"
if [ ! -x .venv/bin/python ]; then
    info "creating .venv"
    "$PYTHON" -m venv .venv
fi
info "installing test and demo dependencies"
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements-dev.txt
ok "$(.venv/bin/python --version)"

# ---------------------------------------------------------------------------
# 7. The demo
# ---------------------------------------------------------------------------

step "Running the CRO demo"
info "builds the server, boots it, registers a bank and a product, onboards a"
info "client, generates a real proof, verifies it, chains it, and exports a PDF"
echo

.venv/bin/python scripts/demo_cro_workflow.py --output-dir ./cro_demo

# ---------------------------------------------------------------------------
# 8. Open it
# ---------------------------------------------------------------------------

step "The Canonical Case File"
CASE_FILE="$(ls -t cro_demo/Case_File_*.pdf 2>/dev/null | head -1 || true)"
[ -n "$CASE_FILE" ] || die "the demo exited 0 but produced no Case_File_*.pdf in ./cro_demo"

ok "$CASE_FILE ($(wc -c < "$CASE_FILE" | tr -d ' ') bytes)"
info "verify its seal at any time with:"
info "  ./scripts/memtara-export verify $CASE_FILE"

# Prove the seal works rather than asserting it does. This is the claim a
# compliance buyer cares about most, and it costs a second to demonstrate.
if ./scripts/memtara-export verify "$CASE_FILE" >/dev/null 2>&1; then
    ok "seal verified — the file matches the digest recorded at export time"
else
    warn "seal verification failed; report this, it should not happen"
fi

if [ "$OPEN_PDF" -eq 1 ]; then
    if command -v open >/dev/null 2>&1; then
        open "$CASE_FILE" || true
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$CASE_FILE" >/dev/null 2>&1 || true
    else
        info "no default viewer found; open it yourself"
    fi
fi

cat <<EOF

${BOLD}What just happened${RESET}
  A synthetic client's device proved, against terms the bank registered in
  advance, that four private figures each cleared the product's thresholds.
  The figures never left the device. The bank holds a proof, a signed
  attestation, a hash-chained audit entry, and the PDF you are looking at.

${BOLD}Where to look next${RESET}
  docs/SALES_LANDING_PAGE.md      what this is, in one page
  docs/REGULATORY_MATRIX.md       the clause mapping, with the gaps named first
  README.md > Honest limits       what it does not do
  clients/prover/README.md        putting the prover in your own app

${BOLD}Talk to us${RESET}
  A pilot is 12 weeks. See docs/PILOT_AGREEMENT_TEMPLATE.md and
  docs/PRICING_MODEL.md, then run scripts/roi_calculator.py with your numbers.

EOF
