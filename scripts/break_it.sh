#!/usr/bin/env bash
#
# "Break it" — run every adversarial attack against the real system and print
# one honest table.
#
# The board's instruction was to stop running happy-path demos: "Does the
# system stop?" is more persuasive to a regulated buyer than a working demo.
# So this script is written to be shown to a bank, which means a BLOCKED row
# must never be able to look like a passing one. If you change the formatting
# below, keep that property.
#
# Each attack module runs as its OWN pytest invocation, not as one session.
# That is deliberate: attacks #5 and #6 mutate on-disk server state (they
# substitute a verification key, and they remove the proof binary) and would
# otherwise corrupt the shared session-scoped server other attacks rely on —
# producing a self-inflicted failure that looks like a finding and is not.
# See tests/break_it/conftest.py for the full reasoning.
#
# Outcomes:
#   STOPPED      the test passed — the attack was attempted and refused
#   NOT STOPPED  the test failed — the attack got through. A finding.
#   BLOCKED      skipped — the capability being attacked does not exist yet,
#                so the attack cannot be run at all. The reason is printed.
#
# Exit status is 1 if anything is NOT STOPPED, 0 otherwise. BLOCKED does not
# fail the run: it is an accurate report of where we are, and hiding it would
# defeat the point of the exercise.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

# bb and nargo are installed under $HOME but are not on the default PATH on
# the founder's machine. Without them attacks #1-#7 skip for a toolchain
# reason rather than a product reason, which would misreport the system as
# less tested than it is.
export PATH="$HOME/.bb:$HOME/.nargo/bin:$HOME/.cargo/bin:$PATH"

# sqlx checks its queries at compile time, so the server the attacks run
# against cannot even be built without a reachable database. Without this the
# whole table reports BLOCKED for a toolchain reason, which reads as "we have
# not tested any of this" when the truth is "the runner was misconfigured".
export DATABASE_URL="${DATABASE_URL:-postgres://memtara:memtara@localhost:5433/memtara}"

PYTHON="${PYTHON:-$REPO_ROOT/.venv/bin/python}"
if [ ! -x "$PYTHON" ]; then
  PYTHON="$(command -v python3)"
fi
if [ -z "$PYTHON" ]; then
  echo "no python interpreter found; set PYTHON=/path/to/python" >&2
  exit 2
fi

ATTACK_DIR="tests/break_it"
if [ ! -d "$ATTACK_DIR" ]; then
  echo "no $ATTACK_DIR directory" >&2
  exit 2
fi

echo
echo "BREAK-IT RUN — $(date -u '+%Y-%m-%d %H:%M:%SZ')"
echo "bb:    $(bb --version 2>/dev/null || echo 'NOT ON PATH')"
echo "nargo: $(nargo --version 2>/dev/null | head -1 || echo 'NOT ON PATH')"
echo

RESULTS_FILE="$(mktemp -t break_it_results)"
trap 'rm -f "$RESULTS_FILE"' EXIT

for module in $(ls "$ATTACK_DIR"/test_attack_*.py | sort); do
  name="$(basename "$module")"

  title="$("$PYTHON" - "$module" <<'PY'
import ast, sys
tree = ast.parse(open(sys.argv[1]).read())
found = {}
for node in tree.body:
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id.startswith("BREAK_IT_"):
                try:
                    found[t.id] = ast.literal_eval(node.value)
                except Exception:
                    pass
print("%s\t%s\t%s\t%s" % (found.get("BREAK_IT_ATTACK_NUMBER", "?"),
                          found.get("BREAK_IT_ATTACK_TITLE", "(untitled)"),
                          " ".join(str(found.get("BREAK_IT_NOTE", "")).split()),
                          found.get("BREAK_IT_STATUS_ON_PASS", "STOPPED")))
PY
)"
  number="$(echo "$title" | cut -f1)"
  label="$(echo "$title" | cut -f2)"
  module_note="$(echo "$title" | cut -f3)"
  status_on_pass="$(echo "$title" | cut -f4)"

  output="$("$PYTHON" -m pytest "$module" -q -rs -p no:warnings 2>&1)"
  status=$?

  # A build or toolchain failure must NEVER be reported as BLOCKED. BLOCKED
  # is a claim about the product — "the capability under attack does not
  # exist yet" — and a broken compiler is not a fact about the product. Left
  # merged, a tree that simply did not build would print a table full of
  # calm-looking rows, which is precisely the dishonesty this harness exists
  # to prevent. COULD NOT RUN is its own state and fails the run.
  if echo "$output" | grep -qE "cargo build failed|error: could not compile|no such file or directory|not on PATH|could not connect|Connection refused"; then
    verdict="COULD NOT RUN"
    reason="$(echo "$output" | grep -iE "cargo build failed|could not compile|not on PATH|could not connect|Connection refused" | head -1 | cut -c1-160)"
  elif echo "$output" | grep -q "^[0-9]* passed"; then
    # A passing test does NOT mean the system stopped the attack. It means the
    # module's assertions held — and some modules assert, correctly and
    # deliberately, that an attack SUCCEEDS. Attack #3 is one: it verifies that
    # the request-time policy snapshot carries no version marker and that a
    # direct tamper of it is caught by nothing, since the `policy` column is
    # never folded into any audit event's hashed payload. That test passes, and
    # the system did not stop the attack.
    #
    # So each module declares BREAK_IT_STATUS_ON_PASS and this runner honours
    # it. It did not, until now: every module carried the constant and the
    # script ignored it, which meant a verified, documented vulnerability
    # printed as STOPPED in a table meant for a bank. That is precisely the
    # false green this whole harness exists to prevent, and it was in the
    # harness itself.
    verdict="${status_on_pass:-STOPPED}"
    # A STOPPED row still carries its module's note. Attack #7 is the reason:
    # the chain-head checkpoint closes it, but only for records the checkpoint
    # covers — there is a residual window of up to 65 seconds during which the
    # newest record is protected by nothing. A bare "STOPPED" in a table shown
    # to a bank would overstate that guarantee, and the caveat would survive
    # only in someone's memory. It travels with the row instead.
    reason="$module_note"
  elif echo "$output" | grep -qE "^SKIPPED|s +\[" || echo "$output" | grep -q "skipped"; then
    verdict="BLOCKED"
    # pytest -rs prints "SKIPPED [1] path:line: <reason>"
    reason="$(echo "$output" | sed -n 's/^SKIPPED \[[0-9]*\] [^:]*:[0-9]*: //p' | head -1)"
    [ -z "$reason" ] && reason="skipped, reason not reported"
  else
    verdict="NOT STOPPED"
    reason="$(echo "$output" | grep -E "^(FAILED|E )" | head -1)"
  fi

  printf '%s\t%s\t%s\t%s\n' "$number" "$label" "$verdict" "$reason" >> "$RESULTS_FILE"
done

# The results file is passed by path, not piped: `python -` already takes its
# script from stdin, so a heredoc and a pipe cannot both feed this process.
"$PYTHON" - "$RESULTS_FILE" <<'PY'
import sys, textwrap

rows = []
for line in sorted(open(sys.argv[1]), key=lambda l: int(l.split("\t")[0]) if l.split("\t")[0].isdigit() else 99):
    parts = line.rstrip("\n").split("\t")
    while len(parts) < 4:
        parts.append("")
    rows.append(parts[:4])

num_w = max([len(r[0]) for r in rows] + [1])
title_w = max([len(r[1]) for r in rows] + [len("ATTACK")])
verdict_w = len("COULD NOT RUN")

sep = "  "
header = f"{'#':>{num_w}}{sep}{'ATTACK':<{title_w}}{sep}{'RESULT':<{verdict_w}}"
print(header)
print("-" * len(header))

counts = {"STOPPED": 0, "NOT STOPPED": 0, "BLOCKED": 0, "COULD NOT RUN": 0}
for num, title, verdict, reason in rows:
    counts[verdict] = counts.get(verdict, 0) + 1
    print(f"{num:>{num_w}}{sep}{title:<{title_w}}{sep}{verdict:<{verdict_w}}")
    if reason:
        indent = " " * (num_w + len(sep))
        for wrapped in textwrap.wrap(reason, width=92):
            print(f"{indent}{wrapped}")

print("-" * len(header))
summary = (f"{counts.get('STOPPED', 0)} stopped   "
           f"{counts.get('NOT STOPPED', 0)} not stopped   "
           f"{counts.get('BLOCKED', 0)} blocked")
if counts.get("COULD NOT RUN", 0):
    summary += f"   {counts['COULD NOT RUN']} could not run"
print(summary)
print()
print("BLOCKED means the capability under attack does not exist yet, so the")
print("attack cannot be run. It is not a pass. Each blocked row names what")
print("would unblock it.")
if counts.get("COULD NOT RUN", 0):
    print()
    print("COULD NOT RUN means the harness itself failed — the tree did not")
    print("build, a tool was missing, or the database was unreachable. It says")
    print("NOTHING about the product, and this run proves less than a clean one.")

sys.exit(1 if (counts.get("NOT STOPPED", 0) or counts.get("COULD NOT RUN", 0)) else 0)
PY
