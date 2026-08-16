"""``memtara-prove`` — generate a structured-product suitability proof on the
holder's device and submit it.

-------------------------------------------------------------------
TWO DEPLOYMENTS, AND WHY THE DIFFERENCE MATTERS
-------------------------------------------------------------------
This one binary covers two situations that look similar and are not:

  ADVISOR TERMINAL     A machine inside the bank, holding an org API key.
                       It can open an assessment (`--org-api-key`) and then
                       answer it, because in that setting the same operator
                       legitimately does both.

  HOLDER'S DEVICE      A phone. It must NEVER hold an org API key — that key
                       can open assessments against every one of the bank's
                       users. It receives a `request_id` out of band (a push
                       notification), answers it with the holder's own
                       session token, and never speaks to the bank's side of
                       the API at all. That is `--request-id`.

Running the full journey from one command is convenient for a demo and for
CI. It is not the shape a production mobile client should copy, and the
mode-selection code below says so where it matters.

-------------------------------------------------------------------
WHERE THE TERMS COME FROM
-------------------------------------------------------------------
The brief this was built from says the CLI should fetch product thresholds
from `GET /api/v1/products/{isin}` and prove against them. It does fetch
them — for display, so a holder can see what they are about to be measured
against before consenting. But it does not prove against them.

The values a proof commits to are the ones returned by
`POST /api/v1/issue-wealth-request`, fixed server-side, and the server
re-checks every one of them at submission. If the CLI took its thresholds
from a separate GET and the two ever disagreed — a product amended between
the two calls, a stale cache, a middlebox — the proof would simply fail to
verify, and the holder would be told their assessment was invalid with no
way to see why. One source, and it is the one the verifier will check
against.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import wealth_client as wc  # noqa: E402

from . import vault as vaultlib  # noqa: E402

DEFAULT_BASE_URL = "http://127.0.0.1:8080"


class UsageError(RuntimeError):
    """A problem with what the operator asked for, not with the system."""


#: Exit code for "the assessment ran and the answer was no".
#:
#: Three, not two, because argparse already uses 2 for a usage error — and an
#: embedder that could not tell "you invoked me wrongly" from "your client is
#: unsuitable" would eventually report one as the other. A decline is a
#: successful run: it produces signed, chained evidence, which is the entire
#: reason the circuit publishes its verdict rather than asserting it.
EXIT_NOT_SUITABLE = 3


# ---------------------------------------------------------------------------
# Output
#
# Two modes. Humans get progress on stderr and a readable summary on stdout;
# `--json` gets one machine-readable object on stdout and nothing else there,
# so the command composes in a pipeline. Progress always goes to stderr so
# `--json` output is never polluted by it.
# ---------------------------------------------------------------------------


class Console:
    def __init__(self, *, json_mode: bool, quiet: bool) -> None:
        self.json_mode = json_mode
        self.quiet = quiet

    def step(self, message: str) -> None:
        if not self.quiet:
            print(message, file=sys.stderr, flush=True)

    def out(self, text: str) -> None:
        if not self.json_mode:
            print(text)

    def emit(self, payload: dict) -> None:
        if self.json_mode:
            json.dump(payload, sys.stdout, indent=2, sort_keys=True, default=str)
            sys.stdout.write("\n")


def _money(value: int) -> str:
    return f"{value:,} AED"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init_vault(args: argparse.Namespace, console: Console) -> int:
    loaded = vaultlib.create(
        Path(args.vault_path),
        income=args.income,
        liquid_assets=args.liquid_assets,
        risk_tolerance=args.risk_tolerance,
        existing_holdings_value=args.existing_holdings_value,
        user_id=args.user_id,
        seed=args.seed,
        overwrite=args.overwrite,
    )
    if args.seed is not None:
        console.step(
            "warning: --seed makes this vault's signing key reproducible. Fine for a demo, "
            "never for a vault protecting a real person's figures."
        )
    x, y = loaded.keypair.public
    console.out(f"vault written to {loaded.path} (mode 0600)")
    console.out("")
    console.out("Baby Jubjub public key — give this to the bank so it can be bound to your account:")
    console.out(f"  x = {x}")
    console.out(f"  y = {y}")
    console.emit({"vault_path": str(loaded.path), "public_key": {"x": str(x), "y": str(y)}, "user_id": loaded.user_id})
    return 0


def cmd_vault_root(args: argparse.Namespace, console: Console) -> int:
    """Compute the Merkle root the server must have on record.

    The server pins `vault_root` at submission: a proof whose root does not
    match what this user synced is refused, because otherwise the circuit's
    Merkle limb only proves the figures are consistent with *some* tree, and a
    client can build one of those to order. So the root has to be registered
    before a proof will be accepted, and this is how a device reports it.
    """
    loaded = vaultlib.load(Path(args.vault_path), allow_insecure_permissions=args.allow_insecure_permissions)
    reason = wc.missing_toolchain_reason(nargo=args.nargo, bb=args.bb)
    if reason:
        # The root is a Poseidon Merkle root, computed by the circuits' own
        # library through `circuits/witness_oracle` rather than by a second
        # Poseidon implementation here. That is a deliberate trade (see that
        # circuit's header) and its cost is exactly this: no nargo, no root.
        raise UsageError(f"cannot compute the vault root here: {reason}")
    oracle = wc.NargoOracle(nargo=args.nargo)
    root, _paths = oracle.merkle(loaded.wealth.leaves())
    console.out(f"vault_root = 0x{root:064x}")
    console.emit({"vault_root": f"0x{root:064x}", "vault_root_decimal": str(root)})
    return 0


def cmd_prove(args: argparse.Namespace, console: Console) -> int:
    reason = wc.missing_toolchain_reason(nargo=args.nargo, bb=args.bb)
    if reason:
        raise UsageError(
            f"cannot generate a proof here: {reason}. This command runs the real Noir and "
            f"Barretenberg toolchain — there is no software fallback, because a fallback would "
            f"mean producing something that is not a proof."
        )

    loaded = vaultlib.load(Path(args.vault_path), allow_insecure_permissions=args.allow_insecure_permissions)

    org_key = args.org_api_key or os.environ.get("MEMTARA_ORG_API_KEY")
    session = args.session_token or os.environ.get("MEMTARA_SESSION_TOKEN")

    if args.request_id:
        request = _resume_request(args, console)
    else:
        if not org_key:
            raise UsageError(
                "opening a new assessment needs an org API key (--org-api-key or "
                "MEMTARA_ORG_API_KEY). A holder's device should not have one: answer an "
                "assessment the bank already opened, with --request-id and --session-token."
            )
        user_id = args.user_id or loaded.user_id
        if not user_id:
            raise UsageError("--user-id is required (or store one in the vault with init-vault --user-id)")
        request = _open_request(args, console, org_key, user_id)

    _print_terms(request, console)

    # The submission credential. A session token is the right answer — the
    # proof is the holder's statement about the holder's figures. Falling back
    # to the org key is permitted by the server (`authorize_org_or_user`) and
    # is what an advisor terminal running the whole journey actually has, so
    # it works, but it is worth being loud about which one was used: the
    # audit trail cannot tell them apart afterwards.
    credential = session or org_key
    if not credential:
        raise UsageError("no credential to submit with: pass --session-token (or --org-api-key)")
    if not session:
        console.step("note: submitting with the org API key, not a holder session token")

    console.step("generating proof — real nargo execute + bb prove, this takes a few seconds…")
    proof = wc.generate_proof(
        request,
        loaded.wealth,
        oracle=wc.NargoOracle(nargo=args.nargo),
        nargo=args.nargo,
        bb=args.bb,
    )

    # Cross-check against an independent Python evaluation of the same four
    # limbs before sending anything. If these disagree, one of the circuit and
    # `WealthVault.expected_verdict` is wrong, and finding that out here — on
    # the device, before a signed attestation exists — is far better than
    # discovering it in a compliance review.
    expected = loaded.wealth.expected_verdict(
        min_income=int(request["min_income"]),
        min_liquidity=int(request["min_liquidity"]),
        max_concentration_percent=int(request["max_concentration_percent"]),
        product_risk_level=int(request["product_risk_level"]),
    )
    if expected != proof.suitable:
        raise RuntimeError(
            f"the circuit answered {proof.suitable} but an independent evaluation of the same "
            f"terms answered {expected}. Refusing to submit. This is a bug in either "
            f"circuits/wealth_suitability or clients/wealth_client.WealthVault.expected_verdict, "
            f"and it must be resolved before any proof from this device is trusted."
        )

    console.step(f"proof generated ({len(proof.proof_b64)} b64 chars); submitting…")

    if args.dry_run:
        # Everything except the submission. Useful for confirming a device can
        # prove at all without consuming the assessment's one-shot nonce.
        console.out("--dry-run: proof generated and NOT submitted; the request is still open.")
        console.emit(
            {
                "dry_run": True,
                "request_id": request["request_id"],
                "suitable": proof.suitable,
                "vault_root": f"0x{proof.vault_root:064x}",
                "public_inputs": proof.public_inputs,
            }
        )
        return 0

    result = wc.submit_assessment(args.base_url, credential, request["request_id"], proof)

    verdict = "SUITABLE" if result["suitable"] else "NOT SUITABLE"
    console.out("")
    console.out(f"  Assessment: {verdict}")
    console.out(f"  Product:    {request.get('product_name') or ''} ({result['product_isin']})")
    console.out(f"  Audit id:   {result['regulatory_audit_id']}")
    console.out(f"  Expires in: {result['expires_in']}s")
    console.out("")
    console.out("proof_token (JWT — verify it against the issuer's published JWKS):")
    console.out(result["proof_token"])

    console.emit(
        {
            "request_id": request["request_id"],
            "product_isin": result["product_isin"],
            "product_name": request.get("product_name"),
            "suitable": result["suitable"],
            "proof_token": result["proof_token"],
            "expires_in": result["expires_in"],
            "regulatory_audit_id": result["regulatory_audit_id"],
            "vault_root": f"0x{proof.vault_root:064x}",
        }
    )
    return 0 if result["suitable"] else EXIT_NOT_SUITABLE


def _open_request(args: argparse.Namespace, console: Console, org_key: str, user_id: str) -> dict:
    if args.show_product:
        # Display only. See the module header for why this is not the source
        # of the terms proved against.
        try:
            product = wc.get_product(args.base_url, org_key, args.product_isin)
            console.step(
                f"registry: {product['product_name']} — risk level {product['risk_level']}, "
                f"approved_by_risk_committee={product['approved_by_risk_committee']}"
            )
            if not product["check_digit_valid"]:
                console.step(f"note: {args.product_isin} fails its ISO 6166 check digit (accepted, recorded)")
        except wc.MemtaraApiError as exc:
            console.step(f"note: could not read the registry entry for display ({exc}); continuing")

    console.step(f"opening assessment for {user_id} against {args.product_isin}…")
    return wc.open_assessment(
        args.base_url,
        org_key,
        user_id=user_id,
        product_isin=args.product_isin,
        ttl_seconds=args.ttl_seconds,
    )


def _resume_request(args: argparse.Namespace, console: Console) -> dict:
    """Answer an assessment somebody else opened.

    The device is handed only a `request_id`, so everything the prover needs —
    the terms, the nonce, the product reference, the window — has to come back
    from the server. That is what `GET /api/v1/wealth-assessments/{id}` is
    for, but it is org-scoped, and a phone has no org key.

    So this path requires `--request-file`: the JSON body the bank received
    from `issue-wealth-request`, handed to the device alongside the
    notification. It is not secret — every value in it is a public input the
    proof will publish anyway — and it means the device needs exactly one
    credential (the holder's own session token) and no read access to the
    bank's side of the API.
    """
    if not args.request_file:
        raise UsageError(
            "--request-id needs --request-file: the issue-wealth-request response, which carries "
            "the nonce, the terms and the product reference the proof must commit to. A device "
            "cannot read those back from the API, because that endpoint is org-scoped and a "
            "device must not hold an org key."
        )
    request = json.loads(Path(args.request_file).read_text(encoding="utf-8"))
    if request.get("request_id") != args.request_id:
        raise UsageError(
            f"--request-id {args.request_id} does not match the request in {args.request_file} "
            f"({request.get('request_id')})"
        )
    console.step(f"answering assessment {args.request_id} opened by the bank")
    return request


def _print_terms(request: dict, console: Console) -> None:
    console.step(
        "terms fixed by the server: "
        f"income >= {_money(int(request['min_income']))}, "
        f"liquid >= {_money(int(request['min_liquidity']))}, "
        f"concentration <= {request['max_concentration_percent']}%, "
        f"risk tolerance >= {request['product_risk_level']}"
    )


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memtara-prove",
        description=(
            "Generate and submit a zero-knowledge structured-product suitability proof. "
            "The four figures never leave this machine; the bank receives one bit and a proof."
        ),
    )
    parser.add_argument("--base-url", default=os.environ.get("MEMTARA_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--json", dest="json_mode", action="store_true", help="machine-readable output on stdout")
    parser.add_argument("--quiet", action="store_true", help="suppress progress on stderr")
    parser.add_argument("--nargo", default=os.environ.get("NARGO_BIN", "nargo"))
    parser.add_argument("--bb", default=os.environ.get("BB_BIN", "bb"))
    parser.add_argument(
        "--allow-insecure-permissions",
        action="store_true",
        help="load a vault whose file mode is readable beyond its owner (test data only)",
    )

    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init-vault", help="create a local vault with a fresh signing key")
    init.add_argument("--vault-path", required=True)
    init.add_argument("--income", type=int, required=True)
    init.add_argument("--liquid-assets", type=int, required=True)
    init.add_argument("--risk-tolerance", type=int, required=True, help="1-5")
    init.add_argument("--existing-holdings-value", type=int, default=0)
    init.add_argument("--user-id", default=None)
    init.add_argument("--seed", type=int, default=None, help="reproducible key — demos and tests only")
    init.add_argument("--overwrite", action="store_true")
    init.set_defaults(func=cmd_init_vault)

    root = sub.add_parser("vault-root", help="print the Merkle root the bank must have on record")
    root.add_argument("--vault-path", required=True)
    root.set_defaults(func=cmd_vault_root)

    prove = sub.add_parser("prove", help="run an assessment (the default command)")
    _add_prove_arguments(prove)
    prove.set_defaults(func=cmd_prove)

    # The brief's invocation is `memtara-prove --user-id ... --product-isin
    # ... --vault-path ...` with no subcommand. Accepting both shapes rather
    # than picking one: the bare form is what anyone reading the
    # documentation will type first, and failing on it with "invalid choice"
    # would be a poor first impression of a tool whose whole job is to be
    # embedded by someone else.
    _add_prove_arguments(parser)
    return parser


def _add_prove_arguments(target: argparse.ArgumentParser) -> None:
    target.add_argument("--vault-path")
    target.add_argument("--user-id")
    target.add_argument("--product-isin")
    target.add_argument("--org-api-key", default=None, help="advisor terminal only; never on a holder's device")
    target.add_argument("--session-token", default=None, help="the holder's own credential")
    target.add_argument("--request-id", default=None, help="answer an assessment the bank already opened")
    target.add_argument("--request-file", default=None, help="the issue-wealth-request response, as JSON")
    target.add_argument("--ttl-seconds", type=int, default=900)
    target.add_argument("--show-product", action="store_true", help="display the registry entry before proving")
    target.add_argument("--dry-run", action="store_true", help="generate a proof but do not submit it")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(json_mode=args.json_mode, quiet=args.quiet)

    func = getattr(args, "func", None)
    if func is None:
        if not args.vault_path:
            parser.print_help(sys.stderr)
            return 1
        func = cmd_prove

    if func is cmd_prove:
        if not args.vault_path:
            raise SystemExit("--vault-path is required")
        if not args.request_id and not args.product_isin:
            raise SystemExit("--product-isin is required when opening a new assessment")

    try:
        return func(args, console)
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except vaultlib.VaultError as exc:
        print(f"vault error: {exc}", file=sys.stderr)
        return 1
    except wc.MemtaraApiError as exc:
        print(f"Memtara API error: {exc}", file=sys.stderr)
        return 1
    except (wc.ProvingError, wc.OracleError) as exc:
        print(f"proving error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        # Covers `urllib.error.URLError`, which is an OSError subclass: a
        # refused connection or an unresolvable host. Left uncaught it prints
        # a forty-line traceback in which the useful sentence is the last one,
        # and an embedder capturing stderr gets all of it.
        print(f"cannot reach Memtara at {args.base_url}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
