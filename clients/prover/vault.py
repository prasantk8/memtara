"""The on-device vault file.

What this file holds is the whole reason the server cannot do the client's
job: four plaintext figures and the key that authorises saying anything about
them. Everything else in Memtara is designed so that this file never leaves
the device it was created on.

-------------------------------------------------------------------
THIS IS NOT WHAT A SHIPPING PRODUCT USES
-------------------------------------------------------------------
A JSON file on disk is the right shape for an advisor terminal, a CI run and
a demonstration, and the wrong shape for a phone. In the mobile app the
signing key belongs in the Secure Enclave / Android Keystore, where it can be
used but not exported, and the figures belong in the encrypted vault that
`vault/` (the Rust crate) already implements. The format here deliberately
mirrors that structure — a key, and a category of figures — so the port is a
substitution rather than a redesign.

Because it is plaintext, this module refuses to load a vault whose file mode
is readable by anyone but its owner. That check is cheap, it catches the
single most likely real mistake (a vault committed to a repository or dropped
in /tmp), and a warning nobody reads would not.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wealth_client import SUBORDER, Keypair, WealthVault  # noqa: E402

VAULT_VERSION = 1

#: The four figures a suitability assessment reads. Named here so a typo in a
#: hand-edited vault fails with "unknown figure 'liquid_asets'" instead of
#: silently proving against a zero.
FIGURE_NAMES = ("income", "liquid_assets", "risk_tolerance", "existing_holdings_value")


class VaultError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadedVault:
    path: Path
    user_id: str | None
    wealth: WealthVault

    @property
    def keypair(self) -> Keypair:
        return self.wealth.keypair


def create(
    path: Path,
    *,
    income: int,
    liquid_assets: int,
    risk_tolerance: int,
    existing_holdings_value: int,
    user_id: str | None = None,
    seed: int | None = None,
    overwrite: bool = False,
) -> LoadedVault:
    """Write a new vault.

    ``seed`` exists so a demo or a test can reproduce a client exactly. It
    defaults to fresh CSPRNG output, and a caller supplying one is asserting
    that this vault is not protecting anything real — the CLI says as much
    when the flag is used.
    """
    if path.exists() and not overwrite:
        raise VaultError(f"{path} already exists; pass --overwrite to replace it")

    _validate_figures(income, liquid_assets, risk_tolerance, existing_holdings_value)

    if seed is None:
        seed = secrets.randbelow(SUBORDER - 1) + 1
    keypair = Keypair.from_seed(seed)

    document: dict[str, Any] = {
        "version": VAULT_VERSION,
        "user_id": user_id,
        # Stored as the seed, not as the derived scalar. `Keypair.from_seed`
        # applies the cofactor-8 multiplication that `eddsa_verify` expects,
        # and storing the post-cofactor scalar would invite someone to
        # reconstruct the keypair without it — producing signatures that fail
        # inside the circuit with no diagnostic beyond "unsatisfied
        # constraint".
        "signing_key_seed": format(seed, "064x"),
        "figures": {
            "income": income,
            "liquid_assets": liquid_assets,
            "risk_tolerance": risk_tolerance,
            "existing_holdings_value": existing_holdings_value,
        },
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    # Created 0600 from the start rather than written and then chmod'ed:
    # between those two calls the file is world-readable, and on a shared
    # advisor terminal that window is enough.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")

    return load(path)


def load(path: Path, *, allow_insecure_permissions: bool = False) -> LoadedVault:
    if not path.is_file():
        raise VaultError(f"no vault at {path}")

    if not allow_insecure_permissions and os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise VaultError(
                f"{path} is mode {mode:04o} — it contains plaintext income and portfolio figures "
                f"and a signing key, and is readable beyond its owner. Run "
                f"`chmod 600 {path}`, or pass --allow-insecure-permissions if this vault is "
                f"disposable test data"
            )

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VaultError(f"{path} is not valid JSON: {exc}") from None

    version = document.get("version")
    if version != VAULT_VERSION:
        raise VaultError(f"{path} declares vault version {version!r}; this tool understands {VAULT_VERSION}")

    figures = document.get("figures")
    if not isinstance(figures, dict):
        raise VaultError(f"{path} has no `figures` object")
    unknown = sorted(set(figures) - set(FIGURE_NAMES))
    if unknown:
        # Refused rather than ignored. A vault carrying `liquid_asets` would
        # otherwise prove against a liquid_assets of zero and fail the
        # assessment for a reason nobody could see.
        raise VaultError(f"{path} has unknown figures: {', '.join(unknown)}")
    missing = sorted(set(FIGURE_NAMES) - set(figures))
    if missing:
        raise VaultError(f"{path} is missing figures: {', '.join(missing)}")

    values = {name: figures[name] for name in FIGURE_NAMES}
    for name, value in values.items():
        if not isinstance(value, int) or isinstance(value, bool):
            raise VaultError(f"{path}: `{name}` must be an integer, got {value!r}")
    _validate_figures(**values)

    seed_hex = document.get("signing_key_seed")
    if not isinstance(seed_hex, str):
        raise VaultError(f"{path} has no `signing_key_seed`")
    try:
        seed = int(seed_hex, 16)
    except ValueError:
        raise VaultError(f"{path}: `signing_key_seed` is not hexadecimal") from None

    return LoadedVault(
        path=path,
        user_id=document.get("user_id"),
        wealth=WealthVault(keypair=Keypair.from_seed(seed), **values),
    )


def _validate_figures(income: int, liquid_assets: int, risk_tolerance: int, existing_holdings_value: int) -> None:
    for name, value in (
        ("income", income),
        ("liquid_assets", liquid_assets),
        ("existing_holdings_value", existing_holdings_value),
    ):
        if value < 0:
            raise VaultError(f"`{name}` must not be negative")
        # The circuit takes u64. A figure above that is not a vault a proof
        # can be generated from, and finding out at `nargo execute` time costs
        # the user a confusing failure several seconds later.
        if value >= 2**64:
            raise VaultError(f"`{name}` exceeds the u64 the circuit accepts")
    if not 1 <= risk_tolerance <= 5:
        # Asserted inside the circuit too. Caught here so a mistyped
        # questionnaire answer is a readable error rather than an
        # unsatisfiable constraint.
        raise VaultError("`risk_tolerance` must be between 1 and 5 (the scale the circuit asserts)")
