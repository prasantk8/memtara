"""The Memtara device prover.

`cli` is the ``memtara-prove`` command; `vault` is the local vault file it
reads. The cryptography lives one directory up in ``clients/wealth_client.py``
and is deliberately not duplicated here — this package is packaging.
"""

from . import cli, vault  # noqa: F401

__all__ = ["cli", "vault"]
