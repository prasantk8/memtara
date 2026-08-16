"""``python -m prover`` — the same entry point as the ``memtara-prove`` shim."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
