"""The offline verification bundle: build it here, verify it anywhere.

An evidence pack is only independent evidence if someone who has never heard
of Memtara can check it on a machine with no network, no credentials and no
cooperation from the firm that produced it. Everything in this package exists
to make that literally true rather than nearly true.

Two halves, and the split is the whole point:

  * `build_bundle.py` runs where the evidence lives. It may call the Memtara
    API, read the live database's exported rows and fetch the issuer's JWKS
    over the network. Producing new evidence legitimately requires the system
    that produced the decision to still exist.

  * `verify_bundle.py` runs where the auditor is. It opens no socket. If it
    ever needs one, the bundle was built wrong, and the test suite asserts
    that by pointing every network path at an unreachable host.

The two verdicts this package reports are always separate, in every output
format, and there is no code path that combines them:

    EVIDENCE INTEGRITY   is this pack the bytes that were sealed?
    DECISION OUTCOME     what did the circuit actually answer?

`bb verify` exiting 0 on a proof of *unsuitability* is a correctly formed
rejection, not an approval. Collapsing the two into one "PASS" would report a
correct decline as an approval in front of an examiner, which is the single
worst thing a tool in this position can do.
"""

from __future__ import annotations

BUNDLE_FORMAT_VERSION = "1.0.0"

# Bumped by hand when the *shape* of the bundle changes: a file added or
# removed, a manifest field renamed, a verification step whose meaning moves.
# Recorded in MANIFEST.json so a bundle opened in 2032 can be read against the
# procedure that was current when it was written, rather than against whatever
# `verify_bundle.py` happens to do that year.
MANIFEST_FILENAME = "MANIFEST.json"
MANIFEST_SIGNATURE_FILENAME = "MANIFEST.json.sig"
