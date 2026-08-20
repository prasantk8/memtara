-- The evidence half of an external anchor: the raw witness bytes, not just
-- the fact that a witness was consulted.
--
-- ---------------------------------------------------------------------
-- WHY A NEW COLUMN RATHER THAN REUSING `anchor_ref`
-- ---------------------------------------------------------------------
-- Migration 0008 already carries `anchor_target` / `anchor_ref` /
-- `anchored_at` and says plainly that they are "deliberately nullable and
-- deliberately empty" until an anchoring job exists. That job is this
-- stage's work (`backend/api/src/audit/anchor.rs`), and the RFC 3161
-- timestamp authority it calls back an ASN.1 `TimeStampToken` — a signed CMS
-- structure a few kilobytes long, not a short opaque id.
--
-- `anchor_ref` was scoped by 0008 as "whatever that witness hands back as
-- proof (a timestamp token, a commit sha, a receipt id)" — a human-readable
-- pointer, `text`, meant to be quoted in a report. Stuffing a base64'd DER
-- blob into it would technically fit, but it would defeat the column's own
-- purpose: `anchor_ref` stops being something a reader can glance at, and an
-- offline verifier reading `anchor_ref` off this table would have to know,
-- out of band, that THIS particular target's reference is secretly an
-- encoded binary rather than a receipt id. A `bytea` column named for what
-- it holds says so structurally. `anchor_ref` keeps its job: this migration
-- sets it to a short, human-checkable locator (`sha256:<hex>` of the token,
-- for the RFC 3161 case) while `anchor_receipt` carries the bytes an offline
-- verifier actually needs to run the cryptographic check — see
-- `scripts/bundle/verify_bundle.py` step 7c and `docs/VERIFY.md` step 7.
--
-- ---------------------------------------------------------------------
-- WHAT THIS DOES NOT CLAIM
-- ---------------------------------------------------------------------
-- A non-null `anchor_receipt` is a claim that SOME bytes were received from
-- SOME process that called itself an anchoring job. It is not a claim that
-- those bytes verify — a corrupted or synthetic value can be written by
-- anyone with database access, exactly like every other column in this
-- table. What makes the receipt evidence rather than an assertion is the
-- same thing that makes the checkpoint's `signed_jws` evidence: an outside
-- party (here, the TSA; there, anyone holding the JWKS) can check it against
-- material this deployment does not control. This migration only makes the
-- bytes storable and shippable; `anchor.rs` is what population looks like
-- and `verify_bundle.py` step 7c is what checking looks like.
--
-- Constraining SHAPE, not truth, follows the same discipline as migration
-- 0010: the check below rejects an empty value under a column whose name
-- promises evidence, and nothing checkable from inside this database can go
-- further than that.

alter table audit_checkpoints
    add column anchor_receipt bytea;

-- The four anchor columns are one fact ("this checkpoint was witnessed
-- externally, by this target, with this reference, at this time, and here
-- are the bytes that prove it") and must appear or be absent together.
-- Migration 0008's version of this check only knew about three of the four
-- columns; replacing rather than merely adding to it is what keeps that
-- true now that a fourth exists. A row with `anchor_ref` set but
-- `anchor_receipt` null would be exactly the half-written claim 0008's
-- constraint existed to refuse, just one column further along.
alter table audit_checkpoints
    drop constraint audit_checkpoints_anchor_complete;

alter table audit_checkpoints
    add constraint audit_checkpoints_anchor_complete check (
        (anchor_target is null and anchor_ref is null and anchored_at is null
             and anchor_receipt is null)
        or (anchor_target is not null and anchor_ref is not null and anchored_at is not null
             and anchor_receipt is not null)
    );

-- Shape, matching the discipline migration 0010 was written to generalise:
-- constrain the new column, then go look for the sibling that was left
-- weaker. `anchor_target` and `anchor_ref` shipped in 0008 with no
-- non-empty check at all — an UPDATE could set either to `''` and the
-- half-written-claim constraint above would not catch it, because an empty
-- string is not null. That asymmetry is closed here rather than quietly
-- left in place for the two columns this migration did not introduce.
alter table audit_checkpoints
    add constraint audit_checkpoints_anchor_receipt_not_empty
    check (anchor_receipt is null or length(anchor_receipt) > 0);

alter table audit_checkpoints
    add constraint audit_checkpoints_anchor_target_not_blank
    check (anchor_target is null or length(btrim(anchor_target)) > 0);

alter table audit_checkpoints
    add constraint audit_checkpoints_anchor_ref_not_blank
    check (anchor_ref is null or length(btrim(anchor_ref)) > 0);

-- No rows to migrate: every existing `audit_checkpoints` row has all four
-- anchor columns null (0008's own header says so — "NOT POPULATED BY ANY
-- CODE PATH TODAY"), so this migration needs no backfill and is safe to run
-- against a database that already has checkpoints in it.
