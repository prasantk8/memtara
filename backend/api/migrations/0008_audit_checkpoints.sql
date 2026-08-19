-- Signed checkpoints over the head of the global audit chain.
--
-- ---------------------------------------------------------------------
-- THE GAP THIS CLOSES
-- ---------------------------------------------------------------------
-- `audit_log` is a hash chain: row N+1's `prev_hash` commits to row N's
-- `event_hash`, so editing row N is detectable by anyone who can walk the
-- chain. That argument is airtight for every row that HAS a successor and
-- says nothing at all about the last one. Nothing commits to the terminal
-- row's `event_hash`, and because `payload` is deliberately never stored
-- (see audit/mod.rs), the terminal row's hash cannot be recomputed from the
-- database either. `update audit_log set event_hash = <32 forged bytes>`
-- on the last row was therefore invisible from the database alone.
--
-- That is the worst row to lose. The newest decision is the one a regulator
-- or a claimant asks about.
--
-- A checkpoint is a signed statement, made outside the chain, of the form
-- "at checkpoint number C, the chain's head was `event_hash` H at `seq` S,
-- and there were N rows at or below S". Once such a statement exists and
-- has been fetched by anybody, the row at S has exactly the protection every
-- other row has: it is committed to by something the database cannot rewrite,
-- because rewriting it requires the Ed25519 private key.
--
-- ---------------------------------------------------------------------
-- WHY EACH SIGNED FIELD IS IN THERE
-- ---------------------------------------------------------------------
-- `head_seq` + `head_event_hash`  -- the actual commitment to the terminal row.
--                                    Either alone is useless: a hash with no
--                                    position doesn't say WHICH row it pins,
--                                    and a position with no hash pins nothing.
-- `covered_row_count`             -- makes TRUNCATION detectable, not only
--                                    mutation. Deleting rows off the end is
--                                    the sibling attack to editing the last
--                                    one, and a checkpoint that commits only
--                                    to (seq, hash) does not catch it: delete
--                                    rows 900..1000 and the surviving chain up
--                                    to 899 is still internally consistent.
--                                    A count over `seq <= head_seq` does catch
--                                    it, because the count is a property of
--                                    the whole covered range rather than of
--                                    its endpoint.
-- `checkpoint_no`                 -- monotonic, so an OLD checkpoint cannot be
--                                    replayed as the current one. Without it,
--                                    an insider who kept a copy of checkpoint 3
--                                    could delete checkpoints 4..12 along with
--                                    the audit rows they cover and present 3 as
--                                    "the latest", and every field in it would
--                                    still verify. A counterparty that has ever
--                                    seen number 12 rejects a later claim of 3.
-- `prev_checkpoint_hash`          -- chains the checkpoints to each other, so
--                                    removing one from the MIDDLE of the run
--                                    breaks the next one's link. This does not
--                                    protect the newest checkpoint (see the
--                                    honesty note below) -- it protects every
--                                    older one, which is the same bargain the
--                                    audit chain itself makes.
-- `iat` / `signed_at`             -- wall-clock evidence of when the head was
--                                    pinned, which is what turns "the exposure
--                                    window" from a hand-wave into a number a
--                                    customer can be quoted.
--
-- ---------------------------------------------------------------------
-- WHAT THIS DOES NOT FIX -- STATED HERE SO NOBODY HAS TO REDISCOVER IT
-- ---------------------------------------------------------------------
-- 1. Rows appended AFTER the newest checkpoint are still unprotected. That
--    residual window is the checkpoint interval, and it is real. It is
--    bounded by MEMTARA_AUDIT_CHECKPOINT_INTERVAL_SECONDS (wall clock) and
--    MEMTARA_AUDIT_CHECKPOINT_MAX_EVENTS (event count), whichever binds
--    first, and can be driven to ~0 on demand via POST /audit/checkpoints.
--    It cannot be driven to exactly 0: a checkpoint is necessarily made
--    after the event it pins.
-- 2. Recursion, honestly: the newest CHECKPOINT has no successor either, so
--    deleting it reverts the head to the previous one. The difference --
--    the entire point of the word "published" -- is that a checkpoint is
--    signed and served publicly, so the copy that matters is the one a
--    counterparty already holds, not the row in this table. See the anchor
--    columns below for the half that is not built yet.
-- 3. CONTENT tamper is untouched by this. `event_hash` commits to
--    `event_type` and `payload`, but `payload` is not stored, so rewriting
--    `event_type` in place while leaving the hash columns alone is still
--    invisible to anyone who does not independently hold the payload. That
--    is a separate finding with a separate fix (ship payloads in the
--    offline verification bundle); a head checkpoint does not address it and
--    should not be described as if it did.

create table audit_checkpoints (
    id                    uuid primary key default gen_random_uuid(),

    -- Monotonic counter. `bigserial` for the same reason `audit_log.seq` is
    -- (migrations/0002): a Postgres sequence's allocation is strictly
    -- increasing and unique regardless of clock resolution or transaction
    -- timing, which is exactly the anti-replay property this field is here
    -- to provide. Not the primary key, so that `id` stays a uuid like every
    -- other table's and the counter stays a plain, comparable integer.
    checkpoint_no         bigserial not null,

    -- The chain head this checkpoint pins.
    head_seq              bigint not null,
    head_event_hash       bytea  not null,

    -- Number of `audit_log` rows with `seq <= head_seq` at signing time.
    covered_row_count     bigint not null,

    -- SHA-256 of the previous checkpoint's compact JWS, or null for the
    -- first checkpoint -- mirroring `audit_log.prev_hash` exactly, including
    -- the null-means-genesis convention.
    prev_checkpoint_hash  bytea,

    -- SHA-256 of THIS checkpoint's compact JWS. Stored rather than
    -- recomputed on read so the linkage query is an index lookup, and
    -- unique because two checkpoints with identical bytes would mean the
    -- monotonic counter had been reused.
    checkpoint_hash       bytea  not null unique,

    -- The evidence. Everything above is an index over what this string
    -- says; this string is what is actually signed, and it is what an
    -- external party verifies. Compact JWS (RFC 7515), EdDSA, verifiable
    -- against /.well-known/jwks.json with any JOSE library and no access to
    -- this database. Same relationship as `audit_log.org_id` has to the
    -- hashed payload (migrations/0005): the columns are the index, the
    -- signed bytes are the evidence.
    signed_jws            text   not null,

    -- RFC 7638 thumbprint of the key that signed it. Present so a
    -- checkpoint made before a key rotation stays verifiable against the
    -- right key rather than silently failing against the current one.
    kid                   text   not null,

    signed_at             timestamptz not null default now(),

    -- ---------------------------------------------------------------
    -- The external half -- NOT POPULATED BY ANY CODE PATH TODAY.
    -- ---------------------------------------------------------------
    -- A checkpoint we hold and could rewrite is worth strictly less than one
    -- we cannot. These three columns are where a witness outside our control
    -- gets recorded: `anchor_target` names the witness ('rfc3161', 'git',
    -- 'ots', 'customer_mailbox', ...), `anchor_ref` is whatever that witness
    -- hands back as proof (a timestamp token, a commit sha, a receipt id),
    -- and `anchored_at` is when it was obtained.
    --
    -- They are deliberately nullable and deliberately empty. Shipping them
    -- now fixes the export shape, so an anchoring job is additive rather
    -- than another migration and another schema negotiation. Until one runs,
    -- a NULL here is the honest statement that this checkpoint has exactly
    -- one copy, in our database, and the only thing standing between an
    -- insider and a rewritten history is possession of the signing key --
    -- which is a real control, but a weaker one than a third-party witness.
    anchor_target         text,
    anchor_ref            text,
    anchored_at           timestamptz,

    -- Shape constraints, so a direct-SQL forgery has to at least be
    -- well-formed. SHA-256 is 32 bytes; a chain head cannot sit at seq 0
    -- (bigserial starts at 1); a covered range containing the head row
    -- contains at least one row.
    constraint audit_checkpoints_head_hash_len check (length(head_event_hash) = 32),
    constraint audit_checkpoints_hash_len      check (length(checkpoint_hash) = 32),
    constraint audit_checkpoints_prev_hash_len check (prev_checkpoint_hash is null
                                                      or length(prev_checkpoint_hash) = 32),
    constraint audit_checkpoints_head_seq_pos  check (head_seq >= 1),
    constraint audit_checkpoints_covers_head   check (covered_row_count >= 1),
    -- An anchor reference without a target, or either without a time, is a
    -- half-written claim of external witness. Refuse the shape outright.
    constraint audit_checkpoints_anchor_complete check (
        (anchor_target is null and anchor_ref is null and anchored_at is null)
        or (anchor_target is not null and anchor_ref is not null and anchored_at is not null)
    )
);

-- Unique, not merely indexed: the counter's whole job is to be unforgeably
-- ordered, and two rows sharing a number would let an old checkpoint be
-- presented as the current one -- the exact replay the counter exists to stop.
create unique index audit_checkpoints_no_idx on audit_checkpoints(checkpoint_no);

-- `head_seq` is unique for the same reason: `emit` refuses to write a second
-- checkpoint at an unmoved head, and a duplicate would mean two different
-- signed statements about the same chain position.
create unique index audit_checkpoints_head_seq_idx on audit_checkpoints(head_seq);

-- "The checkpoint covering seq S" is `min(head_seq) where head_seq >= S`, and
-- "the latest" is `max(checkpoint_no)`. Both are served on public endpoints,
-- so both get an index rather than a sort.
create index audit_checkpoints_signed_at_idx on audit_checkpoints(signed_at desc);
