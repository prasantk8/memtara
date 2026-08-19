-- Corrections to a decision's model attestation.
--
-- ---------------------------------------------------------------------
-- THE DEFECT THIS CLOSES
-- ---------------------------------------------------------------------
-- `tests/break_it/test_attack_11_swap_model_undetected.py` and Finding 7 of
-- docs/BREAK_IT_FINDINGS.md record it, and the finding is not that anyone
-- lied. `decision_model_attestations` is written by
-- `POST /api/v1/issue-wealth-request`, in the same transaction as the
-- assessment — that is, BEFORE the client's device has proved anything,
-- before the verdict exists, and before any human has reviewed it. It is a
-- FORWARD DECLARATION about a decision that has not happened yet, and the
-- evidence record serves it with `state: "recorded"`, the same provenance a
-- fact observed at decision time carries.
--
-- Nothing reconfirms it and, until this file, nothing could. `request_id` is
-- the primary key of that table; there is no PATCH, no PUT, no per-decision
-- model route, and the one write that happens after a decision — the review
-- endpoint — is `deny_unknown_fields` and rejects a model field outright.
-- The one-attestation rule is what keeps attack 4's API surface safe, and it
-- is the same rule that makes an honest correction impossible: an
-- organisation that later discovers the model it named was not the model that
-- ran has no route, no row and no field in which to say so, and the system
-- goes on serving the first declaration forever.
--
-- The attack test's own summary of that state is the sentence this migration
-- exists to falsify: "the honest correction is as impossible as the dishonest
-- one".
--
-- ---------------------------------------------------------------------
-- WHY A SECOND TABLE AND NOT AN UPDATE, A NULLABLE COLUMN, OR A VERSION
-- COLUMN ON THE ORIGINAL ROW
-- ---------------------------------------------------------------------
-- Three shapes were considered and rejected before this one.
--
--   1. UPDATE `decision_model_attestations` in place, with the previous
--      values copied into a `_previous` column pair. Rejected outright. The
--      original row is what the organisation said at the time, and that is a
--      fact ABOUT THE ORGANISATION, not about the model — it is the thing an
--      examiner is entitled to read unaltered, and it is the thing a firm
--      would most want to change. Worse, `audit/binding.rs` makes the row's
--      CONTENTS something the hash chain committed to by rebuilding the
--      payload from the live row at verification time; an UPDATE, however
--      well intentioned, makes `GET /orgs/:id/audit-log/replay` report
--      ALTERED against a decision nobody attacked. A correction path that
--      trips the tamper detector is a correction path nobody will use.
--
--   2. Relax the primary key to allow a second attestation row with a
--      `supersedes` pointer. Rejected: `DecisionEvidence.model` is a single
--      block inside bytes that get sealed, so "which attestation does the
--      sealed record describe" must have exactly one answer at any moment,
--      and the one-row rule is what guarantees it. Weakening a constraint to
--      make a feature fit is how attack 4's API surface would have been
--      opened up as a side effect of closing attack 11.
--
--   3. A monotonic `attestation_version` on `decision_model_attestations`,
--      mirroring `products.terms_version` (0007). Tempting, because the
--      contrast in Finding 7 is drawn against exactly that column, and
--      rejected because the analogy does not survive contact. A product's
--      thresholds are amended by their owner and the version counts the
--      amendments; an attestation is not amended, it is CONTRADICTED, and a
--      contradiction has an author, a date and a reason that a version
--      integer has nowhere to put. What 0007 actually demonstrates is
--      snapshot discipline — the version is copied onto the assessment at
--      open so a later change cannot rewrite what this decision was measured
--      against — and this table keeps that discipline by never touching the
--      snapshot at all.
--
-- So: append-only rows, keyed to the attestation they contradict, each one
-- carrying who said it, what they now say, why, and when.
--
-- ---------------------------------------------------------------------
-- WHY A CORRECTION MUST BE ABLE TO SAY "WE NO LONGER KNOW"
-- ---------------------------------------------------------------------
-- A correction table that could only ever name a replacement model would
-- reproduce the original defect one level up. The realistic discovery is not
-- "it was model B" — it is "the gateway was serving from a pool that day and
-- we cannot reconstruct which deployment answered this request". If the only
-- expressible correction is a named model, an organisation in that position
-- must either name a model it is guessing at or say nothing, and both of
-- those are worse records than the truth. `participated_but_unidentified` is
-- therefore a first-class corrected declaration with its own required
-- reason, exactly as it is in 0006.
--
-- ---------------------------------------------------------------------
-- WHY A CORRECTION CAN NEVER ASSERT `no_ai_participated`
-- ---------------------------------------------------------------------
-- This is the constraint most likely to be questioned, so the argument is
-- here rather than in a commit message.
--
-- 0006 defines `no_ai_participated` as a SIGNED ASSERTION that no AI system
-- took part, serialised as `model: null`, and `wealth/model_intake.rs` exists
-- almost entirely to make that assertion unreachable by accident: silence
-- maps to `participated_but_unidentified`, an empty object is a 400, a blank
-- statement is a 400. The assertion costs the caller a sentence, and that
-- asymmetry is the whole design.
--
-- A correction that could reach it would be a route to the flattering answer
-- that opens LATER — after the verdict, after the review, after a complaint —
-- which is precisely when a firm has the strongest reason to want it and the
-- weakest claim to it. The declaration made when the assessment was opened is
-- the one made before anyone knew how the decision would turn out, and that
-- is what gives it its evidential weight.
--
-- The rule this enforces, stated once: A CORRECTION MAY WEAKEN OR RE-POINT
-- THE ORGANISATION'S AI CLAIM. IT MAY NEVER STRENGTHEN IT INTO THE STRONGEST
-- ASSERTION THE SYSTEM CAN MAKE.
--
-- What that forecloses, named honestly rather than left for someone to
-- discover: an organisation that declared a model at open, and later
-- establishes that the recommendation actually came from a deterministic
-- rules engine with no model in the path, cannot record that here. The
-- correction available to it is `participated_but_unidentified` with a reason
-- naming the discovery — a statement weaker than the truth it believes, and
-- never stronger than it. Retracting a participation claim entirely is a
-- larger act than correcting an identity: it needs a route of its own, with
-- its own evidence requirements, and inventing one inside a field named
-- `corrected_model_provider` would be the "bypass human review" defect dressed
-- up as a feature. It is not built, and this comment is the record that it was
-- considered and declined rather than overlooked.
--
-- The reverse direction is deliberately open. An organisation that declared
-- `no_ai_participated` and later discovers a model was in the path CAN
-- correct to `model_identified` or `participated_but_unidentified`, because
-- that direction is an admission and no rule needs to protect the system from
-- an admission.

create table decision_model_attestation_corrections (
    id uuid primary key default gen_random_uuid(),

    -- References the ATTESTATION, not `disclosure_requests(id)` as the two
    -- tables in 0006 do, and the difference is meaningful: those two are
    -- assertions about a decision and stand on their own, while a correction
    -- is an assertion about an assertion and is meaningless without the one
    -- it contradicts. The foreign key is what makes "a correction with
    -- nothing to correct" unrepresentable rather than merely unlikely.
    request_id uuid not null
        references decision_model_attestations(request_id) on delete cascade,

    -- Denormalised for the same reason `audit_log.org_id` is (0005) and
    -- `decision_reviews.org_id` is (0006): a correction must be attributable
    -- to a tenant without joining through the decision. No foreign key, for
    -- the reason 0005 gives — every referential action available is wrong for
    -- a record that has to be able to outlive the entity it describes.
    org_id uuid not null,

    -- ---------------------------------------------------------------
    -- ORDER
    -- ---------------------------------------------------------------
    -- Per-request and dense from 1, not a global sequence and not
    -- `created_at`. Two reasons, and neither is aesthetics:
    --
    --   * `created_at` is not a safe total order. It is Postgres's clock, it
    --     can tie under rapid inserts, and 0002 already had to add `seq` to
    --     `audit_log` for exactly this reason.
    --   * A DENSE per-request number makes a DELETION visible. Corrections
    --     1, 2 and 4 in the record say plainly that 3 was removed; a global
    --     sequence or a bare timestamp says nothing, because the gaps are
    --     other decisions' rows. The evidence record renders this number, so
    --     the gap is legible to an examiner without database access.
    correction_no integer not null check (correction_no >= 1),
    constraint decision_model_corrections_are_ordered_per_request
        unique (request_id, correction_no),

    -- The organisation's own identifier for whoever is asserting the
    -- correction, and the authority they are asserting it under. Text, not a
    -- foreign key, for the reason `decision_reviews.reviewer_id` gives:
    -- Memtara has no directory of a bank's staff and inventing one would be a
    -- worse claim than quoting theirs. The role is separate from the
    -- identifier because "who" and "with what authority" are different
    -- questions, and a correction to a signed model attestation is exactly
    -- the kind of statement where the second one is asked first.
    asserted_by      text not null check (length(btrim(asserted_by)) > 0),
    asserted_by_role text not null check (length(btrim(asserted_by_role)) > 0),

    -- ---------------------------------------------------------------
    -- WHY
    -- ---------------------------------------------------------------
    -- Same mechanism as `decision_reviews.override_reason` and
    -- `decision_model_attestations.no_ai_attestation`, with a higher floor,
    -- and the floor is not a quality bar in either case. Ten characters is
    -- what 0006 uses to stop `"x"`, `"n/a"` and `"-"` — the three things a
    -- required free-text field actually collects when nobody means to fill it
    -- in. A correction is a statement that a record this organisation already
    -- signed named the wrong deciding system, and ten characters cannot carry
    -- what was discovered, when, or how. Thirty is still not a quality bar
    -- and does not pretend to be one; it is the point at which a caller has
    -- to write a sentence rather than a token. `MIN_CORRECTION_REASON_CHARS`
    -- in wealth/model_correction.rs holds the same number so the two cannot
    -- drift.
    correction_reason text not null,
    constraint decision_model_corrections_reason_is_substantive check (
        length(btrim(correction_reason)) >= 30
    ),

    -- ---------------------------------------------------------------
    -- WHAT IS NOW ASSERTED
    -- ---------------------------------------------------------------
    -- Two values, and the absence of the third is the constraint, not an
    -- oversight — see the header. Named so that the refusal an examiner or a
    -- DBA sees names the rule rather than a column list.
    corrected_declaration text not null,
    constraint decision_model_corrections_cannot_assert_no_ai check (
        corrected_declaration in ('model_identified', 'participated_but_unidentified')
    ),

    -- Only for 'participated_but_unidentified': why the model cannot be
    -- named. Required for the same reason `Provenanced::unpopulated` demands
    -- a reason — a gap that does not name what would fill it is
    -- indistinguishable from a bug — and separate from `correction_reason`,
    -- which answers a different question. "Why are you correcting this" and
    -- "why can you not name the model" have the same answer only sometimes,
    -- and collapsing them would lose whichever one the caller did not think
    -- of first.
    unidentified_reason text,

    -- The seven leaves plus the call timestamp, mirroring 0006's columns and
    -- individually nullable for the reason given there: a caller that knows
    -- the corrected provider and model but not its config fingerprint should
    -- record the two it has and carry the third as an explicit gap, rather
    -- than refusing to correct anything or inventing a value.
    corrected_model_provider                text,
    corrected_model_name                    text,
    corrected_model_version                 text,
    corrected_prompt_version                text,
    corrected_model_environment             text,
    corrected_model_config_fingerprint      text,
    corrected_model_system_prompt_or_policy_id text,
    corrected_model_timestamp               timestamptz,

    -- When the organisation determined the correction, asserted by the
    -- caller, beside the server's own observation of when it arrived. The
    -- same pairing as `decision_reviews.reviewed_at`/`created_at` and for the
    -- same reason: the gap between the two is unforgeable by the caller, and
    -- a batch of corrections all claiming to be weeks apart while arriving in
    -- the same second is visible from these two columns alone.
    asserted_at timestamptz not null,
    created_at  timestamptz not null default now(),

    -- ---------------------------------------------------------------
    -- A GENUINE SECOND OPINION ON THE PARSER
    -- ---------------------------------------------------------------
    -- These do not restate `model_correction.rs`. Each one is a rule that
    -- survives the API being removed from the path, which is the only test
    -- that matters for a constraint: attack 4 demonstrated that every
    -- defence living in a request handler is irrelevant to someone holding a
    -- connection string.

    -- An "identification" that names neither provider nor model is not one.
    -- Same rule as `decision_model_identified_names_something` in 0006, held
    -- at the same strength here so that a correction cannot be the weaker
    -- door into the same table's meaning.
    constraint decision_model_corrections_identified_names_something check (
        corrected_declaration <> 'model_identified'
        or (unidentified_reason is null
            and corrected_model_provider is not null
            and length(btrim(corrected_model_provider)) > 0
            and corrected_model_name is not null
            and length(btrim(corrected_model_name)) > 0)
    ),

    -- And an admission of ignorance must name why, and must not smuggle a
    -- half-populated identity in beside itself. Mirrors
    -- `decision_model_unidentified_names_why`.
    constraint decision_model_corrections_unidentified_names_why check (
        corrected_declaration <> 'participated_but_unidentified'
        or (unidentified_reason is not null
            and length(btrim(unidentified_reason)) >= 10
            and corrected_model_provider is null
            and corrected_model_name is null
            and corrected_model_version is null
            and corrected_prompt_version is null
            and corrected_model_environment is null
            and corrected_model_config_fingerprint is null
            and corrected_model_system_prompt_or_policy_id is null
            and corrected_model_timestamp is null)
    ),

    -- A fingerprint is a digest an examiner recomputes or it is nothing.
    -- 0006 enforces this shape at the API boundary for
    -- `model_config_fingerprint` and constrains only `input_context_fingerprint`
    -- and `output_fingerprint` at the row level; that asymmetry is a real gap
    -- in 0006 and this constraint declines to reproduce it. Lower-case hex,
    -- the same convention as `crypto::signer::proof_digest_hex` and
    -- `circuits/wealth_suitability/vkey/vk_hash`, so an examiner has one rule
    -- to learn.
    constraint decision_model_corrections_fingerprint_is_a_digest check (
        corrected_model_config_fingerprint is null
        or corrected_model_config_fingerprint ~ '^[0-9a-f]{64}$'
    ),

    -- A correction cannot claim to have been determined meaningfully after
    -- it was filed. Deliberately one-sided and deliberately loose: the bound
    -- is generous in the direction of the caller's clock running fast, and
    -- absent in the direction of the past, because a correction determined
    -- months before it was filed is a slow organisation, not a forged row,
    -- and the two timestamps sitting side by side already say so.
    --
    -- Note which clocks these are. `created_at` defaults to Postgres's
    -- `now()`; `asserted_at` reaches this row from the server process, whose
    -- clock the break-it suite documents as running TENS OF MILLISECONDS
    -- BEHIND the database container's. That skew is in the safe direction
    -- here — it makes `created_at` later, not earlier — and the five-minute
    -- allowance is what keeps a legitimate correction from failing on a desk
    -- whose clock is a few minutes fast.
    constraint decision_model_corrections_not_asserted_after_filing check (
        asserted_at <= created_at + interval '5 minutes'
    )
);

create index decision_model_attestation_corrections_org_id_idx
    on decision_model_attestation_corrections(org_id);

-- "Which decisions did model X make?" — the question a firm asks the morning
-- after a model is found to have been misbehaving. 0006 answers it from
-- `decision_model_attestations` alone, and the moment a correction exists
-- that answer is wrong in both directions: it includes decisions since
-- corrected AWAY from X, and it misses decisions since corrected TO X. This
-- index is the second half of that query, and it exists because a partial
-- answer to that particular question is worse than none.
create index decision_model_attestation_corrections_model_idx
    on decision_model_attestation_corrections(
        org_id, corrected_model_provider, corrected_model_name, corrected_model_version);

-- The read the evidence record performs on every fetch: this decision's
-- corrections, in the order they were filed.
create index decision_model_attestation_corrections_request_idx
    on decision_model_attestation_corrections(request_id, correction_no);
