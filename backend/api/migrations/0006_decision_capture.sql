-- Per-decision HUMAN review and per-decision MODEL identity.
--
-- These are the two blocks `DecisionEvidence` v1 carries as explicitly
-- unpopulated placeholders, and they are the two the board named as the
-- product gap: without them the record is "policy/data evidence surrounding
-- an AI workflow", not an AI decision evidence record. Everything else in
-- the schema already had a source in Postgres. Neither of these did.
--
-- ---------------------------------------------------------------------
-- WHY TWO TABLES AND NOT COLUMNS ON `wealth_requests`
-- ---------------------------------------------------------------------
-- Both facts are *assertions made by a named party at a named time*, not
-- properties of the assessment. A reviewer's verdict is made by a person,
-- minutes or hours after the proof; a model identity is asserted by the
-- calling AI system at the moment it opens the assessment. Folding either
-- into `wealth_requests` would put two authors' claims in one row with no
-- way to say which of them wrote which column — and would tie the shape of
-- the capture to the wealth flow specifically, when the next process to get
-- an evidence record will need the same two tables keyed the same way.
--
-- Both are therefore keyed on `disclosure_requests(id)`, which is the
-- decision's natural key (`DecisionBlock::decision_id`), not on
-- `wealth_requests(request_id)`.

-- =====================================================================
-- decision_reviews — what a human did about THIS decision
-- =====================================================================
--
-- The only governance-shaped field before this table was
-- `products.approved_by_risk_committee`, which approves a *catalogue entry*.
-- A product being approved for sale is not a human having looked at one
-- client's recommendation, and mapping the first onto the second would be
-- the "bypass human review" defect dressed up as a feature.
--
-- ---------------------------------------------------------------------
-- ONE REVIEW PER DECISION
-- ---------------------------------------------------------------------
-- `request_id` is the primary key, not a foreign key with a surrogate id.
-- `DecisionEvidence.human_review` is a single block inside bytes that get
-- sealed, so "which review does the sealed record describe" must have
-- exactly one answer. A second review arriving later would either silently
-- change what an already-exported record said, or force the record to carry
-- an array the pinned schema does not have. The endpoint returns 409 rather
-- than overwriting; escalation (a junior's verdict superseded by a senior's)
-- is a real workflow this deliberately does not model yet, and saying so is
-- better than modelling it wrong under a field named `reviewer_id`.
create table decision_reviews (
    request_id  uuid primary key references disclosure_requests(id) on delete cascade,

    -- Denormalised for the same reason `audit_log.org_id` is (0005): a
    -- review must be attributable to a tenant without joining through the
    -- decision. No foreign key, for the same reason 0005 gives — every
    -- referential action available is wrong for a record that has to be
    -- able to outlive the entity it describes.
    org_id      uuid not null,

    -- The bank's own identifier for the reviewer, and the role they were
    -- acting in. Text, not a foreign key: Memtara has no directory of a
    -- bank's staff and inventing one would be a worse claim than quoting
    -- theirs. The org asserts these under its API key, and the audit event
    -- records that it did.
    reviewer_id   text not null check (length(btrim(reviewer_id)) > 0),
    reviewer_role text not null check (length(btrim(reviewer_role)) > 0),

    -- Approved | Rejected | Modified. Required, and the same column on a
    -- decline as on an approval: a declined client's record must not have a
    -- different shape from an approved one, because the seal is a digest
    -- over canonical bytes and a key that appears only on one branch makes
    -- "this was tampered with" and "this client was declined" look alike.
    action      text not null check (action in ('approved', 'rejected', 'modified')),

    -- ---------------------------------------------------------------
    -- THE OVERRIDE PAIRING
    -- ---------------------------------------------------------------
    -- An override with no stated reason is not evidence of anything; it is
    -- the absence of evidence wearing a boolean. The pinned JSON schema
    -- already forbids the pairing for a record, and the Rust builder makes
    -- it unconstructable. This constraint is the third layer, and the only
    -- one that survives someone writing to the database by hand.
    --
    -- The reverse direction is constrained too, and deliberately so:
    -- `override_reason` means "why this reviewer went against the control",
    -- so a reason attached to a non-override is a different fact wearing
    -- this field's name. A reviewer who wants to record why they *agreed*
    -- needs a field that says that, which this is not.
    "override"      boolean not null,
    override_reason text,
    constraint decision_reviews_override_requires_reason check (
        ("override" = false and override_reason is null)
        or ("override" = true
            and override_reason is not null
            and length(btrim(override_reason)) >= 10)
    ),

    -- ---------------------------------------------------------------
    -- REVIEW DURATION — the Cigna field
    -- ---------------------------------------------------------------
    -- In the Cigna litigation the finding that ended the argument was not a
    -- missing signature or an absent policy. It was a duration: medical
    -- directors clearing claims at roughly 1.2 seconds each, in batches,
    -- without opening the file. Every one of those denials had a named
    -- reviewer, a timestamp and an action — a record that this table would
    -- have accepted as complete. What made the pattern visible was how long
    -- each review took, and nothing in a conventional review log records it.
    --
    -- So it is a first-class column from day one, with its own provenance
    -- column beside it. `review_duration_source` matters more than the
    -- number: a duration a reviewer's own client asserts is exactly what a
    -- firm gaming this metric would falsify, and an examiner must be able to
    -- tell an asserted number from a measured one without asking us. A
    -- duration with no source is not admissible as either.
    review_duration_ms     bigint check (review_duration_ms >= 0),
    review_duration_source text check (review_duration_source in (
        -- The reviewing client timed itself and told us. Trust it exactly as
        -- far as you trust the client.
        'reviewer_client_asserted',
        -- The caller gave us when the reviewer opened the case; the server
        -- subtracted it from its own receipt time. Still rests on a
        -- caller-supplied start, but the end is ours.
        'server_computed_from_declared_start'
    )),
    constraint decision_reviews_duration_needs_a_source check (
        (review_duration_ms is null and review_duration_source is null)
        or (review_duration_ms is not null and review_duration_source is not null)
    ),

    -- Which revision of the firm's own review procedure this reviewer worked
    -- under. Nothing in this codebase records a review procedure, so this is
    -- the org's string, stored verbatim.
    human_review_protocol_version text not null
        check (length(btrim(human_review_protocol_version)) > 0),

    -- When the human decided. Asserted by the caller (a review that happened
    -- on a desk five minutes ago is a legitimate submission), which is why
    -- `created_at` sits beside it: the gap between the two is the server's
    -- own, unforgeable observation, and a batch of reviews all claiming to
    -- be hours apart while arriving in the same second is visible from these
    -- two columns alone.
    reviewed_at timestamptz not null,
    created_at  timestamptz not null default now()
);
create index decision_reviews_org_id_idx on decision_reviews(org_id);
create index decision_reviews_reviewer_idx on decision_reviews(org_id, reviewer_id);
-- The index the Cigna query runs on: "show me every review this reviewer
-- filed, in arrival order, with its duration".
create index decision_reviews_duration_idx on decision_reviews(org_id, reviewer_id, created_at);

-- =====================================================================
-- decision_model_attestations — which AI system participated, if any
-- =====================================================================
--
-- Nothing in this repository can source any of these values. There is no
-- LLM gateway here and the founder's scope decision is explicit that there
-- will not be one this quarter: the model identity is supplied by the
-- calling AI system, on the one path the pilot exercises, and this table is
-- where what it supplied is kept.
--
-- ---------------------------------------------------------------------
-- WHY `declaration` IS A COLUMN AND NOT AN ABSENCE
-- ---------------------------------------------------------------------
-- The distinction the Rust type system already encodes has to survive into
-- the database, or the API's honesty ends at the first write:
--
--   'no_ai_participated'          — a SIGNED ASSERTION that no AI system
--                                   took part. Serialises as `model: null`.
--                                   Strong, and commercially valuable to a
--                                   firm that runs no models: they can prove
--                                   it rather than leave a blank.
--   'model_identified'            — an AI took part and here is which.
--   'participated_but_unidentified' — an AI took part and we do not know
--                                   which. An admission of ignorance.
--
-- A missing row is a fourth state and means "the caller said nothing", which
-- the API converts to `participated_but_unidentified` rather than to the
-- no-AI assertion. Silence must never reach the flattering answer.
--
-- The check constraints below make the assertion unreachable by a partial
-- write: 'no_ai_participated' requires a non-empty attestation and forbids
-- every model column, so a row cannot arrive at that declaration by having
-- its model fields left null.
create table decision_model_attestations (
    request_id uuid primary key references disclosure_requests(id) on delete cascade,
    org_id     uuid not null,

    declaration text not null check (declaration in (
        'no_ai_participated',
        'model_identified',
        'participated_but_unidentified'
    )),

    -- Only for 'no_ai_participated': what the org is asserting instead, in
    -- its own words ("assessment produced by the rules engine in
    -- <system>, no model in the path"). Required, because an assertion this
    -- strong with nothing behind it is a checkbox, and a checkbox is what
    -- this whole record exists to replace.
    no_ai_attestation text,

    -- Only for 'participated_but_unidentified': why not. Required for the
    -- same reason `Provenanced::unpopulated` demands a reason — a gap that
    -- does not name what would fill it is indistinguishable from a bug.
    unidentified_reason text,

    -- The seven model leaves plus the call timestamp. Individually nullable
    -- even under 'model_identified': a caller that knows its provider and
    -- model but not its config fingerprint should record the two it has and
    -- carry the third as an explicit gap, not refuse to record anything or
    -- invent a value. `provider` and `model_name` are the exception — see
    -- the constraint below, an "identification" that names neither is not
    -- one.
    model_provider                text,
    model_name                    text,
    model_version                 text,
    prompt_version                text,
    model_environment             text,
    model_config_fingerprint      text,
    model_system_prompt_or_policy_id text,
    model_timestamp               timestamptz,

    -- Siblings of the model block, not children of it, matching
    -- `DecisionBlock`'s layout and for the reason stated there: when no AI
    -- participated the decision still had inputs and an output, and a
    -- fingerprint that vanished along with the model would leave a non-AI
    -- decision with nothing committing to what it was decided on. Both are
    -- lower-case hex SHA-256 when present, enforced at the API boundary.
    input_context_fingerprint text check (input_context_fingerprint ~ '^[0-9a-f]{64}$'),
    output_fingerprint        text check (output_fingerprint ~ '^[0-9a-f]{64}$'),

    created_at timestamptz not null default now(),

    constraint decision_model_no_ai_is_a_positive_assertion check (
        declaration <> 'no_ai_participated'
        or (no_ai_attestation is not null
            and length(btrim(no_ai_attestation)) >= 10
            and unidentified_reason is null
            and model_provider is null
            and model_name is null
            and model_version is null
            and prompt_version is null
            and model_environment is null
            and model_config_fingerprint is null
            and model_system_prompt_or_policy_id is null
            and model_timestamp is null)
    ),
    constraint decision_model_identified_names_something check (
        declaration <> 'model_identified'
        or (no_ai_attestation is null
            and unidentified_reason is null
            and model_provider is not null and length(btrim(model_provider)) > 0
            and model_name is not null and length(btrim(model_name)) > 0)
    ),
    constraint decision_model_unidentified_names_why check (
        declaration <> 'participated_but_unidentified'
        or (no_ai_attestation is null
            and unidentified_reason is not null
            and length(btrim(unidentified_reason)) >= 10
            and model_provider is null
            and model_name is null
            and model_version is null
            and prompt_version is null
            and model_environment is null
            and model_config_fingerprint is null
            and model_system_prompt_or_policy_id is null
            and model_timestamp is null)
    )
);
create index decision_model_attestations_org_id_idx on decision_model_attestations(org_id);
-- "Which decisions did model X make?" — the question a firm asks the morning
-- after a model is found to have been misbehaving, and the one it currently
-- has no way to answer at all.
create index decision_model_attestations_model_idx
    on decision_model_attestations(org_id, model_provider, model_name, model_version);
