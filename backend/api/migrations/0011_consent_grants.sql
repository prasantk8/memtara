-- consent_grants — the record `purpose_hash` has always been mistaken for.
--
-- ---------------------------------------------------------------------
-- WHY THIS EXISTS
-- ---------------------------------------------------------------------
-- `tests/break_it/test_attack_08_consent_revocation.py` has stood as a
-- tripwire since the binding stage: it greps `backend/api/src/` for
-- "consent" and FAILS the moment the word appears anywhere near a table or a
-- route, precisely so a stale green skip can never be mistaken for "consent
-- revocation was verified". Its own analysis is why the tripwire was safe to
-- leave BLOCKED this long: `vault::session::SessionPolicy.purpose_hash`
-- (`wealth/mod.rs`'s `policy` snapshot) is a fixed hash of a hardcoded
-- purpose string, bound once at session-creation time. It has no grant time,
-- no subject acknowledgement, and — the part this table exists to add — no
-- revocation path. A purpose binding says what a session was FOR. It has
-- never said that anyone AGREED to it, and it cannot say that agreement was
-- later withdrawn, because it carries nothing that could be withdrawn.
--
-- `evidence/mod.rs`'s `Consent` struct has carried five leaves —
-- `consent_id`, `consent_version`, `scope`, `granted_at`, `purpose_hash` —
-- since schema 1.0.0, every one of them `Provenanced::unpopulated` because
-- nothing in this repository could source them. This table is the source.
--
-- ---------------------------------------------------------------------
-- WHY REVOCATION IS AN UPDATE THAT SETS A COLUMN, NOT A DELETE
-- ---------------------------------------------------------------------
-- Deleting a withdrawn grant is the tempting shape and the wrong one. A
-- customer who withdraws consent is not asking to have the fact that they
-- once granted it erased — the opposite: the record an examiner needs is
-- "consent existed, covered scope X, and was withdrawn at time Y for reason
-- Z", and a DELETE destroys exactly the half of that sentence that proves
-- the bank once had a lawful basis at all. So a grant row lives forever.
-- Revocation is `revoked_at`/`revocation_reason` moving from null to a
-- value, once, the same discipline `decision_model_attestation_corrections`
-- (migrations/0009) uses for a contradicted attestation: the original fact
-- is never removed, and what changed is recorded beside it.
--
-- ---------------------------------------------------------------------
-- WHY IT CANNOT BE UN-REVOKED OR RE-REVOKED, ENFORCED BELOW THE HANDLER
-- ---------------------------------------------------------------------
-- The API only ever issues `UPDATE ... WHERE revoked_at IS NULL`, so through
-- the API a second revoke is a no-op it refuses (409) rather than performs.
-- Attack 4's whole finding is that a defence living only in a handler is
-- irrelevant to someone holding a connection string: nothing stopped a
-- direct `UPDATE consent_grants SET revoked_at = NULL WHERE id = ...`, which
-- would let an organisation quietly un-revoke a withdrawal — manufacturing
-- the appearance, to anyone reading the row, that consent was never
-- withdrawn — or move `revoked_at` to a different moment after the fact.
-- `consent_grants_guard_revocation` below closes both: once `revoked_at` is
-- set, neither it nor `revocation_reason` may change again, checked in the
-- database rather than trusted to whoever is writing the query.
--
-- Note what this trigger deliberately does NOT guard: every other column,
-- including `scope`. That is not an oversight. Part of this stage's own
-- attack (`test_attack_08_consent_revocation.py`, step 3) is a direct
-- `UPDATE consent_grants SET scope = ...` against a grant a decision was
-- already opened under, and the claim this system makes about that write is
-- DETECTION, not prevention — the same claim `audit/binding.rs` makes about
-- `decision_model_attestations`. A trigger that blocked every UPDATE would
-- make that half of the attack unrunnable rather than caught, which would
-- overstate what this table defends.
--
-- ---------------------------------------------------------------------
-- WHY `scope` NEEDS A FUNCTION AND NOT A BARE CHECK EXPRESSION
-- ---------------------------------------------------------------------
-- The requirement is "a non-empty JSON array of non-empty strings, no
-- floats" — the same "no floats anywhere that will be canonically hashed"
-- rule `audit/binding.rs::check_policy_is_bindable` enforces at the API
-- boundary, held here as the row-level second layer attack 4 argues every
-- API-side rule needs. Postgres CHECK constraints cannot contain a
-- subquery, and `jsonb_array_elements(scope)` is a set-returning function —
-- iterating it to check every element's type needs a query. Wrapping that
-- query in an IMMUTABLE SQL function and calling the function from the CHECK
-- expression is the standard escape: the constraint sees one function call
-- referencing only this row's own column, and Postgres permits it.
--
-- ---------------------------------------------------------------------
-- WHY `purpose_hash` IS CONSTRAINED FROM THIS MIGRATION, NOT A LATER ONE
-- ---------------------------------------------------------------------
-- Finding 11 (migrations/0010) was a column named `..._fingerprint` that
-- accepted anything, discovered only after `decision_model_attestations`
-- already had rows and needed a follow-up migration to close. This table is
-- new, so there is no weaker sibling to quietly match: `purpose_hash ~
-- '^[0-9a-f]{64}$'` is enforced here, at creation, the same shape 0010 had
-- to retrofit. It is nullable — unlike `consent_version` and `granted_via`,
-- which the API always requires — because a grant's scope (the array of
-- purpose strings below) is what enforcement actually reads; `purpose_hash`
-- carries the domain-separated digest for the existing pinned evidence field
-- of the same name when a caller supplies one, and a grant that names its
-- scope in plain strings without also committing to a digest of it is still
-- a real grant.
--
-- ---------------------------------------------------------------------
-- WHAT THIS TABLE DOES NOT CLAIM
-- ---------------------------------------------------------------------
-- It does not prove the named user actually agreed to anything. `granted_by`
-- doesn't exist as a column for the same reason `decision_reviews.reviewer_id`
-- is free text and not a foreign key into a directory Memtara doesn't hold:
-- the row is the ORGANISATION's assertion, made under its API key, that a
-- grant of this shape happened through the channel named in `granted_via`.
-- Memtara verifies proofs; it does not witness consent ceremonies. And it
-- does not claim consent is required for anything beyond the one enforcement
-- point this stage wires up (`issue_wealth_request`) — a table existing is
-- not the same claim as every code path having been made to check it.
create or replace function consent_scope_is_array_of_nonempty_strings(scope jsonb)
returns boolean
language sql
immutable
as $$
    select jsonb_typeof(scope) = 'array'
       and jsonb_array_length(scope) > 0
       and not exists (
           select 1
           from jsonb_array_elements(scope) as elem(value)
           where jsonb_typeof(elem.value) <> 'string'
              or length(btrim(elem.value #>> '{}')) = 0
       )
$$;

create table consent_grants (
    id                 uuid primary key default gen_random_uuid(),

    -- The org that captured the grant, and the user it covers. Real foreign
    -- keys, unlike `decision_reviews.org_id`/`audit_log.org_id`: this row
    -- has no reason to outlive either party the way an audit event does, and
    -- `on delete cascade` matches `disclosure_requests`' own treatment of
    -- both references.
    org_id             uuid not null references organizations(id) on delete cascade,
    user_id            uuid not null references users(id) on delete cascade,

    -- What was agreed to: an array of purpose/category strings, e.g.
    -- ["wealth.suitability_recommendation"]. Non-empty and every element a
    -- non-empty string, enforced by the function above. This is what
    -- enforcement actually reads to decide whether a grant covers a given
    -- decision's business process.
    scope              jsonb not null,
    constraint consent_grants_scope_is_bindable
        check (consent_scope_is_array_of_nonempty_strings(scope)),

    -- The consent POLICY version this grant was made under — the text a
    -- customer actually saw. Required: a grant that does not say which
    -- version of the policy it was made against cannot be checked against
    -- that policy later.
    consent_version    text not null check (length(btrim(consent_version)) > 0),

    -- The domain-separated digest of the purpose this grant covers, when the
    -- capturing system supplies one — see the header for why this is
    -- nullable and `purpose_hash ~ '^[0-9a-f]{64}$'` and not a weaker
    -- sibling of migrations/0010's rule.
    purpose_hash       text check (purpose_hash is null or purpose_hash ~ '^[0-9a-f]{64}$'),

    granted_at         timestamptz not null,

    -- How the grant was captured — e.g. `assisted_kiosk`, `mobile_app`. Free
    -- text rather than an enum for the same reason `Institution::org_type`
    -- is a plain string in the evidence record: the channel taxonomy is the
    -- capturing organisation's, and a reader must not fail closed on a
    -- channel invented after this migration.
    granted_via        text not null check (length(btrim(granted_via)) > 0),

    -- Null until revoked. Once set, `consent_grants_guard_revocation` below
    -- makes both columns immutable — see the header.
    revoked_at         timestamptz,
    revocation_reason  text,
    constraint consent_grants_revocation_needs_reason
        check (
            (revoked_at is null and revocation_reason is null)
            or (
                revoked_at is not null
                and revocation_reason is not null
                and length(btrim(revocation_reason)) >= 10
            )
        ),

    created_at         timestamptz not null default now()
);

create index consent_grants_org_user_idx on consent_grants(org_id, user_id);

-- The query enforcement runs on every `issue-wealth-request`: this user's
-- unrevoked grants, most recently granted first. A partial index, because
-- the only grants that query ever wants are the ones `revoked_at is null`.
create index consent_grants_active_idx
    on consent_grants(org_id, user_id, granted_at desc)
    where revoked_at is null;

create or replace function consent_grants_guard_revocation() returns trigger as $$
begin
    if old.revoked_at is not null and new.revoked_at is distinct from old.revoked_at then
        raise exception
            'consent_grants.revoked_at is set exactly once and never changes after that: '
            'revocation is a fact about a moment, not a status a later write may move or clear '
            '(id=%)', old.id;
    end if;
    if old.revoked_at is not null and new.revocation_reason is distinct from old.revocation_reason then
        raise exception
            'consent_grants.revocation_reason cannot change once revocation is recorded (id=%)',
            old.id;
    end if;
    return new;
end;
$$ language plpgsql;

create trigger consent_grants_revocation_is_final
    before update on consent_grants
    for each row
    execute function consent_grants_guard_revocation();

-- ---------------------------------------------------------------------
-- wealth_requests.consent_grant_id — which grant authorised this decision
-- ---------------------------------------------------------------------
-- Snapshotted at open time, exactly as `terms_version` and `vault_root`
-- are (migrations/0007): `issue_wealth_request` resolves the unrevoked
-- grant covering this decision's business process once, at the moment the
-- decision opens, and this column is that resolution's record. A join at
-- read time would answer a different and wrong question — "which grant
-- covers this user today" — when the record must answer "which grant was
-- live when this decision was opened", which is the whole claim `docs/
-- STAGE_PLAN_CONSENT_AND_WITNESS.md` §A3 makes: a revocation refuses the
-- NEXT decision, and does not retroactively unmake ones already opened.
--
-- `on delete set null`, deliberately not `restrict` and not `cascade`.
-- `restrict` would make `consent_grants` un-deletable while any decision
-- cites it, which would block exactly the direct DELETE
-- `test_attack_08_consent_revocation.py` step 4 exists to demonstrate
-- against. `cascade` would delete the wealth decision along with the grant
-- that once authorised it, which destroys evidence a decision was ever
-- reached — the same mistake the header above rejects for revocation
-- itself, one table over. `set null` is the honest answer: the decision's
-- evidence still stands, and now says its consent basis is unpopulated,
-- with a reason naming what happened, while the grant's own binding events
-- (audit/binding.rs) independently and separately report
-- `source_row_missing` to anyone replaying the chain.
alter table wealth_requests
    add column consent_grant_id uuid references consent_grants(id) on delete set null;
