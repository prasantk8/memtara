-- Two evidence fields that already had a value in this system and no name.
--
--   policy.thresholds.threshold_version — the thresholds were versioned by
--     `updated_at` and an audit diff, which means "which version applied to
--     this assessment" could only be answered by replaying the chain.
--   data.customer.data_provenance.vault_root — the value exists on every
--     wealth proof as circuit public input 2, is checked against the user's
--     registered root before the proof is accepted, and was then discarded.
--
-- Neither needs new data. Both need somewhere to be written down at the
-- moment they are true.

-- =====================================================================
-- products.terms_version — a monotonic version for the threshold set
-- =====================================================================
--
-- ---------------------------------------------------------------------
-- WHY A TRIGGER AND NOT AN INCREMENT IN `amend_product`
-- ---------------------------------------------------------------------
-- The obvious wiring is `set terms_version = terms_version + 1` inside the
-- PATCH handler. Two reasons this is better in the database:
--
--   1. The version is then a property of the row changing, not of the code
--      path that changed it. A backfill script, a migration, a DBA fixing a
--      mis-keyed minimum by hand — every one of those changes what an
--      assessment would be measured against, and every one of them bypasses
--      a handler. A threshold version that only counts the changes made
--      politely is not a version.
--   2. It cannot drift. There is exactly one definition of "the terms
--      changed", written once, next to the columns it is about.
--
-- The bump is conditional on the four columns that are actually compared
-- against a proof's public inputs. Renaming a product or flipping its
-- risk-committee approval is a governance event — audited, and rightly so —
-- but it does not change what an assessment measures, and a version number
-- that moved for it would tell an examiner an assessment ran against
-- different thresholds when it did not.
alter table products add column terms_version integer not null default 1;

create or replace function bump_product_terms_version() returns trigger as $$
begin
    if new.risk_level                is distinct from old.risk_level
    or new.min_income                is distinct from old.min_income
    or new.min_liquidity             is distinct from old.min_liquidity
    or new.max_concentration_percent is distinct from old.max_concentration_percent then
        new.terms_version := old.terms_version + 1;
    else
        -- Explicit rather than implicit: an UPDATE that names
        -- `terms_version` directly must not be able to set it backwards or
        -- hold it still across a real terms change.
        new.terms_version := old.terms_version;
    end if;
    return new;
end;
$$ language plpgsql;

create trigger products_terms_version_bump
    before update on products
    for each row
    execute function bump_product_terms_version();

-- =====================================================================
-- wealth_requests.terms_version — the snapshot
-- =====================================================================
--
-- Same discipline as the four threshold columns beside it, and for the same
-- reason: the assessment must stay reproducible after the product is
-- amended. The version is copied at open time, not joined at read time — a
-- join would report today's version against a proof measured under last
-- month's, which is precisely the misstatement this column exists to
-- prevent.
--
-- Nullable, and NOT backfilled. Assessments opened before this migration
-- were genuinely measured against an unversioned threshold set; writing `1`
-- into them would be inventing a fact. They carry `threshold_version` as an
-- explicit `unpopulated` in the evidence record instead, which is the true
-- statement.
alter table wealth_requests add column terms_version integer;

-- =====================================================================
-- wealth_requests.vault_root — the provenance anchor
-- =====================================================================
--
-- `submit_wealth_proof` already refuses any proof whose `vault_root` public
-- input differs from the root the holder registered
-- (`vault_blobs.vault_root`). So by the time this column is written the
-- value has been checked twice: bound into the circuit, and compared to the
-- server's record.
--
-- Written at submission, not at open, and snapshotted rather than joined:
-- `vault_blobs.vault_root` is a live column that moves every time the holder
-- syncs. An evidence record that resolved it by join would quote the root
-- the client holds *today* as the one the assessment was computed against —
-- which is a false statement in signed bytes, and worse than the empty field
-- it replaced.
--
-- Null until assessed. That absence is honest and legible: an assessment
-- that was opened and never answered has no root to anchor, because no proof
-- was ever computed.
alter table wealth_requests add column vault_root bytea;
