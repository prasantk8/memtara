-- The product registry: a bank's catalogue of structured products, and the
-- suitability terms each one is sold against.
--
-- Before this table existed, `POST /api/v1/issue-wealth-request` took
-- `min_income`, `min_liquidity`, `max_concentration_percent` and
-- `product_risk_level` straight from the caller. That was safe against the
-- *client* — `wealth::submit_wealth_proof` compares every submitted public
-- input against the terms the request was opened with, so the holder can
-- never pick their own thresholds — but it was not safe against the *advisor*.
-- Whoever holds the org API key could open an assessment with
-- `min_income = 0` and receive a cryptographically impeccable proof that the
-- client clears a bar nobody set. The terms have to come from somewhere the
-- person making the recommendation does not control, and this is that place.
--
-- ---------------------------------------------------------------------
-- WHY `(org_id, product_isin)` AND NOT `product_isin` AS THE KEY
-- ---------------------------------------------------------------------
-- The commissioning brief specifies `product_isin` as the primary key. That
-- makes the registry global across tenants, with three consequences that all
-- bite in a deployment serving more than one bank:
--
--   1. Two banks cannot both list the same instrument. Widely-distributed
--      notes are precisely the products several banks sell at once.
--   2. Whoever registers an ISIN first fixes the terms every other bank's
--      assessments are measured against.
--   3. `GET /api/v1/products/{isin}` would answer with another tenant's
--      product governance — the minimum income a competitor requires is a
--      commercially sensitive fact.
--
-- So the key is scoped to the org, with a surrogate `id` so the row can be
-- referenced from `wealth_requests` and named as an audit `ref_id`.
create table products (
    id                        uuid primary key default gen_random_uuid(),
    org_id                    uuid not null references organizations(id) on delete cascade,

    -- ISO 6166 identifier. Structure is enforced at the API boundary
    -- (products::isin); the check digit is computed and logged but not
    -- enforced — see that module for why, and for the specific illustrative
    -- identifier that fails it.
    product_isin              text not null,
    product_name              text not null,

    risk_level                smallint not null check (risk_level between 1 and 5),
    min_income                bigint   not null check (min_income >= 0),
    min_liquidity             bigint   not null check (min_liquidity >= 0),
    max_concentration_percent smallint not null check (max_concentration_percent between 0 and 100),

    -- Product governance. Not decoration: `issue-wealth-request` refuses to
    -- open an assessment against a product this flag is false for. A
    -- suitability assessment against an unapproved instrument is worse than
    -- no assessment, because it produces evidence that a controlled process
    -- was followed when it wasn't.
    approved_by_risk_committee boolean not null default false,

    created_at                timestamptz not null default now(),
    updated_at                timestamptz not null default now(),

    unique (org_id, product_isin)
);
create index products_org_id_idx on products(org_id);

-- Provenance for the evidence pack: which registry row supplied the terms
-- this assessment was measured against.
--
-- Nullable, and deliberately NOT `on delete cascade`. `wealth_requests`
-- already snapshots the terms themselves (that is the whole point of those
-- columns), so a request stays fully self-describing if the product is later
-- retired or its terms revised. This column adds "and here is the catalogue
-- entry it came from" without making the evidence depend on that entry
-- surviving unchanged.
alter table wealth_requests add column product_id uuid references products(id) on delete set null;

-- Snapshotted for the same reason as the terms: the case file and the
-- injected advisor claim both name the product, and a product renamed after
-- an assessment must not retroactively rename it in the evidence.
alter table wealth_requests add column product_name text;
