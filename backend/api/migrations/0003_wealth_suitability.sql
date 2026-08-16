-- Structured-product suitability (DFSA Conduct of Business 3.1).
--
-- Adds the fifth circuit and the per-request terms that a suitability
-- assessment is measured against.

-- The check constraint is unnamed in 0001_init.sql, so Postgres generated
-- `<table>_<column>_check`. Dropping by that generated name is safe here
-- (this is the only check on the column) but `if exists` keeps the migration
-- from failing on a database where it was already renamed by hand.
alter table disclosure_requests drop constraint if exists disclosure_requests_circuit_type_check;
alter table disclosure_requests add constraint disclosure_requests_circuit_type_check check (
    circuit_type in (
        'emergency_session',
        'ai_session',
        'tax_session',
        'identity_session',
        'wealth_suitability'
    )
);

-- The terms a suitability request was opened against.
--
-- These live in their own table rather than inside `disclosure_requests.policy`
-- for one reason that matters: they are not decoration, they are what the
-- submitted public inputs get checked against. A client that could pick its
-- own `min_income` at submission time could prove suitability for any product
-- by proving it against a threshold of zero. `wealth::submit_wealth_proof`
-- compares every one of these columns to the corresponding public input
-- before it will mint a token, so they need to be columns with types, not
-- fields inside a jsonb blob that deserializes as whatever it happens to
-- contain.
--
-- `on delete cascade`: a suitability request has no meaning without the
-- disclosure request it belongs to.
create table wealth_requests (
    request_id                uuid primary key references disclosure_requests(id) on delete cascade,

    -- ISO 6166 identifier for the structured product, e.g. XS1234567890.
    -- Not secret; stored so it can be echoed into the proof token and the
    -- audit trail, which is what ties a recommendation to a product.
    product_isin              text not null,

    -- 32-byte big-endian field element: the ISIN digest bound into the
    -- circuit's `product_ref` public input and into the policy commitment
    -- the client signs. Derived, but stored rather than recomputed so a
    -- future change to the derivation cannot silently invalidate requests
    -- that are already in flight.
    product_ref               bytea not null,

    -- The product's published suitability terms. bigint for the money
    -- figures (the circuit takes u64; bigint is the widest exact integer
    -- Postgres offers and covers every realistic AED value), smallint for
    -- the two 1-100 / 1-5 scales.
    min_income                bigint   not null check (min_income >= 0),
    min_liquidity             bigint   not null check (min_liquidity >= 0),
    max_concentration_percent smallint not null check (max_concentration_percent between 0 and 100),
    product_risk_level        smallint not null check (product_risk_level between 1 and 5),

    -- Copied from the disclosure request at creation so the exact window the
    -- client must prove inside is recoverable without a join, and so the
    -- circuit's `start_time`/`expiry_time` witnesses have a server-side
    -- reference to be checked against.
    window_start              timestamptz not null,
    window_end                timestamptz not null,

    -- The assessment's outcome, written when a proof is accepted. Null while
    -- the request is outstanding. Recorded even when false: DFSA COB 3.1
    -- obliges the firm to have assessed, not to have approved, and a
    -- declined recommendation needs its evidence too.
    suitable                  boolean,
    assessed_at               timestamptz,

    created_at                timestamptz not null default now()
);
create index wealth_requests_isin_idx on wealth_requests(product_isin);
