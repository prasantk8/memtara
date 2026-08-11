-- Memtara backend — initial schema.
-- Design note: the backend stores encrypted vault blobs and vault roots
-- opaquely (vault_blobs) and never plaintext record values or witnesses —
-- proof generation happens client-side. See ARCHITECTURE.md and
-- backend plan (docs/journeys.md) for the trust model this schema encodes.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------

create table users (
    id              uuid primary key default gen_random_uuid(),
    phone_e164      text unique,
    email           text unique,
    uae_pass_sub    text unique,
    display_name    text,
    created_at      timestamptz not null default now(),
    constraint users_has_identifier check (
        phone_e164 is not null or email is not null or uae_pass_sub is not null
    )
);

-- One row per registered passkey (a user may register several devices).
create table webauthn_credentials (
    id              uuid primary key default gen_random_uuid(),
    user_id         uuid not null references users(id) on delete cascade,
    credential_id   bytea not null unique,
    public_key      bytea not null,
    sign_count      bigint not null default 0,
    device_name     text,
    created_at      timestamptz not null default now(),
    last_used_at    timestamptz
);
create index webauthn_credentials_user_id_idx on webauthn_credentials(user_id);

-- WhatsApp/SMS OTP fallback for login and recovery.
create table otp_codes (
    id              uuid primary key default gen_random_uuid(),
    user_id         uuid not null references users(id) on delete cascade,
    code_hash       text not null,
    channel         text not null check (channel in ('sms', 'whatsapp')),
    attempts        int not null default 0,
    expires_at      timestamptz not null,
    consumed_at     timestamptz,
    created_at      timestamptz not null default now()
);
create index otp_codes_user_id_idx on otp_codes(user_id);

-- Opaque, revocable session tokens (not JWTs — see backend plan for why).
create table sessions (
    id              uuid primary key default gen_random_uuid(),
    user_id         uuid not null references users(id) on delete cascade,
    device_id       uuid,
    token_hash      text not null unique,
    created_at      timestamptz not null default now(),
    expires_at      timestamptz not null,
    revoked_at      timestamptz
);
create index sessions_user_id_idx on sessions(user_id);
create index sessions_token_hash_idx on sessions(token_hash);

-- ---------------------------------------------------------------------
-- Vault (opaque to the server)
-- ---------------------------------------------------------------------

create table vault_blobs (
    user_id         uuid primary key references users(id) on delete cascade,
    ciphertext      bytea not null,
    vault_root      bytea not null,
    version         bigint not null default 1,
    updated_at      timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- Relying parties (banks, AI platforms, hospitals, government counters)
-- ---------------------------------------------------------------------

create table organizations (
    id              uuid primary key default gen_random_uuid(),
    name            text not null,
    org_type        text not null check (org_type in ('bank', 'ai_platform', 'hospital', 'government')),
    api_key_hash    text not null unique,
    created_at      timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- Disclosure requests, proofs, and replay protection
-- ---------------------------------------------------------------------

create table disclosure_requests (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references organizations(id) on delete cascade,
    user_id         uuid not null references users(id) on delete cascade,
    circuit_type    text not null check (
        circuit_type in ('emergency_session', 'ai_session', 'tax_session', 'identity_session')
    ),
    policy          jsonb not null,
    status          text not null default 'pending' check (
        status in ('pending', 'fulfilled', 'expired', 'revoked')
    ),
    nonce           bytea not null,
    expires_at      timestamptz not null,
    created_at      timestamptz not null default now()
);
create index disclosure_requests_user_id_idx on disclosure_requests(user_id);
create index disclosure_requests_org_id_idx on disclosure_requests(org_id);
create unique index disclosure_requests_org_nonce_idx on disclosure_requests(org_id, nonce);

create table proofs (
    id              uuid primary key default gen_random_uuid(),
    request_id      uuid not null references disclosure_requests(id) on delete cascade,
    public_inputs   jsonb not null,
    proof_bytes     bytea not null,
    valid           boolean not null,
    verified_at     timestamptz not null default now()
);
create index proofs_request_id_idx on proofs(request_id);

-- The off-circuit replay registry: circuits/lib/src/time_bound.nr threads a
-- nonce through as a public input instead of an in-circuit non-membership
-- proof; this table is the verifier-side registry that decision depends on.
create table used_nonces (
    org_id          uuid not null references organizations(id) on delete cascade,
    nonce           bytea not null,
    used_at         timestamptz not null default now(),
    primary key (org_id, nonce)
);

-- ---------------------------------------------------------------------
-- Audit trail
-- ---------------------------------------------------------------------

create table audit_log (
    id              uuid primary key default gen_random_uuid(),
    event_type      text not null,
    ref_id          uuid,
    event_hash      bytea not null,
    prev_hash       bytea,
    created_at      timestamptz not null default now()
);
create index audit_log_ref_id_idx on audit_log(ref_id);
create index audit_log_created_at_idx on audit_log(created_at);
