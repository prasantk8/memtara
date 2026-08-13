-- audit_log needs a real total order to determine "the last row" when
-- appending to the hash chain (audit/mod.rs). `created_at` (timestamptz)
-- resolution is not fine enough to guarantee this under the chain's
-- advisory-lock-serialized but potentially rapid concurrent inserts: two
-- lock-serialized inserts can land within the same clock tick, and the
-- previous tiebreak (id desc) falls back to a random UUID, which has no
-- relationship to true insertion order. A bigserial column is backed by a
-- Postgres sequence, whose nextval() allocation is strictly increasing and
-- unique regardless of timestamp resolution or transaction timing — it
-- matches the true lock-serialized insertion sequence exactly.
alter table audit_log add column seq bigserial;
create unique index audit_log_seq_idx on audit_log(seq);
