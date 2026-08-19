-- `model_config_fingerprint` must be a digest at the row level, not only at
-- the API boundary.
--
-- ---------------------------------------------------------------------
-- WHY THIS IS A SEPARATE MIGRATION AND NOT AN EDIT TO 0006
-- ---------------------------------------------------------------------
-- Same rule 0002 followed when it added `seq` to `audit_log`: an applied
-- migration is history and editing it makes two databases that ran the same
-- numbered file disagree about what it did. This is a new file.
--
-- ---------------------------------------------------------------------
-- THE INCONSISTENCY IT CLOSES
-- ---------------------------------------------------------------------
-- 0006 created `decision_model_attestations` with three digest-shaped
-- columns and constrained two of them:
--
--     input_context_fingerprint text check (... ~ '^[0-9a-f]{64}$')
--     output_fingerprint        text check (... ~ '^[0-9a-f]{64}$')
--     model_config_fingerprint  text                       -- unconstrained
--
-- `model_intake::parse_digest` validates all three identically on the way
-- in, so through the API the three behave the same. They do not behave the
-- same to anyone holding a connection string, which is the actor every
-- finding in `docs/BREAK_IT_FINDINGS.md` is about. A direct write can put
-- `temperature=0`, an empty string, or a sentence under a column named
-- `..._fingerprint`.
--
-- That matters more than a malformed value usually would, because of what
-- the name promises. `parse_digest`'s own error text says it: a value under
-- a name ending in `_fingerprint` reads to an examiner as a commitment they
-- can recompute. A column that accepts things which are not digests is
-- making that promise without keeping it, and the reader who discovers this
-- is the one who tried to verify a configuration and could not.
--
-- Found by the engineer building the correction path (0009), who
-- constrained the equivalent column there and reported the asymmetry rather
-- than quietly matching the weaker side.
--
-- ---------------------------------------------------------------------
-- WHAT THIS DOES NOT CLAIM
-- ---------------------------------------------------------------------
-- Shape, not truth. A well-formed 64-character hex string that is the digest
-- of nothing in particular still passes, and no constraint available here
-- could tell the difference — the configuration it fingerprints lives in the
-- calling system, which this repository has no access to. The value of the
-- check is narrow and worth stating narrowly: it removes the case where a
-- reader cannot even tell whether a recomputation was ever possible.
--
-- Verified before writing this: zero existing rows violate it, so the
-- constraint is added validated rather than NOT VALID. A NOT VALID
-- constraint would leave exactly the rows this is about unchecked, which is
-- the wrong trade for a table with a handful of pilot rows in it.

alter table decision_model_attestations
    add constraint decision_model_attestations_config_fingerprint_is_a_digest
    check (
        model_config_fingerprint is null
        or model_config_fingerprint ~ '^[0-9a-f]{64}$'
    );
