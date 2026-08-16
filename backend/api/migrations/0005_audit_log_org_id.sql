-- Tenant attribution for the audit chain.
--
-- `GET /orgs/:id/audit-log` scoped an org's trail by joining `ref_id` to
-- `disclosure_requests.org_id`. That works for events about a disclosure
-- request and only for those: a product registered, a product's terms
-- amended, a submission rate-limited — none of them name a disclosure
-- request, so none of them could ever appear in a tenant's trail. This
-- column makes attribution a property of the event rather than an accident
-- of what its `ref_id` happens to point at.
--
-- ---------------------------------------------------------------------
-- WHY THIS COLUMN IS NOT PART OF `event_hash`
-- ---------------------------------------------------------------------
-- The tempting move is to fold `org_id` into the hash so the chain commits
-- to it. That would invalidate every row written before this migration:
-- adding a framed component changes the digest of all existing entries, so
-- the whole prior chain would stop verifying — a self-inflicted tamper
-- alarm, and exactly the wrong signal for a compliance log to emit.
--
-- It is also unnecessary. `audit::append_locked` writes `org_id` into the
-- event *payload* before hashing, and the payload is hashed. So the column
-- is a denormalisation of a fact the chain already commits to: an insider
-- who edits this column to hide an event from a tenant's trail leaves the
-- payload — and therefore `event_hash` — disagreeing with it, which anyone
-- holding the payload can detect. The column is an index; the hash is the
-- evidence.
--
-- No foreign key, on purpose. Every referential action available is wrong
-- here: `cascade` deletes regulatory history when a tenant is removed,
-- `set null` mutates rows in an append-only log, and `restrict` makes the
-- log's existence block ordinary tenant lifecycle operations. An audit
-- trail has to be able to outlive the entity it describes.
alter table audit_log add column org_id uuid;
create index audit_log_org_id_idx on audit_log(org_id);

-- Backfill from the convention that was implicit until now. Safe precisely
-- because the column is outside the hash: filling it in does not disturb any
-- stored `event_hash`. Rows written before this migration carry no `org_id`
-- key inside their hashed payload either, so for them the column is the only
-- attribution there is — which is the honest position, not a hidden one.
update audit_log
   set org_id = dr.org_id
  from disclosure_requests dr
 where dr.id = audit_log.ref_id
   and audit_log.org_id is null;
