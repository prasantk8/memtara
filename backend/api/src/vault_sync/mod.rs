// Vault sync: pure ciphertext plumbing. The backend never decrypts the
// vault, never sees plaintext, never generates proofs from it — this
// module's entire job is storing/retrieving the client-encrypted blob plus
// the Poseidon commitment (`vault_root`) the client computed over it, with
// optimistic concurrency so multi-device sync can't silently clobber a
// write it never saw.
//
// Schema is `vault_blobs` (migrations/0001_init.sql), owned by the schema
// pass — not touched here.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Ceiling on the encrypted blob's size. The vault is a client-side
/// identity record (names, IDs, a handful of documents' worth of fields),
/// not a file store — a few hundred KB is a realistic upper bound even for
/// a vault with many disclosure-relevant records. 8 MiB leaves generous
/// headroom over that while still bounding worst-case request body size
/// (memory held per in-flight request, row bloat in Postgres, and time
/// spent on a single connection) so a buggy or malicious client can't push
/// an unbounded blob through this endpoint.
const MAX_CIPHERTEXT_BYTES: usize = 8 * 1024 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/vault", get(get_vault).put(put_vault).delete(delete_vault))
        .route("/vault/root", get(get_vault_root))
}

fn decode_b64(field: &str, value: &str) -> ApiResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::BadRequest(format!("{field} is not valid base64 (expected URL-safe, no padding)")))
}

fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

// ---------------------------------------------------------------------
// GET /vault
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct VaultResponse {
    ciphertext: String,
    vault_root: String,
    version: i64,
    updated_at: DateTime<Utc>,
}

async fn get_vault(AuthUser(user_id): AuthUser, State(state): State<AppState>) -> ApiResult<Json<VaultResponse>> {
    let row = sqlx::query!(
        r#"
        select ciphertext, vault_root, version, updated_at
        from vault_blobs
        where user_id = $1
        "#,
        user_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(VaultResponse {
        ciphertext: encode_b64(&row.ciphertext),
        vault_root: encode_b64(&row.vault_root),
        version: row.version,
        updated_at: row.updated_at,
    }))
}

// ---------------------------------------------------------------------
// GET /vault/root
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct VaultRootResponse {
    vault_root: String,
    version: i64,
}

async fn get_vault_root(
    AuthUser(user_id): AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<VaultRootResponse>> {
    let row = sqlx::query!(
        r#"
        select vault_root, version
        from vault_blobs
        where user_id = $1
        "#,
        user_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(VaultRootResponse {
        vault_root: encode_b64(&row.vault_root),
        version: row.version,
    }))
}

// ---------------------------------------------------------------------
// PUT /vault
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct PutVaultBody {
    ciphertext: String,
    vault_root: String,
    expected_version: i64,
}

#[derive(Serialize)]
struct PutVaultResponse {
    version: i64,
    updated_at: DateTime<Utc>,
}

/// Optimistic-concurrency write. Multiple devices may hold the same user's
/// session; each must prove (via `expected_version`) that it last read the
/// version it's about to overwrite, or the write is rejected as a conflict
/// rather than silently clobbering a sibling device's sync.
///
/// The compare-and-swap has no check-then-write race window: the "row
/// exists" update is a single `UPDATE ... WHERE user_id = $1 AND version =
/// $2`, and rows-affected tells us atomically (as evaluated by Postgres,
/// not two round trips from us) whether the version matched. The
/// "first-ever sync" path uses `INSERT ... ON CONFLICT DO NOTHING`, which
/// is likewise a single atomic statement, so two concurrent first syncs
/// can't both believe they created row version 1.
async fn put_vault(
    AuthUser(user_id): AuthUser,
    State(state): State<AppState>,
    Json(body): Json<PutVaultBody>,
) -> ApiResult<Json<PutVaultResponse>> {
    let ciphertext = decode_b64("ciphertext", &body.ciphertext)?;
    let vault_root = decode_b64("vault_root", &body.vault_root)?;

    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(ApiError::BadRequest(format!(
            "ciphertext exceeds max size of {MAX_CIPHERTEXT_BYTES} bytes"
        )));
    }
    if body.expected_version < 0 {
        return Err(ApiError::BadRequest("expected_version must not be negative".into()));
    }

    if body.expected_version == 0 {
        // Caller believes no row exists yet. Insert at version 1;
        // ON CONFLICT DO NOTHING means a racing first-sync from another
        // device loses this insert (0 rows affected) rather than
        // clobbering whichever one won, and we report it the same way as
        // any other stale-version conflict below.
        let inserted = sqlx::query!(
            r#"
            insert into vault_blobs (user_id, ciphertext, vault_root, version, updated_at)
            values ($1, $2, $3, 1, now())
            on conflict (user_id) do nothing
            returning version, updated_at
            "#,
            user_id,
            ciphertext,
            vault_root,
        )
        .fetch_optional(&state.db)
        .await?;

        return match inserted {
            Some(row) => Ok(Json(PutVaultResponse {
                version: row.version,
                updated_at: row.updated_at,
            })),
            None => Err(ApiError::Conflict(
                "a vault already exists for this account; re-fetch GET /vault to get the current version \
                 before writing"
                    .into(),
            )),
        };
    }

    // Row is expected to already exist at exactly `expected_version`.
    let updated = sqlx::query!(
        r#"
        update vault_blobs
        set ciphertext = $1,
            vault_root = $2,
            version = version + 1,
            updated_at = now()
        where user_id = $3 and version = $4
        returning version, updated_at
        "#,
        ciphertext,
        vault_root,
        user_id,
        body.expected_version,
    )
    .fetch_optional(&state.db)
    .await?;

    match updated {
        Some(row) => Ok(Json(PutVaultResponse {
            version: row.version,
            updated_at: row.updated_at,
        })),
        None => {
            // Either the version was stale, or no row exists at all
            // (caller sent a nonzero expected_version for a vault that was
            // never created, or was deleted). Both are "you don't have
            // the state you think you have" — re-fetch and retry.
            Err(ApiError::Conflict(
                "expected_version does not match the current stored version; re-fetch GET /vault and retry".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------
// DELETE /vault
// ---------------------------------------------------------------------

async fn delete_vault(AuthUser(user_id): AuthUser, State(state): State<AppState>) -> ApiResult<StatusCode> {
    sqlx::query!("delete from vault_blobs where user_id = $1", user_id)
        .execute(&state.db)
        .await?;
    // Idempotent by design: whether a row existed or not, the caller's
    // post-condition ("no vault stored for me") now holds.
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_round_trips_urlsafe_nopad() {
        let bytes = vec![0u8, 1, 2, 253, 254, 255];
        let encoded = encode_b64(&bytes);
        assert!(!encoded.contains('='), "no padding chars");
        assert!(!encoded.contains('+'), "no standard-base64 chars");
        let decoded = decode_b64("x", &encoded).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn b64_rejects_garbage() {
        assert!(decode_b64("ciphertext", "not base64 at all!!").is_err());
    }

    mod db {
        use super::*;
        use sqlx::postgres::PgPoolOptions;
        use sqlx::PgPool;
        use uuid::Uuid;

        /// These tests hit a live Postgres (same DB the app migrates
        /// against) to exercise the actual atomic UPDATE/INSERT statements
        /// rather than re-implementing their logic in-process. Skips
        /// (rather than fails) if DATABASE_URL isn't reachable, so `cargo
        /// test` still passes in an environment with no DB configured.
        async fn test_pool() -> Option<PgPool> {
            let url = std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://memtara:memtara@localhost:5433/memtara".into());
            PgPoolOptions::new().max_connections(3).connect(&url).await.ok()
        }

        async fn make_user(db: &PgPool) -> Uuid {
            sqlx::query_scalar!(
                r#"insert into users (email) values ($1) returning id"#,
                format!("vault-sync-test-{}@example.invalid", Uuid::new_v4()),
            )
            .fetch_one(db)
            .await
            .expect("insert test user")
        }

        async fn cleanup(db: &PgPool, user_id: Uuid) {
            let _ = sqlx::query!("delete from vault_blobs where user_id = $1", user_id)
                .execute(db)
                .await;
            let _ = sqlx::query!("delete from users where id = $1", user_id).execute(db).await;
        }

        #[tokio::test]
        async fn first_sync_requires_expected_version_zero_and_creates_version_one() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let user_id = make_user(&db).await;

            let inserted = sqlx::query!(
                r#"
                insert into vault_blobs (user_id, ciphertext, vault_root, version, updated_at)
                values ($1, $2, $3, 1, now())
                on conflict (user_id) do nothing
                returning version
                "#,
                user_id,
                b"ciphertext-v1".to_vec(),
                b"root-v1".to_vec(),
            )
            .fetch_optional(&db)
            .await
            .unwrap();

            assert_eq!(inserted.map(|r| r.version), Some(1));
            cleanup(&db, user_id).await;
        }

        #[tokio::test]
        async fn stale_expected_version_is_rejected_and_row_is_unchanged() {
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let user_id = make_user(&db).await;

            sqlx::query!(
                r#"insert into vault_blobs (user_id, ciphertext, vault_root, version) values ($1, $2, $3, 1)"#,
                user_id,
                b"original".to_vec(),
                b"root0".to_vec(),
            )
            .execute(&db)
            .await
            .unwrap();

            // Device A writes with the correct expected_version (1) and
            // should succeed, bumping to version 2.
            let a = sqlx::query!(
                r#"
                update vault_blobs
                set ciphertext = $1, vault_root = $2, version = version + 1, updated_at = now()
                where user_id = $3 and version = $4
                returning version
                "#,
                b"device-a-write".to_vec(),
                b"root-a".to_vec(),
                user_id,
                1i64,
            )
            .fetch_optional(&db)
            .await
            .unwrap();
            assert_eq!(a.map(|r| r.version), Some(2), "correct expected_version must succeed and bump version");

            // Device B, which also last saw version 1 (it never observed
            // A's write), retries the same CAS. This must be rejected —
            // proving the concurrency control actually blocks a stale
            // writer rather than last-write-wins clobbering A's data.
            let b = sqlx::query!(
                r#"
                update vault_blobs
                set ciphertext = $1, vault_root = $2, version = version + 1, updated_at = now()
                where user_id = $3 and version = $4
                returning version
                "#,
                b"device-b-stale-write".to_vec(),
                b"root-b".to_vec(),
                user_id,
                1i64,
            )
            .fetch_optional(&db)
            .await
            .unwrap();
            assert!(b.is_none(), "stale expected_version must affect zero rows, not clobber the newer write");

            // The row must still hold device A's write, untouched by B's
            // rejected attempt.
            let row = sqlx::query!(
                "select ciphertext, version from vault_blobs where user_id = $1",
                user_id,
            )
            .fetch_one(&db)
            .await
            .unwrap();
            assert_eq!(row.ciphertext, b"device-a-write".to_vec());
            assert_eq!(row.version, 2);

            // Device B re-fetches (as the API tells it to), sees version
            // 2, and retries with the now-correct expected_version — this
            // must succeed.
            let retry = sqlx::query!(
                r#"
                update vault_blobs
                set ciphertext = $1, vault_root = $2, version = version + 1, updated_at = now()
                where user_id = $3 and version = $4
                returning version
                "#,
                b"device-b-retry".to_vec(),
                b"root-b2".to_vec(),
                user_id,
                2i64,
            )
            .fetch_optional(&db)
            .await
            .unwrap();
            assert_eq!(retry.map(|r| r.version), Some(3), "retry with correct expected_version must succeed");

            cleanup(&db, user_id).await;
        }

        #[tokio::test]
        async fn concurrent_cas_writes_only_one_winner_survives() {
            // Fires N concurrent UPDATE...WHERE version=$expected attempts
            // at the same starting version from separate pool connections,
            // simulating N devices racing on the same stale read. Exactly
            // one must win (rows_affected == 1 for exactly one), proving
            // there is no check-then-write race window in the CAS itself.
            let Some(db) = test_pool().await else {
                eprintln!("skipping: no DB reachable");
                return;
            };
            let user_id = make_user(&db).await;

            sqlx::query!(
                r#"insert into vault_blobs (user_id, ciphertext, vault_root, version) values ($1, $2, $3, 1)"#,
                user_id,
                b"original".to_vec(),
                b"root0".to_vec(),
            )
            .execute(&db)
            .await
            .unwrap();

            let mut handles = Vec::new();
            for i in 0..8u8 {
                let db = db.clone();
                handles.push(tokio::spawn(async move {
                    sqlx::query!(
                        r#"
                        update vault_blobs
                        set ciphertext = $1, vault_root = $2, version = version + 1, updated_at = now()
                        where user_id = $3 and version = 1
                        "#,
                        vec![i],
                        vec![i],
                        user_id,
                    )
                    .execute(&db)
                    .await
                    .unwrap()
                    .rows_affected()
                }));
            }

            let mut total_winners = 0u64;
            for h in handles {
                total_winners += h.await.unwrap();
            }
            assert_eq!(total_winners, 1, "exactly one of N racing writers at the same expected_version must win");

            let row = sqlx::query!("select version from vault_blobs where user_id = $1", user_id)
                .fetch_one(&db)
                .await
                .unwrap();
            assert_eq!(row.version, 2, "version must have advanced by exactly one step total");

            cleanup(&db, user_id).await;
        }
    }
}
