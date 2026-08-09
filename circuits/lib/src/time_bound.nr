// Time-bound policy enforcement: session windows and freshness checks.
//
// Replay protection (rejecting a reused nonce) is NOT done here. A genuine
// in-circuit non-membership proof against a "used nonces" set is possible
// but heavy (sparse Merkle non-membership with sorted neighbor proofs) and
// is out of scope for this pass. Instead, `nonce` is threaded through as a
// public input on every session circuit's `main` (see circuits/*_session)
// and bound into the policy commitment hash, so the proof is tied to a
// specific nonce; an off-circuit verifier service is responsible for
// rejecting a nonce it has already seen. This matches how replay protection
// is actually done in production ZK session systems.

/// Verify that `current_time` falls within [start_time, expiry_time].
pub fn verify_time_window(current_time: u64, start_time: u64, expiry_time: u64) {
    assert(current_time >= start_time);
    assert(current_time <= expiry_time);
}

/// Verify a session has not expired, allowing an optional grace period.
pub fn verify_session_not_expired(current_time: u64, expiry_time: u64, grace_period: u64) {
    let effective_expiry = expiry_time + grace_period;
    assert(current_time <= effective_expiry);
}

/// Verify a claimed timestamp is within `max_drift_seconds` of `current_time`.
pub fn verify_timestamp_freshness(claimed_time: u64, current_time: u64, max_drift_seconds: u64) {
    let diff = if claimed_time > current_time {
        claimed_time - current_time
    } else {
        current_time - claimed_time
    };
    assert(diff <= max_drift_seconds);
}

/// Verify an emergency session's duration cap from creation time.
pub fn verify_emergency_window(current_time: u64, creation_time: u64, max_duration_seconds: u64) {
    assert(current_time >= creation_time);
    let elapsed = current_time - creation_time;
    assert(elapsed <= max_duration_seconds);
}

#[test]
fn test_time_window() {
    verify_time_window(1723128000, 1723124400, 1723131600);
}

#[test(should_fail)]
fn test_time_window_rejects_expired() {
    verify_time_window(1723140000, 1723124400, 1723131600);
}

#[test]
fn test_session_not_expired_with_grace() {
    verify_session_not_expired(1723131700, 1723131600, 200);
}

#[test(should_fail)]
fn test_session_not_expired_rejects_past_grace() {
    verify_session_not_expired(1723131900, 1723131600, 200);
}

#[test]
fn test_timestamp_freshness() {
    verify_timestamp_freshness(1723128000, 1723128030, 60);
}

#[test(should_fail)]
fn test_timestamp_freshness_rejects_stale() {
    verify_timestamp_freshness(1723128000, 1723128200, 60);
}

#[test]
fn test_emergency_window() {
    verify_emergency_window(1723128000, 1723127400, 3600);
}

#[test(should_fail)]
fn test_emergency_window_rejects_overdue() {
    verify_emergency_window(1723200000, 1723127400, 3600);
}
