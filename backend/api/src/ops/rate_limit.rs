// A fixed-window rate limiter, in process memory.
//
// -------------------------------------------------------------------
// WHAT IT IS FOR, AND WHAT IT IS NOT FOR
// -------------------------------------------------------------------
// `POST /api/v1/submit-wealth-proof` spawns `bb verify`, which is orders of
// magnitude more expensive than every other operation this server performs —
// a subprocess, a proving-system verifier, hundreds of milliseconds of CPU.
// Ten of those per user per minute is generous for the real journey (one
// assessment, one proof) and ruinous for anyone trying to make the server do
// arithmetic on their behalf.
//
// So this limiter exists to bound *expensive work*, not to be a security
// boundary. Three consequences worth stating plainly rather than discovering:
//
//   1. It is per process. Two replicas behind a load balancer permit 2N, not
//      N. The brief sanctioned "simple in-memory or Redis-backed"; this is
//      the in-memory one, and swapping the `Limiter` trait for a Redis
//      implementation is the whole change required. Until then, a deployment
//      that needs a true global limit needs it at the edge.
//   2. It is keyed on the resolved `user_id`, which the caller does not
//      choose — it comes from the disclosure request named in the body. A
//      caller-supplied key would let anyone reset their own bucket.
//   3. It runs *after* one indexed row lookup, because that lookup is what
//      resolves the key. That lookup is therefore not itself protected here.
//      That is the correct division: bounding a primary-key SELECT is the
//      edge's job, and bounding a proving-system subprocess is ours.
//
// Fixed window rather than sliding: a sliding window's fairness at the
// boundary is not worth per-request timestamp lists here, and a burst of at
// most 2N across a window boundary is well inside the headroom of a limit
// chosen to stop sustained abuse.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Decision {
    pub allowed: bool,
    /// Requests left in the current window. Reported to the caller as
    /// `X-RateLimit-Remaining` so a well-behaved client can back off before
    /// it is refused rather than after.
    pub remaining: u32,
    /// Seconds until the window rolls. Becomes `Retry-After` on a refusal —
    /// a 429 without one just invites an immediate retry.
    pub reset_after_seconds: u64,
}

struct Window {
    started: Instant,
    count: u32,
}

pub struct RateLimiter {
    limit: u32,
    window: Duration,
    /// One lock over the whole map. The critical section is a hash lookup
    /// and an integer increment, and the alternative — sharding, or a
    /// lock-free map — buys contention headroom this endpoint will never
    /// need, since every request behind it is about to spend a hundred
    /// milliseconds in a subprocess anyway.
    windows: Mutex<HashMap<String, Window>>,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self { limit, window, windows: Mutex::new(HashMap::new()) }
    }

    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Count one request against `key` and say whether it may proceed.
    ///
    /// A refused request does NOT increment the counter beyond the limit.
    /// That matters: if it did, a client hammering the endpoint would hold
    /// its own window open indefinitely, turning a rate limit into a
    /// self-inflicted lockout that outlasts the abuse.
    pub fn check(&self, key: &str) -> Decision {
        let now = Instant::now();
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());

        // Opportunistic eviction of windows that have rolled. Without it the
        // map grows one entry per distinct user forever, which for a
        // long-lived process is a slow leak rather than a bounded cache.
        // Doing it here — rather than on a timer — keeps the whole limiter
        // free of background tasks.
        if windows.len() > 1024 {
            windows.retain(|_, w| now.duration_since(w.started) < self.window);
        }

        let entry = windows.entry(key.to_string()).or_insert(Window { started: now, count: 0 });
        if now.duration_since(entry.started) >= self.window {
            entry.started = now;
            entry.count = 0;
        }

        let elapsed = now.duration_since(entry.started);
        let reset_after_seconds = self.window.saturating_sub(elapsed).as_secs() + 1;

        if entry.count >= self.limit {
            return Decision { allowed: false, remaining: 0, reset_after_seconds };
        }

        entry.count += 1;
        Decision {
            allowed: true,
            remaining: self.limit.saturating_sub(entry.count),
            reset_after_seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_n_requests_pass_and_the_next_one_does_not() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        assert!(rl.check("user-a").allowed);
        assert!(rl.check("user-a").allowed);
        let third = rl.check("user-a");
        assert!(third.allowed);
        assert_eq!(third.remaining, 0, "the last permitted request must say so");

        let fourth = rl.check("user-a");
        assert!(!fourth.allowed);
        assert!(fourth.reset_after_seconds > 0, "a 429 without a Retry-After just invites an immediate retry");
    }

    #[test]
    fn one_users_limit_does_not_touch_another() {
        // Sounds obvious; is the bug that turns a rate limiter into an
        // outage, because the first tenant to get busy locks out everyone.
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        assert!(rl.check("user-a").allowed);
        assert!(!rl.check("user-a").allowed);
        assert!(rl.check("user-b").allowed, "user-b has its own budget");
    }

    #[test]
    fn refusals_do_not_extend_the_window() {
        // The self-lockout property. A client that keeps hammering after
        // being refused must still be served the moment the window rolls,
        // not pushed further out by its own retries.
        let rl = RateLimiter::new(1, Duration::from_millis(80));
        assert!(rl.check("k").allowed);
        for _ in 0..50 {
            assert!(!rl.check("k").allowed);
        }
        std::thread::sleep(Duration::from_millis(100));
        assert!(rl.check("k").allowed, "the window must roll despite the refused traffic");
    }

    #[test]
    fn the_window_rolls_and_the_budget_comes_back_whole() {
        let rl = RateLimiter::new(2, Duration::from_millis(60));
        assert!(rl.check("k").allowed);
        assert!(rl.check("k").allowed);
        assert!(!rl.check("k").allowed);

        std::thread::sleep(Duration::from_millis(80));
        let after = rl.check("k");
        assert!(after.allowed);
        assert_eq!(after.remaining, 1, "a rolled window restores the full budget, not a partial one");
    }

    #[test]
    fn concurrent_callers_never_exceed_the_limit_in_aggregate() {
        // The property that actually matters under load: whatever
        // interleaving the threads take, the number of allowed requests is
        // exactly the limit — never limit+1 from a lost update.
        use std::sync::Arc;
        let rl = Arc::new(RateLimiter::new(10, Duration::from_secs(60)));
        let allowed = Arc::new(std::sync::atomic::AtomicU32::new(0));

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let rl = Arc::clone(&rl);
                let allowed = Arc::clone(&allowed);
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        if rl.check("contended").allowed {
                            allowed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(allowed.load(std::sync::atomic::Ordering::SeqCst), 10, "400 racing requests, 10 allowed");
    }

    #[test]
    fn stale_windows_are_evicted_rather_than_accumulating_forever() {
        let rl = RateLimiter::new(1, Duration::from_millis(1));
        for i in 0..2000 {
            rl.check(&format!("user-{i}"));
        }
        let len = rl.windows.lock().unwrap().len();
        assert!(len < 2000, "expected eviction to have run; map held {len} entries");
    }
}
