// Prometheus metrics, hand-rolled.
//
// No `prometheus` crate. The exposition format is a documented, stable text
// format and this deployment needs exactly three families; a client library
// would bring a registry, a macro layer and a set of process collectors to
// produce output this file produces in a hundred lines. The same reasoning
// that keeps `clients/wealth_client.py` free of a Python Poseidon applies
// here for a duller reason: fewer moving parts between the number and the
// scrape.
//
// -------------------------------------------------------------------
// WHAT IS DELIBERATELY NOT A LABEL
// -------------------------------------------------------------------
// `org_id`, `user_id`, `product_isin`. `/metrics` is conventionally scraped
// without authentication from inside the perimeter, and a per-org label
// turns it into a tenant directory: anyone who can reach the scrape endpoint
// would learn how many banks use this deployment, and — from
// `memtara_proof_verification_total` going up on a specific org — when a
// named competitor is onboarding clients. Cardinality is the usual argument
// against high-cardinality labels; disclosure is the one that decides it
// here.
//
// The consequence is that per-tenant volume is not answerable from
// `/metrics`. It is answerable from the audit log, behind `OrgAuth`, which is
// where a per-tenant fact belongs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::domain::CircuitType;

/// Upper bounds in seconds. Chosen around what `bb verify` actually costs on
/// the circuits in this repo — a wealth-suitability verification lands near
/// 0.1-0.5s on a developer laptop — with a long tail so a pathological run
/// is visible as a distinct bucket rather than lost in `+Inf`.
const LATENCY_BUCKETS: [f64; 9] = [0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

/// One circuit's verification counters and latency histogram.
///
/// Fixed-size arrays rather than a map: the circuit set is closed
/// (`CircuitType`), so there is nothing to allocate, nothing to lock, and no
/// unbounded label growth. Every write is a relaxed atomic add — a metrics
/// update must never be able to slow down or fail the request it is
/// measuring.
#[derive(Default)]
struct CircuitMetrics {
    verified_ok: AtomicU64,
    verified_rejected: AtomicU64,
    /// Infrastructure failure — `bb` missing, I/O error. Counted separately
    /// because it means "we do not know whether the proof was good", which
    /// operationally is nothing like "the proof was bad".
    errored: AtomicU64,
    buckets: [AtomicU64; LATENCY_BUCKETS.len()],
    count: AtomicU64,
    /// Microseconds, summed. Integer accumulation avoids the drift a
    /// repeatedly-added f64 develops over millions of observations.
    sum_micros: AtomicU64,
}

pub enum VerificationResult {
    /// `bb verify` accepted the proof. Note this says nothing about whether
    /// the circuit's *answer* was favourable — see wealth/mod.rs.
    Accepted,
    Rejected,
    Errored,
}

pub struct Metrics {
    circuits: [CircuitMetrics; 5],
}

impl Default for Metrics {
    fn default() -> Self {
        Self { circuits: Default::default() }
    }
}

/// Stable index into the fixed arrays. Matching on the enum (rather than
/// hashing its name) means adding a circuit is a compile error here, not a
/// silent panic on first use.
fn slot(circuit: CircuitType) -> usize {
    match circuit {
        CircuitType::EmergencySession => 0,
        CircuitType::AiSession => 1,
        CircuitType::TaxSession => 2,
        CircuitType::IdentitySession => 3,
        CircuitType::WealthSuitability => 4,
    }
}

const ALL: [CircuitType; 5] = [
    CircuitType::EmergencySession,
    CircuitType::AiSession,
    CircuitType::TaxSession,
    CircuitType::IdentitySession,
    CircuitType::WealthSuitability,
];

impl Metrics {
    /// Record one completed verification attempt. Called from
    /// `verify::run_bb_verify`, which is the only place a proof is actually
    /// checked — so the counter cannot drift from reality by someone adding a
    /// second verification path and forgetting to instrument it.
    pub fn observe_verification(&self, circuit: CircuitType, result: VerificationResult, elapsed: Duration) {
        let m = &self.circuits[slot(circuit)];
        match result {
            VerificationResult::Accepted => m.verified_ok.fetch_add(1, Ordering::Relaxed),
            VerificationResult::Rejected => m.verified_rejected.fetch_add(1, Ordering::Relaxed),
            VerificationResult::Errored => m.errored.fetch_add(1, Ordering::Relaxed),
        };

        let secs = elapsed.as_secs_f64();
        // Cumulative buckets: Prometheus histograms are "count of
        // observations <= le", so every bucket at or above the observation
        // increments. Getting this wrong produces a histogram that renders
        // without complaint and quantiles that are nonsense.
        for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
            if secs <= *bound {
                m.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        m.count.fetch_add(1, Ordering::Relaxed);
        m.sum_micros.fetch_add(elapsed.as_micros().min(u64::MAX as u128) as u64, Ordering::Relaxed);
    }

    /// Render the exposition text. `registry_size` is passed in rather than
    /// held here because it is a fact about the database, not about this
    /// process — reading it at scrape time is what makes it correct after a
    /// restart, and what makes it correct across replicas.
    pub fn render(&self, registry_size: i64) -> String {
        let mut out = String::with_capacity(4096);

        out.push_str("# HELP memtara_proof_verification_total Proof verifications attempted, by circuit and outcome.\n");
        out.push_str("# TYPE memtara_proof_verification_total counter\n");
        for circuit in ALL {
            let m = &self.circuits[slot(circuit)];
            let c = circuit.as_str();
            for (result, value) in [
                ("accepted", m.verified_ok.load(Ordering::Relaxed)),
                ("rejected", m.verified_rejected.load(Ordering::Relaxed)),
                ("error", m.errored.load(Ordering::Relaxed)),
            ] {
                out.push_str(&format!(
                    "memtara_proof_verification_total{{circuit_type=\"{c}\",result=\"{result}\"}} {value}\n"
                ));
            }
        }

        out.push_str("\n# HELP memtara_proof_latency_seconds Wall time of one `bb verify` invocation.\n");
        out.push_str("# TYPE memtara_proof_latency_seconds histogram\n");
        for circuit in ALL {
            let m = &self.circuits[slot(circuit)];
            let c = circuit.as_str();
            for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
                let v = m.buckets[i].load(Ordering::Relaxed);
                out.push_str(&format!(
                    "memtara_proof_latency_seconds_bucket{{circuit_type=\"{c}\",le=\"{bound}\"}} {v}\n"
                ));
            }
            let count = m.count.load(Ordering::Relaxed);
            // The +Inf bucket must equal `_count`, or the series is invalid.
            out.push_str(&format!(
                "memtara_proof_latency_seconds_bucket{{circuit_type=\"{c}\",le=\"+Inf\"}} {count}\n"
            ));
            let sum = m.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
            out.push_str(&format!("memtara_proof_latency_seconds_sum{{circuit_type=\"{c}\"}} {sum}\n"));
            out.push_str(&format!("memtara_proof_latency_seconds_count{{circuit_type=\"{c}\"}} {count}\n"));
        }

        out.push_str("\n# HELP memtara_product_registry_size Structured products registered across all tenants.\n");
        out.push_str("# TYPE memtara_product_registry_size gauge\n");
        out.push_str(&format!("memtara_product_registry_size {registry_size}\n"));

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the exposition text back into `(series, value)` pairs so tests
    /// assert against what a scraper would actually see, rather than against
    /// the atomics behind it.
    fn series(text: &str) -> std::collections::HashMap<String, f64> {
        text.lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .filter_map(|l| l.rsplit_once(' '))
            .map(|(k, v)| (k.to_string(), v.parse().unwrap()))
            .collect()
    }

    #[test]
    fn an_untouched_registry_still_exposes_every_series_at_zero() {
        // A metric that only appears once it has been incremented is a
        // metric no alert can be written against before the first incident.
        let text = Metrics::default().render(0);
        let s = series(&text);
        for circuit in ALL {
            for result in ["accepted", "rejected", "error"] {
                let key =
                    format!("memtara_proof_verification_total{{circuit_type=\"{}\",result=\"{result}\"}}", circuit.as_str());
                assert_eq!(s.get(&key), Some(&0.0), "{key} missing from a cold start");
            }
        }
    }

    #[test]
    fn buckets_are_cumulative_and_inf_equals_count() {
        let m = Metrics::default();
        m.observe_verification(CircuitType::WealthSuitability, VerificationResult::Accepted, Duration::from_millis(80));
        m.observe_verification(CircuitType::WealthSuitability, VerificationResult::Accepted, Duration::from_millis(300));
        m.observe_verification(CircuitType::WealthSuitability, VerificationResult::Rejected, Duration::from_secs(7));

        let s = series(&m.render(0));
        let b = |le: &str| {
            s[&format!("memtara_proof_latency_seconds_bucket{{circuit_type=\"wealth_suitability\",le=\"{le}\"}}")]
        };
        assert_eq!(b("0.05"), 0.0, "nothing was faster than 50ms");
        assert_eq!(b("0.1"), 1.0, "the 80ms observation");
        assert_eq!(b("0.25"), 1.0);
        assert_eq!(b("0.5"), 2.0, "cumulative: 80ms and 300ms");
        assert_eq!(b("10"), 3.0);
        assert_eq!(b("+Inf"), 3.0);

        let count = s["memtara_proof_latency_seconds_count{circuit_type=\"wealth_suitability\"}"];
        assert_eq!(b("+Inf"), count, "+Inf must equal _count or the histogram is invalid");

        let sum = s["memtara_proof_latency_seconds_sum{circuit_type=\"wealth_suitability\"}"];
        assert!((sum - 7.38).abs() < 1e-6, "sum was {sum}");
    }

    #[test]
    fn outcomes_are_counted_separately_per_circuit() {
        let m = Metrics::default();
        m.observe_verification(CircuitType::TaxSession, VerificationResult::Rejected, Duration::from_millis(10));
        m.observe_verification(CircuitType::WealthSuitability, VerificationResult::Errored, Duration::from_millis(10));

        let s = series(&m.render(0));
        assert_eq!(s["memtara_proof_verification_total{circuit_type=\"tax_session\",result=\"rejected\"}"], 1.0);
        assert_eq!(s["memtara_proof_verification_total{circuit_type=\"tax_session\",result=\"error\"}"], 0.0);
        assert_eq!(s["memtara_proof_verification_total{circuit_type=\"wealth_suitability\",result=\"error\"}"], 1.0);
        assert_eq!(s["memtara_proof_verification_total{circuit_type=\"wealth_suitability\",result=\"rejected\"}"], 0.0);
    }

    #[test]
    fn no_series_carries_a_tenant_identifying_label() {
        // The disclosure argument at the top of this file, as a test. A
        // future `org_id="..."` label added for convenience would fail here
        // rather than quietly turning the scrape endpoint into a customer
        // list.
        let m = Metrics::default();
        m.observe_verification(CircuitType::AiSession, VerificationResult::Accepted, Duration::from_millis(1));
        let text = m.render(3);
        for forbidden in ["org_id", "user_id", "product_isin", "isin"] {
            assert!(!text.contains(forbidden), "metrics exposition leaks `{forbidden}`");
        }
    }

    #[test]
    fn registry_size_is_reported_as_given() {
        let s = series(&Metrics::default().render(17));
        assert_eq!(s["memtara_product_registry_size"], 17.0);
    }
}
