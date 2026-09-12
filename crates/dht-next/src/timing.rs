//! RTT estimation and caller-supplied clocks. No clock is read inside the core.

/// Local deadlines use monotonic milliseconds; signed leases use Unix seconds.
#[derive(Clone, Copy, Debug)]
pub struct Time {
    pub monotonic_ms: u64,
    pub unix_secs: u64,
}
impl Time {
    pub const fn new(monotonic_ms: u64, unix_secs: u64) -> Self {
        Self {
            monotonic_ms,
            unix_secs,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Rtt {
    mean: Option<u64>,
    variation: u64,
    timeout: u64,
}
impl Default for Rtt {
    fn default() -> Self {
        Self {
            mean: None,
            variation: 0,
            timeout: 500,
        }
    }
}
impl Rtt {
    pub fn timeout(&self) -> u64 {
        self.timeout
    }
    pub fn observe(&mut self, sample: u64) {
        let sample = sample.clamp(1, 8000);
        if let Some(mean) = self.mean {
            self.variation = (3 * self.variation + mean.abs_diff(sample)) / 4;
            self.mean = Some((7 * mean + sample) / 8);
        } else {
            self.mean = Some(sample);
            self.variation = sample / 2;
        }
        self.timeout = (self.mean.unwrap() + 4 * self.variation).clamp(200, 4000);
    }
    // Karn's rule: don't interpret a retransmitted reply as a fresh RTT sample.
    // Preserve the backed-off interval until an unambiguous response is measured.
    pub fn ambiguous(&mut self, interval: u64) {
        self.timeout = self.timeout.max(interval).min(4000);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clean_samples_adapt_both_up_and_down() {
        let mut rtt = Rtt::default();
        for _ in 0..20 {
            rtt.observe(40);
        }
        assert_eq!(rtt.timeout(), 200);
        for _ in 0..20 {
            rtt.observe(800);
        }
        assert!(rtt.timeout() >= 800);
        for _ in 0..60 {
            rtt.observe(40);
        }
        assert_eq!(rtt.timeout(), 200);
    }
    #[test]
    fn ambiguous_replies_preserve_backoff_without_fabricating_a_sample() {
        let mut rtt = Rtt::default();
        rtt.observe(40);
        rtt.ambiguous(1600);
        assert_eq!(rtt.timeout(), 1600);
        assert_eq!(rtt.mean, Some(40));
        rtt.observe(40);
        assert_eq!(rtt.timeout(), 200);
    }
}
