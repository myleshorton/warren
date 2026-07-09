//! A small AIMD congestion window for pacing a sender's fragments.
//!
//! Sending every fragment of a large message back-to-back bursts the network and
//! self-inflicts loss. This bounds a burst to a *window* of fragments and adapts
//! that window the way TCP/QUIC do — grow while deliveries are clean (doubling in
//! slow start, then +1 per round in congestion avoidance), halve on loss — using
//! the transport's NACKs as the loss signal.
//!
//! It is **sans-IO**: pure window arithmetic, no clock and no sockets, so the
//! control law is unit-tested directly. `Wire` reads [`Congestion::window`] to
//! size each burst and feeds it [`Congestion::on_delivered`] /
//! [`Congestion::on_loss`] as responses settle.
//!
//! Alongside it, [`Rtt`] tracks a smoothed round-trip time so the sender can
//! pace a window's worth of fragments across one RTT (a fragment every
//! `srtt / window`) rather than by a fixed gap — fast on a short path, gentle on
//! a long one.

use std::time::Duration;

/// Initial window, in fragments (à la TCP's IW10).
const INIT_WINDOW: usize = 10;
/// Never shrink below this — a window of one can still make progress, but two
/// keeps a little pipelining even at the worst loss.
const MIN_WINDOW: usize = 2;
/// Cap the window so a single burst stays bounded (here ~64 * 1200 B ≈ 77 KiB)
/// however long loss stays away.
const MAX_WINDOW: usize = 64;

/// An AIMD congestion window over fragment counts.
#[derive(Debug)]
pub struct Congestion {
    cwnd: usize,
    /// Slow-start threshold: below it the window doubles per clean round, at or
    /// above it it grows by one (congestion avoidance).
    ssthresh: usize,
}

impl Congestion {
    /// A fresh window: `INIT_WINDOW`, in slow start (ssthresh effectively ∞).
    pub fn new() -> Self {
        Self {
            cwnd: INIT_WINDOW,
            ssthresh: usize::MAX,
        }
    }

    /// The current window: how many fragments to send before pausing. Always in
    /// `[MIN_WINDOW, MAX_WINDOW]`.
    pub fn window(&self) -> usize {
        self.cwnd
    }

    /// A response was delivered without drawing a NACK: grow the window —
    /// doubling in slow start, +1 in congestion avoidance — capped at
    /// `MAX_WINDOW`.
    pub fn on_delivered(&mut self) {
        self.cwnd = if self.cwnd < self.ssthresh {
            self.cwnd.saturating_mul(2)
        } else {
            self.cwnd + 1
        }
        .min(MAX_WINDOW);
    }

    /// A response drew a NACK (loss): set the slow-start threshold to half the
    /// window and drop to it — AIMD's multiplicative decrease — flooring at
    /// `MIN_WINDOW`.
    pub fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(MIN_WINDOW);
        self.cwnd = self.ssthresh;
    }
}

impl Default for Congestion {
    fn default() -> Self {
        Self::new()
    }
}

/// Absolute backstop on the smoothed RTT, in case a caller passes an enormous
/// `request_timeout`. The effective cap is the smaller of this and the caller's
/// bound; real RTTs are far below either.
const MAX_RTT: Duration = Duration::from_secs(1);

/// A smoothed round-trip-time estimate (EWMA, TCP's α = 1/8). Fed samples by the
/// sender — the gap between finishing a reply and the peer's next request — and
/// read to pace fragments over one RTT.
///
/// The estimate is capped at `max` (the caller passes `request_timeout`, min'd
/// with [`MAX_RTT`]) so a stalled peer that inflates a sample can't push the
/// pacing gap past the receiver's stall interval — which would turn pacing into
/// spurious NACKs. With the cap, a fragment is spaced at most `cap / window`
/// apart, always comfortably under `request_timeout`.
#[derive(Debug)]
pub struct Rtt {
    srtt: Duration,
    max: Duration,
    /// Whether a real sample has landed yet. The first one *replaces* the assumed
    /// initial (RFC 6298), so the estimate snaps to the actual path immediately
    /// instead of crawling there from a wrong guess; later samples are smoothed.
    sampled: bool,
}

impl Rtt {
    /// Start from an assumed RTT (used until the first real sample lands), capping
    /// the estimate at `max` (the caller's `request_timeout`, itself bounded by
    /// [`MAX_RTT`]).
    pub fn new(initial: Duration, max: Duration) -> Self {
        let max = max.min(MAX_RTT);
        Self {
            srtt: initial.min(max),
            max,
            sampled: false,
        }
    }

    /// The current smoothed RTT.
    pub fn get(&self) -> Duration {
        self.srtt
    }

    /// Fold in a new round-trip sample: the first replaces the assumed initial;
    /// later ones smooth as `srtt = 7/8 srtt + 1/8 sample`. Capped at `max`.
    pub fn sample(&mut self, rtt: Duration) {
        self.srtt = if self.sampled {
            (self.srtt * 7 + rtt) / 8
        } else {
            self.sampled = true;
            rtt
        }
        .min(self.max);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_the_initial_window() {
        assert_eq!(Congestion::new().window(), INIT_WINDOW);
    }

    #[test]
    fn slow_start_doubles_until_the_cap() {
        let mut c = Congestion::new();
        assert_eq!(c.window(), 10);
        c.on_delivered();
        assert_eq!(c.window(), 20);
        c.on_delivered();
        assert_eq!(c.window(), 40);
        c.on_delivered();
        assert_eq!(c.window(), MAX_WINDOW); // 80 capped to 64
        c.on_delivered();
        assert_eq!(c.window(), MAX_WINDOW); // stays capped
    }

    #[test]
    fn loss_halves_then_grows_linearly() {
        let mut c = Congestion::new();
        for _ in 0..5 {
            c.on_delivered(); // ramp to the cap
        }
        assert_eq!(c.window(), MAX_WINDOW); // 64
        c.on_loss();
        assert_eq!(c.window(), 32); // multiplicative decrease
                                    // now at/above ssthresh (32): congestion avoidance, +1 per round
        c.on_delivered();
        assert_eq!(c.window(), 33);
        c.on_delivered();
        assert_eq!(c.window(), 34);
    }

    #[test]
    fn the_window_never_drops_below_the_floor() {
        let mut c = Congestion::new();
        for _ in 0..20 {
            c.on_loss(); // hammer it down
        }
        assert!(c.window() >= MIN_WINDOW);
        assert_eq!(c.window(), MIN_WINDOW);
    }

    #[test]
    fn repeated_loss_keeps_it_at_the_floor_not_below() {
        let mut c = Congestion::new();
        c.on_loss();
        let after_one = c.window();
        c.on_loss();
        assert!(c.window() <= after_one);
        assert!(c.window() >= MIN_WINDOW);
    }

    // A generous cap for the tests that aren't about capping.
    const NO_CAP: Duration = Duration::from_secs(10);

    #[test]
    fn rtt_starts_at_the_initial_estimate() {
        assert_eq!(
            Rtt::new(Duration::from_millis(100), NO_CAP).get(),
            Duration::from_millis(100)
        );
    }

    #[test]
    fn rtt_first_sample_replaces_then_later_ones_smooth() {
        let mut r = Rtt::new(Duration::from_millis(100), NO_CAP);
        // The first sample snaps the estimate to the measured path (not smoothed
        // against the assumed 100ms).
        r.sample(Duration::from_millis(200));
        assert_eq!(r.get(), Duration::from_millis(200));
        // The next smooths: 7/8*200 + 1/8*40 = 180ms.
        r.sample(Duration::from_millis(40));
        assert_eq!(r.get(), Duration::from_millis(180));
    }

    #[test]
    fn rtt_converges_on_a_steady_path() {
        let mut r = Rtt::new(Duration::from_millis(100), NO_CAP);
        for _ in 0..50 {
            r.sample(Duration::from_millis(20));
        }
        // Should have converged close to the steady 20ms.
        let got = r.get();
        assert!(
            got >= Duration::from_millis(20) && got <= Duration::from_millis(22),
            "srtt {got:?} should be ~20ms"
        );
    }

    #[test]
    fn rtt_is_capped_at_the_configured_max() {
        // The estimate never exceeds the cap (derived from request_timeout), even
        // when a stalled peer produces absurd samples.
        let cap = Duration::from_millis(200);
        assert_eq!(Rtt::new(Duration::from_secs(30), cap).get(), cap); // capped up front
        let mut r = Rtt::new(Duration::from_millis(50), cap);
        for _ in 0..100 {
            r.sample(Duration::from_secs(60));
        }
        assert!(r.get() <= cap);
    }

    #[test]
    fn rtt_max_is_bounded_by_the_absolute_backstop() {
        // An enormous request_timeout is still clamped by MAX_RTT.
        assert_eq!(
            Rtt::new(Duration::from_secs(30), Duration::from_secs(600)).get(),
            MAX_RTT
        );
    }
}
