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
}
