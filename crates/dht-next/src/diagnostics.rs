//! Opt-in wall-clock profiling for synchronous core calls on the current thread.
//! Counters aggregate all DHT instances on that thread. Never enable for latency
//! comparisons with uninstrumented implementations; use a separate profiling run.
use std::cell::Cell;
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum Region {
    Sign,
    Verify,
    Handshake,
    Seal,
    Open,
    ValueKey,
}
pub const REGIONS: [Region; 6] = [
    Region::Sign,
    Region::Verify,
    Region::Handshake,
    Region::Seal,
    Region::Open,
    Region::ValueKey,
];
#[derive(Clone, Copy, Debug, Default)]
pub struct Sample {
    pub calls: u64,
    pub nanos: u64,
}
thread_local! {
    static COUNTERS: Cell<[Sample; 6]> = const { Cell::new([Sample { calls: 0, nanos: 0 }; 6]) };
}
pub fn take() -> [Sample; 6] {
    COUNTERS.replace([Sample::default(); 6])
}
pub(crate) struct Span(Region, Instant);
pub(crate) fn span(region: Region) -> Span {
    Span(region, Instant::now())
}
impl Drop for Span {
    fn drop(&mut self) {
        let nanos = self.1.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        COUNTERS.with(|cell| {
            let mut samples = cell.get();
            let sample = &mut samples[self.0 as usize];
            sample.calls = sample.calls.saturating_add(1);
            sample.nanos = sample.nanos.saturating_add(nanos);
            cell.set(samples);
        });
    }
}
