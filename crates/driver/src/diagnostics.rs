//! Bounded, payload-free observations for applications to export to their collector.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Text(&'static str),
    Count(u64),
    Flag(bool),
}

#[derive(Clone, Debug)]
pub struct Event {
    pub name: &'static str,
    pub operation: u64,
    pub generation: u64,
    pub parent: Option<u64>,
    pub outcome: &'static str,
    pub error_code: &'static str,
    pub elapsed_us: u64,
    pub fields: Vec<(&'static str, Value)>,
}

struct Inner {
    events: broadcast::Sender<Event>,
    sequence: AtomicU64,
    generation: AtomicU64,
}

/// An absent observer is allocation-free. Active observers retain at most 512 events.
#[derive(Clone, Default)]
pub struct Observer(Option<Arc<Inner>>);

impl Observer {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(512);
        Self(Some(Arc::new(Inner {
            events,
            sequence: AtomicU64::new(1),
            generation: AtomicU64::new(0),
        })))
    }

    pub(crate) fn generation(&self, generation: u64) {
        if let Some(inner) = &self.0 {
            inner.generation.store(generation, Ordering::Relaxed);
        }
    }

    pub fn subscribe(&self) -> Option<broadcast::Receiver<Event>> {
        self.0.as_ref().map(|inner| inner.events.subscribe())
    }

    pub fn operation(&self, name: &'static str) -> Operation {
        self.child(name, None)
    }

    pub fn child(&self, name: &'static str, parent: Option<u64>) -> Operation {
        let id = self
            .0
            .as_ref()
            .map_or(0, |inner| inner.sequence.fetch_add(1, Ordering::Relaxed));
        Operation {
            observer: self.clone(),
            name,
            id,
            generation: self
                .0
                .as_ref()
                .map_or(0, |inner| inner.generation.load(Ordering::Relaxed)),
            parent,
            start: Instant::now(),
            fields: Vec::new(),
            finished: false,
        }
    }

    pub fn event(
        &self,
        name: &'static str,
        error_code: &'static str,
        fields: Vec<(&'static str, Value)>,
    ) {
        let mut operation = self.operation(name);
        for (name, value) in fields {
            operation.field(name, value);
        }
        operation.finish(error_code);
    }
}

/// Dropping a pending operation records cancellation, including timeout cancellation.
pub struct Operation {
    observer: Observer,
    name: &'static str,
    id: u64,
    generation: u64,
    parent: Option<u64>,
    start: Instant,
    fields: Vec<(&'static str, Value)>,
    finished: bool,
}

impl Operation {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn child(&self, name: &'static str) -> Self {
        let mut operation = self.observer.child(name, Some(self.id));
        operation.generation = self.generation;
        operation
    }

    pub fn field(&mut self, name: &'static str, value: Value) {
        if self.observer.0.is_some() && self.fields.len() < 16 {
            self.fields.push((name, value));
        }
    }

    /// Empty error code denotes success; codes must be stable, payload-free labels.
    pub fn finish(mut self, error_code: &'static str) {
        self.send(
            if error_code.is_empty() {
                "success"
            } else {
                "error"
            },
            error_code,
        );
        self.finished = true;
    }

    fn send(&mut self, outcome: &'static str, error_code: &'static str) {
        if let Some(inner) = &self.observer.0 {
            let _ = inner.events.send(Event {
                name: self.name,
                operation: self.id,
                generation: self.generation,
                parent: self.parent,
                outcome,
                error_code,
                elapsed_us: self.start.elapsed().as_micros().min(u64::MAX as u128) as u64,
                fields: std::mem::take(&mut self.fields),
            });
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if !self.finished {
            self.send("cancelled", "cancelled");
        }
    }
}

pub fn io_code(error: &std::io::Error) -> &'static str {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::TimedOut => "timeout",
        ErrorKind::InvalidData => "invalid_data",
        ErrorKind::InvalidInput => "invalid_input",
        ErrorKind::PermissionDenied => "permission_denied",
        ErrorKind::NotFound => "not_found",
        ErrorKind::AlreadyExists => "already_exists",
        ErrorKind::AddrInUse => "address_in_use",
        ErrorKind::AddrNotAvailable => "address_unavailable",
        ErrorKind::NetworkUnreachable => "network_unreachable",
        ErrorKind::HostUnreachable => "host_unreachable",
        ErrorKind::ConnectionRefused => "connection_refused",
        ErrorKind::ConnectionReset => "connection_reset",
        ErrorKind::ConnectionAborted => "connection_aborted",
        ErrorKind::BrokenPipe => "closed",
        ErrorKind::UnexpectedEof => "unexpected_eof",
        ErrorKind::WouldBlock => "would_block",
        ErrorKind::Interrupted => "interrupted",
        ErrorKind::WriteZero => "write_zero",
        ErrorKind::OutOfMemory => "out_of_memory",
        _ => "io_other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_and_slow_consumers_are_visible() {
        let observer = Observer::new();
        let mut events = observer.subscribe().unwrap();
        let parent = observer.operation("connect");
        let child = parent.child("handshake");
        let id = parent.id();
        drop(child);
        parent.finish("timeout");
        let cancelled = events.recv().await.unwrap();
        assert_eq!(cancelled.parent, Some(id));
        assert_eq!(cancelled.outcome, "cancelled");
        assert_eq!(events.recv().await.unwrap().error_code, "timeout");
        for _ in 0..600 {
            observer.operation("request").finish("");
        }
        assert!(matches!(
            events.recv().await,
            Err(broadcast::error::RecvError::Lagged(88))
        ));
    }
}
