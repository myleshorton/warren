# Authenticated DHT records and signaling

**Status:** the pure signed-record primitive and its bounded replay store are
implemented in `swarm::record`; DHT packet carriage, capability issuance, and
authenticated signaling remain to be integrated.

## Problem

The DHT currently derives a node ID from an Ed25519 public key in `driver`, but
the `swarm` packet format carries only that ID. A receiver therefore cannot prove
that a sender owns the public key whose hash is the claimed node ID. Provider
announcements and relayed signaling inherit that gap: a peer can claim another
node ID or replay a once-valid packet.

## Versioned authenticated envelope

Introduce a versioned DHT packet envelope containing:

- the sender's Ed25519 public key and its derived `NodeId`;
- a monotonically increasing, per-sender sequence number;
- an expiry bounded by a protocol maximum;
- the encoded message body; and
- an Ed25519 signature over a domain-separated canonical byte sequence of all
  preceding fields, including protocol version.

Receivers must reject an envelope unless `hash(public_key) == sender_id`, the
signature verifies, the expiry is within bounds, and its sequence number is not
older than the highest accepted value for that sender and record class.

The initial implementation deliberately starts at the mutable-record boundary:
`SignedAnnouncement` signs the topic, public owner key, sequence, expiry, and
write capability under a domain-separated canonical encoding. Its
`AnnouncementStore` verifies before admission, uses the packet's observed source
endpoint rather than peer-supplied endpoint bytes, rejects non-increasing
sequences, and caps retained topics and records per topic. The recipient-owned
`CapabilityIssuer` mints an unpredictable capability scoped to one `(topic,
owner, expiry)` tuple; `accept_authorized` rejects a token copied into another
owner's record, topic, or longer lease. Authenticated DHT nodes now exchange a
bounded capability request and correlated grant before they transmit a signed
record; the real UDP driver supplies a shared Unix-epoch lease clock while the
core remains sans-I/O. Legacy `Dht::new` instances retain the unsigned
announcement path for deterministic compatibility; the production driver uses
identity-backed authenticated mode.

## Record authority and capability

An announce record is owned by its signed sender. A store accepts an update only
when it is authenticated by that owner, has a newer sequence number, and carries
a per-topic write capability minted by the responsible node. The capability is a
rotating, MAC-protected token bound to the topic, owner ID, endpoint, expiry, and
recipient node; it prevents an off-path party from using storage without first
obtaining permission from the responsible node.

Signaling is similarly authenticated end-to-end by both initiator and target.
Coordinators may relay it but cannot modify addresses, firewall declarations, or
the target/initiator binding. Replay caches remain bounded by expiry and a
per-sender cap.

## Compatibility and migration

This is a wire-protocol version bump. The driver must supply the node identity to
the DHT core for signing, while preserving the core's sans-I/O property. During
migration, authenticated nodes may communicate only with the new version; there
is no safe downgrade path for mutable records. The exact capability exchange and
packet fields must be specified alongside golden encoding vectors before code is
merged.

## Resource limits

Validation must occur before allocating variable-length collections. Each node
enforces caps for replay entries, stored topics, records per topic, records per
owner, token lifetime, packets per source prefix, and pending capability state.
