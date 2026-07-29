# Authenticated DHT records and signaling

**Status:** proposed wire-format change; not implemented.

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
