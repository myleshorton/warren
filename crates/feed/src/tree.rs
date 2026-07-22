//! A binary Merkle tree over log blocks, following the RFC 6962 (Certificate
//! Transparency) tree structure but hashed with BLAKE3.
//!
//! The structure is defined for *any* number of leaves (not just powers of two)
//! and is stable as the log grows, which is what lets a peer verify a single
//! block against a signed root without holding the whole log:
//!
//! - a leaf is `H(0x00 ‖ block)`,
//! - an internal node is `H(0x01 ‖ left ‖ right)`,
//! - a tree of `n > 1` leaves splits at the largest power of two `k < n`, with
//!   the first `k` leaves on the left and the rest on the right.
//!
//! The domain-separating `0x00`/`0x01` prefixes stop a leaf from being reused as
//! an internal node (a second-preimage defense, as in RFC 6962).
//!
//! Functions here are pure and take the leaves as a slice, so the recursive
//! definition doubles as the oracle the property tests check against.

use crypto::{hash, hash_parts, Hash};

/// Domain-separation prefix for a leaf hash.
const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for an internal node hash.
const NODE_PREFIX: u8 = 0x01;

/// Hash a block as a Merkle leaf: `H(0x00 ‖ block)`. Streams the tag and block
/// into the hasher rather than copying the (possibly large) block to prepend the
/// tag.
pub fn leaf_hash(block: &[u8]) -> Hash {
    hash_parts(&[&[LEAF_PREFIX], block])
}

/// Hash an internal node from its children: `H(0x01 ‖ left ‖ right)`.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    hash_parts(&[&[NODE_PREFIX], left, right])
}

/// The stable flat-tree index of the node at `height` covering the leaf range
/// `[offset·2^height, (offset+1)·2^height)` (mafintosh `flat-tree` numbering). A leaf
/// (`height = 0`, `offset = i`) is `2i`; the index never changes as the tree grows, so
/// it's the persistent key for a frozen node. Only called for real tree nodes, so the
/// shift can't overflow (`height ≤ log₂(len) < 64`).
fn node_index(height: u32, offset: u64) -> u64 {
    (offset << (height + 1)) + (1 << height) - 1
}

/// The largest power of two strictly less than `n` (for `n >= 2`).
///
/// Computed in constant time from the bit width: doubling `k` in a loop would
/// overflow `usize` to 0 for `n > 2^63` and spin forever — and `n` can come
/// from an attacker-signed head, so this must never hang on a huge length.
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    // The highest set bit of `n - 1` is `floor(log2(n - 1))`; `1 << that` is the
    // largest power of two `<= n - 1`, i.e. `< n`.
    let highest_bit = usize::BITS - 1 - (n - 1).leading_zeros();
    1usize << highest_bit
}

/// The Merkle root over `leaves` (each already a [`leaf_hash`]). An empty tree
/// hashes to `H("")`, matching RFC 6962's empty-tree definition.
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => hash(&[]),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// The inclusion (audit) path for leaf `index` in a tree of `leaves`: the sibling
/// hashes from the leaf up to the root, deepest sibling first. Returns an empty
/// path for a single-leaf tree. Panics if `index` is out of range.
pub fn audit_path(leaves: &[Hash], index: usize) -> Vec<Hash> {
    assert!(index < leaves.len(), "leaf index out of range");
    let n = leaves.len();
    if n == 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if index < k {
        let mut path = audit_path(&leaves[..k], index);
        path.push(merkle_root(&leaves[k..]));
        path
    } else {
        let mut path = audit_path(&leaves[k..], index - k);
        path.push(merkle_root(&leaves[..k]));
        path
    }
}

/// Reconstruct the root from a leaf hash and its audit `path`, for leaf `index`
/// in a tree of `len` leaves. Returns `None` if the path length doesn't match
/// the tree shape (so a malformed proof can't be coerced into a root).
pub fn root_from_path(leaf: Hash, index: usize, len: usize, path: &[Hash]) -> Option<Hash> {
    if index >= len {
        return None;
    }
    if len == 1 {
        return path.is_empty().then_some(leaf);
    }
    // The audit path lists siblings deepest-first, so the topmost sibling is
    // last — split it off and recurse into the half that holds the leaf.
    let (top_sibling, rest) = path.split_last()?;
    let k = split_point(len);
    if index < k {
        let left = root_from_path(leaf, index, k, rest)?;
        Some(node_hash(&left, top_sibling))
    } else {
        let right = root_from_path(leaf, index - k, len - k, rest)?;
        Some(node_hash(top_sibling, &right))
    }
}

/// An incremental Merkle accumulator: the right-spine subtree roots ("peaks") of
/// an append-only RFC 6962 tree, so the [`root`](Accumulator::root) is maintained
/// as leaves are pushed instead of recomputed from scratch. `peaks[h]`, if set, is
/// the root of a pending perfect subtree of height `h` (i.e. `2^h` leaves). There
/// is one peak per set bit of the leaf count — at most `floor(log2 n) + 1` of them
/// — so `push` and `root` are O(log n), not O(n).
#[derive(Clone, Default)]
pub struct Accumulator {
    peaks: Vec<Option<Hash>>,
    /// Total leaves pushed — the feed length, and the basis for addressing frozen nodes.
    count: u64,
}

impl Accumulator {
    /// An accumulator over zero leaves.
    pub fn new() -> Self {
        Self::default()
    }

    /// Leaves pushed so far.
    // Consumed by Log/Replica in the Phase-B wiring step (they drop their own leaf count).
    #[allow(dead_code)]
    pub fn len(&self) -> u64 {
        self.count
    }

    /// Append one leaf hash, returning the nodes **frozen** by this push — the leaf plus
    /// any internal node completed as equal-height peaks carry upward — each as its
    /// `(flat-tree index, hash)`, ready to persist. Carries like a binary counter: a new
    /// leaf is a height-0 peak; whenever a peak already occupies a height, the two combine
    /// (older on the left, as in the tree) into one peak a height up, and the carry
    /// continues.
    pub fn push(&mut self, leaf: Hash) -> Vec<(u64, Hash)> {
        let index = self.count; // 0-based index of this leaf
        let mut frozen = vec![(index * 2, leaf)]; // the leaf node lives at flat index 2·index
        let mut carry = leaf;
        let mut height = 0u32;
        loop {
            match self.peaks.get_mut(height as usize) {
                None => {
                    self.peaks.push(Some(carry));
                    break;
                }
                Some(slot) => match slot.take() {
                    None => {
                        *slot = Some(carry);
                        break;
                    }
                    // `existing` covers earlier leaves than `carry`, so it's the left.
                    Some(existing) => {
                        carry = node_hash(&existing, &carry);
                        height += 1;
                        // The merged node (now at `height`) covers the last 2^height leaves,
                        // ending at this leaf — a complete perfect subtree, now frozen.
                        let offset = ((index + 1) >> height) - 1;
                        frozen.push((node_index(height, offset), carry));
                    }
                },
            }
        }
        self.count += 1;
        frozen
    }

    /// The Merkle root over all pushed leaves — identical to [`merkle_root`] of the
    /// same leaves (`H("")` for none). Iterating the peaks smallest-height first
    /// and making each (larger) peak the left child of the running node yields
    /// RFC 6962's `node(largest_subtree, node(next, …))` shape.
    pub fn root(&self) -> Hash {
        let mut acc: Option<Hash> = None;
        // `peaks` is smallest-height first; each present peak is larger than the
        // ones already folded, so it becomes the left of the combined node.
        for peak in self.peaks.iter().flatten() {
            acc = Some(match acc {
                None => *peak,
                Some(smaller) => node_hash(peak, &smaller),
            });
        }
        acc.unwrap_or_else(|| hash(&[]))
    }

    /// The inclusion path for leaf `index`, assembled from persisted frozen nodes (read
    /// via `get`, keyed by [`node_index`]) plus the in-RAM peaks — **identical** to
    /// [`audit_path`] over the same leaves, but O(log n) reads instead of O(n) recompute,
    /// and without holding the leaves. `None` if `index` is out of range or a needed node
    /// is missing from the store.
    ///
    /// Two parts, deepest-first: (1) leaf `index` up to its peak, whose siblings are all
    /// frozen perfect-subtree nodes read from `get`; then (2) the peak-bagging siblings —
    /// for a leaf in peak `j` (peaks ordered largest-first, right-recursively bagged into
    /// the root), the bag of every peak right of `j`, then peaks `j-1 … 0`.
    // Consumed by Log/Replica in the Phase-B wiring step (they proof from the store, not leaves).
    #[allow(dead_code)]
    pub fn proof(&self, index: u64, get: impl Fn(u64) -> Option<Hash>) -> Option<Vec<Hash>> {
        if index >= self.count {
            return None;
        }
        // Peaks in root order (largest height first) with each one's base leaf offset.
        let mut peaks: Vec<(u32, Hash, u64)> = self
            .peaks
            .iter()
            .enumerate()
            .rev()
            .filter_map(|(h, slot)| slot.map(|hash| (h as u32, hash, 0u64)))
            .collect();
        let mut base = 0u64;
        for p in peaks.iter_mut() {
            p.2 = base;
            base += 1u64 << p.0;
        }
        // Which peak holds `index`?
        let j = peaks
            .iter()
            .position(|&(h, _, b)| index >= b && index < b + (1u64 << h))?;

        let mut path = Vec::new();
        // (1) Within the peak: sibling at each level d is the adjacent 2^d-block (flip the
        // low bit of the block offset), a frozen node addressed globally.
        for d in 0..peaks[j].0 {
            let sibling = (index >> d) ^ 1;
            path.push(get(node_index(d, sibling))?);
        }
        // (2a) Bag the peaks right of j (smaller, rightmost-first): node(p_{j+1}, node(…)).
        let mut bag: Option<Hash> = None;
        for &(_, hash, _) in peaks[j + 1..].iter().rev() {
            bag = Some(match bag {
                None => hash,
                Some(rest) => node_hash(&hash, &rest),
            });
        }
        if let Some(bag) = bag {
            path.push(bag);
        }
        // (2b) The peaks left of j, nearest first (p_{j-1} … p_0).
        for k in (0..j).rev() {
            path.push(peaks[k].1);
        }
        Some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&[i as u8])).collect()
    }

    #[test]
    fn accumulator_root_matches_from_scratch_at_every_size() {
        // The incrementally-maintained root must equal the recursive oracle for
        // every leaf count, including 0 (empty) and non-powers-of-two.
        let mut acc = Accumulator::new();
        let mut ls: Vec<Hash> = Vec::new();
        assert_eq!(acc.root(), merkle_root(&ls));
        for i in 0..100u32 {
            let leaf = leaf_hash(&i.to_le_bytes());
            acc.push(leaf);
            ls.push(leaf);
            assert_eq!(
                acc.root(),
                merkle_root(&ls),
                "mismatch at {} leaves",
                ls.len()
            );
        }
    }

    #[test]
    fn store_backed_proof_is_identical_to_audit_path() {
        // The Phase-B acceptance criterion: a proof assembled from persisted frozen nodes
        // (collected as `push` freezes them) plus the in-RAM peaks must be BYTE-IDENTICAL
        // to the recursive `audit_path` oracle, for every length and every leaf — and must
        // verify against the root. This is what guarantees roots/proofs are unchanged.
        // Exhaustive to 128 — covers heights 0–7, every peak-count combination, and
        // non-power-of-two lengths. (Verified once up to 512; the oracle is O(n²), so the
        // committed bound stays small enough for CI.)
        use std::collections::HashMap;
        for n in 1..=128u64 {
            let mut acc = Accumulator::new();
            let mut nodes: HashMap<u64, Hash> = HashMap::new();
            let mut ls: Vec<Hash> = Vec::new();
            for i in 0..n {
                let leaf = leaf_hash(&i.to_le_bytes());
                for (idx, hash) in acc.push(leaf) {
                    nodes.insert(idx, hash);
                }
                ls.push(leaf);
            }
            let root = merkle_root(&ls);
            for i in 0..n {
                let got = acc
                    .proof(i, |idx| nodes.get(&idx).copied())
                    .expect("in-range proof exists");
                let want = audit_path(&ls, i as usize);
                assert_eq!(got, want, "store proof != audit_path at n={n} i={i}");
                assert_eq!(
                    root_from_path(ls[i as usize], i as usize, n as usize, &got),
                    Some(root),
                    "store proof fails to verify at n={n} i={i}"
                );
            }
        }
    }

    #[test]
    fn store_proof_out_of_range_is_none() {
        let mut acc = Accumulator::new();
        acc.push(leaf_hash(b"only"));
        assert!(
            acc.proof(1, |_| None).is_none(),
            "index == len is out of range"
        );
        assert_eq!(
            acc.proof(0, |_| None),
            Some(Vec::new()),
            "a single-leaf proof is empty and reads no nodes"
        );
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let l = leaves(1);
        assert_eq!(merkle_root(&l), l[0]);
        assert!(audit_path(&l, 0).is_empty());
    }

    #[test]
    fn every_leaf_proof_reconstructs_the_root() {
        for n in 1..=33 {
            let l = leaves(n);
            let root = merkle_root(&l);
            for i in 0..n {
                let path = audit_path(&l, i);
                assert_eq!(root_from_path(l[i], i, n, &path), Some(root), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn a_wrong_leaf_does_not_reconstruct_the_root() {
        let l = leaves(8);
        let root = merkle_root(&l);
        let path = audit_path(&l, 3);
        // A different leaf at the same position yields a different root.
        let bogus = leaf_hash(b"not the block");
        assert_ne!(root_from_path(bogus, 3, 8, &path), Some(root));
    }

    #[test]
    fn a_truncated_path_is_rejected() {
        let l = leaves(8);
        let mut path = audit_path(&l, 3);
        path.pop();
        assert_eq!(root_from_path(l[3], 3, 8, &path), None);
    }

    #[test]
    fn split_point_is_the_largest_power_of_two_below_n() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(9), 8);
        // Large values must not overflow into an endless loop.
        assert_eq!(split_point(1usize << 63), 1usize << 62);
        assert_eq!(split_point((1usize << 63) + 1), 1usize << 63);
        assert_eq!(split_point(usize::MAX), 1usize << (usize::BITS - 1));
    }

    #[test]
    fn root_from_path_terminates_on_a_huge_length() {
        // A forged head can carry a length near usize::MAX; verification must
        // return (here, reject) rather than hang splitting the range.
        let leaf = leaf_hash(b"x");
        let path = [leaf_hash(b"sibling")];
        assert_eq!(root_from_path(leaf, 0, usize::MAX, &path), None);
    }

    #[test]
    fn distinct_structures_have_distinct_roots() {
        // Domain separation: a two-leaf tree's root is not equal to either leaf.
        let l = leaves(2);
        let root = merkle_root(&l);
        assert_ne!(root, l[0]);
        assert_ne!(root, l[1]);
    }
}
