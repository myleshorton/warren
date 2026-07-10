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
/// the root of a pending perfect subtree of height `h` (i.e. `2^h` leaves); the
/// set peaks are exactly the ones at the set bits of the leaf count, and there are
/// at most `log2(n)` of them — so `push` and `root` are O(log n), not O(n).
#[derive(Clone, Default)]
pub struct Accumulator {
    peaks: Vec<Option<Hash>>,
}

impl Accumulator {
    /// An accumulator over zero leaves.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one leaf hash. Carries equal-height peaks upward like a binary
    /// counter: a new leaf is a height-0 peak; whenever a peak already occupies a
    /// height, the two combine (older on the left, as in the tree) into one peak a
    /// height up, and the carry continues.
    pub fn push(&mut self, leaf: Hash) {
        let mut carry = leaf;
        let mut height = 0;
        loop {
            match self.peaks.get_mut(height) {
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
                    }
                },
            }
        }
    }

    /// The Merkle root over all pushed leaves — identical to [`merkle_root`] of the
    /// same leaves (`H("")` for none). Folds the peaks largest-first, matching
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
