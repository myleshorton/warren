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

use crypto::{hash, Hash};

/// Domain-separation prefix for a leaf hash.
const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for an internal node hash.
const NODE_PREFIX: u8 = 0x01;

/// Hash a block as a Merkle leaf: `H(0x00 ‖ block)`.
pub fn leaf_hash(block: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(1 + block.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(block);
    hash(&buf)
}

/// Hash an internal node from its children: `H(0x01 ‖ left ‖ right)`.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 1 + crypto::HASH_LEN + crypto::HASH_LEN];
    buf[0] = NODE_PREFIX;
    buf[1..1 + crypto::HASH_LEN].copy_from_slice(left);
    buf[1 + crypto::HASH_LEN..].copy_from_slice(right);
    hash(&buf)
}

/// The largest power of two strictly less than `n` (for `n >= 2`).
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
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

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&[i as u8])).collect()
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
    fn distinct_structures_have_distinct_roots() {
        // Domain separation: a two-leaf tree's root is not equal to either leaf.
        let l = leaves(2);
        let root = merkle_root(&l);
        assert_ne!(root, l[0]);
        assert_ne!(root, l[1]);
    }
}
