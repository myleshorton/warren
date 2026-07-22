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
use std::collections::BTreeSet;

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

/// The height of the peak (perfect subtree) containing leaf `index` in a feed of `len`
/// leaves — the peaks being the set bits of `len`, largest (leftmost) first.
fn peak_height(len: u64, index: u64) -> u32 {
    let mut base = 0u64;
    for height in (0..u64::BITS).rev() {
        if (len >> height) & 1 == 0 {
            continue;
        }
        if index >= base && index < base + (1u64 << height) {
            return height;
        }
        base += 1u64 << height;
    }
    0 // index out of range — caller shouldn't reach this
}

/// Split a received audit `proof` for leaf `index` (in a feed of `len` leaves) into the
/// **within-peak** sibling nodes it should persist, as `(flat index, hash)`.
///
/// These are the frozen, stable part of a proof — the first `height(peak(index))` siblings,
/// whose flat indices are the same ones [`Accumulator::proof`] reads. A sparse holder
/// stores them so it can re-serve this block's proof later. The remaining (bagging)
/// siblings are length-dependent — derived from the peaks — so they are dropped here rather
/// than persisted under a flat index they don't stably own.
pub fn proof_nodes(len: u64, index: u64, proof: &[Hash]) -> Vec<(u64, Hash)> {
    let within = peak_height(len, index) as usize;
    proof
        .iter()
        .take(within)
        .enumerate()
        .map(|(d, hash)| (node_index(d as u32, (index >> d) ^ 1), *hash))
        .collect()
}

/// The flat indices of the **within-peak** audit-path nodes for leaf `index` in a feed of
/// `len` leaves — the frozen sibling nodes a holder must keep to re-serve this block's proof
/// (the bagging siblings come from the peaks, so they're never persisted). The index-only
/// twin of [`proof_nodes`]: same `node_index(d, (index >> d) ^ 1)` walk, without the hashes.
/// Used by GC to decide which nodes a retained block still needs.
fn within_peak_indices(len: u64, index: u64) -> impl Iterator<Item = u64> {
    let within = peak_height(len, index);
    (0..within).map(move |d| node_index(d, (index >> d) ^ 1))
}

/// The flat indices of every node a feed of `len` leaves must keep to still serve and prove
/// blocks `[below, len)` after pruning the rest: the **peaks** (needed to seed the
/// accumulator and bag every proof) plus, for each retained block, its **within-peak audit
/// path**. Any node absent from this set covers only pruned leaves — dropping it can't harm
/// a retained block's proof. Note a pruned block's *leaf-hash* node is still kept when it is
/// the sibling of a retained block (that's how the retained block proves without the pruned
/// bytes) — the union over `[below, len)` audit paths captures exactly those.
pub fn retained_node_indices(len: u64, below: u64) -> BTreeSet<u64> {
    let below = below.min(len);
    let mut keep = BTreeSet::new();
    // The peaks: one per set bit of `len`, at their stable flat indices.
    let mut base = 0u64;
    for height in (0..u64::BITS).rev() {
        if (len >> height) & 1 == 1 {
            keep.insert(node_index(height, base >> height));
            base += 1u64 << height;
        }
    }
    // Each retained block's within-peak audit path.
    for j in below..len {
        keep.extend(within_peak_indices(len, j));
    }
    keep
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
///
/// The recursive reference definition — the oracle the [`Accumulator`] and the
/// store-backed [`Accumulator::proof`] are property-tested against. Production paths
/// maintain the root incrementally (the accumulator), so this is test-only.
#[cfg(test)]
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
///
/// The recursive reference definition — the oracle [`Accumulator::proof`] (the
/// store-backed path used in production) is checked byte-for-byte against. Test-only.
#[cfg(test)]
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
    pub fn len(&self) -> u64 {
        self.count
    }

    /// The current peak nodes as `(flat index, hash)`, largest height (leftmost) first —
    /// what a provider hands a sparse subscriber so it can seed [`from_peaks`], verify the
    /// root, and re-serve proofs without holding the whole tree.
    ///
    /// [`from_peaks`]: Accumulator::from_peaks
    pub fn peak_nodes(&self) -> Vec<(u64, Hash)> {
        let mut out = Vec::new();
        let mut base = 0u64;
        for height in (0..self.peaks.len() as u32).rev() {
            if let Some(Some(hash)) = self.peaks.get(height as usize) {
                out.push((node_index(height, base >> height), *hash));
                base += 1u64 << height;
            }
        }
        out
    }

    /// Seed an accumulator for `count` leaves from its persisted **peak** nodes, read via
    /// `get` (keyed by [`node_index`]). O(log n) reads — the fast open path that avoids
    /// re-hashing every block. Returns `None` if any peak node is absent (a feed whose tree
    /// isn't persisted yet), so the caller can fall back to rebuilding from blocks.
    ///
    /// The peaks are the set bits of `count`, largest height (leftmost) first; each is
    /// either a leaf (always persisted) or a completed perfect-subtree root (frozen when it
    /// completed), so for a Phase-B feed they are all present.
    pub fn from_peaks(count: u64, get: impl Fn(u64) -> Option<Hash>) -> Option<Accumulator> {
        let mut peaks: Vec<Option<Hash>> = Vec::new();
        let mut base = 0u64;
        for height in (0..u64::BITS).rev() {
            if (count >> height) & 1 == 0 {
                continue;
            }
            let hash = get(node_index(height, base >> height))?;
            if peaks.len() <= height as usize {
                peaks.resize(height as usize + 1, None);
            }
            peaks[height as usize] = Some(hash);
            base += 1u64 << height;
        }
        Some(Accumulator { peaks, count })
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
    fn from_peaks_reconstructs_the_accumulator() {
        use std::collections::HashMap;
        for n in 0..=200u64 {
            let mut built = Accumulator::new();
            let mut nodes: HashMap<u64, Hash> = HashMap::new();
            for i in 0..n {
                for (idx, h) in built.push(leaf_hash(&i.to_le_bytes())) {
                    nodes.insert(idx, h);
                }
            }
            let seeded = Accumulator::from_peaks(n, |idx| nodes.get(&idx).copied())
                .expect("all peak nodes present for a fully-pushed feed");
            assert_eq!(seeded.root(), built.root(), "root mismatch at n={n}");
            assert_eq!(seeded.len(), n);
            if n > 0 {
                let i = n / 2;
                assert_eq!(
                    seeded.proof(i, |idx| nodes.get(&idx).copied()),
                    built.proof(i, |idx| nodes.get(&idx).copied()),
                    "proof mismatch at n={n} i={i}"
                );
            }
        }
        // A missing peak node yields None so the caller falls back to a block rebuild.
        assert!(Accumulator::from_peaks(5, |_| None).is_none());
    }

    #[test]
    fn proof_nodes_round_trip_lets_a_sparse_holder_reserve() {
        // A sparse holder keeps the peaks (from_peaks) plus, per block it ingests, only
        // that block's within-peak nodes (from proof_nodes). It must then re-emit the
        // *identical* proof — this is the ingest crux Phase C rests on.
        use std::collections::HashMap;
        for n in 1..=128u64 {
            let mut full = Accumulator::new();
            let mut full_nodes: HashMap<u64, Hash> = HashMap::new();
            let mut ls: Vec<Hash> = Vec::new();
            for i in 0..n {
                let leaf = leaf_hash(&i.to_le_bytes());
                for (idx, h) in full.push(leaf) {
                    full_nodes.insert(idx, h);
                }
                ls.push(leaf);
            }
            let root = merkle_root(&ls);
            let sparse_peaks =
                Accumulator::from_peaks(n, |idx| full_nodes.get(&idx).copied()).unwrap();
            for i in 0..n {
                let want = full.proof(i, |idx| full_nodes.get(&idx).copied()).unwrap();
                // Ingest block i: store only its within-peak nodes.
                let sparse: HashMap<u64, Hash> = proof_nodes(n, i, &want).into_iter().collect();
                // Re-emit from peaks (accumulator) + the ingested within-peak nodes only.
                let got = sparse_peaks
                    .proof(i, |idx| sparse.get(&idx).copied())
                    .expect("sparse holder re-emits the proof");
                assert_eq!(got, want, "sparse re-emit != original at n={n} i={i}");
                assert_eq!(
                    root_from_path(ls[i as usize], i as usize, n as usize, &got),
                    Some(root),
                    "re-emitted proof fails to verify at n={n} i={i}"
                );
            }
        }
    }

    #[test]
    fn retained_nodes_keep_the_suffix_provable_and_drop_the_rest() {
        // GC acceptance: for every length and every prune boundary `below`, keeping ONLY
        // the retain-set nodes must still prove every block in `[below, n)` against the
        // original root — and must genuinely shrink (drop nodes) once anything is pruned.
        use std::collections::HashMap;
        for n in 1..=128u64 {
            let mut acc = Accumulator::new();
            let mut all: HashMap<u64, Hash> = HashMap::new();
            let mut ls: Vec<Hash> = Vec::new();
            for i in 0..n {
                let leaf = leaf_hash(&i.to_le_bytes());
                for (idx, h) in acc.push(leaf) {
                    all.insert(idx, h);
                }
                ls.push(leaf);
            }
            let root = merkle_root(&ls);
            for below in 0..=n {
                let keep = retained_node_indices(n, below);
                // Keeping only the retain-set nodes, every retained block still proves.
                let kept: HashMap<u64, Hash> = all
                    .iter()
                    .filter(|(k, _)| keep.contains(k))
                    .map(|(k, v)| (*k, *v))
                    .collect();
                let seeded = Accumulator::from_peaks(n, |idx| kept.get(&idx).copied())
                    .expect("peaks are always retained");
                for j in below..n {
                    let proof = seeded
                        .proof(j, |idx| kept.get(&idx).copied())
                        .expect("a retained block still proves from kept nodes");
                    assert_eq!(
                        root_from_path(ls[j as usize], j as usize, n as usize, &proof),
                        Some(root),
                        "retained block {j} fails to verify after pruning below {below} (n={n})"
                    );
                }
                // Nothing wasted: the retain set never exceeds the full node set, and it
                // strictly shrinks once we prune into a feed with prunable interior nodes.
                assert!(keep.len() <= all.len());
                if below > 1 && n >= 4 {
                    assert!(
                        keep.len() < all.len(),
                        "pruning below {below} of {n} should drop at least one node"
                    );
                }
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
