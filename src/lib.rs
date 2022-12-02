#![feature(test)]
extern crate test;

/// Trait for hashing data inside a merkle tree
/// Using 'sha*' crates like interface, because it's more flexible
pub trait Hasher {
    /// Output type
    type Hash;

    fn new() -> Self;
    fn update(self, data: impl AsRef<[u8]>) -> Self;
    fn finilize(self) -> Self::Hash;
}

/// Salt for leaf
/// For protect solution from second preimage atack, we using some salt for leaves
const LEAF: &[u8] = &[0];
/// Salt for intermdeiate node hashes
/// For protect solution from second preimage atack, we using some salt for leaves
const INTERMEDIATE: &[u8] = &[1];
/// Salt for solo leaf
/// At the leaves level, there may be a lack of a leaf
/// (when there is an odd number of them), in order to
/// avoid a second preimage attack, we add a single prefix
/// in order to separate the two data sets:
/// ```no_compile
/// let first = [b"a", b"b", b"c"];
/// let second = [b"a", b"b", b"c", b"c"];
/// assert_ne!(
///     MerkleTree::from_iter(first.iter()).calculate_root(),
///     MerkleTree::from_iter(second.iter()).calculate_root(),
/// );
/// ```
const DOUBLING: &[u8] = &[2];

/// Crate level extension of the [`Hasher`] trait functionality
trait MerkleTreeHasher: Sized + Hasher {
    fn hash_leaf(data: impl AsRef<[u8]>) -> Self::Hash {
        Self::new().update(LEAF).update(data.as_ref()).finilize()
    }

    fn hash_intermediate(left: impl AsRef<[u8]>, right: impl AsRef<[u8]>) -> Self::Hash {
        Self::new()
            .update(INTERMEDIATE)
            .update(left.as_ref())
            .update(right.as_ref())
            .finilize()
    }

    fn hash_intermediate_doubling(data: impl AsRef<[u8]>) -> Self::Hash {
        Self::new()
            .update(DOUBLING)
            .update(data.as_ref())
            .update(data.as_ref())
            .finilize()
    }
}
impl<H: Hasher> MerkleTreeHasher for H {}

/// Merkle tree structure
/// This solution is deliberately left without incremental calculation for simplicity.
pub struct MerkleTree<H: Hasher> {
    /// Leaves of tree
    leaves: Vec<H::Hash>,
}

impl<I: AsRef<[u8]>, H: Hasher> FromIterator<I> for MerkleTree<H> {
    fn from_iter<T: IntoIterator<Item = I>>(iter: T) -> Self {
        Self {
            leaves: iter
                .into_iter()
                .map(|item| H::hash_leaf(item))
                .collect::<Vec<_>>(),
        }
    }
}

impl<H: Hasher> MerkleTree<H>
where
    H::Hash: AsRef<[u8]>,
{
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn leaves_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn height(&self) -> usize {
        get_merkle_tree_height(self.leaves_count())
    }

    /// Each next level contains half as many nodes.
    /// This is a convergent series, which can be represented as:
    /// Sum[2^k, {k, 0, n}] = 2^(n+1) - 1
    pub fn node_count(&self) -> usize {
        (1 << self
            .height()
            .checked_add(1)
            .expect("Your tree is too tall!"))
            - 1
    }

    pub fn insert_bytes(&mut self, bytes: impl AsRef<[u8]>) {
        self.leaves.push(H::hash_leaf(bytes));
    }

    pub fn get_leaf(&self, index: usize) -> Option<&H::Hash> {
        self.leaves.get(index)
    }

    pub fn calculate_root(&self) -> H::Hash {
        let calculate_next_level = |level: &[H::Hash]| {
            level
                .chunks(2)
                .map(|chunk: &[H::Hash]| match chunk.len() {
                    2 => H::hash_intermediate(&chunk[0], &chunk[1]),
                    1 => H::hash_intermediate_doubling(&chunk[0]),
                    unreachable_chunk_size => unreachable!(
                        "{unreachable_chunk_size} chunk size cannot be reached, 
                            due to the argument in `chunks` fn above"
                    ),
                })
                .collect::<Vec<_>>()
        };

        let mut level_nodes = calculate_next_level(&self.leaves);
        while level_nodes.len() > 1 {
            level_nodes = calculate_next_level(&level_nodes);
        }

        level_nodes.pop().unwrap_or_else(|| H::hash_leaf([0]))
    }

    pub fn get_leaf_openning(&self, index: usize) -> Vec<NodeIndex> {
        get_leaf_openning(self.leaves_count(), index)
    }
}

pub fn get_merkle_tree_height(leaves_count: usize) -> usize {
    (leaves_count as u64).next_power_of_two().trailing_zeros() as usize
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIndex {
    /// Level at merkle tree
    /// From leaves to root
    pub level: usize,
    /// Node index at level
    pub index: usize,
}

/// The Merkle Opening of a value is the partners with which a given leaf is hashed
/// to reconstruct the root.
///
/// In the example above, the opening of H01 would be [H00, H1].
///
/// ,--.    ,--.    ,--.   ,--.
/// |V0|    |V1|    |V2|   |V3|
/// |--|    |--|    |--|   |--|
/// `--'    `--'    `--'   `--'
///   |       |       |      |  
///   |       |       |      |  
/// ,---.  ,---.   ,---.   ,---.
/// |H00|  |H01|   |H10|   |H11|
/// |---|  |---|   |---|   |---|
/// `---'  `---'   `---'   `---'
///    |      |       |     |
///     ----,--.    ,--.----
///         |H0|    |H1|
///         |--|    |--|
///         `--'    `--'
///            |    |
///            ------
///              |
///             ,-.
///             |H|
///             |-|
///             `-'
pub fn get_leaf_openning(leaves_count: usize, mut current_index: usize) -> Vec<NodeIndex> {
    use num_integer::Integer;

    (0..get_merkle_tree_height(leaves_count))
        .map(|level| {
            let (quitient, remainder) = current_index.div_rem(&2);

            let index = if remainder == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            current_index = quitient;

            NodeIndex { level, index }
        })
        .collect()
}

#[cfg(test)]
mod get_leaf_opening_tests {
    use super::{get_leaf_openning, NodeIndex};

    #[test]
    fn get_leaf_opening() {
        assert_eq!(
            get_leaf_openning(4, 0),
            [
                NodeIndex { level: 0, index: 1 },
                NodeIndex { level: 1, index: 1 }
            ]
        );

        assert_eq!(
            get_leaf_openning(4, 1),
            [
                NodeIndex { level: 0, index: 0 },
                NodeIndex { level: 1, index: 1 }
            ]
        );

        assert_eq!(
            get_leaf_openning(4, 2),
            [
                NodeIndex { level: 0, index: 3 },
                NodeIndex { level: 1, index: 0 }
            ]
        );

        assert_eq!(
            get_leaf_openning(4, 3),
            [
                NodeIndex { level: 0, index: 2 },
                NodeIndex { level: 1, index: 0 }
            ]
        );

        assert_eq!(
            get_leaf_openning(10, 0),
            [
                NodeIndex { level: 0, index: 1 },
                NodeIndex { level: 1, index: 1 },
                NodeIndex { level: 2, index: 1 },
                NodeIndex { level: 3, index: 1 }
            ]
        );
    }
}

pub mod std_ {
    use super::Hasher;

    pub struct Wrapper<H: Default + std::hash::Hasher>(H);
    impl<H: Default + std::hash::Hasher> Hasher for Wrapper<H> {
        type Hash = [u8; 8];

        fn new() -> Self {
            Self(H::default())
        }
        fn update(mut self, data: impl AsRef<[u8]>) -> Self {
            self.0.write(data.as_ref());
            self
        }
        fn finilize(self) -> Self::Hash {
            self.0.finish().to_be_bytes()
        }
    }

    pub type DefaultHasher = Wrapper<std::collections::hash_map::DefaultHasher>;
}
pub type StdDefaultHasher = std_::DefaultHasher;

#[cfg(feature = "sha3")]
pub mod sha3 {
    pub use sha3::*;

    use super::Hasher;

    pub struct Wrapper<H: Digest>(H);

    impl<D: Digest> Hasher for Wrapper<D> {
        type Hash = generic_array::GenericArray<u8, <D as digest::OutputSizeUser>::OutputSize>;

        fn new() -> Self {
            Self(D::new())
        }
        fn update(self, data: impl AsRef<[u8]>) -> Self {
            Self(self.0.chain_update(data))
        }
        fn finilize(self) -> Self::Hash {
            D::finalize(self.0)
        }
    }
}

#[cfg(feature = "sha2")]
pub mod sha2 {
    pub use sha2::*;

    use super::Hasher;

    pub struct Wrapper<H: Digest>(H);

    impl<D: Digest> Hasher for Wrapper<D> {
        type Hash = generic_array::GenericArray<u8, <D as digest::OutputSizeUser>::OutputSize>;

        fn new() -> Self {
            Self(D::new())
        }
        fn update(self, data: impl AsRef<[u8]>) -> Self {
            Self(self.0.chain_update(data))
        }
        fn finilize(self) -> Self::Hash {
            D::finalize(self.0)
        }
    }
}

#[cfg(test)]
mod merkle_tree_tests {
    use std::iter;

    use rand::{distributions::Standard, Rng};

    use super::*;

    fn get_random_merkle_tree<const HEIGHT: u32, H: Hasher>() -> MerkleTree<H> {
        let rng = rand::thread_rng();
        MerkleTree::<H>::from_iter(
            rng.sample_iter(Standard)
                .map(u128::to_be_bytes)
                .take(2usize.pow(HEIGHT)),
        )
    }

    #[test]
    fn doubling_second_preimage_atack() {
        use ::sha2::Sha256;
        type MerkleTree = super::MerkleTree<sha2::Wrapper<Sha256>>;

        let first = [b"a", b"b", b"c"];
        let second = [b"a", b"b", b"c", b"c"];

        assert_ne!(
            MerkleTree::from_iter(first.iter()).calculate_root(),
            MerkleTree::from_iter(second.iter()).calculate_root(),
        );
    }

    #[test]
    fn calculate_root_empty() {
        let merkle_tree = MerkleTree::<StdDefaultHasher>::from_iter(iter::empty::<&[u8]>());
        assert!(merkle_tree.is_empty());
        assert_eq!(
            merkle_tree.calculate_root(),
            StdDefaultHasher::hash_leaf([0])
        );
    }

    #[test]
    fn calculate_root_solo() {
        let merkle_tree = MerkleTree::<StdDefaultHasher>::from_iter(iter::once(&[1]));
        assert_eq!(
            merkle_tree.calculate_root(),
            StdDefaultHasher::hash_intermediate_doubling(StdDefaultHasher::hash_leaf([1]),)
        );
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn calculate_root_case1_by_sha2() {
        use ::sha2::{Digest, Sha256};

        let leaves = [b"a", b"b", b"c", b"d"];

        let a = Sha256::new()
            .chain_update(LEAF)
            .chain_update(leaves[0])
            .finalize();
        let b = Sha256::new()
            .chain_update(LEAF)
            .chain_update(leaves[1])
            .finalize();
        let c = Sha256::new()
            .chain_update(LEAF)
            .chain_update(leaves[2])
            .finalize();
        let d = Sha256::new()
            .chain_update(LEAF)
            .chain_update(leaves[3])
            .finalize();

        let ab = Sha256::new()
            .chain_update(INTERMEDIATE)
            .chain_update(a)
            .chain_update(b)
            .finalize();
        let cd = Sha256::new()
            .chain_update(INTERMEDIATE)
            .chain_update(c)
            .chain_update(d)
            .finalize();
        let abcd = Sha256::new()
            .chain_update(INTERMEDIATE)
            .chain_update(ab)
            .chain_update(cd)
            .finalize();

        assert_eq!(
            MerkleTree::<sha2::Wrapper<Sha256>>::from_iter(leaves.iter()).calculate_root(),
            abcd
        );
    }

    #[test]
    fn get_leaves() {
        let leaves: [&[u8]; 3] = [b"first", b"second", b"thirs"];
        let merkle_tree = MerkleTree::<StdDefaultHasher>::from_iter(leaves.iter());

        for (index, leaf) in leaves.iter().enumerate() {
            assert_eq!(
                merkle_tree.get_leaf(index),
                Some(StdDefaultHasher::hash_leaf(leaf)).as_ref()
            );
        }
    }

    #[test]
    fn calculate_root_by_std_height21() {
        let merkle_tree = get_random_merkle_tree::<21, StdDefaultHasher>();
        assert_eq!(merkle_tree.height(), 21);
        let _root = merkle_tree.calculate_root();
    }

    #[test]
    fn calculate_root_by_std_height23() {
        let merkle_tree = get_random_merkle_tree::<23, StdDefaultHasher>();

        assert_eq!(merkle_tree.height(), 23);
        let _root = merkle_tree.calculate_root();
    }

    #[cfg(feature = "sha3")]
    #[test]
    fn node_count() {
        let merkle_tree = get_random_merkle_tree::<2, sha3::Wrapper<sha3::Keccak256>>();
        assert_eq!(merkle_tree.height(), 2);
        assert_eq!(merkle_tree.node_count(), 7);

        assert_eq!(
            get_random_merkle_tree::<10, sha3::Wrapper<sha3::Keccak256>>().node_count(),
            2047
        );

        assert_eq!(
            get_random_merkle_tree::<20, sha3::Wrapper<sha3::Keccak256>>().node_count(),
            2_097_151
        );
    }

    #[cfg(feature = "sha3")]
    #[test]
    fn calculate_root_by_sha3_height10() {
        let merkle_tree = get_random_merkle_tree::<10, sha3::Wrapper<sha3::Keccak512>>();

        assert_eq!(merkle_tree.height(), 10);
        let _root = merkle_tree.calculate_root();
    }

    #[cfg(feature = "sha3")]
    #[test]
    fn calculate_root_by_sha3_height15() {
        let merkle_tree = get_random_merkle_tree::<15, sha3::Wrapper<sha3::Sha3_512>>();

        assert_eq!(merkle_tree.height(), 15);
        let _root = merkle_tree.calculate_root();
    }

    #[bench]
    fn bench_std_height_10(b: &mut test::Bencher) {
        let merkle_tree = get_random_merkle_tree::<10, StdDefaultHasher>();
        b.iter(|| merkle_tree.calculate_root());
    }

    #[cfg(feature = "sha2")]
    #[bench]
    fn bench_sha2_height_10(b: &mut test::Bencher) {
        let merkle_tree = get_random_merkle_tree::<10, sha2::Wrapper<sha2::Sha512>>();
        b.iter(|| merkle_tree.calculate_root());
    }

    #[cfg(feature = "sha3")]
    #[bench]
    fn bench_sha3_height_10(b: &mut test::Bencher) {
        let merkle_tree = get_random_merkle_tree::<10, sha3::Wrapper<sha3::Keccak512>>();
        b.iter(|| merkle_tree.calculate_root());
    }

    #[bench]
    fn bench_std_height_15(b: &mut test::Bencher) {
        let merkle_tree = get_random_merkle_tree::<15, StdDefaultHasher>();
        b.iter(|| merkle_tree.calculate_root());
    }

    #[cfg(feature = "sha2")]
    #[bench]
    fn bench_sha2_height_15(b: &mut test::Bencher) {
        let merkle_tree = get_random_merkle_tree::<15, sha2::Wrapper<sha2::Sha512>>();
        b.iter(|| merkle_tree.calculate_root());
    }

    #[cfg(feature = "sha3")]
    #[bench]
    fn bench_sha3_height_15(b: &mut test::Bencher) {
        let merkle_tree = get_random_merkle_tree::<15, sha3::Wrapper<sha3::Keccak512>>();
        b.iter(|| merkle_tree.calculate_root());
    }

    #[bench]
    fn bench_std_height_20(b: &mut test::Bencher) {
        let merkle_tree = get_random_merkle_tree::<20, StdDefaultHasher>();
        b.iter(|| merkle_tree.calculate_root());
    }

    #[cfg(feature = "sha2")]
    #[bench]
    fn bench_sha2_height_20(b: &mut test::Bencher) {
        let merkle_tree = get_random_merkle_tree::<20, sha2::Wrapper<sha2::Sha512>>();
        b.iter(|| merkle_tree.calculate_root());
    }

    #[cfg(feature = "sha3")]
    #[bench]
    fn bench_sha3_height_20(b: &mut test::Bencher) {
        let merkle_tree = get_random_merkle_tree::<20, sha3::Wrapper<sha3::Keccak512>>();
        b.iter(|| merkle_tree.calculate_root());
    }
}
