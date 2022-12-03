use merkle_tree_assignment::{MerkleTree, StdDefaultHasher};

fn main() {
    let first = [b"e", b"x", b"a", b"m", b"p", b"l", b"e"];
    println!(
        "{}",
        hex::encode(MerkleTree::<StdDefaultHasher>::from_iter(first.iter()).calculate_root())
    );
}
