//! Complete Binary Merkle Tree, this implementation inspired by [Nervos CBMT].
//!
//! [Nervos CBMT]: https://github.com/nervosnetwork/merkle-tree

use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::collections::VecDeque;

#[cfg(feature = "std")]
use std::collections::VecDeque;

use crate::Vec;

pub trait Merge {
    type Item;
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item;
}

pub struct MerkleTree<T, M> {
    nodes: Vec<T>,
    merge: PhantomData<M>,
}

impl<T, M> MerkleTree<T, M>
where
    T: Ord + Default + Clone,
    M: Merge<Item = T>,
{
    /// `leaf_index`: The index of leaves
    pub fn build_proof(&self, leaf_index: &u32) -> Option<MerkleProof<T, M>> {
        if self.nodes.is_empty() {
            return None;
        }

        let leaves_count = ((self.nodes.len() >> 1) + 1) as u32;
        let index = leaves_count + leaf_index - 1;

        if index >= (leaves_count << 1) - 1 {
            return None;
        }

        let mut lemmas = Vec::new();

        if index == 0 {
            return Some(MerkleProof {
                index,
                lemmas,
                merge: PhantomData,
            });
        }

        let mut new_index = index;

        loop {
            let sibling = new_index.sibling();
            lemmas.push(self.nodes[sibling as usize].clone());

            let parent = new_index.parent();
            if parent != 0 {
                new_index = parent;
            } else {
                break;
            }
        }

        Some(MerkleProof {
            index,
            lemmas,
            merge: PhantomData,
        })
    }

    pub fn root(&self) -> T {
        if self.nodes.is_empty() {
            T::default()
        } else {
            self.nodes[0].clone()
        }
    }

    pub fn nodes(&self) -> &Vec<T> {
        &self.nodes
    }
}

pub struct MerkleProof<T, M> {
    index: u32,
    lemmas: Vec<T>,
    merge: PhantomData<M>,
}

impl<T, M> MerkleProof<T, M>
where
    T: Ord + Default + Clone,
    M: Merge<Item = T>,
{
    pub fn new(index: u32, lemmas: Vec<T>) -> Self {
        Self {
            index,
            lemmas,
            merge: PhantomData,
        }
    }

    pub fn root(&self, leaf: &T) -> Option<T> {
        if self.index == 0 && self.lemmas.len() != 0 {
            return None;
        }

        let mut parent = leaf.clone();
        let mut index = self.index;
        let mut lemmas_iter = self.lemmas.iter();

        loop {
            if let Some(sibling) = lemmas_iter.next() {
                parent = if index.is_left() {
                    M::merge(&parent, &sibling)
                } else {
                    M::merge(&sibling, &parent)
                };
                index = index.parent();
            } else {
                break;
            }
        }

        Some(parent)
    }

    pub fn verify(&self, root: &T, leaf: &T) -> bool {
        match self.root(leaf) {
            Some(r) => &r == root,
            _ => false,
        }
    }

    pub fn index(&self) -> &u32 {
        &self.index
    }

    pub fn lemmas(&self) -> &[T] {
        &self.lemmas
    }
}

#[derive(Default)]
pub struct CBMT<T, M> {
    data_type: PhantomData<T>,
    merge: PhantomData<M>,
}

impl<T, M> CBMT<T, M>
where
    T: Ord + Default + Clone,
    M: Merge<Item = T>,
{
    pub fn build_merkle_root(leaves: &[T]) -> T {
        if leaves.is_empty() {
            return T::default();
        }

        let mut queue = VecDeque::with_capacity((leaves.len() + 1) >> 1);

        let mut iter = leaves.rchunks_exact(2);
        while let Some([leaf1, leaf2]) = iter.next() {
            queue.push_back(M::merge(leaf1, leaf2))
        }
        if let [leaf] = iter.remainder() {
            queue.push_front(leaf.clone())
        }

        while queue.len() > 1 {
            let right = queue.pop_front().unwrap();
            let left = queue.pop_front().unwrap();
            queue.push_back(M::merge(&left, &right));
        }

        queue.pop_front().unwrap()
    }

    pub fn build_merkle_tree(leaves: Vec<T>) -> MerkleTree<T, M> {
        let len = leaves.len();
        if len > 0 {
            let mut nodes = vec![T::default(); len - 1];
            nodes.extend(leaves);

            (0..len - 1)
                .rev()
                .for_each(|i| nodes[i] = M::merge(&nodes[(i << 1) + 1], &nodes[(i << 1) + 2]));

            MerkleTree {
                nodes,
                merge: PhantomData,
            }
        } else {
            MerkleTree {
                nodes: vec![],
                merge: PhantomData,
            }
        }
    }

    pub fn build_merkle_proof(leaves: &[T], index: &u32) -> Option<MerkleProof<T, M>> {
        Self::build_merkle_tree(leaves.to_vec()).build_proof(index)
    }
}

pub trait TreeIndex: Clone {
    fn sibling(&self) -> Self;
    fn parent(&self) -> Self;
    fn is_left(&self) -> bool;
    fn is_root(&self) -> bool;
}

macro_rules! impl_tree_index {
    ($t: ty) => {
        impl TreeIndex for $t {
            fn sibling(&self) -> $t {
                if *self == 0 {
                    0
                } else {
                    ((self + 1) ^ 1) - 1
                }
            }

            fn parent(&self) -> $t {
                if *self == 0 {
                    0
                } else {
                    (self - 1) >> 1
                }
            }

            fn is_left(&self) -> bool {
                self & 1 == 1
            }

            fn is_root(&self) -> bool {
                *self == 0
            }
        }
    };
}

impl_tree_index!(u32);
impl_tree_index!(usize);

#[cfg(test)]
mod tests {
    use super::*;

    struct MergeI32 {}

    impl Merge for MergeI32 {
        type Item = i32;
        fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
            right.wrapping_sub(*left)
        }
    }

    type CBMTI32 = CBMT<i32, MergeI32>;
    type CBMTI32Proof = MerkleProof<i32, MergeI32>;

    #[test]
    fn build_cbmt_empty() {
        let leaves = vec![];
        let tree = CBMTI32::build_merkle_tree(leaves);
        assert!(tree.nodes().is_empty());
        assert_eq!(tree.root(), i32::default());
    }

    #[test]
    fn build_cbmt_one() {
        let leaves = vec![1i32];
        let tree = CBMTI32::build_merkle_tree(leaves);
        assert_eq!(&vec![1], tree.nodes());
    }

    #[test]
    fn build_cbmt_two() {
        let leaves = vec![1i32, 2];
        let tree = CBMTI32::build_merkle_tree(leaves);
        assert_eq!(&vec![1, 1, 2], tree.nodes());
    }

    #[test]
    fn build_cbmt_five() {
        let leaves = vec![2i32, 3, 5, 7, 11];
        let tree = CBMTI32::build_merkle_tree(leaves);
        assert_eq!(&vec![4, -2, 2, 4, 2, 3, 5, 7, 11], tree.nodes());
    }

    #[test]
    fn build_cbmt_root_directly() {
        let leaves = vec![2i32, 3, 5, 7, 11];
        assert_eq!(4, CBMTI32::build_merkle_root(&leaves));
    }

    #[test]
    fn rebuild_cbmt_proof() {
        let leaves = vec![2i32, 3, 5, 7, 11];
        let tree = CBMTI32::build_merkle_tree(leaves);
        let root = tree.root();

        // build proof
        let proof = tree.build_proof(&3).unwrap();
        let lemmas = proof.lemmas();
        let index = proof.index();

        // rebuild proof
        let needed_leaf = tree.nodes()[*index as usize].clone();

        let rebuild_proof = CBMTI32Proof::new(*index, lemmas.to_vec());
        assert_eq!(rebuild_proof.verify(&root, &needed_leaf), true);
        assert_eq!(root, rebuild_proof.root(&needed_leaf).unwrap());
    }

    #[test]
    fn build_cbmt_proof() {
        let leaves = vec![2i32, 3, 5, 7, 11, 13];
        let leaf_index = 5u32;
        let proof_leaf = leaves[leaf_index as usize].clone();

        let proof = CBMTI32::build_merkle_proof(&leaves, &leaf_index).unwrap();

        assert_eq!(vec![11, 2, 1], proof.lemmas);
        assert_eq!(Some(1), proof.root(&proof_leaf));

        // merkle proof for single leaf
        let leaves = vec![2i32];
        let leaf_index = 0u32;
        let proof_leaf = leaves[leaf_index as usize].clone();

        let proof = CBMTI32::build_merkle_proof(&leaves, &leaf_index).unwrap();
        assert!(proof.lemmas.is_empty());
        assert_eq!(Some(2), proof.root(&proof_leaf));
    }
}
