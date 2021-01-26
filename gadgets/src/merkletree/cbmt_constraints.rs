//! Complete Binary Merkle Tree Proof gadgets.

use ark_ff::PrimeField;
use zkp_r1cs::{ConstraintSystem, SynthesisError, Variable};

use crate::Vec;

use crate::commitment::abstract_hash::{AbstractHash, AbstractHashOutput};
use crate::merkletree::cbmt::TreeIndex;

pub struct MerkleProofGadget<I: TreeIndex, F: PrimeField, H: AbstractHash<F>> {
    index: I,
    lemmas: Vec<H::Output>,
}

impl<I: TreeIndex, F: PrimeField, H: AbstractHash<F>> MerkleProofGadget<I, F, H> {
    pub fn new(index: I, lemmas: Vec<H::Output>) -> Self {
        MerkleProofGadget { index, lemmas }
    }

    pub fn set_membership<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        root: H::Output,
        leaf: H::Output,
    ) -> Result<(), SynthesisError> {
        let mut parent = leaf.clone();
        let mut index = self.index.clone();
        let mut lemmas_iter = self.lemmas.iter().enumerate();
        loop {
            if let Some((i, sibling)) = lemmas_iter.next() {
                let parent_variable_vec = parent.get_variables();
                let parent_value_vec = parent.get_variable_values();
                let sibling_variable_vec = sibling.get_variables();
                let sibling_value_vec = sibling.get_variable_values();
                let is_left_value = if index.is_left() {
                    Some(F::one())
                } else {
                    Some(F::zero())
                };

                let is_left_variable = cs.alloc(
                    || format!("is_left_variable[{}]", i),
                    || is_left_value.ok_or(SynthesisError::AssignmentMissing),
                )?;

                let input_value = if index.is_left() {
                    parent_value_vec.clone()
                } else {
                    sibling_value_vec.clone()
                };

                let mut input_variable_vec: Vec<Variable> =
                    Vec::with_capacity(input_value.len() as usize);
                for j in 0..input_value.len() as usize {
                    let input_variable = cs.alloc(
                        || format!("input_variable[{}][{}]", i, j),
                        || input_value[j].ok_or(SynthesisError::AssignmentMissing),
                    )?;
                    input_variable_vec.push(input_variable);
                }

                for j in 0..parent_variable_vec.len() as usize {
                    // parent_variable_vec.len = 256; sibling_variable_vec.len = 8
                    if j >= sibling_variable_vec.len() {
                        break;
                    }
                    cs.enforce(
                        || {
                            format!(
                                "is_left*(left[{}][{}]-right[{}][{}])=(input[{}]-right[{}][{}])",
                                i, j, i, j, j, i, j
                            )
                        },
                        |lc| lc + is_left_variable,
                        |lc| lc + parent_variable_vec[j] - sibling_variable_vec[j],
                        |lc| lc + input_variable_vec[j] - sibling_variable_vec[j],
                    );
                }
                parent = if index.is_left() {
                    H::hash_enforce(
                        cs.ns(|| format!("hash_enforce_left_{}", i)),
                        &[&parent, sibling],
                    )?
                } else {
                    H::hash_enforce(
                        cs.ns(|| format!("hash_enforce_right_{}", i)),
                        &[sibling, &parent],
                    )?
                };
                index = index.parent();
            } else {
                break;
            }
        }

        let pre = parent
            .get_variables()
            .iter()
            .zip(root.get_variables().into_iter())
            .map(|(i, l)| (*i, l))
            .collect::<Vec<_>>();

        for (k, (i, j)) in pre.iter().enumerate() {
            cs.enforce(
                || format!("root_must_equal_last_parent_{}", k),
                |lc| lc + *i,
                |lc| lc + CS::one(),
                |lc| lc + *j,
            )
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::ToBytes;
    use sha2::{Digest, Sha256};
    use zkp_r1cs::ConstraintSystem;

    use super::super::cbmt::*;
    use super::*;
    use crate::commitment::mimc::{hash, AbstractHashMimc, AbstractHashMimcOutput};
    use crate::commitment::sha256::{AbstractHashSha256, AbstractHashSha256Output};
    use crate::test_constraint_system::TestConstraintSystem;

    struct MergeSha256;
    struct MergeMimc;

    impl Merge for MergeSha256 {
        type Item = Vec<u8>;

        fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
            let mut input = Vec::new();
            input.extend(&mut left.iter().map(|i| *i));
            input.extend(&mut right.iter().map(|i| *i));
            let mut h = Sha256::new();
            h.update(&input);
            h.finalize().to_vec()
        }
    }

    impl Merge for MergeMimc {
        type Item = Fr;

        fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
            let mut bytes = vec![];
            let _ = left.write(&mut bytes);
            let _ = right.write(&mut bytes);
            hash(&bytes)
        }
    }

    type CBMTSHA256 = CBMT<Vec<u8>, MergeSha256>;
    type CBMTMIMC = CBMT<Fr, MergeMimc>;

    #[test]
    fn test_merkle_tree_sha256() {
        let mut cs = TestConstraintSystem::<Fr>::new();

        // test 10 elements merkle tree.
        let leaves = vec![
            vec![1u8],
            vec![2u8],
            vec![3u8],
            vec![4u8],
            vec![5u8],
            vec![6u8],
            vec![7u8],
        ];

        let tree = CBMTSHA256::build_merkle_tree(leaves.clone());
        let root = tree.root();

        let n_root = AbstractHashSha256Output::alloc(cs.ns(|| "tree_root"), root.clone()).unwrap();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.build_proof(&(i as u32)).unwrap();
            assert!(proof.verify(&root, leaf));

            let n_leaf =
                AbstractHashSha256Output::alloc(cs.ns(|| format!("leaf_{}", i)), leaf.clone())
                    .unwrap();

            let lemmas = proof
                .lemmas()
                .iter()
                .enumerate()
                .map(|(j, v)| {
                    AbstractHashSha256Output::alloc(
                        cs.ns(|| format!("proof_lemmas_{}_{}", i, j)),
                        v.clone(),
                    )
                    .unwrap()
                })
                .collect();

            let g = MerkleProofGadget::<u32, Fr, AbstractHashSha256<Fr>>::new(
                proof.index().clone(),
                lemmas,
            );

            g.set_membership(
                cs.ns(|| format!("set_membership_{}", i)),
                n_root.clone(),
                n_leaf,
            )
            .unwrap();
        }

        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_merkle_tree_mimc() {
        // test 10 elements merkle tree.
        let leaves = vec![
            Fr::from(1u32),
            Fr::from(2u32),
            Fr::from(3u32),
            Fr::from(4u32),
            Fr::from(5u32),
            Fr::from(6u32),
            Fr::from(7u32),
        ];

        let tree = CBMTMIMC::build_merkle_tree(leaves.clone());
        let root = tree.root();

        let mut cs = TestConstraintSystem::<Fr>::new();

        let var_root = AbstractHashMimcOutput::alloc(cs.ns(|| "tree_root"), Some(root)).unwrap();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.build_proof(&(i as u32)).unwrap();
            assert!(proof.verify(&root, leaf));

            let var_leaf =
                AbstractHashMimcOutput::alloc(cs.ns(|| format!("leaf_{}", i)), Some(*leaf))
                    .unwrap();

            let lemmas = proof
                .lemmas()
                .iter()
                .enumerate()
                .map(|(j, v)| {
                    AbstractHashMimcOutput::alloc(
                        cs.ns(|| format!("proof_lemmas_{}_{}", i, j)),
                        Some(*v),
                    )
                    .unwrap()
                })
                .collect();

            let g = MerkleProofGadget::<u32, Fr, AbstractHashMimc<Fr>>::new(
                proof.index().clone(),
                lemmas,
            );

            g.set_membership(
                cs.ns(|| format!("set membership {}", i)),
                var_root.clone(),
                var_leaf,
            )
            .unwrap();
        }

        assert!(cs.is_satisfied());
    }
}
