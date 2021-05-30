//! Complete Binary Merkle Tree Proof gadgets.

use ark_ff::PrimeField;

use crate::composer::{
    abstract_hash::{AbstractHash, AbstractHashOutput},
    Composer, Variable,
};
use crate::Vec;

use super::cbmt::TreeIndex;

impl<F: PrimeField> Composer<F> {
    pub fn merkletree_mermbership<I: TreeIndex, H: AbstractHash<F>>(
        &mut self,
        root: H::Output,
        leaf: H::Output,
        index: I,
        lemmas: Vec<H::Output>,
        pi: F,
    ) {
        let mut parent = leaf.clone();
        let mut index = index.clone();
        let mut lemmas_iter = lemmas.iter();

        loop {
            if let Some(sibling) = lemmas_iter.next() {
                let _parent_variable_vec = parent.get_variables();
                let parent_value_vec = parent.get_variable_values();
                let _sibling_variable_vec = sibling.get_variables();
                let sibling_value_vec = sibling.get_variable_values();
                let is_left_value = if index.is_left() { F::one() } else { F::zero() };

                let _is_left_variable = self.alloc_and_assign(is_left_value);

                let input_value = if index.is_left() {
                    parent_value_vec.clone()
                } else {
                    sibling_value_vec.clone()
                };

                let mut input_variable_vec: Vec<Variable> =
                    Vec::with_capacity(input_value.len() as usize);
                for j in 0..input_value.len() as usize {
                    let input_variable = self.alloc_and_assign(input_value[j]);
                    input_variable_vec.push(input_variable);
                }

                // for j in 0..parent_variable_vec.len() as usize {
                //     // parent_variable_vec.len = 256; sibling_variable_vec.len = 8
                //     if j >= sibling_variable_vec.len() {
                //         break;
                //     }
                //     // "is_left*(left[{}][{}]-right[{}][{}])=(input[{}]-right[{}][{}])"
                //     let left = parent_variable_vec[j] - sibling_variable_vec[j];
                //     let right = input_variable_vec[j] - sibling_variable_vec[j];
                //     is_left_variable * left = right;
                // }
                parent = if index.is_left() {
                    H::hash_enforce(self, &[&parent, sibling])
                } else {
                    H::hash_enforce(self, &[sibling, &parent])
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

        for (i, j) in pre.iter() {
            let v = self.get_value(j);
            self.constrain_to_constant(*i, v, pi);
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::{One, Zero};
    use ark_poly_commit::marlin_pc::MarlinKZG10;
    use ark_std::test_rng;
    use blake2::Blake2s;

    use crate::composer::Composer;
    use crate::*;

    type PC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
    type PlonkInst = Plonk<Fr, Blake2s, PC>;

    use super::super::super::abstract_hash::AbstractHashOutput;
    use super::super::cbmt::*;
    use super::*;

    pub fn ks() -> [Fr; 4] {
        [
            Fr::one(),
            Fr::from(7_u64),
            Fr::from(13_u64),
            Fr::from(17_u64),
        ]
    }

    struct MergeHashMock;

    #[derive(Clone)]
    struct HashMockOutput(Variable, Fr);

    impl AbstractHashOutput<Fr> for HashMockOutput {
        fn get_variables(&self) -> Vec<Variable> {
            vec![self.0]
        }

        fn get_variable_values(&self) -> Vec<Fr> {
            vec![self.1]
        }
    }

    struct HashMock;

    impl AbstractHash<Fr> for HashMock {
        type Output = HashMockOutput;

        fn hash_enforce(composer: &mut Composer<Fr>, params: &[&Self::Output]) -> Self::Output {
            let xor_res = composer.xor_gate(
                params[0].get_variables()[0],
                params[1].get_variables()[0],
                64,
            );
            HashMockOutput(xor_res, composer.assignment[&xor_res])
        }
    }

    impl Merge for MergeHashMock {
        type Item = u64;

        fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
            left ^ right
        }
    }

    type CBMTMOCK = CBMT<u64, MergeHashMock>;

    #[test]
    fn test_merkle_tree_mock() {
        let rng = &mut test_rng();

        // compose
        let mut cs = Composer::new();

        // test 10 elements merkle tree.
        let leaves = vec![1u64, 2u64, 3u64, 4u64, 5u64, 6u64, 7u64];

        let tree = CBMTMOCK::build_merkle_tree(leaves.clone());
        let root = tree.root();

        let n_root = cs.alloc_and_assign(Fr::from(root));
        let root_output = HashMockOutput(n_root, Fr::from(root));

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.build_proof(&(i as u32)).unwrap();
            assert!(proof.verify(&root, leaf));

            let n_leaf = cs.alloc_and_assign(Fr::from(*leaf));
            let leaf_output = HashMockOutput(n_leaf, Fr::from(*leaf));

            let lemmas = proof
                .lemmas()
                .iter()
                .map(|v| {
                    let lemma = cs.alloc_and_assign(Fr::from(*v));
                    HashMockOutput(lemma, Fr::from(*v))
                })
                .collect();

            cs.merkletree_mermbership::<u32, HashMock>(
                root_output.clone(),
                leaf_output,
                *proof.index(),
                lemmas,
                Fr::zero(),
            );
        }

        let ks = ks();
        println!("size of the circuit: {}", cs.size());
        let srs = PlonkInst::setup(1024, rng).unwrap();
        let (pk, vk) = PlonkInst::keygen(&srs, &cs, ks).unwrap();
        let proof = PlonkInst::prove(&pk, &cs, rng).unwrap();
        let result = PlonkInst::verify(&vk, cs.public_inputs(), proof).unwrap();
        assert!(result);
    }
}
