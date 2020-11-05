use ckb_zkp::gadgets::merkletree::cbmt::Merge;
use ckb_zkp::gadgets::merkletree::cbmt::MerkleProof;
use ckb_zkp::gadgets::merkletree::cbmt::CBMT;
use ckb_zkp::gadgets::merkletree::cbmt_constraints::MerkleProofGadget;
use ckb_zkp::gadgets::sha256::AbstractHashSha256;
use ckb_zkp::gadgets::sha256::AbstractHashSha256Output;
use math::One;
use math::Zero;
use sha2::Digest;
use sha2::Sha256;

use curve::bn_256::{Bn_256, Fr};

use rand::prelude::*;
use scheme::groth16::{
    create_random_proof, generate_random_parameters, verifier::prepare_verifying_key,
};
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use std::time::Instant;

struct MergeSha256;

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
type CBMTMIMC = CBMT<Vec<u8>, MergeSha256>;

struct MerkleTreeCircuit {
    proof: Option<MerkleProof<Vec<u8>, MergeSha256>>,
    root: Option<Vec<u8>>,
    leaf: Option<Vec<u8>>,
}

impl ConstraintSynthesizer<Fr> for MerkleTreeCircuit {
    fn generate_constraints<CS: ConstraintSystem<Fr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let var_root = AbstractHashSha256Output::alloc_input(
            cs.ns(|| "tree_root"),
            self.root.unwrap().clone(),
        )
        .unwrap();
        let var_leaf =
            AbstractHashSha256Output::alloc(cs.ns(|| format!("leaf",)), self.leaf.unwrap().clone())
                .unwrap();
        let proof_val = self.proof.ok_or(SynthesisError::AssignmentMissing).unwrap();
        let lemmas = proof_val
            .lemmas()
            .iter()
            .enumerate()
            .map(|(j, v)| {
                AbstractHashSha256Output::alloc(
                    cs.ns(|| format!("proof_lemmas_{}", j)),
                    (*v).clone(),
                )
                .unwrap()
            })
            .collect();
        let g = MerkleProofGadget::<u32, Fr, AbstractHashSha256<Fr>>::new(
            proof_val.index().clone(),
            lemmas,
        );
        g.set_membership(cs.ns(|| format!("set membership")), var_root, var_leaf)
            .unwrap();
        println!("cs.num_constraints: {}", cs.num_constraints());
        Ok(())
    }
}

/// test for use groth16 & bn_256 & mimc gadget.
fn main() {
    let mut rng = thread_rng();
    // TRUSTED SETUP
    println!("TRUSTED SETUP...");
    let proof: MerkleProof<Vec<u8>, MergeSha256> = MerkleProof::new(0, vec![vec![0; 32]; 3]);
    let c = MerkleTreeCircuit {
        proof: Some(proof),
        root: Some(vec![0; 32]),
        leaf: Some(vec![0; 32]),
    };
    println!("before generate_random_parameters");
    let params = generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap();
    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    // begin loop
    // test 10 elements merkle tree.
    let leaves = vec![
        vec![1u8],
        vec![2u8],
        vec![3u8],
        vec![4u8],
        vec![5u8],
        vec![6u8],
        vec![7u8],
        vec![8u8],
    ];

    let tree = CBMTMIMC::build_merkle_tree(leaves.clone());
    let root = tree.root();

    for (i, leaf) in leaves.iter().enumerate() {
        let proof_path = tree.build_proof(&(i as u32)).unwrap();
        assert!(proof_path.verify(&root, leaf));

        let circuit = MerkleTreeCircuit {
            proof: Some(proof_path),
            root: Some(root.clone()),
            leaf: Some((*leaf).clone()),
        };

        println!("GROTH16 START PROVE...");
        let p_start = Instant::now();
        let proof = create_random_proof(&params, circuit, &mut rng).unwrap();
        let p_time = p_start.elapsed();
        println!("GROTH16 PROVE TIME: {:?}", p_time);

        // println!("GROTH16 START VERIFY...");
        let v_start = Instant::now();

        // Vec<u8> to Vec<Fr>
        let mut root_val = Vec::with_capacity(root.len());
        let s = root
            .iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8));

        let mut cnt = 0;
        for (_, v) in s.enumerate() {
            root_val.push(
                if Some(v).ok_or(SynthesisError::AssignmentMissing).unwrap() {
                    Some(Fr::one())
                } else {
                    Some(Fr::zero())
                }
                .unwrap(),
            );

            cnt = cnt + 1;
        }

        // assert!(verify_proof(&pvk, &proof, &root_val).unwrap());
        let v_time = v_start.elapsed();
        println!("GROTH16 VERIFY TIME: {:?}", v_time);
    }

    println!("all is ok");
}
