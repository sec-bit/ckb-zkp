use math::Zero;
use zkp_toolkit::gadgets::merkletree::cbmt::Merge;
use zkp_toolkit::gadgets::merkletree::cbmt::MerkleProof;
use zkp_toolkit::gadgets::merkletree::cbmt::CBMT;
use zkp_toolkit::gadgets::merkletree::cbmt_constraints::MerkleProofGadget;
use zkp_toolkit::gadgets::mimc::AbstractHashMimc;
use zkp_toolkit::gadgets::mimc::AbstractHashMimcOutput;

use curve::bn_256::{Bn_256, Fr};
use zkp_toolkit::gadgets::mimc::hash;

use math::ToBytes;
use rand::prelude::*;
use scheme::groth16::{
    create_random_proof, generate_random_parameters, verifier::prepare_verifying_key, verify_proof,
};
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use std::time::Instant;

struct MergeMimc;

impl Merge for MergeMimc {
    type Item = Fr;

    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let mut bytes = vec![];
        let _ = left.write(&mut bytes);
        let _ = right.write(&mut bytes);
        hash(&bytes)
    }
}

type CBMTMIMC = CBMT<Fr, MergeMimc>;

struct MerkleTreeCircuit {
    proof: Option<MerkleProof<Fr, MergeMimc>>,
    root: Option<Fr>,
    leaf: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MerkleTreeCircuit {
    fn generate_constraints<CS: ConstraintSystem<Fr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let var_root =
            AbstractHashMimcOutput::alloc_input(cs.ns(|| "tree_root"), self.root).unwrap();
        let var_leaf =
            AbstractHashMimcOutput::alloc(cs.ns(|| format!("leaf",)), self.leaf).unwrap();
        let proof_val = self.proof.ok_or(SynthesisError::AssignmentMissing).unwrap();
        let lemmas = proof_val
            .lemmas()
            .iter()
            .enumerate()
            .map(|(j, v)| {
                AbstractHashMimcOutput::alloc(cs.ns(|| format!("proof_lemmas_{}", j)), Some(*v))
                    .unwrap()
            })
            .collect();
        let g = MerkleProofGadget::<u32, Fr, AbstractHashMimc<Fr>>::new(
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
    println!("Running merkletree mimc circuit...");
    // TRUSTED SETUP
    println!("TRUSTED SETUP...");
    // Construct empty parameters for trusted setup
    let leaves_empty = vec![
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
    ];

    let tree_empty = CBMTMIMC::build_merkle_tree(leaves_empty.clone());
    let root_empty = tree_empty.root();
    let proof_path_empty = tree_empty.build_proof(&(0 as u32)).unwrap();
    let c = MerkleTreeCircuit {
        proof: Some(proof_path_empty),
        root: Some(root_empty),
        leaf: Some(Fr::zero()),
    };
    println!("Before generate_random_parameters");
    let start = Instant::now();
    let params = generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap();
    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);
    let total_setup = start.elapsed();
    println!("GROTH16 SETUP TIME: {:?}", total_setup);
    // begin loop
    // test 8 elements merkle tree.
    let leaves = vec![
        Fr::from(1u32),
        Fr::from(2u32),
        Fr::from(3u32),
        Fr::from(4u32),
        Fr::from(5u32),
        Fr::from(6u32),
        Fr::from(7u32),
        Fr::from(8u32),
    ];

    let tree = CBMTMIMC::build_merkle_tree(leaves.clone());
    let root = tree.root();

    for (i, leaf) in leaves.iter().enumerate() {
        let proof_path = tree.build_proof(&(i as u32)).unwrap();
        assert!(proof_path.verify(&root, leaf));

        let circuit = MerkleTreeCircuit {
            proof: Some(proof_path),
            root: Some(root),
            leaf: Some(*leaf),
        };

        println!("GROTH16 START PROVE...");
        let p_start = Instant::now();
        let proof = create_random_proof(&params, circuit, &mut rng).unwrap();
        let p_time = p_start.elapsed();
        println!("GROTH16 PROVE TIME: {:?}", p_time);

        println!("GROTH16 START VERIFY...");
        let v_start = Instant::now();
        assert!(verify_proof(&pvk, &proof, &[root]).unwrap());
        let v_time = v_start.elapsed();
        println!("GROTH16 VERIFY TIME: {:?}", v_time);
    }

    println!("all is ok");
}
