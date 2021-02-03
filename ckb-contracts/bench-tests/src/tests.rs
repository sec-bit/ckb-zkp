use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::*,
    prelude::*,
};
use std::time::Instant;

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::*;
use ark_std::test_rng;
use zkp_r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

use super::*;

const MAX_CYCLES: u64 = 1_000_000_000_000;

pub struct Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
    pub num: u32,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Mini<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let var_x = cs.alloc(|| "x", || self.x.ok_or(SynthesisError::AssignmentMissing))?;

        let var_y = cs.alloc(|| "y", || self.y.ok_or(SynthesisError::AssignmentMissing))?;

        let var_z = cs.alloc_input(
            || "z(output)",
            || self.z.ok_or(SynthesisError::AssignmentMissing),
        )?;

        for _ in 0..self.num {
            cs.enforce(
                || "x * (y + 2) = z",
                |lc| lc + var_x,
                |lc| lc + var_y + (F::from(2u32), CS::one()),
                |lc| lc + var_z,
            );
        }

        Ok(())
    }
}

#[test]
fn test_groth16() {
    use zkp_groth16::{create_random_proof, generate_random_parameters};

    let num = 10;
    let rng = &mut test_rng(); // Only in test code.

    // TRUSTED SETUP
    println!("Groth16 setup...");
    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };
    let params = generate_random_parameters::<E, _, _>(c, rng).unwrap();

    let mut vk_bytes = Vec::new();
    params.vk.serialize(&mut vk_bytes).unwrap();

    println!("Groth16 proving...");

    let c = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let proof = create_random_proof(&params, c, rng).unwrap();

    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).unwrap();

    let mut public_bytes = Vec::new();
    Fr::from(10u32).serialize(&mut public_bytes).unwrap();

    println!("Groth16 verifying on CKB...");

    proving_test(
        vk_bytes.into(),
        proof_bytes.into(),
        public_bytes.into(),
        "universal_groth16_verifier",
        "groth16 verify",
    );
}

#[test]
fn test_bulletproofs() {
    use zkp_bulletproofs::create_random_proof;

    let num = 10;
    let rng = &mut test_rng(); // Only in test code.

    println!("Bulletproofs proving...");

    let c = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let (gens, r1cs, proof) = create_random_proof::<E, _, _>(c, rng).unwrap();

    let mut proof_bytes = Vec::new();
    gens.serialize(&mut proof_bytes).unwrap();
    r1cs.serialize(&mut proof_bytes).unwrap();
    proof.serialize(&mut proof_bytes).unwrap();

    let mut public_bytes = Vec::new();
    Fr::from(10u32).serialize(&mut public_bytes).unwrap();

    println!("Bulletproofs verifying on CKB...");

    proving_test(
        Default::default(),
        proof_bytes.into(),
        public_bytes.into(),
        "mini_bulletproofs_verifier",
        "bulletproofs verify",
    );
}

#[test]
fn test_marlin() {
    use zkp_marlin::{create_random_proof, index, universal_setup};

    let num = 10;
    let rng = &mut test_rng(); // Only in test code.

    // TRUSTED SETUP
    println!("Marlin setup...");
    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let srs = universal_setup::<E, _>(2usize.pow(10), rng).unwrap();
    let (pk, vk) = index(&srs, c).unwrap();

    println!("Marlin proving...");

    let mut vk_bytes = Vec::new();
    vk.serialize(&mut vk_bytes).unwrap();

    let c = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let proof = create_random_proof(&pk, c, rng).unwrap();

    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).unwrap();

    let mut public_bytes = Vec::new();
    Fr::from(10u32).serialize(&mut public_bytes).unwrap();

    println!("Marlin verifying on CKB...");

    proving_test(
        vk_bytes.into(),
        proof_bytes.into(),
        public_bytes.into(),
        "universal_marlin_verifier",
        "marlin verify",
    );
}

use zkp_clinkv2::r1cs as clinkv2_r1cs;

pub struct Clinkv2Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
    pub num: u32,
}

impl<F: PrimeField> clinkv2_r1cs::ConstraintSynthesizer<F> for Clinkv2Mini<F> {
    fn generate_constraints<CS: clinkv2_r1cs::ConstraintSystem<F>>(
        self,
        cs: &mut CS,
        index: usize,
    ) -> Result<(), clinkv2_r1cs::SynthesisError> {
        cs.alloc_input(|| "r1", || Ok(F::one()), index)?;

        let var_x = cs.alloc(
            || "x",
            || {
                self.x
                    .ok_or(clinkv2_r1cs::SynthesisError::AssignmentMissing)
            },
            index,
        )?;

        let var_y = cs.alloc(
            || "y",
            || {
                self.y
                    .ok_or(clinkv2_r1cs::SynthesisError::AssignmentMissing)
            },
            index,
        )?;

        let var_z = cs.alloc_input(
            || "z(output)",
            || {
                self.z
                    .ok_or(clinkv2_r1cs::SynthesisError::AssignmentMissing)
            },
            index,
        )?;

        if index == 0 {
            for _ in 0..self.num {
                cs.enforce(
                    || "x * (y + 2) = z",
                    |lc| lc + var_x,
                    |lc| lc + var_y + (F::from(2u32), CS::one()),
                    |lc| lc + var_z,
                );
            }
        }

        Ok(())
    }
}

#[test]
fn test_clinkv2_kzg10() {
    use zkp_clinkv2::kzg10::{create_random_proof, ProveAssignment, KZG10};
    use zkp_clinkv2::r1cs::ConstraintSynthesizer;

    let n: usize = 100;

    let num = 10;
    let rng = &mut test_rng(); // Only in test code.

    println!("Clinkv2 kzg10 setup...");
    let degree: usize = n.next_power_of_two();
    let kzg10_pp = KZG10::<E>::setup(degree, false, rng).unwrap();
    let (kzg10_ck, kzg10_vk) = KZG10::<E>::trim(&kzg10_pp, degree).unwrap();

    let mut vk_bytes = Vec::new();
    kzg10_vk.serialize(&mut vk_bytes).unwrap();

    println!("Clinkv2 kzg10 proving...");

    let mut prover_pa = ProveAssignment::<E>::default();

    let mut io: Vec<Vec<Fr>> = vec![];
    let mut output: Vec<Fr> = vec![];

    for i in 0..n {
        // Generate a random preimage and compute the image
        {
            // Create an instance of our circuit (with the witness)
            let c = Clinkv2Mini::<Fr> {
                x: Some(Fr::from(2u32)),
                y: Some(Fr::from(3u32)),
                z: Some(Fr::from(10u32)),
                num: num,
            };

            output.push(Fr::from(10u32));
            c.generate_constraints(&mut prover_pa, i).unwrap();
        }
    }
    let one = vec![Fr::one(); n];
    io.push(one);
    io.push(output);

    let proof = create_random_proof(&prover_pa, &kzg10_ck, rng).unwrap();

    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).unwrap();

    let mut public_bytes = Vec::new();
    io.serialize(&mut public_bytes).unwrap();

    println!("Clinkv2 kzg10 verifying on CKB...");

    proving_test(
        vk_bytes.into(),
        proof_bytes.into(),
        public_bytes.into(),
        "mini_clinkv2_kzg10_verifier",
        "clinkv2 kzg10 verify",
    );
}

#[test]
fn test_clinkv2_ipa() {
    use blake2::Blake2s;
    use zkp_clinkv2::ipa::{create_random_proof, InnerProductArgPC, ProveAssignment};
    use zkp_clinkv2::r1cs::ConstraintSynthesizer;

    let n: usize = 100;

    let num = 10;
    let rng = &mut test_rng(); // Only in test code.

    println!("Clinkv2 ipa setup...");
    let degree: usize = n.next_power_of_two();

    let ipa_pp = InnerProductArgPC::<E, Blake2s>::setup(degree, rng).unwrap();
    let (ipa_ck, ipa_vk) = InnerProductArgPC::<E, Blake2s>::trim(&ipa_pp, degree).unwrap();

    let mut vk_bytes = Vec::new();
    ipa_vk.serialize(&mut vk_bytes).unwrap();

    println!("Clinkv2 ipa proving...");

    let mut prover_pa = ProveAssignment::<E, Blake2s>::default();

    let mut io: Vec<Vec<Fr>> = vec![];
    let mut output: Vec<Fr> = vec![];

    for i in 0..n {
        // Generate a random preimage and compute the image
        {
            // Create an instance of our circuit (with the witness)
            let c = Clinkv2Mini::<Fr> {
                x: Some(Fr::from(2u32)),
                y: Some(Fr::from(3u32)),
                z: Some(Fr::from(10u32)),
                num: num,
            };

            output.push(Fr::from(10u32));
            c.generate_constraints(&mut prover_pa, i).unwrap();
        }
    }
    let one = vec![Fr::one(); n];
    io.push(one);
    io.push(output);

    let proof = create_random_proof(&prover_pa, &ipa_ck, rng).unwrap();

    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).unwrap();

    let mut public_bytes = Vec::new();
    io.serialize(&mut public_bytes).unwrap();

    println!("Clinkv2 ipa verifying on CKB...");

    proving_test(
        vk_bytes.into(),
        proof_bytes.into(),
        public_bytes.into(),
        "mini_clinkv2_ipa_verifier",
        "clinkv2 ipa verify",
    );
}

#[test]
fn test_spartan_snark() {
    use zkp_spartan::snark::{create_random_proof, generate_random_parameters};

    let num = 10;
    let rng = &mut test_rng(); // Only in test code.

    println!("Spartan snark setup...");

    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let params = generate_random_parameters::<E, _, _>(c, rng).unwrap();
    let (pk, vk) = params.keypair();

    let mut vk_bytes = Vec::new();
    vk.serialize(&mut vk_bytes).unwrap();

    println!("Spartan snark Creating proof...");
    let c1 = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: 10,
    };

    let proof = create_random_proof(&pk, c1, rng).unwrap();

    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).unwrap();

    let mut public_bytes = Vec::new();
    Fr::from(10u32).serialize(&mut public_bytes).unwrap();

    println!("Spartan snark verifying on CKB...");

    proving_test(
        vk_bytes.into(),
        proof_bytes.into(),
        public_bytes.into(),
        "universal_spartan_snark_verifier",
        "spartan snark verify",
    );
}

#[test]
fn test_spartan_nizk() {
    use zkp_spartan::nizk::{create_random_proof, generate_random_parameters};

    let num = 10;
    let rng = &mut test_rng(); // Only in test code.

    println!("Spartan nizk setup...");

    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let params = generate_random_parameters::<E, _, _>(c, rng).unwrap();
    let (pk, vk) = params.keypair();

    let mut vk_bytes = Vec::new();
    vk.serialize(&mut vk_bytes).unwrap();

    println!("Spartan nizk Creating proof...");
    let c1 = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: 10,
    };

    let proof = create_random_proof(&pk, c1, rng).unwrap();

    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).unwrap();

    let mut public_bytes = Vec::new();
    Fr::from(10u32).serialize(&mut public_bytes).unwrap();

    println!("Spartan nizk verifying on CKB...");

    proving_test(
        vk_bytes.into(),
        proof_bytes.into(),
        public_bytes.into(),
        "universal_spartan_nizk_verifier",
        "spartan nizk verify",
    );
}

// x * (y + 2) = z
fn layers() -> Vec<Vec<(u8, usize, usize)>> {
    let mut layers = Vec::new();

    let mut layer1 = Vec::new();
    layer1.push((0, 1, 2));
    layer1.push((1, 0, 4));
    layer1.push((1, 3, 4));
    layer1.push((1, 4, 4));
    layers.push(layer1);

    let mut layer2 = Vec::new();
    layer2.push((1, 0, 1));
    layer2.push((1, 2, 3));
    layers.push(layer2);

    let mut layer3 = Vec::new();
    layer3.push((0, 0, 1));
    layers.push(layer3);

    layers
}

#[test]
fn test_libra_zk_linear_gkr() {
    use zkp_libra::{circuit::Circuit, libra_zk_linear_gkr::ZKLinearGKRProof, params::Parameters};

    let rng = &mut test_rng(); // Only in test code.

    // 2 * (3 + 2) = 10
    let inputs = vec![Fr::from(2u32), -Fr::from(10u32), Fr::one(), Fr::zero()];
    let witnesses = vec![Fr::from(2u32), Fr::from(3u32), Fr::zero(), Fr::zero()];
    let layers = layers();
    println!("Libra: prepare for constructing circuit...ok");

    let params = Parameters::<E>::new(rng, 8);
    println!("Libra: prepare for constructing circuit...ok");
    let mut vk_bytes = Vec::new();
    params.serialize(&mut vk_bytes).unwrap();

    let circuit = Circuit::new(inputs.len(), witnesses.len(), &layers);
    println!("Libra: construct circuit...ok");

    let (proof, output) =
        ZKLinearGKRProof::prover::<_>(&params, &circuit, &inputs, &witnesses, rng);
    println!("Libra: generate proof...ok");

    let result = proof.verify(&params, &circuit, &output, &inputs);
    println!("Libra: verifier...{}", result);

    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).unwrap();

    let mut public_bytes = Vec::new();
    inputs.serialize(&mut public_bytes).unwrap();
    output.serialize(&mut public_bytes).unwrap();

    println!("Libra verifying on CKB...");

    proving_test(
        vk_bytes.into(),
        proof_bytes.into(),
        public_bytes.into(),
        "mini_libra_zk_linear_gkr_verifier",
        "libra_zk_linear_gkr verify",
    );
}

#[test]
fn test_hyrax_zk_linear_gkr() {
    use zkp_hyrax::{circuit::Circuit, hyrax_proof::HyraxProof, params::Parameters};

    let rng = &mut test_rng(); // Only in test code.

    // 2 * (3 + 2) = 10
    let mut inputs = vec![];
    let mut witnesses = vec![];
    let input = vec![Fr::from(2u32), -Fr::from(10u32), Fr::one(), Fr::zero()];
    let witness = vec![Fr::from(2u32), Fr::from(3u32), Fr::zero(), Fr::zero()];
    inputs.push(input.clone());
    inputs.push(witness.clone());
    witnesses.push(witness);
    witnesses.push(input);

    let layers = layers();
    println!("Hyrax: prepare for constructing circuit...ok");

    let params = Parameters::<E>::new(rng, 8);
    let mut vk_bytes = Vec::new();
    params.serialize(&mut vk_bytes).unwrap();

    let circuit = Circuit::new(4, 4, &layers); // input & witness length is 4.
    println!("Hyrax: construct circuit...ok");

    let (proof, output) =
        HyraxProof::prover::<_>(&params, &witnesses, &inputs, &circuit, witnesses.len(), rng);
    println!("Hyrax: generate proof...ok");

    let result = proof.verify(&params, &output, &inputs, &circuit);
    println!("Hyrax: verifier...{}", result);

    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes).unwrap();

    let mut public_bytes = Vec::new();
    inputs.serialize(&mut public_bytes).unwrap();
    output.serialize(&mut public_bytes).unwrap();

    println!("Hyrax: verifying on CKB...");

    proving_test(
        vk_bytes.into(),
        proof_bytes.into(),
        public_bytes.into(),
        "mini_hyrax_zk_linear_gkr_verifier",
        "hyrax_zk_linear_gkr verify",
    );
}

fn build_test_context(
    vk: Bytes,
    proof_file: Bytes,
    publics: Bytes,
    contract: &str,
) -> (Context, TransactionView) {
    // deploy contract.
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary(contract);
    let contract_out_point = context.deploy_cell(contract_bin);
    // Deploy always_success script as lock script.
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // Build LOCK script using always_success script.
    let lock_script = context
        .build_script(&always_success_out_point, Default::default())
        .expect("build lock script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    // Build TYPE script using the ckb-zkp contract
    let type_script = context
        .build_script(&contract_out_point, Bytes::default())
        .expect("build type script");
    let type_script_dep = CellDep::new_builder().out_point(contract_out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .type_(Some(type_script).pack())
            .build(),
        CellOutput::new_builder()
            .capacity(200u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(300u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![vk, proof_file, publics];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .cell_dep(type_script_dep)
        .build();
    (context, tx)
}

fn proving_test(vk: Bytes, proof: Bytes, publics: Bytes, contract: &str, name: &str) {
    let (mut context, tx) = build_test_context(vk, proof, publics, contract);

    let tx = context.complete_tx(tx);

    let start = Instant::now();
    match context.verify_tx(&tx, MAX_CYCLES) {
        Ok(cycles) => {
            println!("{}: cycles: {}", name, cycles);
        }
        Err(err) => panic!("Failed to pass test: {}", err),
    }
    println!(
        "Verify Mini circuit use {} Time: {:?}",
        name,
        start.elapsed()
    );
}
