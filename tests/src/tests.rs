use super::*;
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::*,
    prelude::*,
};
use std::time::Instant;

use ckb_zkp::{
    bn_256::{Bn_256 as E, Fr},
    math::{test_rng, One, PrimeField, ToBytes},
    r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError},
};

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
    use ckb_zkp::groth16::{generate_random_parameters, prove_to_bytes, verify_from_bytes};

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

    let mut vk_bytes = vec![];
    params.vk.write(&mut vk_bytes).unwrap();

    let c = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let (proof, publics) = prove_to_bytes(&params, c, rng, &[Fr::from(10u32)]).unwrap();
    assert!(verify_from_bytes::<E>(&vk_bytes, &proof, &publics).unwrap());

    proving_test(
        vk_bytes.into(),
        proof.into(),
        publics.into(),
        "universal_groth16_verifier",
        "groth16 verify",
    );
}

#[test]
fn test_marlin() {
    use ckb_zkp::marlin::{index, prove_to_bytes, universal_setup, verify_from_bytes};

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
    println!("Marlin indexer...");
    let (pk, vk) = index(&srs, c).unwrap();
    let mut vk_bytes = vec![];
    vk.write(&mut vk_bytes).unwrap();

    let c = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let (proof, publics) = prove_to_bytes(&pk, c, rng, &[Fr::from(10u32)]).unwrap();
    assert!(verify_from_bytes::<E>(&vk_bytes, &proof, &publics).unwrap());

    proving_test(
        vk_bytes.into(),
        proof.into(),
        publics.into(),
        "universal_marlin_verifier",
        "marlin verify",
    );
}

#[test]
fn test_bulletproofs_mini() {
    use ckb_zkp::bulletproofs::{prove_to_bytes, verify_from_bytes};

    let num = 10;
    let rng = &mut test_rng(); // Only in test code.

    println!("Bulletproofs proving...");

    let c = Mini::<Fr> {
        x: Some(Fr::from(2u32)),
        y: Some(Fr::from(3u32)),
        z: Some(Fr::from(10u32)),
        num: num,
    };

    let (proof, publics) = prove_to_bytes::<E, _, _>(c, rng, &[Fr::from(10u32)]).unwrap();

    println!("Bulletproofs verifying...");

    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    assert!(verify_from_bytes::<E, _>(c, &proof, &publics).unwrap());

    println!("Bulletproofs verifying on CKB...");

    proving_test(
        Default::default(),
        proof.into(),
        publics.into(),
        "mini_bulletproofs_verifier",
        "bulletproofs verify",
    );
}

use ckb_zkp::clinkv2::r1cs as clinkv2_r1cs;

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
fn test_clinkv2_mini() {
    use ckb_zkp::clinkv2::{
        kzg10::KZG10, prove_to_bytes, r1cs::ConstraintSynthesizer, verify_from_bytes,
        ProveAssignment, VerifyAssignment,
    };

    let n: usize = 100;

    let num = 10;
    let rng = &mut test_rng(); // Only in test code.

    println!("Clinkv2 setup...");
    let degree: usize = n.next_power_of_two();
    let kzg10_pp = KZG10::<E>::setup(degree, false, rng).unwrap();
    let (kzg10_ck, kzg10_vk) = KZG10::<E>::trim(&kzg10_pp, degree).unwrap();

    let mut vk_bytes = vec![];
    kzg10_vk.write(&mut vk_bytes).unwrap();

    println!("Clinkv2 proving...");

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

    let (proof, publics) = prove_to_bytes(&prover_pa, &kzg10_ck, rng, &io).unwrap();

    println!("Clinkv2 verifying...");

    let c = Clinkv2Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let mut verifier_pa = VerifyAssignment::<E>::default();
    c.generate_constraints(&mut verifier_pa, 0usize).unwrap();

    assert!(verify_from_bytes::<E>(&verifier_pa, &vk_bytes, &proof, &publics).unwrap());

    println!("Clinkv2 verifying on CKB...");

    proving_test(
        vk_bytes.into(),
        proof.into(),
        publics.into(),
        "mini_clinkv2_verifier",
        "clinkv2 verify",
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
