use super::*;
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_types::{
    bytes::{Buf, Bytes},
    core::{TransactionBuilder, TransactionView},
    packed::*,
    prelude::*,
};
use std::time::Instant;

use ckb_zkp::{
    circuits::mini::Mini,
    curve::bn_256::Bn_256,
    math::{PairingEngine, PrimeField, ToBytes},
    prove_to_bytes,
    scheme::groth16::generate_random_parameters,
    scheme::marlin::{index, universal_setup},
    Curve, Scheme,
};
use rand::prelude::*;

const MAX_CYCLES: u64 = 1_000_000_000_000;

fn test_groth16_verfier<E: PairingEngine>(num: u32) -> (Bytes, Bytes, Bytes) {
    let mut rng = thread_rng();
    // TRUSTED SETUP
    println!("Groth16 setup...");
    let c = Mini::<E::Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };
    let params = generate_random_parameters::<E, _, _>(c, &mut rng).unwrap();

    prove_unify::<E, _, _>(Scheme::Groth16, &params, &params.vk, num)
}

fn test_marlin_verfier<E: PairingEngine>(num: u32) -> (Bytes, Bytes, Bytes) {
    let mut rng = thread_rng();
    // TRUSTED SETUP
    println!("Marlin setup...");
    let c = Mini::<E::Fr> {
        x: None,
        y: None,
        z: None,
        num: num,
    };

    let srs = universal_setup::<E, _>(2usize.pow(10), &mut rng).unwrap();
    println!("marlin indexer...");
    let (ipk, ivk) = index(&srs, c).unwrap();

    prove_unify::<E, _, _>(Scheme::Marlin, &ipk, &ivk, num)
}

fn prove_unify<E: PairingEngine, P: ToBytes, V: ToBytes>(
    s: Scheme,
    p: &P,
    v: &V,
    num: u32,
) -> (Bytes, Bytes, Bytes) {
    let mut rng = thread_rng();

    let mut pk_bytes = vec![];
    p.write(&mut pk_bytes).unwrap();
    let mut vk_bytes = vec![];
    v.write(&mut vk_bytes).unwrap();

    let x_repr = <E::Fr as PrimeField>::BigInt::from(2);
    let x = E::Fr::from_repr(x_repr);

    let y_repr = <E::Fr as PrimeField>::BigInt::from(3);
    let y = E::Fr::from_repr(y_repr);

    let z_repr = <E::Fr as PrimeField>::BigInt::from(10);
    let z = E::Fr::from_repr(z_repr);

    let circuit = Mini {
        x: Some(x),
        y: Some(y),
        z: Some(z),
        num: num,
    };

    println!("start prove");
    let proof_bytes = prove_to_bytes::<E, _, _>(s, &pk_bytes, circuit, &mut rng).unwrap();
    println!("start over");
    let mut publics_bytes = vec![];
    let publics = vec![z];
    (publics.len() as u32).write(&mut publics_bytes).unwrap();
    for i in publics {
        i.write(&mut publics_bytes).unwrap();
    }

    (vk_bytes.into(), proof_bytes.into(), publics_bytes.into())
}

#[test]
fn test_single_verifier() {
    let (vk, proof, publics) = test_groth16_verfier::<Bn_256>(10);
    proving_test(vk, proof, publics, "single_verifier", "single (bn256)");
}

#[test]
fn test_multiple_verifier() {
    let (vk, proof, publics) = test_groth16_verfier::<Bn_256>(10);

    // use groth16
    let mut new_proof = vec![];
    new_proof.push(Scheme::Groth16.to_byte());
    new_proof.extend_from_slice(proof.bytes());

    // use bn_256
    let mut new_publics = vec![];
    new_publics.push(Curve::Bn_256.to_byte());
    new_publics.extend_from_slice(publics.bytes());

    proving_test(
        vk,
        new_proof.into(),
        new_publics.into(),
        "multiple_verifier",
        "multiple (bn256)",
    );

    let (vk2, proof2, publics2) = test_marlin_verfier::<ckb_zkp::curve::Bls12_381>(10);

    // use groth16
    let mut new_proof2 = vec![];
    new_proof2.push(Scheme::Marlin.to_byte());
    new_proof2.extend_from_slice(proof2.bytes());
    //println!("{:?}", new_proof2);

    // use bls12_381
    let mut new_publics2 = vec![];
    new_publics2.push(Curve::Bls12_381.to_byte());
    new_publics2.extend_from_slice(publics2.bytes());
    //println!("{:?}", new_publics2);

    proving_test(
        vk2,
        new_proof2.into(),
        new_publics2.into(),
        "multiple_verifier",
        "multiple (bls12_381)",
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
