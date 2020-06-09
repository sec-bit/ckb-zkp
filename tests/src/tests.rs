use super::*;
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::*,
    prelude::*,
};
use std::fs::File;
use std::io::Read;

// Relative path starts from capsuled-contracts/tests.
const VK_DIR: &str = "../dependencies/zkp-toolkit/trusted_setup/";
const PROOF_DIR: &str = "../dependencies/zkp-toolkit/proofs_files/";
const MAX_CYCLES: u64 = 1000_000_000;

fn build_test_context(proof_file: Bytes, vk: Bytes) -> (Context, TransactionView) {
    // deploy contract.
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-zkp");
    let contract_out_point = context.deploy_contract(contract_bin);
    // Deploy always_success script as lock script.
    let always_success_out_point = context.deploy_contract(ALWAYS_SUCCESS.clone());

    // Build LOCK script using always_success script.
    let lock_script = context
        .build_script(&always_success_out_point, Default::default())
        .expect("build lock script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    // Build TYPE script using the ckb-zkp contract
    let type_script = context
        .build_script(&contract_out_point, vk)
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
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![proof_file, Bytes::new()];

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
#[test]
fn test_prove_bn256() {
    let mut proof_file = File::open(format!("{}/{}", PROOF_DIR, "mimc_proof_bn256")).expect("read proof file");
    let mut proof_bin = Vec::new();
    // read the whole file
    proof_file
        .read_to_end(&mut proof_bin)
        .expect("Failed to read proof file");

    let mut vk_file = File::open(format!("{}/{}", VK_DIR, "mimc-groth16-bn_256.vk")).expect("Failed to read VK file");
    let mut vk_bin = Vec::new();
    vk_file
        .read_to_end(&mut vk_bin)
        .expect("Failed to read VK file");

    let (mut context, tx) = build_test_context(proof_bin.into(), vk_bin.into());

    let tx = context.complete_tx(tx);
    match context.verify_tx(&tx, MAX_CYCLES) {
        Ok(cycles) => {
            println!("cycles: {}", cycles);
        }
        Err(err) => panic!("Failed to pass test: {}", err),
    }
}

#[test]
fn test_prove_bls12_381() {
    let mut proof_file = File::open(format!("{}/{}", PROOF_DIR, "mimc_proof_bls12_381")).expect("read proof file");
    let mut proof_bin = Vec::new();
    // read the whole file
    proof_file
        .read_to_end(&mut proof_bin)
        .expect("Failed to read proof file");

    let mut vk_file = File::open(format!("{}/{}", VK_DIR, "mimc-groth16-bls12_381.vk")).expect("Failed to read VK file");
    let mut vk_bin = Vec::new();
    vk_file
        .read_to_end(&mut vk_bin)
        .expect("Failed to read VK file");

    let (mut context, tx) = build_test_context(proof_bin.into(), vk_bin.into());

    let tx = context.complete_tx(tx);
    match context.verify_tx(&tx, MAX_CYCLES) {
        Ok(cycles) => {
            println!("cycles: {}", cycles);
        }
        Err(err) => panic!("Failed to pass test: {}", err),
    }
}


#[test]
#[ignore]
fn test_no_proof() {
    let (mut context, tx) = build_test_context(Bytes::new(), Bytes::new());

    let tx = context.complete_tx(tx);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("should not pass verification");
}
