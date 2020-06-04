use rand::prelude::*;
use std::path::PathBuf;
// use zkp::{
//     gadget::mimc::{mimc_hash, MiMC},
//     math::PairingEngine,
//     scheme::groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key},
//     Groth16Proof,
// };

/// Parameters we need setup:
/// MIMC HASH CONSTANTS
/// MIMC CIRCUIT ORIGINAL VALUE
/// GROTH16 PARAMETERS
/// GROTH16 PREPARE VERIFICATION KEY
pub fn setup(_p: Option<PathBuf>) {
    println!("Prepareing...");

    let mut rng = rand::thread_rng();

    let seed: [u8; 32] = rng.gen();

    println!("CONSTANTS SEED: {:?}", seed);

    let groth16_seed: [u8; 32] = rng.gen();

    println!("GROTH16 SEED: {:?}", groth16_seed);

    //let constants = constants_with_seed::<E::Fr>();
    //let params = groth16_params_with_seed::<E>(&constants).unwrap();

    //let mut vk_bytes = vec![];
    //params.vk.write(&mut vk_bytes).unwrap();
    //println!("{:?}", vk_bytes);
}
