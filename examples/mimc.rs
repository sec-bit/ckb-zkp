use rand::prelude::*;
use zkp::curve::bn_256::{Bn_256, Fr};
use zkp::gadget::mimc::{constants, MiMC};
use zkp::math::ToBytes;
use zkp::scheme::groth16::generate_random_parameters;
use zkp::{prove, prove_to_bytes, verify, verify_from_bytes, Curve, Gadget, Scheme};

/// test for use groth16 & bn_256 & mimc gadget.
fn main() {
    let bytes = vec![1, 2, 3, 4, 5]; // this is your secret.
    let mut rng = thread_rng();

    // TRUSTED SETUP
    println!("TRUSTED SETUP...");
    let constants = constants::<Fr>();
    let c = MiMC::<Fr> {
        xl: None,
        xr: None,
        constants: &constants,
    };
    let params = generate_random_parameters::<Bn_256, _, _>(c, &mut rng).unwrap();

    // you need save this prove key,
    // when prove, use it as a params.
    let mut pk_bytes = vec![];
    params.write(&mut pk_bytes).unwrap();

    // you need save this verify key,
    // when verify, use it as a params.
    let mut vk_bytes = vec![];
    params.vk.write(&mut vk_bytes).unwrap();

    println!("START PROVE...");
    // START PROVE.
    let proof = prove(
        Gadget::MiMC,
        Scheme::Groth16,
        Curve::Bn_256,
        &bytes,
        &pk_bytes,
        rng,
    )
    .unwrap();

    println!("START VERIFY...");
    // START VERIFY.
    let is_ok = verify(proof, &vk_bytes);
    assert!(is_ok);

    println!("ANOTHER USE BYTES START PROVE...");
    // use Bytes.
    let proof_bytes = prove_to_bytes(
        Gadget::MiMC,
        Scheme::Groth16,
        Curve::Bn_256,
        &bytes,
        &pk_bytes,
        rng,
    )
    .unwrap();

    println!("PROOF FILE LENGTH: {}", proof_bytes.len());

    println!("ANOTHER USE BYTES START VERIFY...");
    let is_ok2 = verify_from_bytes(&proof_bytes, &vk_bytes);
    assert!(is_ok2);

    println!("all is ok");
}
