use ckb_zkp::{
    circuits::mini::Mini,
    curve::bn_256::{Bn_256, Fr},
    math::ToBytes,
    prove_to_bytes,
    scheme::groth16::generate_random_parameters,
    verify_from_bytes, verify_from_bytes_with_curve, Curve, Scheme,
};
use rand::prelude::*;
use std::time::Instant;

/// test for use groth16 & bn_256 & mimc gadget.
fn main() {
    let mut rng = thread_rng();

    // TRUSTED SETUP
    println!("TRUSTED SETUP...");
    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        constraints: 10, // 10-times constraints
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

    let x = Fr::from(2u32);
    let y = Fr::from(3u32);
    let z = Fr::from(10u32);

    let circuit = Mini {
        x: Some(x),
        y: Some(y),
        z: Some(z),
        constraints: 10,
    };

    println!("USE BYTES START PROVE...");
    let p_start = Instant::now();
    let proof_bytes =
        prove_to_bytes::<Bn_256, _, _>(Scheme::Groth16, &pk_bytes, circuit, rng).unwrap();
    let p_time = p_start.elapsed();
    println!("PROVE TIME: {:?}", p_time);

    let mut publics_bytes = vec![];
    let publics = vec![z];
    (publics.len() as u32).write(&mut publics_bytes).unwrap();
    for i in publics {
        i.write(&mut publics_bytes).unwrap();
    }

    println!("PROOF FILE LENGTH: {}", proof_bytes.len());

    println!("USE BYTES START VERIFY...");
    let v_start = Instant::now();
    let is_ok =
        verify_from_bytes::<Bn_256>(Scheme::Groth16, &vk_bytes, &proof_bytes, &publics_bytes);
    let v_time = v_start.elapsed();
    println!("VERIFY TIME: {:?}", v_time);
    assert!(is_ok.unwrap());

    println!("OTHER USE BYTES START VERIFY...");
    let v_start = Instant::now();
    let is_ok = verify_from_bytes_with_curve(
        Curve::Bn_256,
        Scheme::Groth16,
        &vk_bytes,
        &proof_bytes,
        &publics_bytes,
    );
    let v_time = v_start.elapsed();
    println!("OTHER VERIFY TIME: {:?}", v_time);
    assert!(is_ok.unwrap());

    println!("all is ok");
}
