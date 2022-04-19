use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::{One, Zero};
use ark_serialize::*;
use ark_std::test_rng;
use std::time::Instant;
use zkp_hyrax::{circuit::Circuit, hyrax_proof::HyraxProof, params::Parameters};

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
fn mini_hyrax() {
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    let params = Parameters::<E>::new(rng, 8);
    let mut vk_bytes = Vec::new();
    params.serialize(&mut vk_bytes).unwrap();
    println!("[Hyrax] VerifyKey length : {}", vk_bytes.len());

    // 2 * (3 + 2) = 10
    let p_start = Instant::now();

    let mut inputs = vec![];
    let mut witnesses = vec![];
    let input = vec![Fr::from(2u32), -Fr::from(10u32), Fr::one(), Fr::zero()];
    let witness = vec![Fr::from(2u32), Fr::from(3u32), Fr::zero(), Fr::zero()];
    inputs.push(input.clone());
    inputs.push(witness.clone());
    witnesses.push(witness);
    witnesses.push(input);
    let layers = layers();

    let circuit = Circuit::new(4, 4, &layers); // input & witness length is 4.
    let (proof, output) =
        HyraxProof::prover::<_>(&params, &witnesses, &inputs, &circuit, witnesses.len(), rng);
    let p_time = p_start.elapsed();
    println!("[Hyrax] Prove time       : {:?}", p_time);

    let mut proof_bytes = vec![];
    proof.serialize(&mut proof_bytes).unwrap();
    println!("[Hyrax] Proof length     : {}", proof_bytes.len());

    let v_start = Instant::now();
    assert!(proof.verify(&params, &output, &inputs, &circuit));
    let v_time = v_start.elapsed();
    println!("[Hyrax] Verify time      : {:?}", v_time);

    let params2 = Parameters::<E>::deserialize(&vk_bytes[..]).unwrap();
    let proof2 = HyraxProof::<E>::deserialize(&proof_bytes[..]).unwrap();
    assert!(proof2.verify(&params2, &output, &inputs, &circuit));
}
