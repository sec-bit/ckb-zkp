use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::{One, Zero};
use ark_serialize::*;
use ark_std::test_rng;
use std::time::Instant;
use zkp_libra::{circuit::Circuit, libra_zk_linear_gkr::ZKLinearGKRProof, params::Parameters};

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
fn mini_libra() {
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    let params = Parameters::<E>::new(rng, 8);
    let param_to_hash = params.param_to_hash();

    let mut vk_bytes = Vec::new();
    params.serialize(&mut vk_bytes).unwrap();
    println!("[Libra] VerifyKey length : {}", vk_bytes.len());

    // 2 * (3 + 2) = 10
    let p_start = Instant::now();
    let inputs = vec![Fr::from(2u32), -Fr::from(10u32), Fr::one(), Fr::zero()];
    let witnesses = vec![Fr::from(2u32), Fr::from(3u32), Fr::zero(), Fr::zero()];
    let layers = layers();
    let circuit = Circuit::new(inputs.len(), witnesses.len(), &layers);
    let circuit_to_hash = circuit.circuit_to_hash::<E>();
    
    let (proof, output) =
        ZKLinearGKRProof::prover::<_>(&params, &circuit, &inputs, &witnesses, circuit_to_hash, param_to_hash, rng);
    let p_time = p_start.elapsed();
    println!("[Libra] Prove time       : {:?}", p_time);

    let mut proof_bytes = vec![];
    proof.serialize(&mut proof_bytes).unwrap();
    println!("[Libra] Proof length     : {}", proof_bytes.len());

    let v_start = Instant::now();
    assert!(proof.verify(&params, &circuit, &output, &inputs, circuit_to_hash, param_to_hash));
    let v_time = v_start.elapsed();
    println!("[Libra] Verify time      : {:?}", v_time);

    let params2 = Parameters::<E>::deserialize(&vk_bytes[..]).unwrap();
    let proof2 = ZKLinearGKRProof::<E>::deserialize(&proof_bytes[..]).unwrap();
    assert!(proof2.verify(&params2, &circuit, &output, &inputs, circuit_to_hash, param_to_hash));
}
