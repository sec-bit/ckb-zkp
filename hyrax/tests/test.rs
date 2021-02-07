use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::UniformRand;
use ark_std::test_rng;
use rand::Rng;
use zkp_curve::Curve;
use zkp_hyrax::{circuit::Circuit, hyrax_proof::HyraxProof, params::Parameters};

#[test]
fn test_hyrax_gkr() {
    println!("start linear_gkr...");
    let rng = &mut test_rng();
    let mut layers = Vec::new();
    let mut layer = Vec::new();
    layer.push((1, 0, 1));
    layer.push((0, 2, 3));
    layer.push((0, 4, 5));
    layer.push((1, 6, 7));
    layer.push((1, 15, 8));
    layer.push((1, 9, 10));
    layer.push((0, 11, 12));
    layer.push((0, 13, 14));
    layers.push(layer);
    let mut layer = Vec::new();
    layer.push((1, 0, 1));
    layer.push((0, 2, 3));
    layer.push((0, 4, 5));
    layer.push((1, 6, 7));
    layers.push(layer);
    let mut layer = Vec::new();
    layer.push((0, 0, 1));
    layer.push((0, 1, 2));
    layer.push((1, 2, 3));
    layer.push((1, 1, 3));
    layers.push(layer);
    println!("prepare linear_gkr...ok");
    let circuit = Circuit::new(8, 8, &layers);
    println!("construct circuit...ok");
    let mut witnesses = Vec::new();
    let mut inputs = Vec::new();
    let n = 4;
    for _ in 0..n {
        witnesses.push((0..8).map(|_| Fr::rand(rng)).collect::<Vec<_>>());
        inputs.push((0..8).map(|_| Fr::rand(rng)).collect::<Vec<_>>());
    }
    let params = Parameters::new(rng, 8);
    println!("generate parameters...");
    let result = hyrax_zk_parallel_gkr::<E, _>(&params, &witnesses, &inputs, &circuit, rng);
    assert!(result);
    println!("hyrax linear gkr...ok");
}

fn hyrax_zk_parallel_gkr<G: Curve, R: Rng>(
    params: &Parameters<G>,
    witnesses: &Vec<Vec<G::Fr>>,
    inputs: &Vec<Vec<G::Fr>>,
    circuit: &Circuit,
    rng: &mut R,
) -> bool {
    assert_eq!(witnesses.len(), inputs.len());
    let (proof, outputs) =
        HyraxProof::prover(params, witnesses, inputs, circuit, witnesses.len(), rng);
    println!("hyrax_zk_parallel_gkr -- generate proof...ok");
    let result = proof.verify(params, &outputs, inputs, circuit);
    println!("hyrax_zk_parallel_gkr -- verify...{}", result);
    result
}
