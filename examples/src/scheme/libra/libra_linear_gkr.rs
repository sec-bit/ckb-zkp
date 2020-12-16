use curve::curve25519::Curve25519;
use math::{Curve, One, Zero};
use scheme::libra::circuit::Circuit;
use scheme::libra::libra_linear_gkr::LinearGKRProof;

fn prepare_constrcut_circuit<G: Curve>() -> (Vec<G::Fr>, Vec<G::Fr>, Vec<Vec<(u8, usize, usize)>>) {
    let mut inputs = Vec::new();
    let mut witnesses = Vec::new();
    let mut value = G::Fr::zero();
    for _ in 0..8 {
        value += &G::Fr::one();
        inputs.push(value)
    }
    for _ in 0..8 {
        value += &G::Fr::one();
        witnesses.push(value)
    }
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

    (inputs, witnesses, layers)
}

pub fn libra_linear_gkr() {
    println!("start linear_gkr...");
    let (inputs, witnesses, layers) = prepare_constrcut_circuit::<Curve25519>();
    println!("prepare for constructing circuit...ok");

    let circuit = Circuit::new(inputs.len(), witnesses.len(), &layers);
    println!("construct circuit...ok");

    let (proof, output) = LinearGKRProof::<Curve25519>::prover(&circuit, &inputs, &witnesses);
    println!("generate proof...ok");

    let mut inputs2 = witnesses.clone();
    inputs2.extend(&inputs);
    let result = proof.verify(&circuit, &output, &inputs2);
    println!("verifier...{}", result);
}

pub fn main() {
    libra_linear_gkr();
}
