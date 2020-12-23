use curve::bn_256::Bn_256;
use math::{Curve, One, Zero};
use rand::thread_rng;
use scheme::libra::circuit::Circuit;
use scheme::libra::libra_zk_linear_gkr::ZKLinearGKRProof;
use scheme::libra::params::Parameters;

/// circuit structure
///layer3: gate0 = (add, 0, 1), gate1 = (add, 1, 2), gate2 = (mul, 2, 3), gate3 = (mul, 1, 3)
///layer2: gate0 = (mul, 0, 1), gate1 = (add, 2, 3), gate2 = (add, 4, 5), gate3 = (mul, 6, 7)
///layer1: gate0 = (mul, 0, 1), gate1 = (add, 2, 3), gate2 = (add, 4, 5), gate4 = (mul, 6, 7), gate5 = (mul, 15, 8), gate6 = (mul, 9, 10), gate7 =(add, 11, 12), gate8 =(add, 13, 14)
///layer0: witness0,  witness1,  witness2,  witness3,  witness4,  witness5,  witness6,  witness7, input0, input1, input2, input3, input4, input5, input6, input7, input8
///layer0 is input-layer, The first eight items are witnesses, and the last eight items are public inputs
///layer1~layer3 are composed of multiple gates.
///     gaten = (op, left, right) represents the nth gate, op represents the operator, add or multiple,
///     left represents the number of its left node, right  represents the number of its right node
///     e.g. layer2: gate0 = (mul, 0, 1) represents layer2-gate0 = layer1-gate0 * layer1-gate1
fn prepare_construct_circuit<G: Curve>() -> (Vec<G::Fr>, Vec<G::Fr>, Vec<Vec<(u8, usize, usize)>>) {
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

pub fn libra_zk_linear_gkr() {
    let rng = &mut thread_rng();
    println!("start zk linear gkr...");

    let (inputs, witnesses, layers) = prepare_construct_circuit::<Bn_256>();
    println!("prepare for constructing circuit...ok");

    let params = Parameters::<Bn_256>::new(rng, 8);
    println!("prepare for constructing circuit...ok");

    let circuit = Circuit::new(inputs.len(), witnesses.len(), &layers);
    println!("construct circuit...ok");

    let (proof, output) =
        ZKLinearGKRProof::prover::<_>(&params, &circuit, &inputs, &witnesses, rng);
    println!("generate proof...ok");

    let result = proof.verify(&params, &circuit, &output, &inputs);
    println!("verifier...{}", result);
}

pub fn main() {
    libra_zk_linear_gkr();
}
