use ark_ff::One;
use zkp_curve::Curve;
use zkp_curve25519::Curve25519;
use zkp_libra::circuit::Circuit;
use zkp_libra::libra_linear_gkr::LinearGKRProof;

// input0 * witness0 + input1 * witness1 = 18
/// circuit structure
///layer2: gate0 = (add, 0, 1)
///layer1: gate0 = (mul, 0, 2), gate1 = (mul, 1, 3)
///layer0: witness0, witness1,  input0, input1
///layer0 is input-layer, The first two items are witnesses, and the last two items are public inputs
///layer1~layer3 are composed of multiple gates.
///     gaten = (op, left, right) represents the nth gate, op represents the operator, add or multiple,
///     left represents the number of its left node, right  represents the number of its right node
///     e.g. layer2: gate0 = (mul, 0, 1) represents layer2-gate0 = layer1-gate0 * layer1-gate1
fn prepare_construct_circuit<G: Curve>() -> (Vec<G::Fr>, Vec<G::Fr>, Vec<Vec<(u8, usize, usize)>>) {
    let inputs = vec![
        G::Fr::one() + &G::Fr::one(),                 //2
        G::Fr::one() + &G::Fr::one() + &G::Fr::one(), //3
    ];

    let witnesses = vec![
        G::Fr::one() + &G::Fr::one() + &G::Fr::one(), //3
        G::Fr::one() + &G::Fr::one() + &G::Fr::one() + &G::Fr::one(), //4
    ];
    let mut layers = Vec::new();
    let mut layer = Vec::new();
    layer.push((1, 0, 2));
    layer.push((1, 1, 3));
    layers.push(layer);
    let mut layer = Vec::new();
    layer.push((0, 0, 1));
    layers.push(layer);

    (inputs, witnesses, layers)
}

pub fn libra_linear_gkr() {
    println!("start linear_gkr...");
    let (inputs, witnesses, layers) = prepare_construct_circuit::<Curve25519>();
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
