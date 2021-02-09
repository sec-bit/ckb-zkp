use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::One;
use ark_std::test_rng;
use zkp_libra::{
    circuit::Circuit, libra_linear_gkr::LinearGKRProof, libra_zk_linear_gkr::ZKLinearGKRProof,
    params::Parameters,
};

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
fn prepare_construct_circuit() -> (Vec<Fr>, Vec<Fr>, Vec<Vec<(u8, usize, usize)>>) {
    let inputs = vec![
        Fr::one() + &Fr::one(),              //2
        Fr::one() + &Fr::one() + &Fr::one(), //3
    ];

    let witnesses = vec![
        Fr::one() + &Fr::one() + &Fr::one(),              //3
        Fr::one() + &Fr::one() + &Fr::one() + &Fr::one(), //4
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

#[test]
fn test_libra_linear_gkr_2() {
    println!("start linear_gkr...");
    let (inputs, witnesses, layers) = prepare_construct_circuit();
    println!("prepare for constructing circuit...ok");

    let circuit = Circuit::new(inputs.len(), witnesses.len(), &layers);
    println!("construct circuit...ok");

    let (proof, output) = LinearGKRProof::<E>::prover(&circuit, &inputs, &witnesses);
    println!("generate proof...ok");

    let mut inputs2 = witnesses.clone();
    inputs2.extend(&inputs);
    let result = proof.verify(&circuit, &output, &inputs2);
    println!("verifier...{}", result);
}

#[test]
fn test_libra_zk_linear_gkr_2() {
    let rng = &mut test_rng();
    println!("start zk linear gkr...");

    let (inputs, witnesses, layers) = prepare_construct_circuit();
    println!("prepare for constructing circuit...ok");

    let params = Parameters::<E>::new(rng, 8);
    println!("prepare for constructing circuit...ok");

    let circuit = Circuit::new(inputs.len(), witnesses.len(), &layers);
    println!("construct circuit...ok");

    let (proof, output) =
        ZKLinearGKRProof::prover::<_>(&params, &circuit, &inputs, &witnesses, rng);
    println!("generate proof...ok");

    let result = proof.verify(&params, &circuit, &output, &inputs);
    println!("verifier...{}", result);
}
