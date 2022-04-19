use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::One;
use ark_std::test_rng;
use rand::Rng;
use zkp_hyrax::{circuit::Circuit, hyrax_proof::HyraxProof, params::Parameters};

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
fn prepare_construct_circuit() -> (Vec<Vec<Fr>>, Vec<Vec<Fr>>, Vec<Vec<(u8, usize, usize)>>) {
    let mut inputs_vec = Vec::new();
    let mut witnesses_vec = Vec::new();
    let inputs = vec![
        Fr::one() + &Fr::one(),              //2
        Fr::one() + &Fr::one() + &Fr::one(), //3
    ];
    let witnesses = vec![
        Fr::one() + &Fr::one() + &Fr::one(),              //3
        Fr::one() + &Fr::one() + &Fr::one() + &Fr::one(), //4
    ];
    inputs_vec.push(inputs);
    witnesses_vec.push(witnesses);

    let inputs = vec![
        Fr::one() + &Fr::one() + &Fr::one(),              //3
        Fr::one() + &Fr::one() + &Fr::one() + &Fr::one(), //4
    ];
    let witnesses = vec![
        Fr::one() + &Fr::one(),              //2
        Fr::one() + &Fr::one() + &Fr::one(), //3
    ];
    inputs_vec.push(inputs);
    witnesses_vec.push(witnesses);

    let mut layers = Vec::new();
    let mut layer = Vec::new();
    layer.push((1, 0, 2));
    layer.push((1, 1, 3));
    layers.push(layer);
    let mut layer = Vec::new();
    layer.push((0, 0, 1));
    layers.push(layer);

    (inputs_vec, witnesses_vec, layers)
}

fn hyrax_zk_gkr<R: Rng>(
    params: &Parameters<E>,
    witnesses: &Vec<Vec<Fr>>,
    inputs: &Vec<Vec<Fr>>,
    circuit: &Circuit,
    rng: &mut R,
) -> bool {
    assert_eq!(witnesses.len(), inputs.len());
    let (proof, outputs) =
        HyraxProof::prover(params, witnesses, inputs, circuit, witnesses.len(), rng);
    println!("hyrax_zk_gkr -- generate proof...ok");
    let result = proof.verify(params, &outputs, inputs, circuit);
    println!("hyrax_zk_gkr -- verify...{}", result);
    result
}

#[test]
fn test_hyrax_zk_parallel_gkr_2() {
    println!("start linear_gkr...");
    let rng = &mut test_rng();
    let (inputs, witnesses, layers) = prepare_construct_circuit();
    println!("prepare for constructing circuit...ok");
    let circuit = Circuit::new(2, 2, &layers);
    println!("construct circuit...ok");
    let params = Parameters::new(rng, 2);
    println!("generate parameters...");
    let result = hyrax_zk_gkr(&params, &witnesses, &inputs, &circuit, rng);
    assert!(result);
    println!("hyrax linear gkr...ok");
}
