use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::UniformRand;
use ark_std::test_rng;
use rand::Rng;
use zkp_hyrax::{circuit::Circuit, hyrax_proof::HyraxProof, params::Parameters};

/// circuit structure
/// layer3: gate0 = (add, 0, 1), gate1 = (add, 1, 2), gate2 = (mul, 2, 3), gate3 = (mul, 1, 3)
/// layer2: gate0 = (mul, 0, 1), gate1 = (add, 2, 3), gate2 = (add, 4, 5), gate3 = (mul, 6, 7)
/// layer1: gate0 = (mul, 0, 1), gate1 = (add, 2, 3), gate2 = (add, 4, 5), gate4 = (mul, 6, 7), gate5 = (mul, 15, 8), gate6 = (mul, 9, 10), gate7 =(add, 11, 12), gate8 =(add, 13, 14)
/// layer0: witness0,  witness1,  witness2,  witness3,  witness4,  witness5,  witness6,  witness7, input0, input1, input2, input3, input4, input5, input6, input7, input8
/// layer0 is input-layer, The first eight items are witnesses, and the last eight items are public inputs
/// layer1~layer3 are composed of multiple gates.
///     gaten = (op, left, right) represents the nth gate, op represents the operator, add or multiple,
///     left represents the number of its left node, right  represents the number of its right node
///     e.g. layer2: gate0 = (mul, 0, 1) represents layer2-gate0 = layer1-gate0 * layer1-gate1
fn prepare_construct_circuit<R: Rng>(
    rng: &mut R,
) -> (Vec<Vec<Fr>>, Vec<Vec<Fr>>, Vec<Vec<(u8, usize, usize)>>) {
    let mut witnesses_vec = Vec::new();
    let mut inputs_vec = Vec::new();
    let n = 4;
    for _ in 0..n {
        witnesses_vec.push((0..8).map(|_| Fr::rand(rng)).collect::<Vec<_>>());
        inputs_vec.push((0..8).map(|_| Fr::rand(rng)).collect::<Vec<_>>());
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
    let circuit_to_hash = circuit.circuit_to_hash::<E>();
    let param_to_hash= params.param_to_hash();
    
    let (proof, outputs) =
        HyraxProof::prover(params, witnesses, inputs, circuit, circuit_to_hash, param_to_hash, witnesses.len(), rng);
    println!("hyrax_zk_gkr -- generate proof...ok");
    let result = proof.verify(params, &outputs, inputs, circuit, circuit_to_hash, param_to_hash);
    println!("hyrax_zk_gkr -- verify...{}", result);
    result
}

#[test]
fn test_hyrax_zk_parallel_gkr() {
    println!("start linear_gkr...");
    let rng = &mut test_rng();
    let (inputs, witnesses, layers) = prepare_construct_circuit(rng);
    println!("prepare for constructing circuit...ok");
    let circuit = Circuit::new(8, 8, &layers);
    println!("construct circuit...ok");
    let params = Parameters::new(rng, 8);
    println!("generate parameters...");
    let result = hyrax_zk_gkr(&params, &witnesses, &inputs, &circuit, rng);
    assert!(result);
    println!("hyrax linear gkr...ok");
}
