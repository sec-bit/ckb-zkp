use curve::bn_256::Bn_256;
use math::{Curve, One};
use rand::thread_rng;
use rand::Rng;
use scheme::hyrax::circuit::Circuit;
use scheme::hyrax::hyrax_proof::HyraxProof;
use scheme::hyrax::params::Parameters;

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
fn prepare_construct_circuit<G: Curve>() -> (
    Vec<Vec<G::Fr>>,
    Vec<Vec<G::Fr>>,
    Vec<Vec<(u8, usize, usize)>>,
) {
    let mut inputs_vec = Vec::new();
    let mut witnesses_vec = Vec::new();
    let inputs = vec![
        G::Fr::one() + &G::Fr::one(),                 //2
        G::Fr::one() + &G::Fr::one() + &G::Fr::one(), //3
    ];
    let witnesses = vec![
        G::Fr::one() + &G::Fr::one() + &G::Fr::one(), //3
        G::Fr::one() + &G::Fr::one() + &G::Fr::one() + &G::Fr::one(), //4
    ];
    inputs_vec.push(inputs);
    witnesses_vec.push(witnesses);

    let inputs = vec![
        G::Fr::one() + &G::Fr::one() + &G::Fr::one(), //3
        G::Fr::one() + &G::Fr::one() + &G::Fr::one() + &G::Fr::one(), //4
    ];
    let witnesses = vec![
        G::Fr::one() + &G::Fr::one(),                 //2
        G::Fr::one() + &G::Fr::one() + &G::Fr::one(), //3
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

fn hyrax_zk_parallel_gkr() {
    println!("start linear_gkr...");
    let rng = &mut thread_rng();
    let (inputs, witnesses, layers) = prepare_construct_circuit::<Bn_256>();
    println!("prepare for constructing circuit...ok");
    let circuit = Circuit::new(2, 2, &layers);
    println!("construct circuit...ok");
    let params = Parameters::new(rng, 2);
    println!("generate parameters...");
    let result = hyrax_zk_gkr::<Bn_256, _>(&params, &witnesses, &inputs, &circuit, rng);
    assert!(result);
    println!("hyrax linear gkr...ok");
}

fn hyrax_zk_gkr<G: Curve, R: Rng>(
    params: &Parameters<G>,
    witnesses: &Vec<Vec<G::Fr>>,
    inputs: &Vec<Vec<G::Fr>>,
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

pub fn main() {
    hyrax_zk_parallel_gkr();
}
