use curve::bls12_381::{Bls12_381, Fr as Bls12_381Fr};
use curve::bn_256::{Bn_256, Fr as Bn256Fr, Parameters as Bn256Parameters};
use math::curves::models::bn::BnParameters;
use math::test_rng;
use math::PairingEngine;
use rand::Rng;
use scheme::groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    Parameters, PreparedVerifyingKey,
};
use zkp::{
    gadget::mimc::{mimc, MiMC},
    prove, verify, Curve, Groth16Proof, Scheme,
};

use std::env;
use std::fs::read;
use std::fs::File;
use std::io::Write;

const MIMC_ROUNDS: usize = 322;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 4 {
        println!("Args. like: mimc-zkp groth16 bn256 prove --file=./groth16_proof");
        println!("            mimc-zkp groth16 bn256 prove --string=iamscretvalue");
        println!("            mimc-zkp groth16 bn256 verify --file=./groth16_proof");
        return;
    }

    let _s = match args[1].as_str() {
        "groth16" => Scheme::Groth16,
        _ => Scheme::Groth16,
    };

    let c = match args[2].as_str() {
        "bn256" => Curve::Bn_256,
        "bls12_381" => Curve::Bls12_381,
        _ => Curve::Bn_256,
    };

    match args[3].as_str() {
        "prove" => match c {
            Curve::Bn_256 => {
                groth16_bn256_prove();
            }
            Curve::Bls12_381 => {
                groth16_prove::<Bls12_381>();
            }
        },
        "verify" => match c {
            Curve::Bn_256 => {
                groth16_bn256_verify();
            }
            Curve::Bls12_381 => {
                groth16_verify::<Bls12_381>();
            }
        },
        _ => println!("not implemented!"),
    }
}

fn groth16_prove<E: PairingEngine>() {}

fn groth16_bn256_prove() {
    println!("Prepareing...");

    let rng = &mut test_rng();

    let constants: Vec<Bn256Fr> = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();

    let xl = rng.gen();
    let xr = rng.gen();
    let image = mimc(xl, xr, &constants);

    let c = MiMC::<Bn256Fr> {
        xl: None,
        xr: None,
        constants: &constants,
    };

    let params = generate_random_parameters::<Bn_256, _, _>(c, rng).unwrap();

    let mc = MiMC {
        xl: Some(xl),
        xr: Some(xr),
        constants: &constants,
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    // Create a groth16 proof with our parameters.
    let proof = create_random_proof(mc, &params, rng).unwrap();

    let groth16_proof = Groth16Proof::new(pvk.clone(), proof, vec![image]).to_bytes(&params.vk);

    let mut f = File::create("./groth16_proof").unwrap();
    f.write(&groth16_proof).unwrap();

    println!("Groth16 Proof: {:?}", groth16_proof.len());
}

fn groth16_verify<E: PairingEngine>() {}

fn groth16_bn256_verify() {
    println!("Prepareing...");

    let verify_proof_bytes = read("./groth16_proof").unwrap();

    let verify_groth16_proof = Groth16Proof::<Bn_256>::from_bytes(&verify_proof_bytes);

    let (pvk, proof, public_inputs) = verify_groth16_proof.unwrap().destruct();

    println!("Verifying proofs...");

    let result = verify_proof(&pvk, &proof, &public_inputs).unwrap_or(false);

    println!("Groth16 Verify: {}", result);
}
