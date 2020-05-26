use rand::prelude::*;
use zkp::{
    gadget::mimc::{mimc_hash, MiMC},
    math::PairingEngine,
    scheme::groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key},
    Groth16Proof,
};

const MIMC_ROUNDS: usize = 322;

pub fn groth16_prove<E: PairingEngine>(bytes: &[u8]) -> Vec<u8>
where
    rand::distributions::Standard: rand::distributions::Distribution<E::Fr>,
{
    println!("Prepareing...");

    let mut rng = rand::thread_rng();

    let constants: Vec<E::Fr> = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();

    let (xl, xr, image) = mimc_hash(bytes, &constants);
    println!("Mimc hash: {}", image);

    let c = MiMC::<E::Fr> {
        xl: None,
        xr: None,
        constants: &constants,
    };

    let params = generate_random_parameters::<E, _, _>(c, &mut rng).unwrap();

    let mc = MiMC {
        xl: Some(xl),
        xr: Some(xr),
        constants: &constants,
    };

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    // Create a groth16 proof with our parameters.
    let proof = create_random_proof(mc, &params, &mut rng).unwrap();

    Groth16Proof::new(pvk.clone(), proof, vec![image]).to_bytes(&params.vk)
}
