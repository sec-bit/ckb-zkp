use zkp::{
    gadget::mimc::{constants, groth16_params, mimc_hash, MiMC},
    math::{PairingEngine, ToBytes},
    scheme::groth16::{create_random_proof, prepare_verifying_key},
    Groth16Proof,
};

pub fn groth16_prove<E: PairingEngine>(bytes: &[u8]) -> Vec<u8>
where
    rand::distributions::Standard: rand::distributions::Distribution<E::Fr>,
{
    println!("Prepareing...");

    let constants = constants::<E::Fr>();
    let params = groth16_params::<E>(&constants).unwrap();

    let (xl, xr, image) = mimc_hash(bytes, &constants);
    println!("Mimc hash: {}", image);

    let mc = MiMC {
        xl: Some(xl),
        xr: Some(xr),
        constants: &constants,
    };

    println!("Creating proofs...");

    let mut vk_bytes = vec![];
    params.vk.write(&mut vk_bytes).unwrap();

    println!("{:?}", vk_bytes);

    // Create a groth16 proof with our parameters.
    let proof = create_random_proof(mc, &params, &mut rand::thread_rng()).unwrap();

    Groth16Proof::new(prepare_verifying_key(&params.vk), proof, vec![image]).to_bytes(&params.vk)
}
