use zkp::{
    gadget::mimc::{constants, MiMC},
    math::{PairingEngine, ToBytes},
    scheme::groth16::generate_random_parameters,
};

/// Groth16 parameters we need setup:
pub fn groth16_setup<E: PairingEngine, R: rand::Rng>(
    mut rng: R,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    println!("Prepareing...");
    let constants = constants::<E::Fr>();

    let c = MiMC::<E::Fr> {
        xl: None,
        xr: None,
        constants: &constants,
    };

    let params = generate_random_parameters::<E, _, _>(c, &mut rng).unwrap();

    let mut pk_bytes = vec![];
    params.write(&mut pk_bytes).unwrap();

    let mut vk_bytes = vec![];
    params.vk.write(&mut vk_bytes).unwrap();

    Ok((pk_bytes, vk_bytes))
}
