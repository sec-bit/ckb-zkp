use ckb_zkp::{
    gadget::mini::Mini,
    math::{PairingEngine, ToBytes},
    scheme::groth16::{generate_random_parameters, prepare_verifying_key},
};

/// Groth16 parameters we need setup:
pub fn groth16_setup<E: PairingEngine, R: rand::Rng>(
    mut rng: R,
    is_prepare: bool,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    println!("Prepareing...");

    let c = Mini::<E::Fr> {
        x: None,
        y: None,
        z: None,
    };

    let params = generate_random_parameters::<E, _, _>(c, &mut rng).unwrap();

    let mut pk_bytes = vec![];
    params.write(&mut pk_bytes).unwrap();

    let mut vk_bytes = vec![];
    if is_prepare {
        let pvk = prepare_verifying_key(&params.vk);
        pvk.write(&mut vk_bytes).unwrap();
    } else {
        params.vk.write(&mut vk_bytes).unwrap();
    }

    Ok((pk_bytes, vk_bytes))
}
