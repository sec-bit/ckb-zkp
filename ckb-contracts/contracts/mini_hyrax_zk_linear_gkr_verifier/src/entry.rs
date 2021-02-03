use alloc::vec::Vec;
use core::result::Result;

use ckb_std::{ckb_constants::Source, high_level::load_cell_data};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_serialize::*;

use zkp_hyrax::{circuit::Circuit, hyrax_proof::HyraxProof, params::Parameters};

use crate::error::Error;

// x * (y + 2) = z
fn layers() -> Vec<Vec<(u8, usize, usize)>> {
    let mut layers = Vec::new();

    let mut layer1 = Vec::new();
    layer1.push((0, 1, 2));
    layer1.push((1, 0, 4));
    layer1.push((1, 3, 4));
    layer1.push((1, 4, 4));
    layers.push(layer1);

    let mut layer2 = Vec::new();
    layer2.push((1, 0, 1));
    layer2.push((1, 2, 3));
    layers.push(layer2);

    let mut layer3 = Vec::new();
    layer3.push((0, 0, 1));
    layers.push(layer3);

    layers
}

pub fn main() -> Result<(), Error> {
    // load verify key.
    let vk_data = match load_cell_data(0, Source::Output) {
        Ok(data) => data,
        Err(err) => return Err(err.into()),
    };

    // load proof.
    let proof_data = match load_cell_data(1, Source::Output) {
        Ok(data) => data,
        Err(err) => return Err(err.into()),
    };

    // load public info.
    let public_data = match load_cell_data(2, Source::Output) {
        Ok(data) => data,
        Err(err) => return Err(err.into()),
    };

    let params = Parameters::<E>::deserialize(&vk_data[..]).map_err(|_e| Error::Encoding)?;

    let proof = HyraxProof::<E>::deserialize(&proof_data[..]).map_err(|_e| Error::Encoding)?;
    let (inputs, outputs) = <(Vec<Vec<Fr>>, Vec<Vec<Fr>>)>::deserialize(&public_data[..])
        .map_err(|_e| Error::Encoding)?;

    // inputs length is 4, witness length is 4.
    let circuit = Circuit::new(4, 4, &layers());

    match proof.verify(&params, &outputs, &inputs, &circuit) {
        true => Ok(()),
        false => Err(Error::Verify),
    }
}
