use alloc::vec::Vec;
use core::result::Result;

use ckb_std::{ckb_constants::Source, high_level::load_cell_data};

use crate::error::Error;

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_serialize::*;
use zkp_spartan::nizk::{verify_proof, Proof, VerifyKey};

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

    let vk = VerifyKey::<E>::deserialize(&vk_data[..]).map_err(|_e| Error::Encoding)?;
    let proof = Proof::<E>::deserialize(&proof_data[..]).map_err(|_e| Error::Encoding)?;
    let mut publics = Vec::new();
    publics.push(Fr::deserialize(&public_data[..]).map_err(|_e| Error::Encoding)?);

    match verify_proof(&vk, &proof, &publics) {
        Ok(true) => Ok(()),
        _ => Err(Error::Verify),
    }
}
