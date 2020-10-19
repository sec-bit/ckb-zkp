use alloc::vec::Vec;
use core::result::Result;

use ckb_std::{ckb_constants::Source, high_level::load_cell_data};

use crate::error::Error;

use ckb_zkp::{
    bn_256::{Bn_256 as E, Fr},
    spartan::snark::{verify_proof, Proof, VerifyKey},
};

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

    let proof: Proof<E> = postcard::from_bytes(&proof_data).map_err(|_e| Error::Encoding)?;
    let vk: VerifyKey<E> = postcard::from_bytes(&vk_data).map_err(|_e| Error::Encoding)?;
    let publics: Vec<Fr> = postcard::from_bytes(&public_data).map_err(|_e| Error::Encoding)?;

    match verify_proof(&vk, &proof, &publics) {
        Ok(true) => Ok(()),
        _ => Err(Error::Verify),
    }
}
