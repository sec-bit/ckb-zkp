use core::result::Result;

use ckb_std::{ckb_constants::Source, high_level::load_cell_data};

use crate::error::Error;

use ckb_zkp::{bn_256, marlin};

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

    match marlin::verify_from_bytes::<bn_256::Bn_256>(&vk_data, &proof_data, &public_data) {
        Ok(true) => Ok(()),
        _ => Err(Error::Verify),
    }
}
