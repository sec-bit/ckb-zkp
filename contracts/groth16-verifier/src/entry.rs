use core::result::Result;

use ckb_std::{ckb_constants::Source, error::SysError, high_level::load_cell_data};

use crate::error::Error;

use ckb_zkp::verify_from_bytes;

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

    if verify_from_bytes(&vk_data, &proof_data, &public_data) {
        Ok(())
    } else {
        Err(Error::Verify)
    }
}
