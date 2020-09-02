use core::result::Result;

use ckb_std::{ckb_constants::Source, debug, high_level::load_cell_data};

use crate::error::Error;

use ckb_zkp::{verify_from_bytes_with_curve, Curve, Scheme};

pub fn main() -> Result<(), Error> {
    // load verify key.
    let vk_data = match load_cell_data(0, Source::Output) {
        Ok(data) => data,
        Err(err) => return Err(err.into()),
    };

    // load proof.
    let mut proof_data = match load_cell_data(1, Source::Output) {
        Ok(data) => data,
        Err(err) => return Err(err.into()),
    };

    // load public info.
    let mut public_data = match load_cell_data(2, Source::Output) {
        Ok(data) => data,
        Err(err) => return Err(err.into()),
    };

    // scheme is proof's data frist item.
    debug!("scheme {:?}", proof_data[0]);
    let s = Scheme::from_byte(proof_data.remove(0)).map_err(|_| Error::Params)?;

    // curve is public's data frist item.
    debug!("curve: {:?}", public_data[0]);
    let c = Curve::from_byte(public_data.remove(0)).map_err(|_| Error::Params)?;

    match verify_from_bytes_with_curve(c, s, &vk_data, &proof_data, &public_data) {
        Ok(true) => Ok(()),
        _ => Err(Error::Verify),
    }
}
