use alloc::vec::Vec;
use core::result::Result;

use ckb_std::{ckb_constants::Source, debug, high_level::load_cell_data};

use crate::error::Error;

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_serialize::*;
use blake2::Blake2s;
use zkp_plonk::{Plonk, Proof, VerifierKey};

type PC = MarlinKZG10<E, DensePolynomial<Fr>>;
type PlonkInst = Plonk<Fr, Blake2s, PC>;

pub fn main() -> Result<(), Error> {
    // load verify key.
    let vk_data = match load_cell_data(0, Source::Output) {
        Ok(data) => data,
        Err(err) => return Err(err.into()),
    };

    debug!("vk_data is {:?}", vk_data.len());

    // load proof.
    let proof_data = match load_cell_data(1, Source::Output) {
        Ok(data) => data,
        Err(err) => return Err(err.into()),
    };

    debug!("proof_data is {:?}", proof_data.len());

    // load public info.
    let public_data = match load_cell_data(2, Source::Output) {
        Ok(data) => data,
        Err(err) => return Err(err.into()),
    };

    debug!("public data is {:?}", public_data.len());

    let vk =
        VerifierKey::<Fr, PC>::deserialize_unchecked(&vk_data[..]).map_err(|_e| Error::Encoding)?;

    let proof =
        Proof::<Fr, PC>::deserialize_unchecked(&proof_data[..]).map_err(|_e| Error::Encoding)?;

    let publics =
        Vec::<Fr>::deserialize_unchecked(&public_data[..]).map_err(|_e| Error::Encoding)?;

    match PlonkInst::verify(&vk, &publics, proof) {
        Ok(true) => Ok(()),
        _ => Err(Error::Verify),
    }
}
