use alloc::vec::Vec;
use blake2::Blake2s;
use ckb_std::{ckb_constants::Source, high_level::load_cell_data};
use core::result::Result;

use crate::error::Error;

use ark_ff::One;
use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_serialize::*;
use zkp_clinkv2::ipa::{verify_proof, Proof, VerifyAssignment, VerifyKey};
use zkp_clinkv2::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

struct Mini {
    pub x: Option<Fr>,
    pub y: Option<Fr>,
    pub z: Option<Fr>,
    pub num: u32,
}

impl ConstraintSynthesizer<Fr> for Mini {
    fn generate_constraints<CS: ConstraintSystem<Fr>>(
        self,
        cs: &mut CS,
        index: usize,
    ) -> Result<(), SynthesisError> {
        cs.alloc_input(|| "r1", || Ok(Fr::one()), index)?;

        let var_x = cs.alloc(
            || "x",
            || self.x.ok_or(SynthesisError::AssignmentMissing),
            index,
        )?;

        let var_y = cs.alloc(
            || "y",
            || self.y.ok_or(SynthesisError::AssignmentMissing),
            index,
        )?;

        let var_z = cs.alloc_input(
            || "z(output)",
            || self.z.ok_or(SynthesisError::AssignmentMissing),
            index,
        )?;

        if index == 0 {
            for _ in 0..self.num {
                cs.enforce(
                    || "x * (y + 2) = z",
                    |lc| lc + var_x,
                    |lc| lc + var_y + (Fr::from(2u32), CS::one()),
                    |lc| lc + var_z,
                );
            }
        }

        Ok(())
    }
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

    let proof = Proof::<E>::deserialize(&proof_data[..]).map_err(|_e| Error::Encoding)?;
    let vk = VerifyKey::<E>::deserialize(&vk_data[..]).map_err(|_e| Error::Encoding)?;
    let publics = Vec::<Vec::<Fr>>::deserialize(&public_data[..]).map_err(|_e| Error::Encoding)?;

    // Demo circuit
    let c = Mini {
        x: None,
        y: None,
        z: None,
        num: 10,
    };

    let mut verifier_pa = VerifyAssignment::<E, Blake2s>::default();
    c.generate_constraints(&mut verifier_pa, 0usize)
        .map_err(|_| Error::Verify)?;

    match verify_proof::<E, Blake2s>(&verifier_pa, &vk, &proof, &publics) {
        Ok(true) => Ok(()),
        _ => Err(Error::Verify),
    }
}
