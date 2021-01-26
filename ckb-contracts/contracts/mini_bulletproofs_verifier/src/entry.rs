use alloc::vec::Vec;
use core::result::Result;

use ckb_std::{ckb_constants::Source, high_level::load_cell_data};

use crate::error::Error;

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_serialize::*;
use zkp_bulletproofs::{verify_proof, Generators, Proof, R1csCircuit};
use zkp_r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

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
    ) -> Result<(), SynthesisError> {
        let var_x = cs.alloc(|| "x", || self.x.ok_or(SynthesisError::AssignmentMissing))?;

        let var_y = cs.alloc(|| "y", || self.y.ok_or(SynthesisError::AssignmentMissing))?;

        let var_z = cs.alloc_input(
            || "z(output)",
            || self.z.ok_or(SynthesisError::AssignmentMissing),
        )?;

        for _ in 0..self.num {
            cs.enforce(
                || "x * (y + 2) = z",
                |lc| lc + var_x,
                |lc| lc + var_y + (Fr::from(2u32), CS::one()),
                |lc| lc + var_z,
            );
        }

        Ok(())
    }
}

pub fn main() -> Result<(), Error> {
    // load verify key.
    let _vk_data = match load_cell_data(0, Source::Output) {
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

    let gens = Generators::<E>::deserialize(&proof_data[..]).map_err(|_e| Error::Encoding)?;
    let r1cs = R1csCircuit::<E>::deserialize(&proof_data[..]).map_err(|_e| Error::Encoding)?;
    let proof = Proof::<E>::deserialize(&proof_data[..]).map_err(|_e| Error::Encoding)?;

    let mut publics = Vec::new();
    publics.push(Fr::deserialize(&public_data[..]).map_err(|_e| Error::Encoding)?);

    // Demo circuit
    let _c = Mini {
        x: None,
        y: None,
        z: None,
        num: 10,
    };

    match verify_proof(&gens, &proof, &r1cs, &publics) {
        Ok(true) => Ok(()),
        _ => Err(Error::Verify),
    }
}
