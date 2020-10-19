use alloc::vec::Vec;
use core::result::Result;

use ckb_std::{ckb_constants::Source, high_level::load_cell_data};

use crate::error::Error;

use ckb_zkp::{
    bn_256::{Bn_256 as E, Fr},
    clinkv2::kzg10::{verify_proof, Proof, VerifyAssignment, VerifyKey},
    clinkv2::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError},
    math::PrimeField,
};

struct Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
    pub num: u32,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Mini<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
        index: usize,
    ) -> Result<(), SynthesisError> {
        cs.alloc_input(|| "r1", || Ok(F::one()), index)?;

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
                    |lc| lc + var_y + (F::from(2u32), CS::one()),
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

    let proof: Proof<E> = postcard::from_bytes(&proof_data).map_err(|_e| Error::Encoding)?;
    let vk: VerifyKey<E> = postcard::from_bytes(&vk_data).map_err(|_e| Error::Encoding)?;
    let publics: Vec<Vec<Fr>> = postcard::from_bytes(&public_data).map_err(|_e| Error::Encoding)?;

    // Demo circuit
    let c = Mini::<Fr> {
        x: None,
        y: None,
        z: None,
        num: 10,
    };

    let mut verifier_pa = VerifyAssignment::<E>::default();
    c.generate_constraints(&mut verifier_pa, 0usize)
        .map_err(|_| Error::Verify)?;

    match verify_proof(&verifier_pa, &vk, &proof, &publics) {
        Ok(true) => Ok(()),
        _ => Err(Error::Verify),
    }
}
