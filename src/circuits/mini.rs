use math::PrimeField;
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

pub struct Mini<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
    pub z: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Mini<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let var_x = cs.alloc(|| "x", || self.x.ok_or(SynthesisError::AssignmentMissing))?;

        let var_y = cs.alloc(|| "y", || self.y.ok_or(SynthesisError::AssignmentMissing))?;

        let var_z = cs.alloc_input(
            || "z(output)",
            || self.z.ok_or(SynthesisError::AssignmentMissing),
        )?;

        cs.enforce(
            || "x * (y + 2) = z",
            |lc| lc + var_x,
            |lc| lc + var_y + (F::from(2u32), CS::one()),
            |lc| lc + var_z,
        );

        Ok(())
    }
}
