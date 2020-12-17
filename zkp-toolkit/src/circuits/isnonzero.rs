use math::PrimeField;
use scheme::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

struct Isnonzero<F: PrimeField> {
    check_num: Option<F>,
}

impl<E: PrimeField> ConstraintSynthesizer<E> for Isnonzero<E> {
    fn generate_constraints<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let check_num_var = cs.alloc(
            || "check_num_var",
            || self.check_num.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let inv_var = cs.alloc(
            || "elhemeral inverse",
            || {
                let tmp = self
                    .check_num
                    .clone()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                if tmp == E::zero() {
                    Err(SynthesisError::DivisionByZero)
                } else {
                    tmp.inverse().ok_or(SynthesisError::AssignmentMissing)
                }
            },
        )?;

        // Constrain a * inv = 1, which is only valid
        // iff a has a multiplicative inverse, untrue
        // for zero.
        cs.enforce(
            || "nonzero assertion constraint",
            |lc| lc + check_num_var,
            |lc| lc + inv_var,
            |lc| lc + CS::one(),
        );

        Ok(())
    }
}
