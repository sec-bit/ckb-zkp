use ark_ff::PrimeField;
use zkp_r1cs::{ConstraintSystem, SynthesisError, Variable};

#[derive(Clone)]
pub struct AllocatedFr<F: PrimeField> {
    value: Option<F>,
    variable: Variable,
}

impl<F: PrimeField> AllocatedFr<F> {
    pub fn get_variable(&self) -> Variable {
        self.variable
    }

    pub fn get_value(&self) -> Option<F> {
        self.value
    }

    pub fn alloc<FN, CS>(mut cs: CS, value: FN) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
        FN: FnOnce() -> Result<F, SynthesisError>,
    {
        let mut new_value = None;

        let var = cs.alloc(
            || "fr",
            || {
                let tmp = value()?;
                new_value = Some(tmp);
                Ok(tmp)
            },
        )?;

        Ok(AllocatedFr {
            value: new_value,
            variable: var,
        })
    }

    pub fn alloc_input<FN, CS>(mut cs: CS, value: FN) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<F>,
        FN: FnOnce() -> Result<F, SynthesisError>,
    {
        let mut new_value = None;

        let var = cs.alloc_input(
            || "fr",
            || {
                let tmp = value()?;
                new_value = Some(tmp);
                Ok(tmp)
            },
        )?;

        Ok(AllocatedFr {
            value: new_value,
            variable: var,
        })
    }

    pub fn inputize<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let input = cs.alloc_input(
            || "input variable",
            || self.value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        cs.enforce(
            || "enforce input is correct",
            |lc| lc + input,
            |lc| lc + CS::one(),
            |lc| lc + self.variable,
        );

        Ok(())
    }

    pub fn isnonzero<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<F>,
    {
        let inv_var = cs.alloc(
            || "elhemeral inverse",
            || {
                let tmp = self.value.ok_or(SynthesisError::AssignmentMissing)?;
                if tmp == F::zero() {
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
            |lc| lc + self.variable,
            |lc| lc + inv_var,
            |lc| lc + CS::one(),
        );

        Ok(())
    }
}
