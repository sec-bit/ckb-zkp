use math::PrimeField;
use scheme::r1cs::{ConstraintSystem, SynthesisError, Variable};

use crate::Vec;

pub trait AbstractHashOutput: Clone {
    fn get_variables(&self) -> Vec<Variable>;
}

pub trait AbstractHash<F: PrimeField> {
    type Output: AbstractHashOutput;

    fn hash_enforce<CS>(cs: CS, params: &[&Self::Output]) -> Result<Self::Output, SynthesisError>
    where
        CS: ConstraintSystem<F>;
}
