use ark_ff::PrimeField;
use zkp_r1cs::{ConstraintSystem, SynthesisError, Variable};

use crate::Vec;

pub trait AbstractHashOutput<F: PrimeField>: Clone {
    fn get_variables(&self) -> Vec<Variable>;

    fn get_variable_values(&self) -> Vec<Option<F>>;
}

pub trait AbstractHash<F: PrimeField> {
    type Output: AbstractHashOutput<F>;

    fn hash_enforce<CS>(cs: CS, params: &[&Self::Output]) -> Result<Self::Output, SynthesisError>
    where
        CS: ConstraintSystem<F>;
}
