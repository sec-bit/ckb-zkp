use ark_ff::PrimeField;

use crate::composer::{Composer, Variable};

use crate::Vec;

pub trait AbstractHashOutput<F: PrimeField>: Clone {
    fn get_variables(&self) -> Vec<Variable>;

    fn get_variable_values(&self) -> Vec<F>;
}

pub trait AbstractHash<F: PrimeField> {
    type Output: AbstractHashOutput<F>;

    fn hash_enforce(composer: &mut Composer<F>, params: &[&Self::Output]) -> Self::Output;
}
