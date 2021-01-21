use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use core::marker::PhantomData;
use zkp_r1cs::SynthesisError;

use crate::{String, ToString};

pub mod indexer;

pub mod prover;

pub mod verifier;

pub mod constraint_systems;

pub mod arithmetic;

#[derive(Debug)]
pub enum Error {
    InstanceDoesNotMatchIndex,
    NonSquareMatrix,
    MissingEval(String),
    ConstraintSystemError(SynthesisError),
    Unclassified,
}

impl From<SynthesisError> for Error {
    fn from(other: SynthesisError) -> Self {
        Error::ConstraintSystemError(other)
    }
}

pub struct AHP<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField> AHP<F> {
    pub const INDEXER_POLYNOMIALS: [&'static str; 12] = [
        // Polynomials for A
        "a_row",
        "a_col",
        "a_val",
        "a_row_col",
        // Polynomials for B
        "b_row",
        "b_col",
        "b_val",
        "b_row_col",
        // Polynomials for C
        "c_row",
        "c_col",
        "c_val",
        "c_row_col",
    ];

    pub const PROVER_POLYNOMIALS: [&'static str; 9] = [
        // first round
        "w", "z_a", "z_b", "mask", // second round
        "t", "g_1", "h_1", // third round
        "g_2", "h_2",
    ];

    pub fn polynomial_labels() -> impl Iterator<Item = String> {
        Self::INDEXER_POLYNOMIALS
            .iter()
            .chain(&Self::PROVER_POLYNOMIALS)
            .map(|s| s.to_string())
    }

    pub fn max_degree(
        num_constraints: usize,
        num_variables: usize,
        num_non_zeros: usize,
    ) -> Result<usize, Error> {
        let zk_bound = 1;
        let num_padded = core::cmp::max(num_constraints, num_variables);
        let domain_h_size = EvaluationDomain::<F>::compute_size_of_domain(num_padded)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_k_size = EvaluationDomain::<F>::compute_size_of_domain(num_non_zeros)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        Ok(*[
            3 * domain_h_size + 2 * zk_bound - 1, // mask
            3 * domain_k_size - 3,                // domain_b
        ]
        .iter()
        .max()
        .unwrap())
    }
}
