use ark_ff::{FftField as Field, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_poly_commit::{LCTerm, LinearCombination};
use ark_std::{borrow::Borrow, vec};

use crate::composer::Error as CSError;
use crate::data_structures::LabeledPolynomial;
use crate::utils::scalar_mul;

mod preprocessor;
pub use preprocessor::{PreprocessorInfo, PreprocessorKeys};

mod prover;
pub use prover::Prover;

mod verifier;
pub use verifier::Verifier;

pub trait EvaluationsProvider<F: Field> {
    /// Get the evaluation of linear combination `lc` at `point`.
    fn get_lc_eval(
        &self,
        lc: &LinearCombination<F>,
        point: F,
    ) -> Result<F, Error>;
}

impl<'a, F: Field> EvaluationsProvider<F>
    for ark_poly_commit::Evaluations<F, F>
{
    fn get_lc_eval(
        &self,
        lc: &LinearCombination<F>,
        point: F,
    ) -> Result<F, Error> {
        let key = (lc.label.clone(), point);
        self.get(&key)
            .copied()
            .ok_or_else(|| Error::MissingEvaluation(lc.label.clone()))
    }
}

impl<F: Field, T: Borrow<LabeledPolynomial<F>>> EvaluationsProvider<F>
    for Vec<T>
{
    fn get_lc_eval(
        &self,
        lc: &LinearCombination<F>,
        point: F,
    ) -> Result<F, Error> {
        let mut acc = DensePolynomial::zero();
        for (coeff, term) in lc.iter() {
            acc = if let LCTerm::PolyLabel(label) = term {
                let poly = self
                    .iter()
                    .find(|p| {
                        let p: &LabeledPolynomial<F> = (*p).borrow();
                        p.label() == label
                    })
                    .ok_or_else(|| {
                        Error::MissingEvaluation(format!(
                            "Missing {} for {}",
                            label, lc.label
                        ))
                    })?
                    .borrow();
                acc + scalar_mul(poly, coeff)
            } else {
                assert!(term.is_one());
                acc + DensePolynomial::from_coefficients_vec(vec![*coeff])
            };
        }

        let eval = acc.evaluate(&point);
        Ok(eval)
    }
}

#[derive(Debug)]
pub enum Error {
    SynthesisError(CSError),
    MissingEvaluation(String),
    Other,
}

impl From<CSError> for Error {
    fn from(err: CSError) -> Error {
        Error::SynthesisError(err)
    }
}
