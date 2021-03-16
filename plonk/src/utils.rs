use ark_ff::{FftField as Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, UVPolynomial,
};
use ark_std::cfg_iter;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub fn scalar_mul<F: Field>(
    poly: &DensePolynomial<F>,
    scalar: &F,
) -> DensePolynomial<F> {
    if poly.is_zero() || scalar.is_zero() {
        return DensePolynomial::zero();
    }
    let coeffs: Vec<_> = cfg_iter!(poly.coeffs)
        .map(|coeff| *scalar * coeff)
        .collect();
    DensePolynomial::from_coefficients_vec(coeffs)
}

pub fn get_domain_generator<F: Field>(
    domain: impl EvaluationDomain<F>,
) -> F {
    domain.element(1)
}
