use ark_ff::{FftField as Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain,
    Evaluations as EvaluationsOnDomain, UVPolynomial,
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

pub fn get_domain_generator<F: Field>(domain: impl EvaluationDomain<F>) -> F {
    domain.element(1)
}

pub fn first_lagrange_poly<F: Field>(
    domain: impl EvaluationDomain<F>,
) -> DensePolynomial<F> {
    let mut l = vec![F::zero(); domain.size()];
    l[0] = F::one();
    EvaluationsOnDomain::from_vec_and_domain(l, domain).interpolate()
}

pub fn evaluate_first_lagrange_poly<F: Field>(
    domain: impl EvaluationDomain<F>,
    zeta: F,
) -> F {
    let n = domain.size() as u64;
    let numerator = zeta.pow(&[n]) - F::one();
    let denumerator = (F::from(n) * (zeta - F::one())).inverse().unwrap();
    numerator * denumerator
}

pub fn pad_to_size<F: Field>(v: &[F], expected_size: usize) -> Vec<F> {
    let diff = expected_size - v.len();
    let zeros = vec![F::zero(); diff];
    let mut v = v.to_vec();
    v.extend(zeros.iter());

    v
}
