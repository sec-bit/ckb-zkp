use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain,
    Evaluations, GeneralEvaluationDomain, UVPolynomial,
};
use ark_std::cfg_into_iter;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::composer::{Composer, Selectors};
use crate::Error;

mod arithmetic;
mod permutation;

pub struct ProverKey<F: Field> {
    n: usize,

    arithmetic: arithmetic::ProverKey<F>,
    permutation: permutation::ProverKey<F>,

    domain_n: GeneralEvaluationDomain<F>,
    domain_4n: GeneralEvaluationDomain<F>,

    v_4n_inversed: Vec<F>,
}

pub fn generate_prover_key<F: Field>(
    cs: &Composer<F>,
    ks: [F; 4],
) -> Result<ProverKey<F>, Error> {
    let selectors = cs.preprocess(&ks)?;
    let Selectors {
        n,
        q_0,
        q_1,
        q_2,
        q_3,
        q_c,
        q_m,
        q_arith,
        sigma_0,
        sigma_1,
        sigma_2,
        sigma_3,
    } = selectors;
    let domain_n = GeneralEvaluationDomain::<F>::new(n)
        .ok_or(Error::PolynomialDegreeTooLarge)?;
    let domain_4n = GeneralEvaluationDomain::<F>::new(4 * n)
        .ok_or(Error::PolynomialDegreeTooLarge)?;

    let q_0_poly = Evaluations::from_vec_and_domain(q_0.clone(), domain_n)
        .interpolate();
    let q_1_poly = Evaluations::from_vec_and_domain(q_1.clone(), domain_n)
        .interpolate();
    let q_2_poly = Evaluations::from_vec_and_domain(q_2.clone(), domain_n)
        .interpolate();
    let q_3_poly = Evaluations::from_vec_and_domain(q_3.clone(), domain_n)
        .interpolate();

    let q_m_poly = Evaluations::from_vec_and_domain(q_m.clone(), domain_n)
        .interpolate();
    let q_c_poly = Evaluations::from_vec_and_domain(q_c.clone(), domain_n)
        .interpolate();

    let q_arith_poly =
        Evaluations::from_vec_and_domain(q_arith.clone(), domain_n)
            .interpolate();

    let sigma_0_poly =
        Evaluations::from_vec_and_domain(sigma_0.clone(), domain_n)
            .interpolate();
    let sigma_1_poly =
        Evaluations::from_vec_and_domain(sigma_1.clone(), domain_n)
            .interpolate();
    let sigma_2_poly =
        Evaluations::from_vec_and_domain(sigma_2.clone(), domain_n)
            .interpolate();
    let sigma_3_poly =
        Evaluations::from_vec_and_domain(sigma_3.clone(), domain_n)
            .interpolate();

    let q_0_4n = domain_4n.coset_fft(&q_0_poly);
    let q_1_4n = domain_4n.coset_fft(&q_1_poly);
    let q_2_4n = domain_4n.coset_fft(&q_2_poly);
    let q_3_4n = domain_4n.coset_fft(&q_3_poly);

    let q_m_4n = domain_4n.coset_fft(&q_m_poly);
    let q_c_4n = domain_4n.coset_fft(&q_c_poly);

    let q_arith_4n = domain_4n.coset_fft(&q_arith_poly);

    let sigma_0_4n = domain_4n.coset_fft(&sigma_0_poly);
    let sigma_1_4n = domain_4n.coset_fft(&sigma_1_poly);
    let sigma_2_4n = domain_4n.coset_fft(&sigma_2_poly);
    let sigma_3_4n = domain_4n.coset_fft(&sigma_3_poly);

    let v_poly = vanishing_poly(domain_n);
    let v_4n = domain_4n.coset_fft(&v_poly);
    let v_4n_inversed: Vec<_> =
        cfg_into_iter!(v_4n).map(|v| v.inverse().unwrap()).collect();

    Ok(ProverKey {
        n,
        arithmetic: arithmetic::ProverKey {
            q_0: (q_0_poly, q_0, q_0_4n),
            q_1: (q_1_poly, q_1, q_1_4n),
            q_2: (q_2_poly, q_2, q_2_4n),
            q_3: (q_3_poly, q_3, q_3_4n),

            q_m: (q_m_poly, q_m, q_m_4n),
            q_c: (q_c_poly, q_c, q_c_4n),

            q_arith: (q_arith_poly, q_arith, q_arith_4n),
        },
        permutation: permutation::ProverKey {
            ks,
            sigma_0: (sigma_0_poly, sigma_0, sigma_0_4n),
            sigma_1: (sigma_1_poly, sigma_1, sigma_1_4n),
            sigma_2: (sigma_2_poly, sigma_2, sigma_2_4n),
            sigma_3: (sigma_3_poly, sigma_3, sigma_3_4n),
        },

        domain_n,
        domain_4n,

        v_4n_inversed,
    })
}

pub fn generate_verifier_key<F: Field>(
    cs: &Composer<F>,
) -> Result<VerifierKey<F>, Error> {
    let n = cs.size();
    let domain = GeneralEvaluationDomain::<F>::new(n)
        .ok_or(Error::PolynomialDegreeTooLarge)?;

    Ok(VerifierKey { n, domain })
}

impl<F: Field> ProverKey<F> {
    pub fn size(&self) -> usize {
        self.n
    }

    pub fn arithmetic_key(&self) -> &arithmetic::ProverKey<F> {
        &self.arithmetic
    }

    pub fn permutation_key(&self) -> &permutation::ProverKey<F> {
        &self.permutation
    }

    pub fn v_4n_inversed(&self) -> &[F] {
        &self.v_4n_inversed
    }

    pub fn domain_n(&self) -> impl EvaluationDomain<F> {
        self.domain_n
    }

    pub fn domain_4n(&self) -> impl EvaluationDomain<F> {
        self.domain_4n
    }
}

pub struct VerifierKey<F: Field> {
    n: usize,
    domain: GeneralEvaluationDomain<F>,
}

impl<F: Field> VerifierKey<F> {
    pub fn size(&self) -> usize {
        self.n
    }

    pub fn domain_n(&self) -> impl EvaluationDomain<F> {
        self.domain
    }
}

fn vanishing_poly<F: Field>(
    domain: impl EvaluationDomain<F>,
) -> Polynomial<F> {
    let size = domain.size();
    let mut coeffs = vec![F::zero(); size + 1];
    coeffs[0] = -F::one();
    coeffs[size] = F::one();
    Polynomial::from_coefficients_vec(coeffs)
}
