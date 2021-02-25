use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
};
use ark_std::{cfg_into_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::scalar_mul;

pub struct ProverKey<F: Field> {
    pub ks: [F; 4],
    pub sigma_0: (DensePolynomial<F>, Vec<F>, Vec<F>),
    pub sigma_1: (DensePolynomial<F>, Vec<F>, Vec<F>),
    pub sigma_2: (DensePolynomial<F>, Vec<F>, Vec<F>),
    pub sigma_3: (DensePolynomial<F>, Vec<F>, Vec<F>),
}

impl<F: Field> ProverKey<F> {
    pub(crate) fn compute_z(
        &self,
        domain_n: impl EvaluationDomain<F>,
        domain_4n: impl EvaluationDomain<F>,
        w: (&[F], &[F], &[F], &[F]),
        beta: &F,
        gamma: &F,
    ) -> (DensePolynomial<F>, Vec<F>, Vec<F>) {
        let n = domain_n.size();
        let roots: Vec<_> = domain_n.elements().collect();
        let (w_0, w_1, w_2, w_3) = w;

        let perms: Vec<_> = cfg_into_iter!(0..n)
            .map(|i| {
                let numerator = Self::numerator_factor(
                    &w_0[i],
                    &roots[i],
                    &self.ks[0],
                    beta,
                    gamma,
                ) * Self::numerator_factor(
                    &w_1[i],
                    &roots[i],
                    &self.ks[1],
                    beta,
                    gamma,
                ) * Self::numerator_factor(
                    &w_2[i],
                    &roots[i],
                    &self.ks[2],
                    beta,
                    gamma,
                ) * Self::numerator_factor(
                    &w_3[i],
                    &roots[i],
                    &self.ks[3],
                    beta,
                    gamma,
                );

                let denumerator = Self::denumerator_factor(
                    &w_0[i],
                    &self.sigma_0.1[i],
                    beta,
                    gamma,
                ) * Self::denumerator_factor(
                    &w_1[i],
                    &self.sigma_1.1[i],
                    beta,
                    gamma,
                ) * Self::denumerator_factor(
                    &w_2[i],
                    &self.sigma_2.1[i],
                    beta,
                    gamma,
                ) * Self::denumerator_factor(
                    &w_3[i],
                    &self.sigma_3.1[i],
                    beta,
                    gamma,
                );
                let denumerator = denumerator.inverse().unwrap();

                numerator * denumerator
            })
            .collect();

        let mut z = Vec::<F>::with_capacity(n);
        let mut acc = F::one();
        z.push(acc);
        for i in 0..(n - 1) {
            acc *= perms[i];
            z.push(acc);
        }
        assert_eq!(z[n - 1] * perms[n - 1], F::one());

        let z_poly = Evaluations::from_vec_and_domain(z.clone(), domain_n)
            .interpolate();
        let z_4n = domain_4n.coset_fft(&z_poly);

        (z_poly, z, z_4n)
    }

    pub(crate) fn compute_quotient(
        &self,
        domain_4n: impl EvaluationDomain<F>,
        w: (&[F], &[F], &[F], &[F]),
        z: &[F],
        beta: &F,
        gamma: &F,
        factor: &F,
    ) -> Vec<F> {
        let (w_0, w_1, w_2, w_3) = w;

        let size = domain_4n.size();
        let linear_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&[F::zero(), F::one()]),
            domain_4n,
        );

        cfg_into_iter!((0..size))
            .map(|i| {
                let next = if i / 4 == (size / 4 - 1) {
                    i % 4
                } else {
                    i + 4
                };

                (Self::numerator_factor(
                    &w_0[i],
                    &linear_4n[i],
                    &self.ks[0],
                    beta,
                    gamma,
                ) * Self::numerator_factor(
                    &w_1[i],
                    &linear_4n[i],
                    &self.ks[1],
                    beta,
                    gamma,
                ) * Self::numerator_factor(
                    &w_2[i],
                    &linear_4n[i],
                    &self.ks[2],
                    beta,
                    gamma,
                ) * Self::numerator_factor(
                    &w_3[i],
                    &linear_4n[i],
                    &self.ks[3],
                    beta,
                    gamma,
                ) * z[i]
                    - Self::denumerator_factor(
                        &w_0[i],
                        &self.sigma_0.2[i],
                        beta,
                        gamma,
                    ) * Self::denumerator_factor(
                        &w_1[i],
                        &self.sigma_1.2[i],
                        beta,
                        gamma,
                    ) * Self::denumerator_factor(
                        &w_2[i],
                        &self.sigma_2.2[i],
                        beta,
                        gamma,
                    ) * Self::denumerator_factor(
                        &w_3[i],
                        &self.sigma_3.2[i],
                        beta,
                        gamma,
                    ) * z[next])
                    * factor
            })
            .collect()
    }

    pub(crate) fn compute_linearisation(
        &self,
        w_evals: (&F, &F, &F, &F),
        z_shifted_eval: &F,
        z_poly: &DensePolynomial<F>,
        beta: &F,
        gamma: &F,
        zeta: &F,
        factor: &F,
    ) -> (F, F, F, DensePolynomial<F>) {
        let sigma_0_zeta = self.sigma_0.0.evaluate(zeta);
        let sigma_1_zeta = self.sigma_1.0.evaluate(zeta);
        let sigma_2_zeta = self.sigma_2.0.evaluate(zeta);
        let (w_0, w_1, w_2, w_3) = w_evals;
        let numerator = (self.ks[0] * beta * zeta + gamma + w_0)
            * (self.ks[1] * beta * zeta + gamma + w_1)
            * (self.ks[2] * beta * zeta + gamma + w_2)
            * (self.ks[3] * beta * zeta + gamma + w_3)
            * factor;

        let denumerator = (sigma_0_zeta * beta + gamma + w_0)
            * (sigma_1_zeta * beta + gamma + w_1)
            * (sigma_2_zeta * beta + gamma + w_2)
            * beta
            * z_shifted_eval
            * factor;

        (
            sigma_0_zeta,
            sigma_1_zeta,
            sigma_2_zeta,
            scalar_mul(z_poly, &numerator)
                + scalar_mul(&self.sigma_3.0, &(-denumerator)),
        )
    }

    fn numerator_factor(w: &F, root: &F, k: &F, beta: &F, gamma: &F) -> F {
        *w + *k * beta * root + gamma
    }

    fn denumerator_factor(w: &F, sigma: &F, beta: &F, gamma: &F) -> F {
        *w + *beta * sigma + gamma
    }
}
