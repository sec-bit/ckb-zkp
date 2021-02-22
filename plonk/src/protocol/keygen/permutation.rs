use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
};
use ark_std::{cfg_into_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::scalar_mul;

pub struct ProverKey<F: Field> {
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
        w_0: &[F],
        w_1: &[F],
        w_2: &[F],
        w_3: &[F],
        beta: &F,
        gamma: &F,
        ks: &[F; 4],
    ) -> (DensePolynomial<F>, Vec<F>, Vec<F>) {
        let n = domain_n.size();
        let roots: Vec<_> = domain_n.elements().collect();

        let perms: Vec<_> = cfg_into_iter!(0..n)
            .map(|i| {
                let numerator = Self::numerator_factor(
                    &w_0[i], &roots[i], &ks[0], beta, gamma,
                ) * Self::numerator_factor(
                    &w_1[i], &roots[i], &ks[1], beta, gamma,
                ) * Self::numerator_factor(
                    &w_2[i], &roots[i], &ks[2], beta, gamma,
                ) * Self::numerator_factor(
                    &w_3[i], &roots[i], &ks[3], beta, gamma,
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

        assert_eq!(n, z.len());
        let z_poly = Evaluations::from_vec_and_domain(z.clone(), domain_n)
            .interpolate();
        let z_evals_ext = domain_4n.fft(&z_poly);

        (z_poly, z, z_evals_ext)
    }
    pub(crate) fn compute_linearisation(
        &self,
        w_0_eval: &F,
        w_1_eval: &F,
        w_2_eval: &F,
        w_3_eval: &F,
        z_shifted_eval: &F,
        z_poly: &DensePolynomial<F>,
        beta: &F,
        gamma: &F,
        zeta: &F,
        alpha: &F,
        ks: &[F; 4],
    ) -> DensePolynomial<F> {
        let alpha_squared = alpha.square();
        let sigma_0_eval = self.sigma_0.0.evaluate(zeta);
        let sigma_1_eval = self.sigma_1.0.evaluate(zeta);
        let sigma_2_eval = self.sigma_2.0.evaluate(zeta);

        let numerator = (ks[0] * beta * zeta + gamma + w_0_eval)
            * (ks[1] * beta * zeta + gamma + w_1_eval)
            * (ks[2] * beta * zeta + gamma + w_2_eval)
            * (ks[3] * beta * zeta + gamma + w_3_eval);

        let denumerator = (sigma_0_eval * beta + gamma + w_0_eval)
            * (sigma_1_eval * beta + gamma + w_1_eval)
            * (sigma_2_eval * beta + gamma + w_2_eval)
            * beta
            * z_shifted_eval;

        scalar_mul(z_poly, &(alpha_squared * numerator))
            + scalar_mul(&self.sigma_3.0, &(-alpha_squared * denumerator))
    }

    pub(crate) fn compute_quotient(
        &self,
        domain_4n: impl EvaluationDomain<F>,
        w_0: &[F],
        w_1: &[F],
        w_2: &[F],
        w_3: &[F],
        z: &[F],
        beta: &F,
        gamma: &F,
        alpha: &F,
        ks: &[F; 4],
    ) -> Vec<F> {
        let size = domain_4n.size();
        let roots: Vec<_> = domain_4n.elements().collect();
        let alpha_squared = alpha.square();

        cfg_into_iter!((0..size))
            .map(|i| {
                let next = if i == size { 0 } else { i + 1 };
                alpha_squared
                    * (Self::numerator_factor(
                        &w_0[i], &roots[i], &ks[0], beta, gamma,
                    ) * Self::numerator_factor(
                        &w_1[i], &roots[i], &ks[1], beta, gamma,
                    ) * Self::numerator_factor(
                        &w_2[i], &roots[i], &ks[2], beta, gamma,
                    ) * Self::numerator_factor(
                        &w_3[i], &roots[i], &ks[3], beta, gamma,
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
            })
            .collect()
    }

    fn numerator_factor(w: &F, root: &F, k: &F, beta: &F, gamma: &F) -> F {
        *w + *k * beta * root + gamma
    }

    fn denumerator_factor(w: &F, sigma: &F, beta: &F, gamma: &F) -> F {
        *w + *beta * sigma + gamma
    }
}
