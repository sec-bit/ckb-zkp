use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain,
    Evaluations, GeneralEvaluationDomain,
};
use ark_std::cfg_into_iter;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::Vec;

pub struct ProverKey<F: Field> {
    pub sigma_0: (Polynomial<F>, Vec<F>, Vec<F>),
    pub sigma_1: (Polynomial<F>, Vec<F>, Vec<F>),
    pub sigma_2: (Polynomial<F>, Vec<F>, Vec<F>),
    pub sigma_3: (Polynomial<F>, Vec<F>, Vec<F>),

    pub domain_n: GeneralEvaluationDomain<F>,
    pub domain_4n: GeneralEvaluationDomain<F>,
}

impl<F: Field> ProverKey<F> {
    pub(crate) fn compute_z_poly(
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
    ) -> (Polynomial<F>, Vec<F>, Vec<F>) {
        let n = domain_n.size();
        let roots: Vec<_> = domain_n.elements().collect();

        let perms: Vec<_> = cfg_into_iter!(0..domain_n.size())
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

    pub(crate) fn numerator_factor(
        w: &F,
        root: &F,
        k: &F,
        beta: &F,
        gamma: &F,
    ) -> F {
        *w + *k * beta * root + gamma
    }

    pub(crate) fn denumerator_factor(
        w: &F,
        sigma: &F,
        beta: &F,
        gamma: &F,
    ) -> F {
        *w + *beta * sigma + gamma
    }

    pub(crate) fn compute_copy_ext_i(
        &self,
        index: usize,
        w_0_i: &F,
        w_1_i: &F,
        w_2_i: &F,
        w_3_i: &F,
        z_i: &F,
        beta: &F,
        gamma: &F,
    ) -> F {
        let sigma_0_i = &self.sigma_0.1[index];
        let sigma_1_i = &self.sigma_1.1[index];
        let sigma_2_i = &self.sigma_2.1[index];
        let sigma_3_i = &self.sigma_3.1[index];

        F::zero()
    }
}
