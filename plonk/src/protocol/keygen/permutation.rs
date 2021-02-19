use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain,
    Evaluations,
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
    ) -> (Polynomial<F>, Vec<F>, Vec<F>) {
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

    pub(crate) fn compute_quotient_identity(
        &self,
        domain_4n: impl EvaluationDomain<F>,
        w_0: &[F],
        w_1: &[F],
        w_2: &[F],
        w_3: &[F],
        z: &[F],
        beta: &F,
        gamma: &F,
        ks: &[F; 4],
        factor: &F,
    ) -> Vec<F> {
        let size = domain_4n.size();
        let roots: Vec<_> = domain_4n.elements().collect();

        cfg_into_iter!((0..size))
            .map(|i| {
                *factor
                    * Self::numerator_factor(
                        &w_0[i], &roots[i], &ks[0], beta, gamma,
                    )
                    * Self::numerator_factor(
                        &w_1[i], &roots[i], &ks[1], beta, gamma,
                    )
                    * Self::numerator_factor(
                        &w_2[i], &roots[i], &ks[2], beta, gamma,
                    )
                    * Self::numerator_factor(
                        &w_3[i], &roots[i], &ks[3], beta, gamma,
                    )
                    * z[i]
            })
            .collect()
    }

    pub(crate) fn compute_quotient_copy(
        &self,
        domain_4n: impl EvaluationDomain<F>,
        w_0: &[F],
        w_1: &[F],
        w_2: &[F],
        w_3: &[F],
        z: &[F],
        beta: &F,
        gamma: &F,
        factor: &F,
    ) -> Vec<F> {
        let size = domain_4n.size();
        cfg_into_iter!((0..size))
            .map(|i| {
                let next = if i == size { 0 } else { i + 1 };
                *factor
                    * Self::denumerator_factor(
                        &w_0[i],
                        &self.sigma_0.2[i],
                        beta,
                        gamma,
                    )
                    * Self::denumerator_factor(
                        &w_1[i],
                        &self.sigma_1.2[i],
                        beta,
                        gamma,
                    )
                    * Self::denumerator_factor(
                        &w_2[i],
                        &self.sigma_2.2[i],
                        beta,
                        gamma,
                    )
                    * Self::denumerator_factor(
                        &w_3[i],
                        &self.sigma_3.2[i],
                        beta,
                        gamma,
                    )
                    * z[next]
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
