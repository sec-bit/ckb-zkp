use ark_ff::FftField as Field;
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Evaluations};
use ark_poly_commit::LinearCombination;
use ark_std::{cfg_into_iter, vec, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::data_structures::LabeledPolynomial;

pub struct PermutationKey<F: Field> {
    pub sigma_0: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub sigma_1: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub sigma_2: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub sigma_3: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
}

impl<F: Field> PermutationKey<F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        ark_std::vec![
            &self.sigma_0.0,
            &self.sigma_1.0,
            &self.sigma_2.0,
            &self.sigma_3.0
        ]
        .into_iter()
    }

    pub(crate) fn compute_z(
        &self,
        domain_n: impl EvaluationDomain<F>,
        domain_4n: impl EvaluationDomain<F>,
        k: &[F; 4],
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
                    &w_0[i], &roots[i], &k[0], beta, gamma,
                ) * Self::numerator_factor(
                    &w_1[i], &roots[i], &k[1], beta, gamma,
                ) * Self::numerator_factor(
                    &w_2[i], &roots[i], &k[2], beta, gamma,
                ) * Self::numerator_factor(
                    &w_3[i], &roots[i], &k[3], beta, gamma,
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
        (0..(n - 1)).into_iter().for_each(|i| {
            acc *= perms[i];
            z.push(acc);
        });
        assert_eq!(z[n - 1] * perms[n - 1], F::one());

        let z_poly =
            Evaluations::from_vec_and_domain(z.clone(), domain_n).interpolate();
        let z_4n = domain_4n.coset_fft(&z_poly);

        (z_poly, z, z_4n)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compute_quotient(
        &self,
        domain_4n: impl EvaluationDomain<F>,
        ks: &[F; 4],
        w: (&[F], &[F], &[F], &[F]),
        z: &[F],
        beta: &F,
        gamma: &F,
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

                Self::numerator_factor(
                    &w_0[i],
                    &linear_4n[i],
                    &ks[0],
                    beta,
                    gamma,
                ) * Self::numerator_factor(
                    &w_1[i],
                    &linear_4n[i],
                    &ks[1],
                    beta,
                    gamma,
                ) * Self::numerator_factor(
                    &w_2[i],
                    &linear_4n[i],
                    &ks[2],
                    beta,
                    gamma,
                ) * Self::numerator_factor(
                    &w_3[i],
                    &linear_4n[i],
                    &ks[3],
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
                    ) * z[next]
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn construct_linear_combination(
        k: &[F; 4],
        w_evals: (F, F, F, F),
        z_shifted_eval: F,
        sigma_0_eval: F,
        sigma_1_eval: F,
        sigma_2_eval: F,
        beta: F,
        gamma: F,
        point: F,
    ) -> LinearCombination<F> {
        let (w_0, w_1, w_2, w_3) = w_evals;
        let numerator = (k[0] * beta * point + gamma + w_0)
            * (k[1] * beta * point + gamma + w_1)
            * (k[2] * beta * point + gamma + w_2)
            * (k[3] * beta * point + gamma + w_3);

        let denumerator = (sigma_0_eval * beta + gamma + w_0)
            * (sigma_1_eval * beta + gamma + w_1)
            * (sigma_2_eval * beta + gamma + w_2)
            * beta
            * z_shifted_eval;

        LinearCombination::new(
            "permutation",
            vec![(numerator, "z"), (-denumerator, "sigma_3")],
        )
    }

    fn numerator_factor(w: &F, root: &F, k: &F, beta: &F, gamma: &F) -> F {
        *w + *k * beta * root + gamma
    }

    fn denumerator_factor(w: &F, sigma: &F, beta: &F, gamma: &F) -> F {
        *w + *beta * sigma + gamma
    }
}
