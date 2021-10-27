use ark_ff::FftField as Field;
use crate::LabeledPolynomial;
use ark_poly::EvaluationDomain;
use ark_poly_commit::LinearCombination;
use ark_std::{cfg_into_iter, vec, vec::Vec};

pub struct MimcKey<F: Field> {
    pub q_mimc: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    //pub q_mimc_c: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
}

impl<F: Field> MimcKey<F>{
    pub(crate) fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        vec![
            &self.q_mimc.0,
            //&self.q_mimc_c.0,
        ]
            .into_iter()
    }

    pub(crate) fn compute_quotient(
        &self,
        domain_4n: impl EvaluationDomain<F> + Sync,
        w_4n: (&[F], &[F], &[F], &[F]),
        alpha: &F,
    ) -> Vec<F> {
        let alpha_2 = alpha.square();
        let alpha_4 = alpha_2.square();
        let alpha_8 = alpha_4.square();
        let alpha_7 :F = alpha_4 * alpha_2 * alpha;

        let (w_0_4n, w_1_4n, w_2_4n, w_3_4n) = w_4n;
        let size = domain_4n.size();
        let q_mimc_2 = &self.q_mimc.2;
        //let q_mimc_c_2 = &self.q_mimc_c.2;

        cfg_into_iter!((0..size))
            .map(|i| {
                let next = if i / 4 == (size / 4 - 1) {
                    i % 4
                } else {
                    i + 4
                };
                if q_mimc_2[i].is_zero() {
                    F::zero()
                } else {
                    let tmp :F = w_1_4n[i] + w_0_4n[i] + w_3_4n[i];
                    q_mimc_2[i] * (
                        alpha_7 * (w_2_4n[i] - tmp.square() * tmp)
                        + alpha_8 * (w_0_4n[next] - w_2_4n[i].square() * tmp)
                        )
                }
            })
            .collect()
    }

    pub(crate) fn construct_linear_combination(
        w_zeta: (F, F, F, F),
        w_0_shifted_zeta: F,
        alpha: F,
    ) -> LinearCombination<F> {
        let (w_0, w_1, w_2, w_3) = w_zeta;

        let alpha_2 = alpha.square();
        let alpha_4 = alpha_2.square();
        let alpha_8 = alpha_4.square();
        let alpha_7 :F = alpha_4 * alpha_2 * alpha;

        let tmp :F = w_1 + w_0 + w_3;

        LinearCombination::new(
            "mimc",
            vec![
                (alpha_7 * (w_2 - tmp.square() * tmp) + alpha_8 * (w_0_shifted_zeta - w_2.square() * tmp),
                 "q_mimc"),
            ],
        )
    }

    pub(crate) fn compute_quotient_nosponge(
        &self,
        domain_4n: impl EvaluationDomain<F> + Sync,
        w_4n: (&[F], &[F], &[F], &[F]),
        alpha: &F,
    ) -> Vec<F> {
        let alpha_2 = alpha.square();
        let alpha_4 = alpha_2.square();
        let alpha_8 = alpha_4.square();
        let alpha_7 :F = alpha_4 * alpha_2 * alpha;

        let (w_0_4n, w_1_4n, w_2_4n, w_3_4n) = w_4n;
        let size = domain_4n.size();
        let q_mimc_2 = &self.q_mimc.2;
        //let q_mimc_c_2 = &self.q_mimc_c.2;

        cfg_into_iter!((0..size))
            .map(|i| {
                let next = if i / 4 == (size / 4 - 1) {
                    i % 4
                } else {
                    i + 4
                };
                if q_mimc_2[i].is_zero() {
                    F::zero()
                } else {
                    let tmp :F = w_0_4n[i] + w_2_4n[i];
                    q_mimc_2[i] * (
                        alpha_7 * (w_3_4n[i] - tmp.square() * tmp)
                            + alpha_8 * (w_0_4n[next] - w_3_4n[i] - w_1_4n[i])
                    )
                }
            })
            .collect()
    }

    pub(crate) fn construct_linear_combination_nosponge(
        w_zeta: (F, F, F, F),
        w_0_shifted_zeta: F,
        alpha: F,
    ) -> LinearCombination<F> {
        let (w_0, w_1, w_2, w_3) = w_zeta;

        let alpha_2 = alpha.square();
        let alpha_4 = alpha_2.square();
        let alpha_8 = alpha_4.square();
        let alpha_7 :F = alpha_4 * alpha_2 * alpha;

        let tmp :F = w_2 + w_0;

        LinearCombination::new(
            "mimc",
            vec![
                (alpha_7 * (w_3 - tmp.square() * tmp) + alpha_8 * (w_0_shifted_zeta - w_3 - w_1),
                 "q_mimc"),
            ],
        )
    }

}