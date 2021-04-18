use ark_ff::FftField as Field;
use ark_poly::EvaluationDomain;
use ark_poly_commit::LinearCombination;
use ark_std::{cfg_into_iter, vec, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::data_structures::LabeledPolynomial;

pub struct ArithmeticKey<F: Field> {
    pub q_0: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_1: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_2: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_3: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_m: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_c: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_arith: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
}

impl<F: Field> ArithmeticKey<F> {
    pub(crate) fn construct_linear_combination(
        w_zeta: (F, F, F, F),
        q_arith_zeta: F,
    ) -> LinearCombination<F> {
        let (w_0_eval, w_1_eval, w_2_eval, w_3_eval) = w_zeta;
        LinearCombination::new(
            "arithmetic",
            vec![
                (q_arith_zeta * w_0_eval, "q_0"),
                (q_arith_zeta * w_1_eval, "q_1"),
                (q_arith_zeta * w_2_eval, "q_2"),
                (q_arith_zeta * w_3_eval, "q_3"),
                (q_arith_zeta * w_1_eval * w_2_eval, "q_m"),
                (q_arith_zeta, "q_c"),
            ],
        )
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        vec![
            &self.q_0.0,
            &self.q_1.0,
            &self.q_2.0,
            &self.q_3.0,
            &self.q_m.0,
            &self.q_c.0,
            &self.q_arith.0,
        ]
        .into_iter()
    }

    pub(crate) fn compute_quotient(
        &self,
        domain_4n: impl EvaluationDomain<F> + Sync,
        w_4n: (&[F], &[F], &[F], &[F]),
        pi_4n: &[F],
    ) -> Vec<F> {
        let size = domain_4n.size();
        let (w_0_4n, w_1_4n, w_2_4n, w_3_4n) = w_4n;
        let q_0_2 = &self.q_0.2;
        let q_1_2 = &self.q_1.2;
        let q_2_2 = &self.q_2.2;
        let q_3_2 = &self.q_3.2;
        let q_m_2 = &self.q_m.2;
        let q_c_2 = &self.q_c.2;
        let q_arith_2 = &self.q_arith.2;

        cfg_into_iter!((0..size))
            .map(|i| {
                Self::evaluate(
                    &w_0_4n[i],
                    &w_1_4n[i],
                    &w_2_4n[i],
                    &w_3_4n[i],
                    &q_0_2[i],
                    &q_1_2[i],
                    &q_2_2[i],
                    &q_3_2[i],
                    &q_m_2[i],
                    &q_c_2[i],
                    &q_arith_2[i],
                    &pi_4n[i],
                )
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate(
        w_0: &F,
        w_1: &F,
        w_2: &F,
        w_3: &F,
        q_0: &F,
        q_1: &F,
        q_2: &F,
        q_3: &F,
        q_m: &F,
        q_c: &F,
        q_arith: &F,
        pi: &F,
    ) -> F {
        if q_arith.is_zero() {
            F::zero()
        } else {
            (*q_0 * w_0
                + (*q_1) * w_1
                + (*q_2) * w_2
                + (*q_3) * w_3
                + (*q_m) * w_1 * w_2
                + q_c
                + pi)
                * q_arith
        }
    }
}
