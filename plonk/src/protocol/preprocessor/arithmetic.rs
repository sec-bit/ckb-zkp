use ark_ff::FftField as Field;
use ark_poly::EvaluationDomain;
use ark_poly_commit::LinearCombination;
use ark_std::{cfg_into_iter, vec, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::data_structures::LabeledPolynomial;

pub struct Key<F: Field> {
    pub q_0: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_1: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_2: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_3: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_m: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_c: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
    pub q_arith: (LabeledPolynomial<F>, Vec<F>, Vec<F>),
}

impl<F: Field> Key<F> {
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
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

    pub(crate) fn compute_linearisation(
        &self,
        w_evals: (F, F, F, F),
        q_arith_eval: F,
    ) -> LinearCombination<F> {
        let (w_0_eval, w_1_eval, w_2_eval, w_3_eval) = w_evals;
        let mut lc = LinearCombination::new(
            "arithmetic",
            vec![
                (w_0_eval, "q_0"),
                (w_1_eval, "q_1"),
                (w_2_eval, "q_2"),
                (w_3_eval, "q_q_3"),
                (w_1_eval * w_2_eval, "q_m"),
                (F::one(), "q_c"),
            ],
        );
        lc *= q_arith_eval;
        lc
    }

    pub(crate) fn compute_quotient(
        &self,
        domain_4n: impl EvaluationDomain<F>,
        w_0: &[F],
        w_1: &[F],
        w_2: &[F],
        w_3: &[F],
        pi: &[F],
    ) -> Vec<F> {
        let size = domain_4n.size();
        cfg_into_iter!((0..size))
            .map(|i| {
                Self::evaluate(
                    &w_0[i],
                    &w_1[i],
                    &w_2[i],
                    &w_3[i],
                    &self.q_0.2[i],
                    &self.q_1.2[i],
                    &self.q_2.2[i],
                    &self.q_3.2[i],
                    &self.q_m.2[i],
                    &self.q_c.2[i],
                    &self.q_arith.2[i],
                    &pi[i],
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
