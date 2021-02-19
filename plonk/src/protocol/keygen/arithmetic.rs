use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial as Polynomial, EvaluationDomain,
};
use ark_std::cfg_into_iter;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::Vec;

pub struct ProverKey<F: Field> {
    pub q_0: (Polynomial<F>, Vec<F>, Vec<F>),
    pub q_1: (Polynomial<F>, Vec<F>, Vec<F>),
    pub q_2: (Polynomial<F>, Vec<F>, Vec<F>),
    pub q_3: (Polynomial<F>, Vec<F>, Vec<F>),

    pub q_m: (Polynomial<F>, Vec<F>, Vec<F>),
    pub q_c: (Polynomial<F>, Vec<F>, Vec<F>),

    pub q_arith: (Polynomial<F>, Vec<F>, Vec<F>),
}

impl<F: Field> ProverKey<F> {
    pub(crate) fn compute_quotient(
        &self,
        domain_4n: impl EvaluationDomain<F>,
        w_0: &[F],
        w_1: &[F],
        w_2: &[F],
        w_3: &[F],
        factor: &F,
    ) -> Vec<F> {
        let size = domain_4n.size();
        cfg_into_iter!((0..size))
            .map(|i| {
                *factor
                    * Self::evaluate(
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
                    )
            })
            .collect()
    }

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
    ) -> F {
        let zero = F::zero();
        if q_arith.is_zero() {
            F::zero()
        } else {
            (*q_0) * w_0
                + (*q_1) * w_1
                + (*q_2) * w_2
                + (*q_3) * w_3
                + (*q_m) * w_1 * w_2
                + (*q_c)
        }
    }
}
