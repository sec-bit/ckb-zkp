use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Polynomial,
};
use ark_std::{cfg_into_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::utils::scalar_mul;

pub struct ProverKey<F: Field> {
    pub q_0: (DensePolynomial<F>, Vec<F>, Vec<F>),
    pub q_1: (DensePolynomial<F>, Vec<F>, Vec<F>),
    pub q_2: (DensePolynomial<F>, Vec<F>, Vec<F>),
    pub q_3: (DensePolynomial<F>, Vec<F>, Vec<F>),
    pub q_m: (DensePolynomial<F>, Vec<F>, Vec<F>),
    pub q_c: (DensePolynomial<F>, Vec<F>, Vec<F>),
    pub q_arith: (DensePolynomial<F>, Vec<F>, Vec<F>),
}

impl<F: Field> ProverKey<F> {
    pub(crate) fn compute_linearisation(
        &self,
        w_0_eval: &F,
        w_1_eval: &F,
        w_2_eval: &F,
        w_3_eval: &F,
        point: &F,
    ) -> (F, DensePolynomial<F>) {
        let q_0_poly = &self.q_0.0;
        let q_1_poly = &self.q_1.0;
        let q_2_poly = &self.q_2.0;
        let q_3_poly = &self.q_3.0;
        let q_m_poly = &self.q_m.0;
        let q_c_poly = &self.q_c.0;
        let q_arith_eval = self.q_arith.0.evaluate(point);

        let poly = &(scalar_mul(q_0_poly, w_0_eval)
            + scalar_mul(q_1_poly, w_1_eval)
            + scalar_mul(q_2_poly, w_2_eval)
            + scalar_mul(q_3_poly, w_3_eval)
            + scalar_mul(q_m_poly, &(*w_1_eval * w_2_eval)))
            + q_c_poly;

        (q_arith_eval, scalar_mul(&poly, &(q_arith_eval)))
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
