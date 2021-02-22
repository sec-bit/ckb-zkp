use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Polynomial,
    UVPolynomial,
};
use ark_std::{cfg_into_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::scalar_mul;

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
        zeta: &F,
        alpha: &F,
    ) -> DensePolynomial<F> {
        let q_0 = &self.q_0.0;
        let q_1 = &self.q_1.0;
        let q_2 = &self.q_2.0;
        let q_3 = &self.q_3.0;
        let q_m = &self.q_m.0;
        let q_c = &self.q_c.0;
        let q_arith = &self.q_arith.0;

        let q_arith_eval = q_arith.evaluate(zeta);

        let poly = scalar_mul(q_0, w_0_eval)
            + scalar_mul(q_1, w_1_eval)
            + scalar_mul(q_2, w_2_eval)
            + scalar_mul(q_3, w_3_eval)
            + scalar_mul(q_m, &(*w_1_eval * w_2_eval));
        let poly = &poly + q_c;

        scalar_mul(&poly, &(q_arith_eval * alpha))
    }

    pub(crate) fn compute_quotient(
        &self,
        domain_4n: impl EvaluationDomain<F>,
        w_0: &[F],
        w_1: &[F],
        w_2: &[F],
        w_3: &[F],
        alpha: &F,
    ) -> Vec<F> {
        let size = domain_4n.size();
        cfg_into_iter!((0..size))
            .map(|i| {
                *alpha
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
