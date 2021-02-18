use ark_ff::FftField as Field;
use ark_poly::{
    univariate::DensePolynomial as Polynomial, GeneralEvaluationDomain,
};

use crate::Vec;

pub struct ProverKey<F: Field> {
    pub q_0: (Polynomial<F>, Vec<F>, Vec<F>),
    pub q_1: (Polynomial<F>, Vec<F>, Vec<F>),
    pub q_2: (Polynomial<F>, Vec<F>, Vec<F>),
    pub q_3: (Polynomial<F>, Vec<F>, Vec<F>),

    pub q_m: (Polynomial<F>, Vec<F>, Vec<F>),
    pub q_c: (Polynomial<F>, Vec<F>, Vec<F>),

    pub q_arith: (Polynomial<F>, Vec<F>, Vec<F>),

    pub domain_n: GeneralEvaluationDomain<F>,
    pub domain_4n: GeneralEvaluationDomain<F>,
}

impl<F: Field> ProverKey<F> {
    pub fn compute_eval_i(
        &self,
        index: usize,
        w_0_i: &F,
        w_1_i: &F,
        w_2_i: &F,
        w_3_i: &F,
    ) -> F {
        let q_0_i = &self.q_0.1[index];
        let q_1_i = &self.q_1.1[index];
        let q_2_i = &self.q_2.1[index];
        let q_3_i = &self.q_3.1[index];
        let q_m_i = &self.q_m.1[index];
        let q_c_i = &self.q_c.1[index];
        let q_arith_i = &self.q_arith.1[index];

        (*q_arith_i)
            * ((*q_0_i) * w_0_i
                + (*q_1_i) * w_1_i
                + (*q_2_i) * w_2_i
                + (*q_3_i) * w_3_i
                + (*q_m_i) * w_1_i * w_2_i
                + (*q_c_i))
    }
}
