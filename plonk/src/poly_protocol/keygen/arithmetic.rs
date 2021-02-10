use ark_ff::FftField as Field;
use ark_poly::{univariate::DensePolynomial as Polynomial, Evaluations};

pub struct ProverKey<F: Field> {
    pub q_0: (Polynomial<F>, Evaluations<F>),
    pub q_1: (Polynomial<F>, Evaluations<F>),
    pub q_2: (Polynomial<F>, Evaluations<F>),
    pub q_3: (Polynomial<F>, Evaluations<F>),

    pub q_m: (Polynomial<F>, Evaluations<F>),
    pub q_c: (Polynomial<F>, Evaluations<F>),

    pub q_arith: (Polynomial<F>, Evaluations<F>),
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
