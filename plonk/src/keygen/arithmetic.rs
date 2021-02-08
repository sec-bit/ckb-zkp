use ark_ff::FftField as Field;
use ark_poly::{univariate::DensePolynomial as Polynomial, Evaluations};

pub struct ProverKey<F: Field> {
    pub q_0: (Polynomial<F>, Evaluations<F>),
    pub q_1: (Polynomial<F>, Evaluations<F>),
    pub q_2: (Polynomial<F>, Evaluations<F>),
    pub q_3: (Polynomial<F>, Evaluations<F>),

    pub q_m: (Polynomial<F>, Evaluations<F>),
    pub q_c: (Polynomial<F>, Evaluations<F>),
    pub pi: (Polynomial<F>, Evaluations<F>),

    pub q_arith: (Polynomial<F>, Evaluations<F>),
}
