use ark_ff::FftField as Field;
use ark_poly::{univariate::DensePolynomial as Polynomial, Evaluations};

pub struct ProverKey<F: Field> {
    pub sigma_0: (Polynomial<F>, Evaluations<F>),
    pub sigma_1: (Polynomial<F>, Evaluations<F>),
    pub sigma_2: (Polynomial<F>, Evaluations<F>),
    pub sigma_3: (Polynomial<F>, Evaluations<F>),
}
